import io
import logging
import os
import struct

from curio import socket
import curio

from ssh.stream import Buffer
from . import encryption as enc
from . import message as msg
from . import mac
DEBUG = logging.DEBUG
logger = logging.getLogger("ssh")


def code_to_desc(code):
    try:
        return msg.HANDLERS.get(code).desc
    except Exception:
        return str(code)


class Packet:
    min_size: int = 16
    block_size: int = 8

    def __init__(
        self,
        data: bytes | None = None,
        payload: bytes | None = None,
        packet_length: int = 0,
        padding_length: int = 0,
    ):
        self.packet_length = packet_length
        self.padding_length = padding_length
        self.raw_data = data  # raw packet to send
        self.payload = payload  # main paload
        self.opcode = payload[0] if payload else 0

    @classmethod
    def build(cls, payload: bytes, block_size=8, etm=False) -> "Packet":
        # https://datatracker.ietf.org/doc/html/rfc4253#section-6
        block_size = max(block_size, cls.block_size)
        # etm mode, 4 bytes to make up for packet length which is not included in encrypted data
        # encrypted separately
        addlen = 4 if etm else 0
        padding_length = (addlen + block_size) - ((4 + 1 + len(payload)) % block_size)
        if padding_length < 4:
            padding_length += block_size
        packet_length = 1 + len(payload) + padding_length  # 1 is len(len(padding))
        total_size = 4 + packet_length
        min_size = max(block_size, cls.min_size)
        if total_size < min_size:
            add = min_size - total_size
            packet_length += add + addlen
            total_size += add + addlen
            padding_length += add + addlen
        padding = os.urandom(padding_length)
        packet = struct.pack(">IB", packet_length, padding_length) + payload + padding
        assert total_size % block_size == addlen, f"{total_size} % {block_size} != {addlen}"
        return Packet(
            data=packet,
            packet_length=packet_length,
            padding_length=padding_length,
        )

    def __bytes__(self):
        return bytes(self.raw_data)


class KexInfo:
    pass


class Connection:
    recv_size = 2048
    block_size = 8

    def __init__(self) -> None:
        self.sock = None
        self.buf = None
        self.seq_no = 0
        self.server_seq_no = 0
        self.encrypted = False
        self.block_size = 8
        self.client_mac = self.server_mac = None
        self.server_enc = self.client_enc = None
        self.lock = curio.Lock()
        self.wlock = curio.Lock()

    async def connect(self, host: str, port: int) -> None:
        if self.sock is None:
            self.sock = socket.socket()
        await self.sock.connect((host, port))
        self.buf = self.sock.makefile("rb")
        

    async def read(self, size: int) -> bytes:
        data = await self.buf.read(size)
        while len(data) < size:
            b = await self.buf.read(size - len(data))
            if not b:
                raise ConnectionAbortedError("server closed")
            data += b
        return data

    async def read_packet(self) -> Packet:
        async with self.lock:
            if self.encrypted:
                return await self.read_encrypted_packet()
            size = int.from_bytes(await self.read(4))
            padding_length = int.from_bytes(await self.read(1))
            payload = await self.read(size - padding_length - 1)
            padding = await self.read(padding_length)
            assert (
                4 + 1 + len(payload) + len(padding)
            ) % self.block_size == 0, " block_size != 0"
            p = Packet(payload=payload)
            logger.log(
                logging.DEBUG,
                f"[incoming packet_length={size} opcode={code_to_desc(p.opcode)}]",
            )
            self.server_seq_no += 1 & 0xFFFFFFFF
        return p

    async def read_encrypted_packet(self) -> Packet:
        decrypt = self.server_enc.decrypt
        addlen = 4 if self.server_enc.etm else 0
        if self.server_enc.etm:
            encrypted_size = await self.read(4)
            size = int.from_bytes(self.server_enc.decrypt_size(encrypted_size, self.server_seq_no))
            data = await self.read(size)
            mac = await self.read(16)
            assert self.server_enc.verify(encrypted_size + data, mac, self.server_seq_no), "mac verification failed"
            data = io.BytesIO(decrypt(data, self.server_seq_no))
        else:
            size = int.from_bytes(decrypt(await self.read(4)))
            data = io.BytesIO(decrypt(await self.read(size)))
        padding_length = data.read(1)[0]
        payload = data.read(size - padding_length - 1)
        padding = data.read(padding_length)
        assert (
            (4 + 1 + len(payload) + len(padding)) % self.block_size == addlen
        ), f" block_size != addlen {size+4} % {self.block_size} != {addlen}"
        p = Packet(payload=payload)
        if self.server_enc.etm:
            # mac has been verified above
            pass
        else:
            mac = await self.read(self.server_mac.size)
            my_mac = self.server_mac.digest(
                struct.pack(">IIB", self.server_seq_no, size, padding_length)
                + payload
                + padding
            )
            assert mac == my_mac, "mac mismatch: %s != %s" % (mac.hex(), my_mac.hex())
        logger.log(
            logging.DEBUG,
            f"[incoming encrypted packet_length={size} opcode={code_to_desc(p.opcode)}]",
        )
        # self.server_enc.finalize()
        self.server_seq_no += 1 & 0xFFFFFFFF
        return p

    async def send_encrypted_packet(self):
        pass

    # def compute_mac(self,algo,data)
    async def send_packet(self, data: bytes) -> None:
        async with self.wlock:
            s = ""
            etm = False
            if self.encrypted:
                s = "encrypted"
                etm = self.client_enc.etm
            cmd = code_to_desc(data[0])
            p = Packet.build(data, block_size=self.block_size, etm=etm)
            data = bytes(p)
            assert p.packet_length + 4 == len(data), "%s != %s" % (
                p.packet_length + 4,
                len(data),
            )
            logger.log(
                logging.DEBUG,
                f"[{s} outgoing] {cmd=} {p.packet_length=} {len(data)=} {p.padding_length=}",
            )
            mac = b""
            if self.encrypted:
                if self.client_enc.etm:
                    data = self.client_enc.encrypt(data, self.seq_no)
                    mac = self.client_enc.digest(data, self.seq_no)
                else:
                    mac = self.client_mac.digest(int.to_bytes(self.seq_no, 4) + data)
                    data = self.client_enc.encrypt(data)
            await self.sock.sendall(data + mac)
            self.seq_no += 1 & 0xFFFFFFFF

    async def send(self, data: bytes) -> None:
        await self.sock.send(data)

    async def readline(self) -> bytes:
        return await self.buf.readline()

    def set_block_size(self, block_size: int) -> None:
        self.block_size = block_size

    def set_encryptor(self, client: enc.AES | enc.ChaCha20Poly1305, server: enc.AES | enc.ChaCha20Poly1305) -> None:
        self.client_enc = client
        self.server_enc = server

    def set_mac_algo(self, client: mac.HMAC, server: mac.HMAC) -> None:
        self.client_mac = client
        self.server_mac = server

    def start_encryption(self)  -> None:
        # return
        self.encrypted = True
        self.block_size = self.client_enc.block_size
        # self.server_seq_no = self.seq_no = 0

    async def close(self):
        if self.sock:
            await self.sock.close()
