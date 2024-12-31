import io
import logging
import os
import struct

from curio import socket
import curio

from ssh.stream import Buffer

from . import message as msg

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
    def build(cls, payload: bytes, block_size=8) -> "Packet":
        # https://datatracker.ietf.org/doc/html/rfc4253#section-6
        block_size = max(block_size, cls.block_size)
        padding_length = block_size - ((4 + 1 + len(payload)) % block_size)
        if padding_length < 4:
            padding_length += block_size
        packet_length = 1 + len(payload) + padding_length  # 1 is len(len(padding))
        total_size = 4 + packet_length
        min_size = max(block_size, cls.min_size)
        if total_size < min_size:
            add = min_size - total_size
            packet_length += add
            total_size += add
            padding_length += add
        padding = os.urandom(padding_length)
        buf = Buffer()
        buf.write_int(packet_length)
        buf.write_byte(int.to_bytes(padding_length, 1))
        buf.write_byte(payload)
        buf.write_byte(padding)
        assert total_size % block_size == 0
        return Packet(
            data=buf.getvalue(),
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
        self.buf = io.BytesIO()
        self.seq_no = 0
        self.server_seq_no = 0
        self.encrypted = False
        self.block_size = 8
        self.client_mac = self.server_mac = None
        self.server_enc = self.client_enc = None
        self.lock = curio.Lock()
        self.wlock = curio.Lock()

    async def connect(self, host, port):
        if self.sock is None:
            self.sock = socket.socket()
        await self.sock.connect((host, port))

    async def read(self, size):
        data = self.buf.read(size)
        while len(data) < size:
            pos = self.buf.tell()
            b = await self.sock.recv(size * 4)  # read upto 4x requested size
            if not b:
                raise ConnectionAbortedError("server closed")
            self.buf.seek(0, os.SEEK_END)
            self.buf.write(b)
            self.buf.seek(pos)
            data += self.buf.read(size - len(data))
        return data

    async def read_packet(self):
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

    async def read_encrypted_packet(self):
        decrypt = self.server_enc.decrypt
        size = int.from_bytes(decrypt(await self.read(4)))
        padding_length = int.from_bytes(decrypt(await self.read(1)))
        payload = decrypt(await self.read(size - padding_length - 1))
        padding = decrypt(await self.read(padding_length))
        assert (
            4 + 1 + len(payload) + len(padding)
        ) % self.block_size == 0, " block_size != 0"
        p = Packet(payload=payload)
        mac = await self.read(self.server_mac.size)
        my_mac = self.server_mac.digest(
            struct.pack(">IIB", self.server_seq_no, size, padding_length)
            + payload
            + padding
        )
        assert mac == my_mac, (
            "error computed mac not match server mac mac(%s) != my_mac(%s) "
            % (mac.hex(), my_mac.hex())
        )
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
    async def send_packet(self, data: bytes):
        async with self.wlock:
            s = ""
            if self.encrypted:
                s = "encrypted"
            cmd = code_to_desc(data[0])
            p = Packet.build(data, block_size=self.block_size)
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
                mac = self.client_mac.digest(int.to_bytes(self.seq_no, 4) + data)
                data = self.client_enc.encrypt(data)
            await self.sock.sendall(data + mac)
            self.seq_no += 1 & 0xFFFFFFFF

    async def send(self, data):
        await self.sock.send(data)

    async def readline(self):
        line = self.buf.readline()
        if not line.endswith(b"\n"):
            pos = self.buf.tell()
            data = await self.sock.recv(self.recv_size)
            self.buf.seek(0, os.SEEK_END)
            self.buf.write(data)
            self.buf.seek(pos)
            line += self.buf.readline()
        return line

    def set_block_size(self, block_size):
        self.block_size = block_size

    def set_encryptor(self, client, server):
        self.client_enc = client
        self.server_enc = server

    def set_mac_algo(self, client, server):
        self.client_mac = client
        self.server_mac = server

    def start_encryption(self):
        # return
        self.encrypted = True
        self.block_size = self.client_enc.block_size
        # self.server_seq_no = self.seq_no = 0

    async def close(self):
        await self.sock.close()
