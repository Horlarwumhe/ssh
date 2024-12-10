import logging
import os

import trio

from ssh import util
from ssh.stream import Buffer

from . import encryption as enc
from . import kex, mac
from . import message as msg
from .packet import Connection

DEBUG = logging.DEBUG


class SSHClient:
    version = "SSH-2.0-to_be_determined"
    available_kex_algo: dict[str, kex.DHKex] = {
        "diffie-hellman-group14-sha256": kex.DHGroup14SHA256,
        "diffie-hellman-group16-sha512": kex.DHGroup16SHA512,
        "curve25519-sha256": str,
        "diffie-hellman-group14-sha1": kex.DHGroup14SHA1,
        "diffie-hellman-group1-sha1": kex.DHGroup1SHA1,
        "diffie-hellman-group18-sha512": kex.DHGroup18SHA512,
    }
    available_encryption_algo: dict[str, enc.AES] = {
        "aes256-ctr": enc.AESCTR256,
        "aes128-ctr": enc.AESCTR128,
        "aes192-ctr": enc.AESCTR192,
    }
    available_mac_algo: dict[str, mac.HMAC] = {
        "none": None,
        "hmac-sha2-256": mac.HMACSHA256,
        "hmac-sha2-512": mac.HMACSHA512,
        "hmac-sha1": mac.HMACSHA1,
    }

    available_server_host_key_algo: dict[str, callable] = {
        "rsa-sha2-512": key.RSAKey,
        "rsa-sha2-256": key.RSAKey,
    }

    def __init__(self) -> None:
        self.sock = Connection()
        self.logger = logging.getLogger("ssh")
        self.kex_algo = None
        self.server_host_key_algo = None
        self.encryption_algo = None
        self.mac_algo = None
        self.compression_algo = None
        self.kex_init = None
        self.server_kex_init = None
        self.kex_result = None
        self.session_id = None

    async def connect(self, host, port, start_kex=False):
        await self.sock.connect(host, port)
        while True:
            line = await self.sock.readline()
            if line.startswith(b"SSH-"):
                self.remote_version = line.decode().strip()
                self._log(
                    logging.INFO, " setting remote_version %s" % self.remote_version
                )
                break
            self.logger.info("got %s" % line)
            if not line:
                raise ConnectionResetError("server diconnnected")
        await self.sock.send(self.version.encode() + b"\r\n")
        if start_kex:
            await self.start_kex()

    async def get_packets(self):
        pass

    async def run(self):
        async with trio.open_nursery() as nursery:
            nursery.start_soon(self.loop, "a")
            nursery.start_soon(self.loop, "b")

    async def start_kex(self):
        req = msg.SSHMsgKexInit(
            cookie=os.urandom(16),
            kex_algo=list(self.available_kex_algo.keys()),
            server_host_key_algo=list(self.available_server_host_key_algo),
            encryption_algo_client_to_server=list(
                self.available_encryption_algo.keys()
            ),
            encryption_algo_server_to_client=list(
                self.available_encryption_algo.keys()
            ),
            mac_algo_client_to_server=list(self.available_mac_algo.keys()),
            mac_algo_server_to_client=list(self.available_mac_algo.keys()),
            compression_algo_client_to_server=list(("none",)),
            compression_algo_server_to_client=list(("none",)),
            languages_client_to_server=list(),
            languages_server_to_client=list(),
            first_kex_packet_follows=False,
        )
        await self.sock.send_packet(bytes(req))
        packet = await self.sock.read_packet()
        resp = msg.HANDLERS[packet.opcode].parse(Buffer(packet.payload))
        self.server_kex_init = resp
        self.kex_init = req
        self.set_algos(resp)
        self.logger.log(DEBUG, "Kex algo: %s", " ,".join(resp.kex_algo))
        kex_result = await self.available_kex_algo[self.kex_algo](self).start()
        if not self.session_id:
            self.session_id = kex_result.H
        self.set_ciphers(kex_result.K, kex_result.H)
        await self.end_kex_init()
        self.sock.start_encryption()
        # await self.sock.send_packet(bytes(self.kex_init))

    def set_algos(self, server_kex: msg.SSHMsgKexInit):
        self.kex_algo = list(
            filter(lambda x: x in server_kex.kex_algo, self.available_kex_algo)
        )[0]
        self.server_host_key_algo = list(
            filter(
                lambda x: x in server_kex.server_host_key_algo,
                self.available_server_host_key_algo,
            )
        )[0]
        self.encryption_algo = list(
            filter(
                lambda x: x in server_kex.encryption_algo_client_to_server,
                self.available_encryption_algo,
            )
        )[0]
        self.mac_algo = list(
            filter(
                lambda x: x in server_kex.mac_algo_client_to_server,
                self.available_mac_algo,
            )
        )[0]
        self.compression_algo = "none"  # TODO
        self.logger.log(logging.DEBUG, "Kex Algo: %s", self.kex_algo)
        self.logger.log(
            logging.DEBUG, "server host key algo: %s", self.server_host_key_algo
        )
        self.logger.log(logging.DEBUG, "encryption algo: %s", self.encryption_algo)
        self.logger.log(logging.DEBUG, "mac algo: %s", self.mac_algo)
        self.logger.log(logging.DEBUG, "compression algo: %s", self.compression_algo)

    def set_ciphers(self, K, H):
        # K || H || "A" || session_id)
        # https://datatracker.ietf.org/doc/html/rfc4253#section-7.2
        # Dont use any cipher or mac algo that needs key greater choosen sha
        b = util.deflate_long(K)
        K = int.to_bytes(len(b), 4) + b  # mpint encoded
        hash_algo = self.available_kex_algo[self.kex_algo].hash_algo
        encryptor = self.available_encryption_algo[self.encryption_algo]
        key_size, iv_size = encryptor.key_size, encryptor.block_size
        mac_algo = self.available_mac_algo[self.mac_algo]
        if mac_algo is None:
            pass
        else:
            mac_size = mac_algo.size
        client_to_server_iv = hash_algo(K + H + b"A" + self.session_id)[:iv_size]
        server_to_client_iv = hash_algo(K + H + b"B" + self.session_id)[:iv_size]
        client_to_server_key = hash_algo(K + H + b"C" + self.session_id)[:key_size]
        server_to_client_key = hash_algo(K + H + b"D" + self.session_id)[:key_size]
        if mac_algo is not None:
            client_to_server_mac = hash_algo(K + H + b"E" + self.session_id)[:mac_size]
            server_to_client_mac = hash_algo(K + H + b"F" + self.session_id)[:mac_size]
            self.sock.set_mac_algo(
                mac_algo(client_to_server_mac), mac_algo(server_to_client_mac)
            )

        self.sock.set_encryptor(
            encryptor(client_to_server_key, client_to_server_iv),
            encryptor(server_to_client_key, server_to_client_iv),
        )
        assert len(client_to_server_iv) == iv_size, (
            "(iv size) %s != cipher iv_size (%s)" % (len(client_to_server_iv), iv_size)
        )
        assert len(client_to_server_key) == key_size, (
            "(key size) %s != cipher key_size (%s)"
            % (len(client_to_server_iv), key_size)
        )
        if mac_algo:
            assert len(client_to_server_mac) == mac_size, (
                "(mac key size) %s != mac key_size (%s)"
                % (len(client_to_server_mac), mac_size)
            )

    async def end_kex_init(self):
        req = msg.SSHMsgNewKeys()
        await self.sock.send_packet(bytes(req))
        packet = await self.sock.read_packet()
        self.logger.log(DEBUG, "New keys: %s", packet.opcode)

    def _log(self, level, message):
        self.logger.log(level, message)
