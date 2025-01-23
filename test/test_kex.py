from ssh import kex
from ssh.client import SSHClient
from ssh.message import (
    SSHMsgKexInit,
    SSHMessageKexDHReply,
    SSHSignature,
    SSHMsgKexECDHReply,
)
import os
import pytest


class KexResult:
    H: bytes
    K: bytes


class DHKex(kex.DHKex):
    def __init__(self, client: SSHClient):
        self.client = client

    async def send_kex_init(self, e):
        self.e = e

    async def start(self):
        res = await super().start()
        server = KexResult()
        server.H = self.server_H
        server.K = self.server_K
        return server, res

    async def receive_kex_reply(self):
        # Simulate the server sending a KEXDH_REPLY message
        key = self.client.available_server_host_key_algo[
            self.client.server_host_key_algo
        ]
        host_key = key.generate()
        y, f = self.generate_key_pair()
        K = self.compute_shared_secret(self.e, y)
        H = self.compute_signature_hash(bytes(host_key), self.e, f, K)
        sig = host_key.sign(H, self.client.server_host_key_algo)
        sig = bytes(SSHSignature(sig=sig, algo=self.client.server_host_key_algo))
        self.server_H = H
        self.server_K = K
        return SSHMessageKexDHReply(
            host_key=bytes(host_key),
            f=f,
            sig=sig,
        )


class Curve25519(kex.Curve25519):
    async def send_kex_init(self, pub):
        self.client_pub = pub

    async def start(self):
        res = await super().start()
        server = KexResult()
        server.H = self.server_H
        server.K = self.server_K
        return server, res

    async def receive_kex_reply(self):
        # Simulate the server sending a KEXECDH_REPLY message
        key = self.client.available_server_host_key_algo[
            self.client.server_host_key_algo
        ]
        host_key = key.generate()
        pk, pub = self.generate_key_pair()
        K = self.compute_shared_secret(pk, self.client_pub)
        H = self.compute_signature_hash(bytes(host_key), self.client_pub, pub, K)
        sig = host_key.sign(H, self.client.server_host_key_algo)
        sig = bytes(SSHSignature(sig=sig, algo=self.client.server_host_key_algo))
        self.server_H = H
        self.server_K = K
        return SSHMsgKexECDHReply(
            host_key=bytes(host_key),
            pub_key=pub,
            sig=sig,
        )


class DHGroup1SHA1(DHKex, kex.DHGroup1SHA1):
    pass


class DHGroup14SHA1(DHKex, kex.DHGroup1SHA1):
    pass


class DHGroup14SHA256(DHKex, kex.DHGroup14SHA256):
    pass


class DHGroup16SHA512(DHKex, kex.DHGroup16SHA512):
    pass


class Client(SSHClient):
    available_kex_algo: dict[str, kex.DHKex] = {
        "diffie-hellman-group14-sha256": DHGroup14SHA256,
        "diffie-hellman-group16-sha512": DHGroup16SHA512,
        "curve25519-sha256": Curve25519,
        "curve25519-sha256@libssh.org": Curve25519,
        "diffie-hellman-group14-sha1": DHGroup14SHA1,
        "diffie-hellman-group1-sha1": DHGroup1SHA1,
        # "diffie-hellman-group18-sha512": DHGroup18SHA512,
    }

    def __init__(self, kex_algo, server_host_key_algo):
        super().__init__()
        self.version = "SSH-client-test-1.0"
        self.remote_version = "OpenSSH-2.0"

        self.kex_algo = kex_algo
        self.server_host_key_algo = server_host_key_algo
        kex_algo = [self.kex_algo]
        server_host_key_algo = [self.server_host_key_algo]
        self.kex_init = SSHMsgKexInit(
            cookie=os.urandom(16),
            kex_algo=kex_algo,
            server_host_key_algo=server_host_key_algo,
            encryption_algo_client_to_server=list(("a", "b", "c", "d")),
            encryption_algo_server_to_client=list(("a", "b", "c", "d")),
            mac_algo_client_to_server=list(("f", "g", "h", "i")),
            mac_algo_server_to_client=list(("f", "g", "h", "i")),
            compression_algo_client_to_server=list(("none",)),
            compression_algo_server_to_client=list(("none",)),
            languages_client_to_server=list(),
            languages_server_to_client=list(),
            first_kex_packet_follows=False,
        )

        self.server_kex_init = SSHMsgKexInit(
            cookie=os.urandom(16),
            kex_algo=kex_algo,
            server_host_key_algo=server_host_key_algo,
            encryption_algo_client_to_server=list(("a", "b", "c", "d")),
            encryption_algo_server_to_client=list(("a", "b", "c", "d")),
            mac_algo_client_to_server=list(("f", "g", "h", "i")),
            mac_algo_server_to_client=list(("f", "g", "h", "i")),
            compression_algo_client_to_server=list(("none",)),
            compression_algo_server_to_client=list(("none",)),
            languages_client_to_server=list(),
            languages_server_to_client=list(),
            first_kex_packet_follows=False,
        )


KEX_ALGOS = [
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group14-sha256",
    "diffie-hellman-group16-sha512",
    "curve25519-sha256@libssh.org",
    "curve25519-sha256",
]
SERVER_HOST_KEY_ALGOS = [
    "ssh-ed25519",
    "rsa-sha2-256",
    "rsa-sha2-512",
]


@pytest.mark.asyncio
@pytest.mark.parametrize("kex_algo", KEX_ALGOS)
@pytest.mark.parametrize("host_algo", SERVER_HOST_KEY_ALGOS)
async def test_kex_algo(kex_algo, host_algo):
    client = Client(kex_algo=kex_algo, server_host_key_algo=host_algo)
    server, client = await client.available_kex_algo[client.kex_algo](client).start()

    assert server.K == client.K
    assert server.H == client.H
