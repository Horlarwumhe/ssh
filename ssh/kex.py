import logging
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

import ssh.client
from ssh import message as msg
from ssh.stream import Buffer

from .hash import sha1, sha256, sha512


@dataclass
class KexResult:
    K: int
    H: bytes


log = logging.getLogger("ssh")


class DHKex:
    name: str  # https://github.com/openssh/openssh-portable/blob/master/kex.h#L53-L67
    key_size: int  # https://datatracker.ietf.org/doc/html/rfc3526#section-2
    P: int
    G: int
    hash_algo: callable

    def __init__(self, client: "ssh.client.SSHClient"):
        self.client = client

    async def start(self) -> KexResult:
        # https://datatracker.ietf.org/doc/html/rfc4253#section-8
        log.log(logging.INFO, f"Using {self.name} key_size {self.key_size}")
        q = (self.P - 1) // 2
        x = int.from_bytes(os.urandom(q.bit_length() // 8))
        assert x < q, "error x < (P-1)//2 %d < %d" % (x, q)
        e = pow(self.G, x, self.P)
        req = msg.SSHMsgKexDHInit(e=e)
        await self.client.sock.send_packet(bytes(req))
        packet = await self.client.sock.read_packet()
        m = Buffer(packet.payload)
        if packet.opcode != msg.SSHMessageKexDHReply.opcode:
            raise
        resp = msg.SSHMessageKexDHReply.parse(m)
        server_host_key = resp.host_key
        f = resp.f
        sig = resp.sig
        K = pow(f, x, self.P)
        s = bytes(
            msg.DHHashSig(
                client_version=self.client.version,
                server_version=self.client.remote_version,
                host_key=server_host_key,
                client_kex_init=bytes(self.client.kex_init),
                server_kex_init=bytes(self.client.server_kex_init),
                e=e,
                f=f,
                K=K,
            )
        )
        H = type(self).hash_algo(s)
        server_key = self.client.available_server_host_key_algo[
            self.client.server_host_key_algo
        ].from_buffer(Buffer(server_host_key))
        buf = Buffer(sig)
        hash_name = buf.read_string()
        assert server_key.verify(
            buf.read_binary(), H, hash_name
        ), "Signature verification failed"
        return KexResult(K=K, H=H)


class DHGroup1SHA1(DHKex):
    name: str = "diffie-hellman-group1-sha1"
    key_size: int = 1024
    hash_algo = sha1
    P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF  # noqa
    G = 2


class DHGroup14SHA1(DHKex):
    name: str = "diffie-hellman-group14-sha1"
    key_size: int = 2048
    hash_algo = sha1
    P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF  # noqa
    G = 2


class DHGroup14SHA256(DHKex):
    name: str = "diffie-hellman-group14-sha256"
    key_size: int = 2048
    hash_algo = sha256
    P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF  # noqa
    G = 2


class DHGroup16SHA512(DHKex):
    key_size: int = 4096
    name: str = "diffie-hellman-group16-sha512"
    hash_algo = sha512
    P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF  # noqa
    G = 2


class DHGroup18SHA512(DHKex):
    key_size: int = 8192
    name: str = "diffie-hellman-group18-sha512"
    hash_algo = sha512



class Curve25519:
    name: str = "curve25519-sha256"
    hash_algo: callable = sha256

    def __init__(self, client: "ssh.client.SSHClient"):
        self.client = client

    async def start(self):
        # https://datatracker.ietf.org/doc/html/rfc5656#section-4
        log.log(logging.INFO, f"Using {self.name}  key exchnage")
        pk = X25519PrivateKey.generate()
        pub = pk.public_key().public_bytes_raw()
        req = msg.SSHMsgKexECDHInit(pub_key=pub)
        await self.client.send_message(req)
        packet = await self.client.sock.read_packet()
        res = msg.SSHMsgKexECDHReply.parse(Buffer(packet.payload))
        sig = res.sig
        server_pub = X25519PublicKey.from_public_bytes(res.pub_key)
        K = int.from_bytes(pk.exchange(server_pub))
        H = type(self).hash_algo(
            bytes(
                msg.ECDHHashSig(
                    client_version=self.client.version,
                    server_version=self.client.remote_version,
                    client_kex_init=bytes(self.client.kex_init),
                    server_kex_init=bytes(self.client.server_kex_init),
                    server_host_key=res.host_key,
                    client_pub_key=pub,
                    server_pub_key=res.pub_key,
                    K=K,
                )
            )
        )
        server_key = self.client.available_server_host_key_algo[
            self.client.server_host_key_algo
        ].from_buffer(Buffer(res.host_key))
        sig = Buffer(sig)
        hash_name = sig.read_string()
        assert server_key.verify(
            sig.read_binary(), H, hash_name
        ), "Signature verification failed"
        return KexResult(K=K,H=H)


