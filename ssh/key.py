from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
from ssh.stream import Buffer


class RSAKey:
    HASHES = {
        "ssh-rsa": hashes.SHA1,
        "ssh-rsa-cert-v01@openssh.com": hashes.SHA1,
        "rsa-sha2-256": hashes.SHA256,
        "rsa-sha2-256-cert-v01@openssh.com": hashes.SHA256,
        "rsa-sha2-512": hashes.SHA512,
        "rsa-sha2-512-cert-v01@openssh.com": hashes.SHA512,
    }

    def __init__(self, pk=None, pub=None):
        self.pk = pk
        self.pub: rsa.RSAPublicKey = pub

    @classmethod
    def pub_from_number(cls, n: int, e: int):
        return cls(pub=rsa.RSAPublicNumbers(e=e, n=n).public_key())

    def verify(self, sig, message, algo=""):
        try:
            self.pub.verify(sig, message, padding.PKCS1v15(), self.HASHES[algo]())
        except InvalidSignature:
            return False
        return True

    @classmethod
    def generate(cls):
        key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        return cls(pk=key, pub=key.public_key())

    @classmethod
    def from_buffer(cls, b: Buffer):
        assert "ssh-rsa" in b.read_string()
        return cls.pub_from_number(e=b.read_mpint(), n=b.read_mpint())
