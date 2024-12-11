from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

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
        self.pk: rsa.RSAPrivateKey = pk
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

    def sign(self, message: bytes, algo: str):
        return self.pk.sign(
            message, padding=padding.PKCS1v15(), algorithm=self.HASHES[algo]()
        )

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

    @classmethod
    def from_file(cls, path, password=None):
        data = open(path, "rb").read()  # file closed.
        # shortcut
        if b"RSA" in data:
            pk = serialization.load_pem_private_key(data, password)
        elif b"OPENSSH" in data:
            pk = serialization.load_ssh_private_key(data, password)
        return cls(pk=pk, pub=pk.public_key())

    def __bytes__(self):
        b = Buffer()
        b.write_string("ssh-rsa")
        b.write_mpint(self.pub.public_numbers().e)
        b.write_mpint(self.pub.public_numbers().n)
        return b.getvalue()