import cryptography.exceptions
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
from cryptography.hazmat.primitives.poly1305 import Poly1305


class AES:
    key_size: int
    mode: modes.Mode
    algo: algorithms.AES
    block_size: int
    etm = False

    def __init__(self, key: bytes, iv: bytes):
        self.key = key
        self.iv = iv
        self.decryptor = self.encryptor = None

    def encrypt(self, data: bytes) -> bytes:
        if self.encryptor:
            return self.encryptor.update(data)
        cipher = Cipher(self.algo(self.key), self.mode(self.iv))
        self.encryptor = cipher.encryptor()
        return self.encryptor.update(data)

    def decrypt(self, data: bytes) -> bytes:
        if self.decryptor:
            return self.decryptor.update(data)
        cipher = Cipher(self.algo(self.key), self.mode(self.iv))
        self.decryptor = cipher.decryptor()
        return self.decryptor.update(data)

    def finalize(self):
        self.decryptor.finalize()
        self.decryptor = None


class AESCTR128(AES):
    key_size = 128 // 8  # bit
    block_size = 128 // 8  # bit
    mode = modes.CTR
    algo = algorithms.AES128


class AESCTR256(AES):
    key_size = 256 // 8
    block_size = 128 // 8
    mode = modes.CTR
    algo = algorithms.AES256


class AESCTR192(AES):
    key_size = 256 // 8
    block_size = 128 // 8
    mode = modes.CTR


ONE = int.to_bytes(1, 8, "little")
ZERO = int.to_bytes(0, 8, "little")


# https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.chacha20poly1305?annotate=HEAD
class ChaCha20Poly1305:
    key_size = 512 // 8
    block_size = 8
    etm = True

    def __init__(self, key: bytes, iv=None):
        # ignore iv for chacha20
        self.key1 = key[32:]  # size key
        self.key2 = key[:32]  # payload key
        assert len(self.key1) == len(self.key2) == 32

    def decrypt(self, ciphertext: bytes, seq_num: int) -> bytes:
        nonce = ONE + int.to_bytes(seq_num, 8)  # nonce for payload
        payload = self.do_decrypt(self.key2, nonce, ciphertext)
        return payload

    def encrypt(self, plaintext: bytes, seq_num: int) -> bytes:
        nonce = ZERO + int.to_bytes(seq_num, 8)  # nonce for size
        size = self.do_encrypt(self.key1, nonce, plaintext[:4])
        nonce = ONE + int.to_bytes(seq_num, 8)  # nonce for payload
        payload = self.do_encrypt(self.key2, nonce, plaintext[4:])
        return size + payload

    def decrypt_size(self, ciphertext: bytes, seq_num: int) -> bytes:
        nonce = ZERO + int.to_bytes(seq_num, 8)  # nonce for size
        return self.do_decrypt(self.key1, nonce, ciphertext)

    def do_encrypt(self, key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
        cipher = Cipher(ChaCha20(key, nonce), None)
        return cipher.encryptor().update(plaintext)

    def do_decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
        cipher = Cipher(ChaCha20(key, nonce), None)
        return cipher.decryptor().update(ciphertext)

    def verify(self, ciphertext: bytes, mac: bytes, seq_num: int) -> bool:
        key = self.generate_mac_key(seq_num)
        try:
            Poly1305.verify_tag(key, ciphertext, mac)
        except cryptography.exceptions.InvalidSignature:
            return False
        return True

    def digest(self, ciphertext: bytes, seq_num: int) -> bytes:
        key = self.generate_mac_key(seq_num)
        return Poly1305.generate_tag(key, ciphertext)

    def generate_mac_key(self, seq_num: int) -> bytes:
        nonce = ZERO + int.to_bytes(seq_num, 8)
        return self.do_encrypt(self.key2, nonce, b"\x00" * 32)[:32]
