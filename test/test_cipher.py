import random
from ssh.encryption import ChaCha20Poly1305, AESCTR256
from ssh.packet import Packet
import os


def test_chacha20_encrypt():
    key = os.urandom(ChaCha20Poly1305.key_size)
    cipher = ChaCha20Poly1305(key)

    for _ in range(10):
        # encrypt
        size = random.randint(8, 32768)
        packet = Packet.build(os.urandom(size), etm=True)
        seq_num = random.randint(0, 2**32 - 1)
        ciphertext = cipher.encrypt(bytes(packet), seq_num)
        mac = cipher.digest(ciphertext, seq_num)
        assert len(ciphertext) == len(bytes(packet))

        # decrypt
        size = ChaCha20Poly1305(key).decrypt_size(ciphertext[:4], seq_num)
        payload = ChaCha20Poly1305(key).decrypt(ciphertext[4:], seq_num)
        assert int.from_bytes(size) == packet.packet_length
        assert size + payload == bytes(packet)
        assert cipher.verify(ciphertext, mac, seq_num)


def test_aes_encrypt():
    key = os.urandom(AESCTR256.key_size)
    iv = os.urandom(AESCTR256.block_size)
    cipher = AESCTR256(key, iv)

    for _ in range(10):
        size = random.randint(8, 32768)
        packet = Packet.build(os.urandom(size), etm=False)
        chiphertext = cipher.encrypt(bytes(packet))
        assert len(chiphertext) == len(bytes(packet))

        # decrypt
        payload = cipher.decrypt(chiphertext)
        assert payload == bytes(packet)
