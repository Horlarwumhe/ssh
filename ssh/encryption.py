from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class AES:
    key_size: int
    mode: modes.Mode
    algo: algorithms.AES
    block_size: int

    def __init__(self,key,iv):
        self.key = key
        self.iv = iv
        self.decryptor = self.encryptor = None

    def encrypt(self,data):
        if self.encryptor:
            return self.encryptor.update(data)
        cipher = Cipher(self.algo(self.key), self.mode(self.iv))
        self.encryptor = cipher.encryptor()
        return  self.encryptor.update(data)

    def decrypt(self,data):
        if self.decryptor:
            return self.decryptor.update(data)
        cipher = Cipher(self.algo(self.key), self.mode(self.iv))
        self.decryptor = cipher.decryptor()
        return self.decryptor.update(data)
    
    def finalize(self):
        self.decryptor.finalize()
        self.decryptor = None


class AESCTR128(AES):
    key_size = 128//8 # bit
    block_size = 128//8 # bit
    mode = modes.CTR
    algo = algorithms.AES128

class AESCTR256(AES):
   key_size = 256//8
   block_size = 128//8
   mode = modes.CTR
   algo = algorithms.AES256

class AESCTR192(AES):
   key_size = 256//8
   block_size = 128//8
   mode = modes.CTR
#    algo = algorithms.AES192