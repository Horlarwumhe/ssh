import hmac


class HMAC:
    algo: str
    size: int

    def __init__(self, key):
        self.key = key

    def digest(self, data):
        return hmac.digest(self.key, data, self.algo)


class HMACSHA256(HMAC):
    algo = "sha256"
    size = 256 // 8


class HMACSHA512(HMAC):
    algo = "sha512"
    size = 512 // 8


class HMACSHA1(HMAC):
    algo = "sha1"
    size = 160 // 8
