import hashlib


def sha1(s):
    if isinstance(s, str):
        s = s.encode()
    return hashlib.sha1(s).digest()


def sha256(s):
    if isinstance(s, str):
        s = s.encode()
    return hashlib.sha256(s).digest()


def sha512(s):
    if isinstance(s, str):
        s = s.encode()
    return hashlib.sha512(s).digest()


def sha384(s):
    if isinstance(s, str):
        s = s.encode()
    return hashlib.sha384(s).digest()

