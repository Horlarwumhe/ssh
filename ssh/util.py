import struct


def inflate_long(s, always_positive=False):
    """turns a normalized byte string into a long-int
    (adapted from Crypto.Util.number)"""
    out = 0
    negative = 0
    if not always_positive and (len(s) > 0) and (byte_ord(s[0]) >= 0x80):
        negative = 1
    if len(s) % 4:
        filler = zero_byte
        if negative:
            filler = max_byte
        # never convert this to ``s +=`` because this is a string, not a number
        # noinspection PyAugmentAssignment
        s = filler * (4 - len(s) % 4) + s
    for i in range(0, len(s), 4):
        out = (out << 32) + struct.unpack(">I", s[i : i + 4])[0]
    if negative:
        out -= 1 << (8 * len(s))
    return out


zero_byte = b"\x00"
max_byte = b"\xff"


def deflate_long(n, add_sign_padding=True):
    """turns a long-int into a normalized byte string
    (adapted from Crypto.Util.number)"""
    # after much testing, this algorithm was deemed to be the fastest
    s = bytes()
    n = int(n)
    while (n != 0) and (n != -1):
        s = struct.pack(">I", n & 0xFFFFFFFF) + s
        n >>= 32
    # strip off leading zeros, FFs
    for i in enumerate(s):
        if (n == 0) and (i[1] != 0):
            break
        if (n == -1) and (i[1] != 0xFF):
            break
    else:
        # degenerate case, n was either 0 or -1
        i = (0,)
        if n == 0:
            s = zero_byte
        else:
            s = max_byte
    s = s[i[0] :]
    if add_sign_padding:
        if (n == 0) and (byte_ord(s[0]) >= 0x80):
            s = zero_byte + s
        if (n == -1) and (byte_ord(s[0]) < 0x80):
            s = max_byte + s
    return s


def byte_chr(c):
    assert isinstance(c, int)
    return struct.pack("B", c)


def byte_mask(c, mask):
    assert isinstance(c, int)
    return struct.pack("B", c & mask)


def byte_ord(c):
    # In case we're handed a string instead of an int.
    if not isinstance(c, int):
        c = ord(c)
    return c
