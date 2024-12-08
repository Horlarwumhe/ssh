import io

from . import util


class Buffer(io.BytesIO):
    def read_int(self) -> int:
        return int.from_bytes(self.read(4))

    def read_list(self):
        return self.read_string().split(",")

    def read_binary(self) -> bytes:
        size = self.read_int()
        return self.read(size)

    def read_string(self) -> str:
        return self.read_binary().decode()

    def read_bool(self) -> bool:
        return int.from_bytes(self.read(1)) != 0

    def read_byte(self, n: int = 1):
        return self.read(n)

    def read_mpint(self):
        return util.inflate_long(self.read_binary())

    def write_int(self, i: int):
        self.write(int.to_bytes(i, 4))

    def write_string(self, s: str):
        self.write_int(len(s.encode()))
        self.write(s.encode())

    def write_binary(self, b: bytes):
        self.write_int(len(b))
        self.write(b)

    def write_bool(self, b: bool):
        self.write(int.to_bytes(b))

    def write_byte(self, b: bytes):
        return self.write(b)

    def write_mpint(self, i: int):
        self.write_binary(util.deflate_long(i))
        # s = round((i.bit_length()+7)/8)
        # b = int.to_bytes(i,s,signed=True)
        # assert len(b) == s, "mpint error len(b): %s != s:%s "%(len(b),s)
        # self.write_binary(b)

    def write_list(self, l: list[str]):
        self.write_string(",".join(l))
