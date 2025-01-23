import io

from . import util


class Buffer(io.BytesIO):
    def read_int(self) -> int:
        return int.from_bytes(self.read(4))

    def read_int64(self) -> int:
        return int.from_bytes(self.read(8))

    def read_list(self):
        return self.read_string().split(",")

    def read_binary(self) -> bytes:
        return self.read(self.read_int())

    def read_string(self) -> str:
        return self.read_binary().decode()

    def read_bool(self) -> bool:
        return int.from_bytes(self.read(1)) != 0

    def read_byte(self, n: int = 1):
        return self.read(n)

    def read_mpint(self):
        return int.from_bytes(self.read_binary(), "big", signed=True)

    def write_int(self, i: int):
        self.write(int.to_bytes(i, 4))

    def write_int64(self, i: int):
        self.write(int.to_bytes(i, 8))

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
        self.write(util.to_mpint(i))

    def write_list(self, l: list[str]):
        self.write_string(",".join(l))
