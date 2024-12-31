
def to_mpint(value: int) -> bytes:

    l = value.bit_length()
    l += (l % 8 == 0 and value != 0 and value != -1 << (l - 1))
    l = (l + 7) // 8

    return l.to_bytes(4, 'big') + value.to_bytes(l, 'big', signed=True)

def check_closed(func):
    async def wrapper(self,*args,**kwargs):
        if self.closed:
            name = "Channel" if "Channel" in str(self) else "Connection"
            raise RuntimeError(f"{name} is closed")
        return await func(self,*args,**kwargs)
    return wrapper

