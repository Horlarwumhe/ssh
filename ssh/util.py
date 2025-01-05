import functools

import curio


def to_mpint(value: int) -> bytes:
    l = value.bit_length()
    l += l % 8 == 0 and value != 0 and value != -1 << (l - 1)
    l = (l + 7) // 8

    return l.to_bytes(4, "big") + value.to_bytes(l, "big", signed=True)


def check_closed(func):
    @functools.wraps(func)
    async def wrapper(self, *args, **kwargs):
        if self.closed:
            name = "Channel" if "Channel" in str(self) else "Connection"
            raise RuntimeError(f"{name} is closed")
        return await func(self, *args, **kwargs)

    return wrapper


def timeout(func):
    @functools.wraps(func)
    async def wrapper(self, *args, **kwargs):
        if self.timeout is not None:
            try:
                return await curio.timeout_after(self.timeout, func(self, *args, **kwargs))
            except curio.TaskTimeout:
                raise TimeoutError("Operation timed out") from None
        return await func(self, *args, **kwargs)

    return wrapper
