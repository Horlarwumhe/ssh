from ssh.packet import Packet
import os
import io
import random
import pytest


@pytest.mark.parametrize("etm", (True, False, 9))
@pytest.mark.parametrize("block_size", (8, 16, 32))
def test_build(etm, block_size):
    size = random.randint(8, 32768)
    payload = os.urandom(size)
    p = Packet.build(payload, block_size=block_size, etm=etm)
    assert p.packet_length + 4 == len(bytes(p))
    b = io.BytesIO(bytes(p))
    assert int.from_bytes(b.read(4)) == p.packet_length
    assert b.read(1)[0] == p.padding_length
    assert b.read(p.packet_length - p.padding_length - 1) == payload
    assert len(b.read()) == p.padding_length
