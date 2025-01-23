

import pytest
import os
import io

from ssh.util import to_mpint

def test_mpint():
    for bit in (8,16,32,64,128,256,512,1024,2048,4096):
        num = int.from_bytes(os.urandom(bit))
        b = io.BytesIO(to_mpint(num))
        size = int.from_bytes(b.read(4),'big')
        byte = b.read(size)
        assert size == len(byte)
        assert int.from_bytes(byte,'big') == num
