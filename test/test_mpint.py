import sys

import rsa 
sys.path.append('../')
from paramiko.message import Message
import random
from ssh.stream import Buffer, Writer
import os
import itertools
bits = itertools.cycle([128,512,126,256,160,180,512])
def test_mpint():
    m = Message()
    w = Writer()
    for x in range(20):
        b = next(bits)
        i = rsa.prime.getprime(b)
        m.add_mpint(i)
        w.write_mpint(i)
        # print('using %s -> adding %s'%(b,i))
    r = Buffer(w.getvalue())
    m.rewind()
    for x in range(20):
        a = m.get_mpint()
        b = r.read_mpint()
        # print('a ==== b %s == %s '%(a,b))
        assert a == b
    m.rewind()
    r.seek(0)
    for x in range(20):
        ms,rs = m.get_int(),r.read_int()
        assert r.read_byte(rs) == m.get_bytes(ms)


    
