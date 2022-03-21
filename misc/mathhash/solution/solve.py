import os
from ptrlib import *

HOST = os.getenv('HOST', '0.0.0.0')
PORT = os.getenv('PORT', '10001')

logger.level = 0
def doit(key):
    sock.sendlineafter(": ", key.hex())
    r = int(sock.recvlineafter(": "), 16)
    return r

sock = Socket(HOST, int(PORT))

flag = 'zer0pts'
original = doit(b'\x00'*8)

for pos in range(7, 100):
    for delta in range(0x100):
        r = doit(b'\x00'*pos+bytes([delta]))
        if original >> 63 != r >> 63:
            c = (0x80 - delta) % 0x100
            flag += chr(c)
            print(flag)
            break
    else:
        break
    if '}' in flag:
        break

sock.close()
