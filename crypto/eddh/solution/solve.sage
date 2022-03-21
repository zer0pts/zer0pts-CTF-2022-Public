from ptrlib import Socket, Process
from Crypto.Util.Padding import pad
from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse
from Crypto.Cipher import AES
from hashlib import sha256
import ast
import os

n = 256
p = 64141017538026690847507665744072764126523219720088055136531450296140542176327
a = 362
d = 1
q = 64141017538026690847507665744072764126693080268699847241685146737444135961328
c = 4
gx = 36618472676058339844598776789780822613436028043068802628412384818014817277300
gy = 9970247780441607122227596517855249476220082109552017755637818559816971965596

def xor(xs, ys):
    return bytes(x^^y for x, y in zip(xs, ys))

def pad(b, l):
    return b + b"\0" + b"\xff" * (l - (len(b) + 1))

def unpad(b):
    l = -1
    while b[l] != 0:
        l -= 1
    return b[:l]

def add(P, Q):
    (x1, y1) = P
    (x2, y2) = Q

    x3 = (x1*y2 + y1*x2) * inverse(1 + d*x1*x2*y1*y2, p) % p
    y3 = (y1*y2 - a*x1*x2) * inverse(1 - d*x1*x2*y1*y2, p) % p
    return (x3, y3)

def mul(x, P):
    Q = (0, 1)
    x = x % q
    while x > 0:
        if x % 2 == 1:
            Q = add(Q, P)
        P = add(P, P)
        x = x >> 1
    return Q

def to_bytes(P):
    x, y = P
    return int(x).to_bytes(n // 8, "big") + int(y).to_bytes(n // 8, "big")


sock = Socket("localhost", 10929)

sg = ast.literal_eval(sock.recvlineafter("sG = ").decode())
sock.sendlineafter("tG = ", "{}".format((0, 2)))

msg = b"\0"
sock.sendline(msg.hex())

res = bytes.fromhex(sock.recvline().decode())
y = bytes_to_long(xor(res[-n//8:], b"\xff" * 256))
s = discrete_log(GF(p)(y), GF(p)(2))
assert pow(2, s, p) == y
print("s = {}".format(s))

share = to_bytes(mul(int(s), (0, 2)))
sock.sendline(xor(pad(b"flag", 2*n//8), share).hex())

r = bytes.fromhex(sock.recvline().decode())
msg = unpad(xor(r, share))
aes = AES.new(key=sha256(long_to_bytes(s)).digest(), mode=AES.MODE_ECB)
print(aes.decrypt(msg))

