from Crypto.Util.number import inverse, isPrime
from ptrlib import Socket

P = 2 ** 1000 - 1
while not isPrime(P): P -= 2
e = 65537

oracles_0 = []
oracles_1 = []
for i in range(15):
    sock = Socket("localhost", 9999)
    assert P == int(sock.recvlineafter("P = "))
    n = int(sock.recvlineafter("n = "))
    assert e == int(sock.recvlineafter("e = "))
    x1 = int(sock.recvlineafter("x1 = "))
    x2 = int(sock.recvlineafter("x2 = "))

    v = (x1 + x2) * inverse(2, n) % n
    sock.sendlineafter("v: ", str(v))

    c1 = int(sock.recvlineafter("c1 = "))
    c2 = int(sock.recvlineafter("c2 = "))
    x = (c1 + c2) % n
    oracles_0.append(x if x % 2 == 0 else x + n)
    oracles_1.append(x if x % 2 == 1 else x + n)

assert len(set([o % 2 for o in oracles_0])) == 1
assert len(set([o % 2 for o in oracles_1])) == 1

def solve(oracles):
    BIT = 1024
    AVG = 2 ** BIT - 1
    l = [abs(AVG - o) for o in oracles]

    res = AVG
    while not all([d == 0 for d in l]):
        msb = 1 << (max(l).bit_length() - 1)
        res -= msb
        l = [abs(d - msb) for d in l]
    if res == 0: return
    flag = pow(res, inverse(e, P - 1), P)
    print(flag.to_bytes((flag.bit_length() + 7) // 8, "big"))

solve(oracles_0)
solve(oracles_1)
