from z3 import *
import string
import re

tap = [0,1,3,4,5,6,9,12,13,16,19,20,21,22,25,28,37,38,41,42,45,46,50,52,54,56,58,60,61,63,64,65,66,67,71,72,79,80,81,82,87,88,89,90,91,92,94,95,96,97]
comp0 = [0,0,0,0,1,1,0,0,0,1,0,1,1,1,1,0,1,0,0,1,0,1,0,1,0,1,0,1,0,1,1,0,1,0,0,1,0,0,0,0,0,0,0,1,0,1,0,1,0,1,0,0,0,0,1,0,1,0,0,1,1,1,1,0,0,1,0,1,0,1,1,1,1,1,1,1,1,1,0,1,0,1,1,1,1,1,1,0,1,0,1,0,0,0,0,0,0,1,1,0]
comp1 = [0,1,0,1,1,0,0,1,0,1,1,1,1,0,0,1,0,1,0,0,0,1,1,0,1,0,1,1,1,0,1,1,1,1,0,0,0,1,1,0,1,0,1,1,1,0,0,0,0,1,0,0,0,1,0,1,1,1,0,0,0,1,1,1,1,1,1,0,1,0,1,1,1,0,1,1,1,1,0,0,0,1,0,0,0,0,1,1,1,0,0,0,1,0,0,1,1,0,0,0]
fb0 = [1,1,1,1,0,1,0,1,1,1,1,1,1,1,1,0,0,1,0,1,1,1,1,1,1,1,1,1,1,0,0,1,1,0,0,0,0,0,0,1,1,1,0,0,1,0,0,1,0,1,0,1,0,0,1,0,1,1,1,1,0,1,0,1,0,1,0,0,0,0,0,0,0,0,0,1,1,0,1,0,0,0,1,1,0,1,1,1,0,0,1,1,1,0,0,1,1,0,0,0]
fb1 = [1,1,1,0,1,1,1,0,0,0,0,1,1,1,0,1,0,0,1,1,0,0,0,1,0,0,1,1,0,0,1,0,1,1,0,0,0,1,1,0,0,0,0,0,1,1,0,1,1,0,0,0,1,0,0,0,1,0,0,1,0,0,1,0,1,1,0,1,0,1,0,0,1,0,1,0,0,0,1,1,1,1,0,1,1,1,1,1,0,0,0,0,0,0,1,0,0,0,0,1]

def hyper_feedback(i, cs):
    v = (fb0[i], fb1[i])
    if v == (0, 0):
        return 0
    elif v == (0, 1):
        return cs
    elif v == (1, 0):
        return cs ^ 1
    elif v == (1, 1):
        return 1

def bit(x, n):
    return (x >> n) & 1

def search(enc, r, s, max_length, flag='', bitstack=[]):
    #print(flag.encode(), bitstack)
    solver = Solver()
    orig_r, orig_s = BitVec('r', 100), BitVec('s', 100)
    cr = bit(orig_s, 1) ^ bit(orig_r, 14)
    cs = bit(orig_s, 51) ^ bit(orig_r, 4)

    # __nightmare_r(orig_r, 0, cr) --> r
    fb = bit(orig_r, 99)
    for i in range(100):
        rc = 0
        if i > 0:
            rc = bit(orig_r, i-1)
        if i in tap:
            rc ^= fb
        rc ^= bit(orig_r, i) & cr
        solver.add(rc == r[i])

    # __nightmare_s(orig_s, 0, cs) --> s
    fb = bit(orig_s, 99)
    s_i = [0 for i in range(100)]
    s_i[99] = bit(orig_s, 98)
    for i in range(1, 99):
        s_i[i] = bit(orig_s, i-1) ^ ((bit(orig_s, i) ^ comp0[i]) & (bit(orig_s, i+1) ^ comp1[i]))
    for i in range(100):
        solver.add(s[i] == s_i[i] ^ fb ^ hyper_feedback(i, cs))

    # Find all possible states
    while True:
        result = solver.check()
        if result == sat:
            m = solver.model()

            new_r, new_s = [], []
            for i in range(100):
                new_r.append((m[orig_r].as_long() >> i) & 1)
                new_s.append((m[orig_s].as_long() >> i) & 1)

            new_bitstack = list(bitstack)
            new_bitstack.append(new_r[0] ^ new_s[0])

            solver.add(Not(And(orig_r == m[orig_r], orig_s == m[orig_s])))
            new_flag = flag
            if len(new_bitstack) == 8:
                c = 0
                for i in range(8):
                    c |= (new_bitstack[7-i]) << i
                c ^= enc[-1-len(new_flag)]
                if chr(c) not in string.printable:
                    continue

                new_flag = chr(c) + new_flag
                print(new_flag.strip(), len(new_flag), bin(c), hex(c))

                if len(new_flag) == max_length:
                    print("[+] Candidate: " + new_flag)
                    if new_flag.startswith("zer0pts{"):
                        print("[+] FLAG: " + new_flag)
                    continue

                new_bitstack = []

            search(enc, new_r, new_s, max_length, new_flag, new_bitstack)
        else:
            break

if __name__ == '__main__': 
    with open("../distfiles/flag.txt.enc", "rb") as f:
        f.seek(0, 2)
        size = f.tell()
        f.seek(0, 0)
        enc = f.read(size - 26)
        rb = f.read(13)
        sb = f.read(13)

    r, s = [], []
    for i in range(13):
        for j in range(8):
            if i*8+j < 100:
                r.append((rb[i] >> j) & 1)
                s.append((sb[i] >> j) & 1)

    search(enc, r, s, size-26)
