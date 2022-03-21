from Crypto.Util.number import long_to_bytes

with open('./distfiles/output.txt', 'r') as f:
    n = int(f.readline().strip().split(" = ")[1], 16)
    c = int(f.readline().strip().split(" = ")[1], 16)

e = 0x10001

P.<x> = PolynomialRing(ZZ)
for i in range(10000):
    if i % 100 == 0:
        print(i)
    f = n - (2^1024 - 1 - x + i) * x
    roots = f.roots()
    if len(roots) != 0:
        print("[+] found roots:", roots)
        p = int(roots[0][0])
        q = n // p
        d = int(Mod(e, n - p - q + 1)^(-1))
        print(long_to_bytes(pow(c, d, n)))
        break
