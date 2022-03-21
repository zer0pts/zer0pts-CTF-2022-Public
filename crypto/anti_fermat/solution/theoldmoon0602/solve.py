import gmpy2

e = 65537
with open("./distfiles/output.txt") as f:
    n = int(f.readline().strip().split(" = ")[1], 16)
    c = int(f.readline().strip().split(" = ")[1], 16)

alpha = 0
M = 2**1024
while True:
    alpha += 1

    p_q = M + alpha
    root, ok = gmpy2.iroot( p_q**2 - 4 * n , 2)
    if not ok:
        continue

    p = (p_q + root) // 2
    q = (p_q - root) // 2

    if n % p == 0 and n % q == 0:
        break

d = pow(e, -1, (p - 1) * (q - 1))
m = pow(c, d, n)
print(bytes.fromhex(hex(m)[2:]))
