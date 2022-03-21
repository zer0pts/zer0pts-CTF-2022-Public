import ast

with open("output.txt") as f:
    n = int(f.readline().strip().split(" = ")[1])
    a = int(f.readline().strip().split(" = ")[1])
    b = int(f.readline().strip().split(" = ")[1])
    c = ast.literal_eval(f.readline().strip().split(" = ")[1])


load("./defund.sage")
PR.<dx, dy> = PolynomialRing(Zmod(n))

diffs = []
for i in range(len(c) // 2):
    x, y = c[2*i], c[2*i+1]
    f = (x + dx)**3 + a*(x + dx) + b - (y + dy)**2
    for r in small_roots(f, [2**128, 2**128])[0]:
         d = int(r)
         if d.bit_length() > 130:
            d = d - n
         diffs.append(d)

m = b''
for i in range(len(diffs)):
    p = c[i] + diffs[i]
    m += bytes.fromhex(hex(p ^^ c[i])[2:])
print(m)
