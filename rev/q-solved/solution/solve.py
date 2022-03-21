import json
from z3 import *

with open("../distfiles/circuit.json", "r") as f:
    circ = json.load(f)

bits = [Bool(f'b{i}') for i in range(circ['memory'])]

s = Solver()
for cs in circ['circuit']:
    l = []
    for (x, c) in cs:
        l.append(bits[c] if x else Not(bits[c]))
    s.add(Or(l))

r = s.check()
if r == sat:
    m = s.model()
    f = 0
    for i, b in enumerate(bits):
        f |= (1 if m[b] else 0) << i

    print(int.to_bytes(f, circ['memory']//8, 'little'))

else:
    print(":(")
