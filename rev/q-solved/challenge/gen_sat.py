import json
from ptrlib import u32
from z3 import *

flag = b"zer0pts{FLAG_by_Gr0v3r's_4lg0r1thm}"
ansList = []
N = len(flag)
for i in range(N):
    c = flag[i] ^ flag[(i+1)%N]
    ansList.append(c)

#s = Solver()
s = Goal()
flag = [BitVec(f"flag{i}", 8) for i in range(N)]

s.add(flag[0] & 0xff == ord('z'))
for i in range(N):
    s.add(flag[i] ^ flag[(i+1)%N] == ansList[i])

""" test
s = Goal()
flag = [BitVec(f"flag{i}", 1) for i in range(8)]

s.add(flag[0] == 0)
s.add(flag[1] == flag[0] ^ 1)
s.add(flag[2] == 0)
s.add(flag[3] == 0)
s.add(flag[4] == 0)
s.add(flag[5] == 0)
s.add(flag[6] == flag[0] ^ 1)
s.add(flag[7] == 0)
#"""

#set_option(max_args=10000000, max_lines=1000000, max_depth=10000000, max_visited=1000000)

t = Then('simplify', 'eq2bv', 'card2bv', 'simplify', 'bit-blast', 'tseitin-cnf', 'simplify')

v = []
n_ancilla = 0
n_variable = 0
for clause in t(s)[0]:
    if clause.sexpr().startswith('(not '):
        x = int(clause.children()[0].sexpr().split('!')[1])
        n_variable = max(n_variable, x + 1)
        v.append([(False, x)])

    elif clause.sexpr().startswith('(or '):
        v.append([])
        for const in clause.children():
            if const.sexpr().startswith('(not '):
                x = int(const.children()[0].sexpr().split('!')[1])
                n_variable = max(n_variable, x + 1)
                v[-1].append((False, x))
            else:
                x = int(const.sexpr().split('!')[1])
                n_variable = max(n_variable, x + 1)
                v[-1].append((True, x))

    elif clause.sexpr().startswith('k!'):
        x = int(clause.sexpr().split('!')[1])
        n_variable = max(n_variable, x + 1)
        v.append([(True, x)])

    else:
        print(clause)
        print(clause.sexpr())
        exit(1)

    n_ancilla += 1

circ = {
    "memory": n_variable,
    "ancilla": n_ancilla,
    "circuit": v
}

with open("circuit.json", "w") as f:
    json.dump(circ, f)
print(n_variable)
print(n_ancilla)
