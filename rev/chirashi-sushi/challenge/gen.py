from random import shuffle, randint, seed
import sys

seed(1337)

MACRO = """
#define _DEFINE_VAL(type, symbol) \
void f_##symbol (void (*fp)(type* (*ret)(void))){  \
    static type symbol; \
    type* f() { return &symbol; } \
    fp(f); \
}
#define DEFINE_VAL(type, symbol) _DEFINE_VAL(type, symbol)

#define __GET_VAL(type, symbol, local_symbol, id) \
type* local_symbol; \
void g_##id(type* (*ret)(void)) { \
    local_symbol = ret(); \
} \
f_##symbol(g_##id);

#define _GET_VAL(type, symbol, local_symbol, id) __GET_VAL(type, symbol, local_symbol, id)
#define GET_VAL(type, symbol, local_symbol) _GET_VAL(type, symbol, local_symbol, __COUNTER__)
"""

vals = [
    ("mod", "long long"),
    ("cnt", "long long"),
    ("mul", "long long"),
    ("end", "long long"),
    ("a", "unsigned long long"),
    ("b", "unsigned long long"),
    ("c", "unsigned long long"),
    ("d", "unsigned long long")
]

if len(sys.argv) < 3:
    print(f'[!] usage: python gen.py [source] [dest]')
    exit(1)

src_path = sys.argv[-2]
dest_path = sys.argv[-1]

with open(src_path, "r") as f:
    src = f.read()

res = ""
ls = src.splitlines(keepends=True)

def skip(m=lambda x: x):
    global res, ls
    res += m(ls[0])
    ls = ls[1:]
def skip_while(f, m=lambda x: x):
    while len(ls) != 0 and f(ls[0]): skip(m)

skip_while(lambda l: l.startswith("#include"))

defs = []
def_vals = []
get_vals = []

func_names = {}

for val, type in vals:
    def_val = val.upper()
    
    symbol = f'X{hex(randint(16**6, 16**7))[-6:]}'
    func_names[val] = f'f_{symbol}'
    defs.append(f"#define {def_val} {symbol}\n")
    def_vals.append(f"DEFINE_VAL({type}, {def_val})\n")
    for i in range(src.count(f"_{val}") - 1):
        get_vals.append(f"GET_VAL({type}, {def_val}, {val}{i + 1})\n")

shuffle(defs)
shuffle(def_vals)
shuffle(get_vals)

ls = [MACRO] + defs + ["\n"] + def_vals + ["\n"] + ls

skip_while(lambda l: "main" not in l)
skip()

ls = get_vals + ["// ORIGINAL_SOURCE\n"] + ls

skip_while(lambda l: not l.startswith("// ORIGINAL_SOURCE"))

cnts = { key: 0 for key, _ in vals }
def reducer(l: str):
    if "TMP_VAL_DECLARE" in l: return "\n"
    for val, _ in vals:
        l = l.replace(f'_f_{val}', func_names[val])
        while f"_{val}" in l:
            cnts[val] += 1
            l = l.replace(f"_{val}", f'*{val}{cnts[val]}', 1)
    return l

skip_while(lambda _: True, reducer)

with open(dest_path, "w") as f:
    f.write(res)
