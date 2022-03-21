# orthogonal lattice attack

def find_orthogonal_lattice(v, p):
    """
    basis of orthogonal lattice is the n x n matrix, where n is the length of v
    each rows of orthogonal lattice is orthogonal to v
    each rows are independent each other
    """

    M = matrix.identity(ZZ, len(v))
    for i in range(len(v)):
        M[i,0] = - v[i] * inverse_mod(v[0], p) % p
    M[0,0] = p
    return M

def kernelLLL(M):
    n=M.nrows()
    m=M.ncols()
    if m < 2*n: return M.right_kernel().matrix()
    K=2^(m//2)*M.height()
    MB = (K*M).T.augment(matrix.identity(m)) # m x (n + m)

    MB2=MB.LLL().T
    assert MB2[:n,:m-n]==0

    Ke=MB2[n:,:m-n].T
    return Ke

def allones(v):
    if all([ x in [0, 1] for x in v]):
        return v
    if all([ x in [-1, 0] for x in v]):
        return -v
    return None

def recoverBinary(M5):
    # 適当に結合して0,1からなるベクトルを作る
    # -1と1が両方あるようなやつも足して見るといい感じになったりするので
    # alloneを通してないやつを足している
    lv = [allones(vi) for vi in M5 if allones(vi)]
    n = M5.nrows()
    for v in lv:
        for i in range(n):
            nv = allones(M5[i] - v)
            if nv and nv not in lv:
                lv.append(nv)
            nv = allones(M5[i] + v)
            if nv and nv not in lv:
                lv.append(nv)
    return matrix(lv)


import ast
with open("output.txt", "r") as f:
    p = ast.literal_eval(f.readline().strip())
    h = ast.literal_eval(f.readline().strip())

m = len(h)
n = 8

# --- solving ---
print("--- start ({}, {}) ---".format(n, m))

# 1. find orthogonal lattice M
M = find_orthogonal_lattice(h,p) # m x m matrix
print("LLL...")
t1 = cputime()
M2 = M.LLL()
t2 = cputime()
print("Done ", t2-t1)
MOrtho = M2[:m-n]                # n x m matrix

# x = orthogonalLatticeAttack(M2[:m-n])
# print(x.nrows(), x.ncols())
ke = kernelLLL(MOrtho)
print(ke.nrows(), ke.ncols())

blocksize=2
while blocksize < n:
    print("bs=",blocksize)
    if blocksize==2:
        M5=ke.LLL()
    else:
        M5=M5.BKZ(block_size=blocksize)

    if all([x in [-1, 0, 1] for row in M5 for x in row]):
        break

    if blocksize == 2:
        blocksize = 10
    else:
        blocksize += 10

MB = recoverBinary(M5)

for row in MB:
    flag = int("".join([str(x) for x in row])[::-1], 2)
    flag = flag.to_bytes((m + 7) // 8, "big")
    if b"zer0pts{" in flag:
        print(flag)
