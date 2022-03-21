with open('./distfiles/output.txt', 'r') as f:
    exec(f.read())

beta = 2**1024 - 1
ep = int((beta - sqrt(beta**2 - 4*n)) / 2)

delta = 0
while n%(ep+delta) != 0 and n%(ep-delta) != 0:
    delta += 1

if n % (ep+delta) == 0:
    p, q = ep+delta, n//(ep+delta)
else:
    p, q = ep-delta, n//(ep-delta)

d = inverse_mod(65537, (p-1)*(q-1))
flag = int.to_bytes(int(power_mod(c, d, n)), 2048//8, 'big')

print(flag.strip(b'\0').decode())
