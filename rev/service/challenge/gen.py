import hashlib

s = b"zer0pts{m0d1fy1ng_PE_1mp0rts_1s_4n_34sy_0bfusc4t10n}\r\n"
s += b'\x00' * (0x40 - len(s))

for i in range(0, len(s), 2):
    h = hashlib.sha256(s[i:i+2]).digest().hex()
    print('"\\x'+'\\x'.join([h[j:j+2] for j in range(0, 64, 2)]) + '"')
