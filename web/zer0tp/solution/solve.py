import os
from itertools import product
from random import shuffle
import string
import zlib
import base64
import requests
from hashlib import md5

APP_HOST = os.getenv("HOST", "localhost")
APP_PORT = os.getenv("PORT", "8077")
ZER0TP_HOST = os.getenv("ZER0TP_HOST", "localhost")
ZER0TP_PORT = os.getenv("ZER0TP_PORT", "8080")

SECRET_BYTES = 12
SECRET_LEN = len(base64.b64encode(os.urandom(SECRET_BYTES)))

# |Σ|=4, n=3
DE_BRUIJN_TEMPLATE = b'000100200301101201302102202303103203311121131221231321332223233300'[:0x30-5]
DE_BRUIJN = DE_BRUIJN_TEMPLATE
l = list(range(0x20))
shuffle(l)
head = l[:4]
for i, c in enumerate(head):
  DE_BRUIJN = DE_BRUIJN.replace(str(i).encode(), bytearray([c]))

prev_username = DE_BRUIJN
password = 'p4ssw0rd'
res = requests.post(f'http://{ZER0TP_HOST}:{ZER0TP_PORT}/api/register', {
  "username": prev_username,
  "password": password
}).json()
assert res["result"] == "OK"

print(f'[+] registered as {prev_username}')

q = 0
def oracle(query: bytes):
  global q, prev_username
  q += 1
  assert all(0 <= c < 0x80 for c in query) and len(query) < 50
  res = requests.post(f'http://{ZER0TP_HOST}:{ZER0TP_PORT}/api/rename', {
    "username": prev_username.decode(),
    "password": password,
    "new_username": query.decode(),
    "new_password": password
  }).json()
  assert res["result"] == "OK"
  prev_username = query
  res = requests.post(f'http://{ZER0TP_HOST}:{ZER0TP_PORT}/api/login', {
    "username": query.decode(),
    "password": password    
  }).json()
  assert res["result"] == "OK"
  return res["id"].encode(), bytes.fromhex(res["token"])

block_lens = [
  16, # zlib header
  1,  # bfinal
  2,  # btypes
  5,  # literal/length code length
  5,  # distance code length
  4,  # stager code length
  *([3] * 10), 1 # stager canonical codes
]
assert(sum(block_lens) == 64)
blocks = [(l, set()) for l in block_lens]

def add_block_info(data):
  bindata = int.from_bytes(data, "little")
  def next(n):
    nonlocal bindata
    res = bindata & ((1 << n) - 1)
    bindata >>= n
    return res
  for length, cands in blocks:
    val = next(length)
    cands.add(val)

PREFIX = b'#$'
ALPHABET = (string.ascii_letters + string.digits + "+/").encode()

print("[+] calculating candidates of each blocks...")
for i in range(1000):
  s = base64.b64encode(os.urandom(SECRET_BYTES))
  cur = PREFIX
  while len(cur) != len(PREFIX + s):
    for c in ALPHABET:
      payload = DE_BRUIJN + cur[-2:] + bytearray([c]) + PREFIX
      data = zlib.compress(payload + s)
      add_block_info(data)
    cur += bytearray([s[len(cur) - len(PREFIX)]])

combs = 1
for _, cands in blocks: combs *= len(cands)
print(f"[+] calculated.")

assert len(blocks[1][1]) == 1
assert len(blocks[2][1]) == 1

prod = list(product(*[[*cands] for _, cands in blocks]))
def compute_blocks(salt, hash):
  for block_vals in prod:
    data = 0
    bit_len = 0
    def add(b, len):
      nonlocal data, bit_len
      assert b < 2 ** len
      data += (b << bit_len)
      bit_len += len
    for val, length in zip(block_vals, block_lens):
      add(val, length)
    assert(bit_len == 64)
    cur_hash = md5(salt + data.to_bytes(bit_len // 8, "little")).digest()
    if hash != cur_hash: continue
    return block_vals
  assert False

DEBUG = True
init = PREFIX
def solve(cur):
  print(f'[+] {cur=}')
  if len(cur) - len(init) == SECRET_LEN:
    return cur[len(init):]
  res = None
  for c in ALPHABET:
    if res is not None: break
    payload = DE_BRUIJN + cur[-2:] + bytearray([c]) + PREFIX 
    salt, hash = oracle(payload)
    if compute_blocks(salt, hash)[3] == 0: continue
    res = solve(cur + bytearray([c]))
  return res

res = solve(init)
assert res is not None

response = requests.post(f'http://{ZER0TP_HOST}:{ZER0TP_PORT}/api/set_admin', {
  "username": prev_username.decode(),
  "secret": res.decode(),
  "admin": "1"
}).json()
assert response["result"] == "OK"

username = base64.b64encode(os.urandom(SECRET_BYTES)).decode()
id, token = oracle(username.encode())

s = requests.Session()
content = s.post(f'http://{APP_HOST}:{APP_PORT}/login', {
  "username": username,
  "id": id,
  "token": token.hex()
}).content

print(content.split(b'<h1>')[1].split(b'</h1>')[0])
print(f'{q=}')
