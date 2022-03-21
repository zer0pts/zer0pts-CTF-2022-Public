  A = arch
  A == ARCH_X86_64 ? next : dead
  A = sys_number
  A >= 0x40000000 ? dead : next

  A == open     ? dead : next
  A == openat   ? dead : next
  A == execve   ? dead : next
  A == execveat ? dead : next
  A == creat  ? dead : next
  A == fork   ? dead : next
  A == vfork  ? dead : next
  A == clone  ? dead : next
  A == ptrace ? dead : next
  A == kill   ? dead : next
  A == tkill  ? dead : next
  A == tgkill ? dead : next
  A == process_vm_readv  ? dead : next
  A == process_vm_writev ? dead : next

  return ALLOW

dead:
  return KILL
