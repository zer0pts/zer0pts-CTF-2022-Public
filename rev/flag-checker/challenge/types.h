#pragma once

#include "ntos.h"

typedef BYTE u8;
typedef BYTE byte;

typedef INT32 i32;
typedef UINT32 u32;
typedef INT64 i64;
typedef UINT64 u64;

typedef SIZE_T usize;
typedef SSIZE_T isize;
typedef LPBYTE byte_ptr;

// typedef'd funcs

typedef NTSTATUS(NTAPI* fn_NtQueryInformationProcess)(
  HANDLE           ProcessHandle,
  DWORD            ProcessInformationClass,
  PVOID            ProcessInformation,
  ULONG            ProcessInformationLength,
  usize* ReturnLength
  );