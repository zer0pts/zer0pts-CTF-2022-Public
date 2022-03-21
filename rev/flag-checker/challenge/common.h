#pragma once

#define EGG_SIGNATURE 0xbadf00dcafedeadULL

#include <ctype.h>
#include <stdio.h>
#include "types.h"
#include "ntos.h"
#include "tricks.h"

typedef struct BASE_RELOCATION_BLOCK {
  DWORD PageAddress;
  DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
  USHORT Offset : 12;
  USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

#define CountRelocationEntries(dwBlockSize)		\
	(dwBlockSize -								\
	sizeof(BASE_RELOCATION_BLOCK)) /			\
	sizeof(BASE_RELOCATION_ENTRY)

void hexdump(void* ptr, int buflen) {
  unsigned char* buf = (unsigned char*)ptr;
  int i, j;
  for (i = 0; i < buflen; i += 16) {
    fprintf(stdout, "%06x: ", i);
    for (j = 0; j < 16; j++)
      if (i + j < buflen)
        fprintf(stdout, "%02x ", buf[i + j]);
      else
        fprintf(stdout, "   ");
    fprintf(stdout, " ");
    for (j = 0; j < 16; j++)
      if (i + j < buflen)
        fprintf(stdout, "%c", isprint(buf[i + j]) ? buf[i + j] : '.');
    fprintf(stdout, "\n");
  }
}


#define NTDLL_HASH  0x8e3b6971
#define KERNEL32_HASH  0xbf5afd6f
#define ADVAPI32_HASH 0x1c9a8509
#define GDI32_HASH 0x90479937
#define USER32_HASH 0xb4c88397
#define SHELL32_HASH 0x9201e928


#define LDR_LOAD_DLL 0xb0988fe4
#define LDR_GET_PROC 0xe54cc407

typedef NTSYSAPI
NTSTATUS
(NTAPI
  * t_LdrLoadDll)(
    IN PWCHAR               PathToFile OPTIONAL,
    IN ULONG                Flags OPTIONAL,
    IN PUNICODE_STRING      ModuleFileName,
    OUT HMODULE* ModuleHandle);

typedef
NTSYSAPI
NTSTATUS
(NTAPI*
  t_GetProc)(
    IN HMODULE              ModuleHandle,
    IN PANSI_STRING         FunctionName,
    IN WORD                 Oridinal,
    OUT PVOID* FunctionAddress);

u32 hash_it(wchar_t* buf, usize len, bool is_dll) {
  u32 ans{};
  u8* p = (u8*)buf;
  for (usize i = 0; i < len; i++) {
    auto c = p[i];
    if (is_dll && c >= 'A' && c <= 'Z') c |= 0x20;
    ans = _rotr(ans, 13) + c;
  }
  return ans;
}

struct DIR_BASIC_INFO {
  UNICODE_STRING Name;
  UNICODE_STRING TypeName;
};

byte_ptr load_fn(u32 dll_hash, u32 fn_hash);

byte_ptr resolve_fn(byte_ptr base_addr, u32 fn_hash) {
  char uni_dll_name[256], dll_name[128];
  auto nt_hdr = PIMAGE_NT_HEADERS64(base_addr + *(u32*)(base_addr + 0x3c));
  auto exp_dir_rva = nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
  auto exp_dir_size = nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
  auto exp_dir = PIMAGE_EXPORT_DIRECTORY(base_addr + exp_dir_rva);
  auto n_funcs = exp_dir->NumberOfNames;
  auto fn_ptr_list = (u32*)(base_addr + exp_dir->AddressOfFunctions);
  auto name_ptr_list = (u32*)(base_addr + exp_dir->AddressOfNames);
  auto ord_ptr_list = (WORD*)(base_addr + exp_dir->AddressOfNameOrdinals);
  for (usize i{}; i < n_funcs; ++i) {
    char* name = (char*)base_addr + name_ptr_list[i];
    if (hash_it((wchar_t*)name, strlen(name), false) == fn_hash) {
      auto fn_rva = fn_ptr_list[ord_ptr_list[i]];
      auto fn_ptr = (byte_ptr)(base_addr + fn_rva);
      if (fn_ptr >= byte_ptr(exp_dir) && fn_ptr <= byte_ptr(exp_dir) + exp_dir_size) {
        // forwarded entry
        memset(uni_dll_name, 0, sizeof uni_dll_name);
        memset(dll_name, 0, sizeof dll_name);

        auto ptr = strchr((char*)fn_ptr, '.');
        memcpy(dll_name, fn_ptr, (char*)ptr - (char*)fn_ptr);
        strcat(dll_name, ".dll");
        char* fn_name = ptr + 1;
        // char* dll_name = buffer;
        // do ldr load dll
        ANSI_STRING ansi{};
        ansi.Buffer = dll_name;
        ansi.Length = strlen(dll_name);
        ansi.MaximumLength = ansi.Length + 1;
        UNICODE_STRING uni{};
        uni.Length = 2 * ansi.Length;
        uni.MaximumLength = uni.Length + 2;
        uni.Buffer = (PWSTR)uni_dll_name;
        xRtlAnsiStringToUnicodeString(&uni, &ansi, FALSE);
        HMODULE h_module{};
        xLdrLoadDll(nullptr, 0, &uni, &h_module);
        ansi.Buffer = fn_name;
        ansi.Length = strlen(fn_name);
        ansi.MaximumLength = ansi.Length;
        xGetProc(h_module, &ansi, 0, (PVOID*)&fn_ptr);
      }
      return fn_ptr;
    }
  }
  return nullptr;
}

byte_ptr try_load_lib(u32 dll_hash, u32 fn_hash) {
  char buffer[0x1000];
  char context[0x1000]{};
  ULONG nbytes{};
  for (u32 i{ 1 }; ; ++i) {
    auto handle = HANDLE((ULONG_PTR)i << 2);
    auto status = xNtQueryObject(handle, ObjectNameInformation, buffer, sizeof buffer, &nbytes);
    if (status == STATUS_INVALID_HANDLE)
      continue;
    auto p_info = POBJECT_NAME_INFORMATION(buffer);
    if (hash_it(p_info->Name.Buffer, p_info->Name.Length, false) != KNOWN_DLL_HASH) {
      continue;
    }
    while (1) {
      status = xNtQueryDirectoryObject(handle, buffer, sizeof buffer, TRUE, FALSE, (PULONG)&context, nullptr);
      if (status == STATUS_NO_MORE_ENTRIES || status == STATUS_ACCESS_DENIED) {
        break;
      }
      auto p_dll_name = &((DIR_BASIC_INFO*)buffer)->Name;
      if (hash_it(p_dll_name->Buffer, p_dll_name->Length, true) != dll_hash) {
        continue;
      }
      HMODULE dll_addr{};
      xLdrLoadDll(NULL, 0, p_dll_name, &dll_addr);
      return resolve_fn(byte_ptr(dll_addr), fn_hash);
    }
  }
  return nullptr;
}

byte_ptr load_fn(u32 dll_hash, u32 fn_hash) {
  auto ldr_data = NtCurrentPeb()->Ldr;
  auto curr = ldr_data->InLoadOrderModuleList.Flink;
  auto head = curr;

  do {
    auto tmp = PLDR_DATA_TABLE_ENTRY(curr);
    curr = curr->Flink;
    if (curr == head) break;
    if (hash_it(tmp->BaseDllName.Buffer, tmp->BaseDllName.Length, true) != dll_hash)
      continue;
    auto base_addr = byte_ptr(tmp->DllBase);
    auto fn_ptr = resolve_fn(base_addr, fn_hash);
    return fn_ptr;
    // curr = curr->Flink;
  } while (curr != head);
  // fprintf(stdout, "No Fn found for {%x, %x}", dll_hash, fn_hash);
  return try_load_lib(dll_hash, fn_hash);
}

