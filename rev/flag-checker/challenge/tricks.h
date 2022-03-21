#pragma once
#define MyHeap  ((HANDLE)(NtCurrentPeb()->ProcessHeap))

#define xCreateToolhelp32Snapshot ((HANDLE(WINAPI*)(DWORD, DWORD))load_fn(KERNEL32_HASH, 0xe454dfed))

#define xThread32First ((BOOL(WINAPI*)(HANDLE, LPTHREADENTRY32))load_fn(KERNEL32_HASH, 0xb83bb6ea))

#define xThread32Next ((BOOL(WINAPI*)(HANDLE, LPTHREADENTRY32))load_fn(KERNEL32_HASH, 0x86fed608))

#define xOpenThread ((HANDLE(WINAPI*)(DWORD,BOOL,DWORD))load_fn(KERNEL32_HASH, 0x58c91e6f))


// ....

#define xProcess32FirstW ((BOOL(WINAPI*)(HANDLE,PPROCESSENTRY32W))load_fn(KERNEL32_HASH, 0xd53992a4))
#define xProcess32NextW ((BOOL(WINAPI*)(HANDLE,PPROCESSENTRY32W))load_fn(KERNEL32_HASH, 0x2a523c0a))

#define xGetThreadTimes ((BOOL(WINAPI*)(HANDLE,PFILETIME,PFILETIME,PFILETIME,PFILETIME))load_fn(KERNEL32_HASH, 0x6d1caeeb))

#define xCloseHandle ((BOOL(WINAPI*)(HANDLE))load_fn(KERNEL32_HASH, 0xffd97fb))
#define xHeapAlloc ((PVOID(WINAPI*)(HANDLE,DWORD,SIZE_T))load_fn(KERNEL32_HASH, 0x2500383c))
#define xHeapFree ((BOOL(WINAPI*)(HANDLE,DWORD,PVOID))load_fn(KERNEL32_HASH, 0x10c32616))

#define xOpenProcess ((HANDLE(WINAPI*)(DWORD,BOOL,DWORD))load_fn(KERNEL32_HASH, 0xefe297c0))

#define xReadProcessMemory ((BOOL(WINAPI*)(HANDLE,LPCVOID,LPVOID,SIZE_T,PSIZE_T))load_fn(KERNEL32_HASH, 0x579d1be9))
#define xReadFile ((BOOL(WINAPI*)(HANDLE,LPVOID,DWORD,LPDWORD,LPOVERLAPPED))load_fn(KERNEL32_HASH, 0x10fa6516))
#define xWriteFile ((BOOL(WINAPI*)(HANDLE,LPVOID,DWORD,LPDWORD,LPOVERLAPPED))load_fn(KERNEL32_HASH, 0xe80a791f))
#define xDuplicateHandle ((BOOL(WINAPI*)(HANDLE,HANDLE,HANDLE,LPHANDLE,DWORD,BOOL,DWORD))load_fn(KERNEL32_HASH, 0xbd566724))

#define xCreateNamedPipeW ((HANDLE(WINAPI*)(LPCWSTR,DWORD,DWORD,DWORD,DWORD,DWORD,DWORD,LPSECURITY_ATTRIBUTES))load_fn(KERNEL32_HASH, 0xb2d685c))
#define xConnectNamedPipe ((BOOL(WINAPI*)(HANDLE,LPOVERLAPPED))load_fn(KERNEL32_HASH, 0xcb09c9f9))
#define xFlushFileBuffers ((BOOL(WINAPI*)(HANDLE))load_fn(KERNEL32_HASH, 0x37f385d9))
#define xDisconnectNamedPipe ((BOOL(WINAPI*)(HANDLE))load_fn(KERNEL32_HASH, 0xdc7ccd45))
#define xGetTempPathW ((DWORD(WINAPI*)(DWORD,LPWSTR))load_fn(KERNEL32_HASH, 0x5b8aca49))
#define xGetTempFileNameW ((UINT(WINAPI*)(LPCWSTR,LPCWSTR,UINT,LPWSTR))load_fn(KERNEL32_HASH, 0xe7ac224e))
#define xCreateThread ((HANDLE(WINAPI*)(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId))load_fn(KERNEL32_HASH, 0xca2bd06b))
#define xAllocConsole ((BOOL(WINAPI*)())load_fn(KERNEL32_HASH, 0xd9f868d8))
#define xFreeConsole ((BOOL(WINAPI*)())load_fn(KERNEL32_HASH, 0x4f76990f))
#define xGetConsoleWindow ((HWND(WINAPI*)())load_fn(KERNEL32_HASH, 0x6af5e778))

// ntdll
#define xNtQueryInformationProcess ((NTSTATUS(NTAPI*)(HANDLE,DWORD,PVOID,ULONG,usize*))load_fn(NTDLL_HASH, 0xb10fd839))
#define xNtWriteVirtualMemory ((NTSTATUS(NTAPI*)(HANDLE,PVOID,LPVOID,SIZE_T,PSIZE_T))load_fn(NTDLL_HASH, 0xc5108cc2))
#define xNtAllocateVirtualMemory ((NTSTATUS(NTAPI*)(HANDLE,PVOID*,ULONG*,PSIZE_T,ULONG,ULONG))load_fn(NTDLL_HASH, 0xd33bcabd))
#define xNtReadVirtualMemory ((NTSTATUS(NTAPI*)(HANDLE,PVOID,PVOID,SIZE_T,PSIZE_T))load_fn(NTDLL_HASH, 0x3aefa5aa))
#define xNtMapViewOfSection ((NTSTATUS(NTAPI*)(HANDLE,HANDLE,PVOID*,ULONG_PTR,SIZE_T,PLARGE_INTEGER,PSIZE_T,SECTION_INHERIT,ULONG,ULONG))load_fn(NTDLL_HASH, 0xd5159b94))
#define xNtGetContextThread ((NTSTATUS(NTAPI*)(HANDLE,PCONTEXT))load_fn(NTDLL_HASH, 0xe935e393))
#define xNtSetContextThread ((NTSTATUS(NTAPI*)(HANDLE,PCONTEXT))load_fn(NTDLL_HASH, 0x6935e395))
#define xNtFreeVirtualMemory ((NTSTATUS(NTAPI*)(HANDLE,PVOID*,PSIZE_T,ULONG))load_fn(NTDLL_HASH, 0xdb63b5ab))
#define xRtlInitUnicodeString ((VOID(NTAPI*)(PUNICODE_STRING,PCWSTR))load_fn(NTDLL_HASH, 0x3035d02a))
#define xNtOpenFile ((NTSTATUS(NTAPI*)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PIO_STATUS_BLOCK,ULONG,ULONG))load_fn(NTDLL_HASH, 0x852974b8))
#define xNtSetInformationFile ((NTSTATUS(NTAPI*)(HANDLE,PIO_STATUS_BLOCK,PVOID,ULONG,FILE_INFORMATION_CLASS))load_fn(NTDLL_HASH, 0xc7533a80))
#define xNtWriteFile ((NTSTATUS(NTAPI*)(HANDLE,HANDLE,PIO_APC_ROUTINE,PVOID,PIO_STATUS_BLOCK,PVOID,ULONG,PLARGE_INTEGER,PULONG))load_fn(NTDLL_HASH, 0x680e1933))

#define xNtCreateSection ((NTSTATUS(NTAPI*)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PLARGE_INTEGER,ULONG,ULONG,HANDLE))load_fn(NTDLL_HASH, 0x5bb29bcb))
#define xNtOpenSection ((NTSTATUS(NTAPI*)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES))load_fn(NTDLL_HASH, 0x92b5dd95))

#define xNtQueryObject ((NTSTATUS(NTAPI*)(HANDLE,DWORD,PVOID,ULONG,PULONG))load_fn(NTDLL_HASH, 0xfeedf510))

#define xLdrLoadDll  ((t_LdrLoadDll)load_fn(NTDLL_HASH, LDR_LOAD_DLL))
#define xGetProc  ((t_GetProc)load_fn(NTDLL_HASH, LDR_GET_PROC))
#define MyLastErr (NtCurrentTeb()->LastErrorValue)

#define xRtlAnsiStringToUnicodeString ((NTSTATUS(NTAPI*)(PUNICODE_STRING,PANSI_STRING,BOOL))load_fn(NTDLL_HASH, 0xeb6c8389))
#define xNtQueryDirectoryObject ((NTSTATUS(NTAPI*)(HANDLE DirectoryHandle, PVOID Buffer, ULONG Length, BOOLEAN ReturnSingleEntry, BOOLEAN RestartScan, PULONG Context, PULONG ReturnLength))load_fn(NTDLL_HASH, 0x3b2aa494))
#define xNtDelayExecution ((NTSTATUS(NTAPI*)(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval))load_fn(NTDLL_HASH, 0xd4f11852))

#define KNOWN_DLL_HASH 0xd40a331c


#define xCryptAcquireContextW ((BOOL(WINAPI*)(HCRYPTPROV *phProv, LPCWSTR szContainer, LPCWSTR szProvider, DWORD dwProvType, DWORD dwFlags))load_fn(ADVAPI32_HASH, 0x43c28bf0))
#define xCryptCreateHash ((BOOL(WINAPI*)(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY hKey, DWORD dwFlags, HCRYPTHASH *phHash))load_fn(ADVAPI32_HASH, 0x4105a130))
#define xCryptHashData ((BOOL(WINAPI*)(HCRYPTHASH hHash, const BYTE *pbData, DWORD dwDataLen, DWORD dwFlags))load_fn(ADVAPI32_HASH, 0xc2122629))
#define xCryptDeriveKey ((BOOL(WINAPI*)(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTHASH hBaseData, DWORD dwFlags, HCRYPTKEY *phKey))load_fn(ADVAPI32_HASH, 0xb56d274a))
#define xCryptDecrypt ((BOOL(WINAPI*)(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen))load_fn(ADVAPI32_HASH, 0x59202584))

#define xCryptDestroyHash ((BOOL(WINAPI*)(HCRYPTHASH))load_fn(ADVAPI32_HASH, 0x25d4ae7a))
#define xCryptDestroyKey ((BOOL(WINAPI*)(HCRYPTKEY))load_fn(ADVAPI32_HASH, 0x95e24580))
#define xCryptReleaseContext ((BOOL(WINAPI*)(HCRYPTPROV hProv, DWORD dwFlags))load_fn(ADVAPI32_HASH, 0x5ae8e894))

#define xFindWindowExW ((HWND(WINAPI*)(HWND,HWND,LPCWSTR,LPCWSTR))load_fn(USER32_HASH, 0xcb543365))
#define xShellExecuteExW ((BOOL(WINAPI*)(SHELLEXECUTEINFOW*))load_fn(SHELL32_HASH, 0xfc2ed8dd))
#define xShowWindow ((BOOL(WINAPI*)(HWND,int))load_fn(USER32_HASH, 0xc95d4f83))
#define xGetClientRect ((BOOL(WINAPI*)(HWND,LPRECT))load_fn(USER32_HASH, 0x157f8399))
// gdi32

#define xCreateDIBSection ((HBITMAP(WINAPI*)(HDC hdc, const BITMAPINFO *pbmi, UINT usage, void **ppvBits, HANDLE hSection, DWORD offset))load_fn(GDI32_HASH, 0x89364153))
#define xCreateCompatibleBitmap ((HBITMAP(WINAPI*)(HDC hdc, int cx, int cy))load_fn(GDI32_HASH, 0x1eb1121f))
#define xSetDIBits ((int(WINAPI*)(HDC hdc, HBITMAP hbm, UINT start, UINT cLines, const void *lpBits, const BITMAPINFO *lpbmi, UINT ColorUse))load_fn(GDI32_HASH, 0xdc74b775))
#define xGetDC ((HDC(WINAPI*)(HWND))load_fn(USER32_HASH, 0xcc248d43))
#define xCreateCompatibleDC ((HDC(WINAPI*)(HDC hdc))load_fn(GDI32_HASH, 0x66f33a69))
#define xSelectObject ((HGDIOBJ(WINAPI*)(HDC hdc, HGDIOBJ h))load_fn(GDI32_HASH, 0xfe97a655))
#define xBitBlt ((BOOL(WINAPI*)(HDC hdc, int x, int y, int cx, int cy, HDC hdcSrc, int x1, int y1, DWORD rop))load_fn(GDI32_HASH, 0xeb66a115))