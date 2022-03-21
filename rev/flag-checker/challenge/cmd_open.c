#include <windows.h>
#include <Shlwapi.h>

#pragma comment(lib, "shell32.lib")

int main() {
    ShellExecuteW(
        NULL, L"open",
        L"C:\\Windows\\System32\\cmd.exe",
        NULL, NULL, SW_SHOW
    );
    return 0;
}