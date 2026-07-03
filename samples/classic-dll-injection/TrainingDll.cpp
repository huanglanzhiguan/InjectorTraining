#include <windows.h>

#pragma comment(lib, "user32.lib")

static DWORD WINAPI ShowMessage(LPVOID)
{
    MessageBoxW(nullptr,
                L"Hello from injected DLL!",
                L"InjectorTraining",
                MB_OK | MB_ICONINFORMATION);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(module);

        HANDLE thread = CreateThread(nullptr, 0, ShowMessage, nullptr, 0, nullptr);
        if (thread)
        {
            CloseHandle(thread);
        }
    }

    return TRUE;
}

