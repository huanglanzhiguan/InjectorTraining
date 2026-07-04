#include "Win32Helpers.h"

#include "Handle.h"

#include <tlhelp32.h>

#include <cstdio>
#include <cwchar>

namespace lab
{
static bool GetModuleFileBaseName(HMODULE module, wchar_t* output, DWORD outputCount)
{
    wchar_t modulePath[MAX_PATH] = {};
    DWORD length = GetModuleFileNameW(module, modulePath, _countof(modulePath));
    if (length == 0 || length >= _countof(modulePath))
    {
        PrintLastError(L"GetModuleFileNameW");
        return false;
    }

    const wchar_t* baseName = wcsrchr(modulePath, L'\\');
    baseName = baseName ? baseName + 1 : modulePath;

    if (wcscpy_s(output, outputCount, baseName) != 0)
    {
        wprintf(L"Failed to copy module base name.\n");
        return false;
    }

    return true;
}

static UniqueHandle CreateModuleSnapshot(DWORD pid)
{
    DWORD last_error = ERROR_SUCCESS;

    for (int attempt = 0; attempt < 5; ++attempt)
    {
        UniqueHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid));
        if (snapshot.valid())
        {
            return snapshot;
        }

        last_error = GetLastError();
        if (last_error != ERROR_BAD_LENGTH)
        {
            break;
        }

        Sleep(25);
    }

    SetLastError(last_error);
    PrintLastError(L"CreateToolhelp32Snapshot(modules)");
    return UniqueHandle();
}

void PrintLastError(const wchar_t* action)
{
    wprintf(L"%s failed. GetLastError() = %lu\n", action, GetLastError());
}

bool GetFullFilePath(const wchar_t* input, wchar_t* output, DWORD outputCount)
{
    DWORD length = GetFullPathNameW(input, outputCount, output, nullptr);
    if (length == 0 || length >= outputCount)
    {
        PrintLastError(L"GetFullPathNameW");
        return false;
    }

    DWORD attributes = GetFileAttributesW(output);
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY))
    {
        wprintf(L"Path does not point to a file: %s\n", output);
        return false;
    }

    return true;
}

bool BuildSystemExecutablePath(const wchar_t* exeName, wchar_t* output, DWORD outputCount)
{
    UINT length = GetSystemDirectoryW(output, outputCount);
    if (length == 0 || length >= outputCount)
    {
        PrintLastError(L"GetSystemDirectoryW");
        return false;
    }

    if (wcscat_s(output, outputCount, L"\\") != 0 ||
        wcscat_s(output, outputCount, exeName) != 0)
    {
        wprintf(L"Failed to build system executable path for %s.\n", exeName);
        return false;
    }

    return true;
}

std::uintptr_t FindRemoteModuleBase(DWORD pid, const wchar_t* moduleName)
{
    UniqueHandle snapshot = CreateModuleSnapshot(pid);
    if (!snapshot.valid())
    {
        return 0;
    }

    MODULEENTRY32W entry = {};
    entry.dwSize = sizeof(entry);

    if (!Module32FirstW(snapshot.get(), &entry))
    {
        PrintLastError(L"Module32FirstW");
        return 0;
    }

    do
    {
        if (_wcsicmp(entry.szModule, moduleName) == 0)
        {
            return reinterpret_cast<std::uintptr_t>(entry.modBaseAddr);
        }
    } while (Module32NextW(snapshot.get(), &entry));

    wprintf(L"Could not find %s in target process.\n", moduleName);
    return 0;
}

bool FindRemoteModuleByPath(DWORD pid, const wchar_t* modulePath, std::uintptr_t& moduleBase)
{
    moduleBase = 0;

    UniqueHandle snapshot = CreateModuleSnapshot(pid);
    if (!snapshot.valid())
    {
        return false;
    }

    MODULEENTRY32W entry = {};
    entry.dwSize = sizeof(entry);

    if (!Module32FirstW(snapshot.get(), &entry))
    {
        PrintLastError(L"Module32FirstW");
        return false;
    }

    do
    {
        if (_wcsicmp(entry.szExePath, modulePath) == 0)
        {
            moduleBase = reinterpret_cast<std::uintptr_t>(entry.modBaseAddr);
            return true;
        }
    } while (Module32NextW(snapshot.get(), &entry));

    return false;
}

LPTHREAD_START_ROUTINE ResolveRemoteProcAddress(DWORD pid,
                                                const wchar_t* moduleName,
                                                const char* procName)
{
    HMODULE requestedLocalModule = GetModuleHandleW(moduleName);
    if (!requestedLocalModule)
    {
        PrintLastError(L"GetModuleHandleW");
        return nullptr;
    }

    FARPROC localProc = GetProcAddress(requestedLocalModule, procName);
    if (!localProc)
    {
        PrintLastError(L"GetProcAddress");
        return nullptr;
    }

    HMODULE actualLocalModule = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCWSTR>(localProc),
                            &actualLocalModule))
    {
        PrintLastError(L"GetModuleHandleExW");
        return nullptr;
    }

    wchar_t actualModuleName[MAX_PATH] = {};
    if (!GetModuleFileBaseName(actualLocalModule, actualModuleName, _countof(actualModuleName)))
    {
        return nullptr;
    }

    std::uintptr_t remoteModule = FindRemoteModuleBase(pid, actualModuleName);
    if (!remoteModule)
    {
        return nullptr;
    }

    std::uintptr_t rva =
        reinterpret_cast<std::uintptr_t>(localProc) -
        reinterpret_cast<std::uintptr_t>(actualLocalModule);

    wprintf(L"Resolved %S through %s at RVA 0x%Ix\n",
            procName,
            actualModuleName,
            rva);

    return reinterpret_cast<LPTHREAD_START_ROUTINE>(remoteModule + rva);
}
}
