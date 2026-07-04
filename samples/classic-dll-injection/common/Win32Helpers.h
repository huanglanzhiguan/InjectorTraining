#pragma once

#include <windows.h>

#include <cstdint>

namespace lab
{
void PrintLastError(const wchar_t* action);
bool GetFullFilePath(const wchar_t* input, wchar_t* output, DWORD outputCount);
std::uintptr_t FindRemoteModuleBase(DWORD pid, const wchar_t* moduleName);
bool FindRemoteModuleByPath(DWORD pid, const wchar_t* modulePath, std::uintptr_t& moduleBase);
LPTHREAD_START_ROUTINE ResolveRemoteProcAddress(DWORD pid,
                                                const wchar_t* moduleName,
                                                const char* procName);
}
