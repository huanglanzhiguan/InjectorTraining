#pragma once

#include <windows.h>

namespace lab
{
enum class LaunchMethod
{
    CreateRemoteThread,
    NtCreateThreadEx,
    QueueUserAPC
};

bool InjectDllWithLoadLibraryRemoteThread(DWORD targetPid, const wchar_t* dllPath);
bool InjectDllWithLoadLibrary(DWORD targetPid,
                              const wchar_t* dllPath,
                              LaunchMethod launchMethod);
}
