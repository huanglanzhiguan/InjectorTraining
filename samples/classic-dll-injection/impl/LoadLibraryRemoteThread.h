#pragma once

#include <windows.h>

namespace lab
{
enum class LoadMethod
{
    LoadLibraryW,
    LdrLoadDll
};

enum class LaunchMethod
{
    CreateRemoteThread,
    NtCreateThreadEx,
    QueueUserAPC
};

bool InjectDllWithLoadLibraryRemoteThread(DWORD targetPid, const wchar_t* dllPath);
bool InjectDll(DWORD targetPid,
               const wchar_t* dllPath,
               LoadMethod loadMethod,
               LaunchMethod launchMethod);
bool InjectDllWithLoadLibrary(DWORD targetPid,
                              const wchar_t* dllPath,
                              LaunchMethod launchMethod);
}
