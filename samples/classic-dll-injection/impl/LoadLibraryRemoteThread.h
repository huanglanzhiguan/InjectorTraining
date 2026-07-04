#pragma once

#include <windows.h>

namespace lab
{
enum class RemoteThreadLaunchMethod
{
    CreateRemoteThread,
    NtCreateThreadEx
};

bool InjectDllWithLoadLibraryRemoteThread(DWORD targetPid, const wchar_t* dllPath);
bool InjectDllWithLoadLibrary(DWORD targetPid,
                              const wchar_t* dllPath,
                              RemoteThreadLaunchMethod launchMethod);
}
