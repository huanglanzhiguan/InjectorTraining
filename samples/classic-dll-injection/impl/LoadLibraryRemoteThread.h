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
    QueueUserAPC,
    ThreadHijack
};

struct QueueUserApcConfig
{
    DWORD threadId = 0;
};

struct ThreadHijackConfig
{
    DWORD threadId = 0;
};

struct InjectorConfig
{
    LoadMethod loadMethod = LoadMethod::LoadLibraryW;
    LaunchMethod launchMethod = LaunchMethod::CreateRemoteThread;
    QueueUserApcConfig queueUserApc;
    ThreadHijackConfig threadHijack;
};

bool InjectDllWithLoadLibraryRemoteThread(DWORD targetPid, const wchar_t* dllPath);
bool InjectDll(DWORD targetPid,
               const wchar_t* dllPath,
               const InjectorConfig& config);
bool InjectDllWithLoadLibrary(DWORD targetPid,
                              const wchar_t* dllPath,
                              const InjectorConfig& config);
}
