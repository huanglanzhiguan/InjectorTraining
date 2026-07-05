#pragma once

#include <windows.h>

namespace lab
{
enum class LoadMethod
{
    LoadLibraryW,
    LdrLoadDll,
    LdrpLoadDll,
    LdrpLoadDllInternal,
    ManualMap
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

enum class ManualMapHeaderMode
{
    Keep,
    Erase,
    Fake
};

struct ManualMapConfig
{
    ManualMapHeaderMode headerMode = ManualMapHeaderMode::Keep;
};

struct InjectorConfig
{
    LoadMethod loadMethod = LoadMethod::LoadLibraryW;
    LaunchMethod launchMethod = LaunchMethod::CreateRemoteThread;
    QueueUserApcConfig queueUserApc;
    ThreadHijackConfig threadHijack;
    ManualMapConfig manualMap;
};

bool InjectDll(DWORD targetPid,
               const wchar_t* dllPath,
               const InjectorConfig& config);
}
