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

struct ManualMapConfig
{
    bool eraseHeaders = false;
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
