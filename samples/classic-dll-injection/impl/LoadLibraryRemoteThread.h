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

struct QueueUserApcConfig
{
    DWORD threadId = 0;
};

struct InjectorConfig
{
    LoadMethod loadMethod = LoadMethod::LoadLibraryW;
    LaunchMethod launchMethod = LaunchMethod::CreateRemoteThread;
    QueueUserApcConfig queueUserApc;
};

bool InjectDllWithLoadLibraryRemoteThread(DWORD targetPid, const wchar_t* dllPath);
bool InjectDll(DWORD targetPid,
               const wchar_t* dllPath,
               const InjectorConfig& config);
bool InjectDllWithLoadLibrary(DWORD targetPid,
                              const wchar_t* dllPath,
                              const InjectorConfig& config);
}
