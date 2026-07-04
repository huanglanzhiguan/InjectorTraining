#include "LoadLibraryRemoteThread.h"

#include "../common/Handle.h"
#include "../common/Win32Helpers.h"

#include <cstdio>
#include <cwchar>

namespace lab
{
namespace
{
using NtCreateThreadExFn = LONG(NTAPI*)(PHANDLE ThreadHandle,
                                        ACCESS_MASK DesiredAccess,
                                        PVOID ObjectAttributes,
                                        HANDLE ProcessHandle,
                                        PVOID StartRoutine,
                                        PVOID Argument,
                                        ULONG CreateFlags,
                                        SIZE_T ZeroBits,
                                        SIZE_T StackSize,
                                        SIZE_T MaximumStackSize,
                                        PVOID AttributeList);

bool NtSuccess(LONG status)
{
    return status >= 0;
}

void PrintNtStatus(const wchar_t* action, LONG status)
{
    wprintf(L"%s failed. NTSTATUS = 0x%08lX\n", action, static_cast<unsigned long>(status));
}

NtCreateThreadExFn ResolveNtCreateThreadEx()
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
    {
        PrintLastError(L"GetModuleHandleW(ntdll.dll)");
        return nullptr;
    }

    auto function = reinterpret_cast<NtCreateThreadExFn>(
        GetProcAddress(ntdll, "NtCreateThreadEx"));
    if (!function)
    {
        PrintLastError(L"GetProcAddress(NtCreateThreadEx)");
        return nullptr;
    }

    return function;
}

UniqueHandle LaunchWithCreateRemoteThread(HANDLE process,
                                          LPTHREAD_START_ROUTINE startRoutine,
                                          LPVOID argument)
{
    wprintf(L"Launching remote thread with CreateRemoteThread.\n");

    UniqueHandle remoteThread(CreateRemoteThread(process,
                                                nullptr,
                                                0,
                                                startRoutine,
                                                argument,
                                                0,
                                                nullptr));
    if (!remoteThread.valid())
    {
        PrintLastError(L"CreateRemoteThread");
    }

    return remoteThread;
}

UniqueHandle LaunchWithNtCreateThreadEx(HANDLE process,
                                        LPTHREAD_START_ROUTINE startRoutine,
                                        LPVOID argument)
{
    wprintf(L"Launching remote thread with NtCreateThreadEx.\n");

    const auto ntCreateThreadEx = ResolveNtCreateThreadEx();
    if (!ntCreateThreadEx)
    {
        return UniqueHandle();
    }

    HANDLE thread = nullptr;
    const LONG status = ntCreateThreadEx(&thread,
                                         THREAD_ALL_ACCESS,
                                         nullptr,
                                         process,
                                         reinterpret_cast<PVOID>(startRoutine),
                                         argument,
                                         0,
                                         0,
                                         0,
                                         0,
                                         nullptr);
    if (!NtSuccess(status))
    {
        PrintNtStatus(L"NtCreateThreadEx", status);
        return UniqueHandle();
    }

    return UniqueHandle(thread);
}

UniqueHandle LaunchRemoteThread(HANDLE process,
                                LPTHREAD_START_ROUTINE startRoutine,
                                LPVOID argument,
                                RemoteThreadLaunchMethod launchMethod)
{
    switch (launchMethod)
    {
    case RemoteThreadLaunchMethod::CreateRemoteThread:
        return LaunchWithCreateRemoteThread(process, startRoutine, argument);

    case RemoteThreadLaunchMethod::NtCreateThreadEx:
        return LaunchWithNtCreateThreadEx(process, startRoutine, argument);

    default:
        wprintf(L"Unsupported remote thread launch method.\n");
        return UniqueHandle();
    }
}

const wchar_t* LaunchMethodName(RemoteThreadLaunchMethod launchMethod)
{
    switch (launchMethod)
    {
    case RemoteThreadLaunchMethod::CreateRemoteThread:
        return L"CreateRemoteThread";
    case RemoteThreadLaunchMethod::NtCreateThreadEx:
        return L"NtCreateThreadEx";
    default:
        return L"unknown";
    }
}
}

bool InjectDllWithLoadLibrary(DWORD targetPid,
                              const wchar_t* dllPath,
                              RemoteThreadLaunchMethod launchMethod)
{
    std::uintptr_t existingModule = 0;
    if (FindRemoteModuleByPath(targetPid, dllPath, existingModule))
    {
        wprintf(L"%s is already loaded in the target at 0x%p.\n",
                dllPath,
                reinterpret_cast<void*>(existingModule));
        wprintf(L"LoadLibraryW would only increment the loader reference count; "
                L"DllMain(DLL_PROCESS_ATTACH) will not run again.\n");
        wprintf(L"Restart TargetApp to repeat the visible MessageBox demo.\n");
        return true;
    }

    UniqueHandle process(OpenProcess(PROCESS_CREATE_THREAD |
                                         PROCESS_QUERY_INFORMATION |
                                         PROCESS_VM_OPERATION |
                                         PROCESS_VM_WRITE |
                                         PROCESS_VM_READ,
                                     FALSE,
                                     targetPid));
    if (!process.valid())
    {
        PrintLastError(L"OpenProcess");
        return false;
    }

    SIZE_T dllPathBytes = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    LPVOID remoteDllPath = VirtualAllocEx(process.get(),
                                          nullptr,
                                          dllPathBytes,
                                          MEM_COMMIT | MEM_RESERVE,
                                          PAGE_READWRITE);
    if (!remoteDllPath)
    {
        PrintLastError(L"VirtualAllocEx");
        return false;
    }

    if (!WriteProcessMemory(process.get(), remoteDllPath, dllPath, dllPathBytes, nullptr))
    {
        PrintLastError(L"WriteProcessMemory");
        VirtualFreeEx(process.get(), remoteDllPath, 0, MEM_RELEASE);
        return false;
    }

    LPTHREAD_START_ROUTINE remoteLoadLibraryW =
        ResolveRemoteProcAddress(targetPid, L"kernel32.dll", "LoadLibraryW");
    if (!remoteLoadLibraryW)
    {
        VirtualFreeEx(process.get(), remoteDllPath, 0, MEM_RELEASE);
        return false;
    }

    UniqueHandle remoteThread = LaunchRemoteThread(process.get(),
                                                   remoteLoadLibraryW,
                                                   remoteDllPath,
                                                   launchMethod);
    if (!remoteThread.valid())
    {
        VirtualFreeEx(process.get(), remoteDllPath, 0, MEM_RELEASE);
        return false;
    }

    WaitForSingleObject(remoteThread.get(), INFINITE);
    VirtualFreeEx(process.get(), remoteDllPath, 0, MEM_RELEASE);

    wprintf(L"Remote LoadLibraryW thread launched with %s finished. "
            L"Check TargetApp for detection rows and the message box.\n",
            LaunchMethodName(launchMethod));
    return true;
}

bool InjectDllWithLoadLibraryRemoteThread(DWORD targetPid, const wchar_t* dllPath)
{
    return InjectDllWithLoadLibrary(targetPid,
                                    dllPath,
                                    RemoteThreadLaunchMethod::CreateRemoteThread);
}
}
