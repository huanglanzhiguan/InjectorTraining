#include "LoadLibraryRemoteThread.h"

#include "../common/Handle.h"
#include "../common/TargetProcess.h"
#include "../common/Win32Helpers.h"

#include <cstdio>
#include <cwchar>

namespace lab
{
namespace
{
constexpr DWORD kApcLoadWaitTimeoutMs = 5000;
constexpr DWORD kApcLoadPollIntervalMs = 100;

using NtCreateThreadExFn = NTSTATUS(NTAPI*)(PHANDLE ThreadHandle,
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

bool NtSuccess(NTSTATUS status)
{
    return status >= 0;
}

void PrintNtStatus(const wchar_t* action, NTSTATUS status)
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

bool WaitForRemoteThread(HANDLE thread)
{
    const DWORD wait_result = WaitForSingleObject(thread, INFINITE);
    if (wait_result != WAIT_OBJECT_0)
    {
        PrintLastError(L"WaitForSingleObject(remote thread)");
        return false;
    }

    return true;
}

bool LaunchWithCreateRemoteThread(HANDLE process,
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
        return false;
    }

    return WaitForRemoteThread(remoteThread.get());
}

bool LaunchWithNtCreateThreadEx(HANDLE process,
                                LPTHREAD_START_ROUTINE startRoutine,
                                LPVOID argument)
{
    wprintf(L"Launching remote thread with NtCreateThreadEx.\n");

    const auto ntCreateThreadEx = ResolveNtCreateThreadEx();
    if (!ntCreateThreadEx)
    {
        return false;
    }

    HANDLE thread = nullptr;
    const NTSTATUS status = ntCreateThreadEx(&thread,
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
        return false;
    }

    UniqueHandle remoteThread(thread);
    return WaitForRemoteThread(remoteThread.get());
}

bool WaitForRemoteModuleLoad(DWORD targetPid, const wchar_t* dllPath)
{
    const ULONGLONG deadline = GetTickCount64() + kApcLoadWaitTimeoutMs;

    do
    {
        std::uintptr_t moduleBase = 0;
        if (FindRemoteModuleByPath(targetPid, dllPath, moduleBase))
        {
            wprintf(L"Observed DLL loaded in target at 0x%p.\n",
                    reinterpret_cast<void*>(moduleBase));
            return true;
        }

        Sleep(kApcLoadPollIntervalMs);
    } while (GetTickCount64() < deadline);

    return false;
}

bool QueueLoadLibraryApc(DWORD targetPid,
                         const wchar_t* dllPath,
                         LPTHREAD_START_ROUTINE startRoutine,
                         LPVOID argument,
                         bool& canReleaseRemoteArgument)
{
    wprintf(L"Queueing LoadLibraryW APCs with QueueUserAPC.\n");

    canReleaseRemoteArgument = true;

    const std::vector<DWORD> threadIds = EnumerateThreadIdsForProcess(targetPid);
    if (threadIds.empty())
    {
        wprintf(L"No target threads found for PID %lu.\n", targetPid);
        return false;
    }

    DWORD queuedCount = 0;
    for (DWORD threadId : threadIds)
    {
        UniqueHandle thread(OpenThread(THREAD_SET_CONTEXT, FALSE, threadId));
        if (!thread.valid())
        {
            wprintf(L"Skipping thread %lu; OpenThread failed with GetLastError() = %lu\n",
                    threadId,
                    GetLastError());
            continue;
        }

        // QueueUserAPC accepts one pointer-sized argument. In this x64 lab,
        // LoadLibraryW has the same calling convention and one pointer argument;
        // the HMODULE return value is ignored by APC dispatch.
        const DWORD queued = QueueUserAPC(reinterpret_cast<PAPCFUNC>(startRoutine),
                                         thread.get(),
                                         reinterpret_cast<ULONG_PTR>(argument));
        if (queued == 0)
        {
            wprintf(L"QueueUserAPC failed for thread %lu. GetLastError() = %lu\n",
                    threadId,
                    GetLastError());
            continue;
        }

        ++queuedCount;
        canReleaseRemoteArgument = false;
        wprintf(L"Queued APC to thread %lu.\n", threadId);
    }

    if (queuedCount == 0)
    {
        wprintf(L"Could not queue APC to any target thread.\n");
        return false;
    }

    wprintf(L"Queued %lu APC(s). Waiting up to %lu ms for an alertable thread to dispatch one.\n",
            queuedCount,
            kApcLoadWaitTimeoutMs);

    if (WaitForRemoteModuleLoad(targetPid, dllPath))
    {
        wprintf(L"Leaving the remote DLL path buffer allocated because other queued APCs may dispatch later.\n");
        return true;
    }

    wprintf(L"DLL load was not observed. QueueUserAPC only runs when a target thread enters an alertable wait.\n");
    wprintf(L"Leaving the remote DLL path buffer allocated because a queued APC may still dispatch later.\n");
    return false;
}

bool LaunchLoadLibrary(HANDLE process,
                       DWORD targetPid,
                       const wchar_t* dllPath,
                       LPTHREAD_START_ROUTINE startRoutine,
                       LPVOID argument,
                       LaunchMethod launchMethod,
                       bool& canReleaseRemoteArgument)
{
    canReleaseRemoteArgument = true;

    switch (launchMethod)
    {
    case LaunchMethod::CreateRemoteThread:
        return LaunchWithCreateRemoteThread(process, startRoutine, argument);

    case LaunchMethod::NtCreateThreadEx:
        return LaunchWithNtCreateThreadEx(process, startRoutine, argument);

    case LaunchMethod::QueueUserAPC:
        return QueueLoadLibraryApc(targetPid,
                                   dllPath,
                                   startRoutine,
                                   argument,
                                   canReleaseRemoteArgument);

    default:
        wprintf(L"Unsupported launch method.\n");
        return false;
    }
}

const wchar_t* LaunchMethodName(LaunchMethod launchMethod)
{
    switch (launchMethod)
    {
    case LaunchMethod::CreateRemoteThread:
        return L"CreateRemoteThread";
    case LaunchMethod::NtCreateThreadEx:
        return L"NtCreateThreadEx";
    case LaunchMethod::QueueUserAPC:
        return L"QueueUserAPC";
    default:
        return L"unknown";
    }
}
}

bool InjectDllWithLoadLibrary(DWORD targetPid,
                              const wchar_t* dllPath,
                              LaunchMethod launchMethod)
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

    bool canReleaseRemoteDllPath = true;
    if (!LaunchLoadLibrary(process.get(),
                           targetPid,
                           dllPath,
                           remoteLoadLibraryW,
                           remoteDllPath,
                           launchMethod,
                           canReleaseRemoteDllPath))
    {
        if (canReleaseRemoteDllPath)
        {
            VirtualFreeEx(process.get(), remoteDllPath, 0, MEM_RELEASE);
        }
        return false;
    }

    if (canReleaseRemoteDllPath)
    {
        VirtualFreeEx(process.get(), remoteDllPath, 0, MEM_RELEASE);
    }

    wprintf(L"Remote LoadLibraryW launched with %s finished. "
            L"Check TargetApp for detection rows and the message box.\n",
            LaunchMethodName(launchMethod));
    return true;
}

bool InjectDllWithLoadLibraryRemoteThread(DWORD targetPid, const wchar_t* dllPath)
{
    return InjectDllWithLoadLibrary(targetPid,
                                    dllPath,
                                    LaunchMethod::CreateRemoteThread);
}
}
