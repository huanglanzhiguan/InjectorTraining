#include "LoadLibraryRemoteThread.h"

#include "../common/Handle.h"
#include "../common/SymbolResolver.h"
#include "../common/TargetProcess.h"
#include "../common/Win32Helpers.h"

#include <algorithm>
#include <climits>
#include <cstddef>
#include <cstdio>
#include <cwchar>
#include <cstdint>

namespace lab
{
namespace
{
constexpr DWORD kApcLoadWaitTimeoutMs = 5000;
constexpr DWORD kApcLoadPollIntervalMs = 100;
constexpr ULONG kWindows10Build1809 = 17763;

struct RemoteUnicodeString
{
    USHORT length = 0;
    USHORT maximum_length = 0;
    ULONG padding = 0;
    std::uintptr_t buffer = 0;
};

struct LdrLoadDllRemoteContext
{
    std::uintptr_t ldr_load_dll = 0;
    RemoteUnicodeString dll_name;
    std::uintptr_t module_handle = 0;
    NTSTATUS status = 0;
    ULONG padding = 0;
    wchar_t dll_path[MAX_PATH] = {};
};

struct LdrpPathSearchContext
{
    std::uintptr_t dll_search_path_out = 0;
    std::uintptr_t unknown_0[3] = {};
    std::uintptr_t original_full_dll_name = 0;
    std::uintptr_t unknown_1[7] = {};
    std::uint64_t unknown_2[4] = {};
};

struct LdrpUnicodeStringBundle
{
    RemoteUnicodeString string;
    wchar_t static_buffer[128] = {};
};

struct LdrpLoadDllRemoteContext
{
    std::uintptr_t ldrp_load_dll = 0;
    std::uintptr_t ldrp_dereference_module = 0;
    RemoteUnicodeString dll_name;
    LdrpPathSearchContext search_context;
    std::uintptr_t entry = 0;
    NTSTATUS status = 0;
    ULONG padding = 0;
    wchar_t dll_path[MAX_PATH] = {};
};

struct LdrpLoadDllInternalRemoteContext
{
    std::uintptr_t ldrp_preprocess_dll_name = 0;
    std::uintptr_t ldrp_load_dll_internal = 0;
    std::uintptr_t ldrp_dereference_module = 0;
    RemoteUnicodeString dll_name;
    LdrpUnicodeStringBundle preprocessed_name;
    LdrpPathSearchContext search_context;
    ULONG flags = 0;
    ULONG padding0 = 0;
    std::uintptr_t entry = 0;
    NTSTATUS status = 0;
    ULONG padding1 = 0;
    wchar_t dll_path[MAX_PATH] = {};
};

struct HijackRemoteContext
{
    std::uintptr_t start_routine = 0;
    std::uintptr_t argument = 0;
    std::uintptr_t nt_continue = 0;
    std::uintptr_t result = 0;
    alignas(16) CONTEXT original_context = {};
};

static_assert(sizeof(void*) == 8, "The remote LdrLoadDll stub is x64-only.");
static_assert(offsetof(LdrLoadDllRemoteContext, dll_name) == 0x08);
static_assert(offsetof(LdrLoadDllRemoteContext, module_handle) == 0x18);
static_assert(offsetof(LdrLoadDllRemoteContext, status) == 0x20);
static_assert(sizeof(LdrpPathSearchContext) == 0x80);
static_assert(offsetof(LdrpLoadDllRemoteContext, dll_name) == 0x10);
static_assert(offsetof(LdrpLoadDllRemoteContext, search_context) == 0x20);
static_assert(offsetof(LdrpLoadDllRemoteContext, entry) == 0xA0);
static_assert(offsetof(LdrpLoadDllRemoteContext, status) == 0xA8);
static_assert(offsetof(LdrpLoadDllRemoteContext, dll_path) == 0xB0);
static_assert(offsetof(LdrpLoadDllInternalRemoteContext, dll_name) == 0x18);
static_assert(offsetof(LdrpLoadDllInternalRemoteContext, preprocessed_name) == 0x28);
static_assert(offsetof(LdrpUnicodeStringBundle, static_buffer) == 0x10);
static_assert(offsetof(LdrpLoadDllInternalRemoteContext, search_context) == 0x138);
static_assert(offsetof(LdrpLoadDllInternalRemoteContext, flags) == 0x1B8);
static_assert(offsetof(LdrpLoadDllInternalRemoteContext, entry) == 0x1C0);
static_assert(offsetof(LdrpLoadDllInternalRemoteContext, status) == 0x1C8);
static_assert(offsetof(LdrpLoadDllInternalRemoteContext, dll_path) == 0x1D0);
static_assert(offsetof(HijackRemoteContext, original_context) == 0x20);

// x64 adapter:
//   rcx = LdrLoadDllRemoteContext*
//   calls ctx->ldr_load_dll(nullptr, nullptr, &ctx->dll_name, &ctx->module_handle)
//   stores NTSTATUS in ctx->status
//
// CreateRemoteThread/NtCreateThreadEx/QueueUserAPC only give the launched code
// one pointer-sized argument. The stub expands that one context pointer into
// the four-argument native loader call.
const unsigned char kLdrLoadDllStub[] = {
    // sub rsp, 38h
    0x48, 0x83, 0xEC, 0x38,
    // mov [rsp+28h], rcx
    0x48, 0x89, 0x4C, 0x24, 0x28,
    // mov rax, [rcx]
    0x48, 0x8B, 0x01,
    // xor ecx, ecx
    0x33, 0xC9,
    // xor edx, edx
    0x33, 0xD2,
    // mov r8, [rsp+28h]
    0x4C, 0x8B, 0x44, 0x24, 0x28,
    // add r8, 8
    0x49, 0x83, 0xC0, 0x08,
    // mov r9, [rsp+28h]
    0x4C, 0x8B, 0x4C, 0x24, 0x28,
    // add r9, 18h
    0x49, 0x83, 0xC1, 0x18,
    // call rax
    0xFF, 0xD0,
    // mov rcx, [rsp+28h]
    0x48, 0x8B, 0x4C, 0x24, 0x28,
    // mov [rcx+20h], eax
    0x89, 0x41, 0x20,
    // add rsp, 38h
    0x48, 0x83, 0xC4, 0x38,
    // ret
    0xC3,
};

// x64 adapter:
//   rcx = LdrpLoadDllRemoteContext*
//   calls ctx->ldrp_load_dll(&ctx->dll_name, &ctx->search_context, 0, &ctx->entry)
//   stores NTSTATUS in ctx->status
//   dereferences the returned loader entry when LdrpDereferenceModule is available
//
// This modern form matches the Windows 10 1809+ x64 private signature used by
// current Windows builds. Older builds used different private call shapes, so
// the injector validates the OS build before launching this stub.
const unsigned char kLdrpLoadDllStub[] = {
    // sub rsp, 38h
    0x48, 0x83, 0xEC, 0x38,
    // mov [rsp+28h], rcx
    0x48, 0x89, 0x4C, 0x24, 0x28,
    // mov rax, [rcx]
    0x48, 0x8B, 0x01,
    // lea rcx, [rcx+10h]
    0x48, 0x8D, 0x49, 0x10,
    // mov rdx, [rsp+28h]
    0x48, 0x8B, 0x54, 0x24, 0x28,
    // add rdx, 20h
    0x48, 0x83, 0xC2, 0x20,
    // xor r8d, r8d
    0x45, 0x33, 0xC0,
    // mov r9, [rsp+28h]
    0x4C, 0x8B, 0x4C, 0x24, 0x28,
    // add r9, 0A0h
    0x49, 0x81, 0xC1, 0xA0, 0x00, 0x00, 0x00,
    // call rax
    0xFF, 0xD0,
    // mov rcx, [rsp+28h]
    0x48, 0x8B, 0x4C, 0x24, 0x28,
    // mov [rcx+0A8h], eax
    0x89, 0x81, 0xA8, 0x00, 0x00, 0x00,
    // test eax, eax
    0x85, 0xC0,
    // jl +1Ah
    0x7C, 0x1A,
    // mov rdx, [rcx+0A0h]
    0x48, 0x8B, 0x91, 0xA0, 0x00, 0x00, 0x00,
    // test rdx, rdx
    0x48, 0x85, 0xD2,
    // jz +0Eh
    0x74, 0x0E,
    // mov rax, [rcx+8]
    0x48, 0x8B, 0x41, 0x08,
    // test rax, rax
    0x48, 0x85, 0xC0,
    // jz +05h
    0x74, 0x05,
    // mov rcx, rdx
    0x48, 0x89, 0xD1,
    // call rax
    0xFF, 0xD0,
    // add rsp, 38h
    0x48, 0x83, 0xC4, 0x38,
    // ret
    0xC3,
};

// x64 adapter:
//   rcx = LdrpLoadDllInternalRemoteContext*
//   calls LdrpPreprocessDllName first to produce the internal name bundle/flags
//   calls LdrpLoadDllInternal with the modern Windows 10/11 x64 argument layout
//   stores the loader NTSTATUS in ctx->status
//   dereferences the returned loader entry when LdrpDereferenceModule is available
//
// The ninth stack argument is harmless on Windows 10 and required on current
// Windows 11 builds. Because x64 callers clean their own stack, this one stub
// can demonstrate both modern variants.
const unsigned char kLdrpLoadDllInternalStub[] = {
    // sub rsp, 58h
    0x48, 0x83, 0xEC, 0x58,
    // mov [rsp+48h], rcx
    0x48, 0x89, 0x4C, 0x24, 0x48,
    // mov rax, [rcx]
    0x48, 0x8B, 0x01,
    // lea rcx, [rcx+18h]
    0x48, 0x8D, 0x49, 0x18,
    // mov rdx, [rsp+48h]
    0x48, 0x8B, 0x54, 0x24, 0x48,
    // add rdx, 28h
    0x48, 0x83, 0xC2, 0x28,
    // xor r8d, r8d
    0x45, 0x33, 0xC0,
    // mov r9, [rsp+48h]
    0x4C, 0x8B, 0x4C, 0x24, 0x48,
    // add r9, 1B8h
    0x49, 0x81, 0xC1, 0xB8, 0x01, 0x00, 0x00,
    // call rax
    0xFF, 0xD0,
    // mov rcx, [rsp+48h]
    0x48, 0x8B, 0x4C, 0x24, 0x48,
    // mov [rcx+1C8h], eax
    0x89, 0x81, 0xC8, 0x01, 0x00, 0x00,
    // test eax, eax
    0x85, 0xC0,
    // jl +7Ah
    0x7C, 0x7A,
    // mov rax, [rcx+8]
    0x48, 0x8B, 0x41, 0x08,
    // lea rdx, [rcx+138h]
    0x48, 0x8D, 0x91, 0x38, 0x01, 0x00, 0x00,
    // mov r8d, [rcx+1B8h]
    0x44, 0x8B, 0x81, 0xB8, 0x01, 0x00, 0x00,
    // mov r9d, 4
    0x41, 0xB9, 0x04, 0x00, 0x00, 0x00,
    // mov qword ptr [rsp+20h], 0
    0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00,
    // mov qword ptr [rsp+28h], 0
    0x48, 0xC7, 0x44, 0x24, 0x28, 0x00, 0x00, 0x00, 0x00,
    // lea r10, [rcx+1C0h]
    0x4C, 0x8D, 0x91, 0xC0, 0x01, 0x00, 0x00,
    // mov [rsp+30h], r10
    0x4C, 0x89, 0x54, 0x24, 0x30,
    // lea r10, [rcx+1C8h]
    0x4C, 0x8D, 0x91, 0xC8, 0x01, 0x00, 0x00,
    // mov [rsp+38h], r10
    0x4C, 0x89, 0x54, 0x24, 0x38,
    // mov qword ptr [rsp+40h], 0
    0x48, 0xC7, 0x44, 0x24, 0x40, 0x00, 0x00, 0x00, 0x00,
    // lea rcx, [rcx+28h]
    0x48, 0x8D, 0x49, 0x28,
    // call rax
    0xFF, 0xD0,
    // mov rcx, [rsp+48h]
    0x48, 0x8B, 0x4C, 0x24, 0x48,
    // mov eax, [rcx+1C8h]
    0x8B, 0x81, 0xC8, 0x01, 0x00, 0x00,
    // test eax, eax
    0x85, 0xC0,
    // jl +1Ah
    0x7C, 0x1A,
    // mov rdx, [rcx+1C0h]
    0x48, 0x8B, 0x91, 0xC0, 0x01, 0x00, 0x00,
    // test rdx, rdx
    0x48, 0x85, 0xD2,
    // jz +0Eh
    0x74, 0x0E,
    // mov rax, [rcx+10h]
    0x48, 0x8B, 0x41, 0x10,
    // test rax, rax
    0x48, 0x85, 0xC0,
    // jz +05h
    0x74, 0x05,
    // mov rcx, rdx
    0x48, 0x89, 0xD1,
    // call rax
    0xFF, 0xD0,
    // add rsp, 58h
    0x48, 0x83, 0xC4, 0x58,
    // ret
    0xC3,
};

// x64 thread-hijack adapter:
//   rcx = HijackRemoteContext*
//   calls ctx->start_routine(ctx->argument)
//   stores the routine return value in ctx->result
//   calls NtContinue(&ctx->original_context, FALSE) to resume original code
//
// The injector points the hijacked thread's RIP at this stub and keeps the
// thread's real stack. NtContinue restores the original RIP, RSP, and registers.
const unsigned char kThreadHijackStub[] = {
    // mov rbx, rcx
    0x48, 0x89, 0xCB,
    // and rsp, -10h
    0x48, 0x83, 0xE4, 0xF0,
    // sub rsp, 20h
    0x48, 0x83, 0xEC, 0x20,
    // mov rax, [rbx]
    0x48, 0x8B, 0x03,
    // mov rcx, [rbx+8]
    0x48, 0x8B, 0x4B, 0x08,
    // call rax
    0xFF, 0xD0,
    // mov [rbx+18h], rax
    0x48, 0x89, 0x43, 0x18,
    // mov rax, [rbx+10h]
    0x48, 0x8B, 0x43, 0x10,
    // lea rcx, [rbx+20h]
    0x48, 0x8D, 0x4B, 0x20,
    // xor edx, edx
    0x33, 0xD2,
    // call rax
    0xFF, 0xD0,
    // jmp $
    0xEB, 0xFE,
};

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

bool GetWindowsBuildNumber(ULONG& buildNumber)
{
    buildNumber = 0;

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
    {
        PrintLastError(L"GetModuleHandleW(ntdll.dll)");
        return false;
    }

    using RtlGetVersionFn = LONG(WINAPI*)(PRTL_OSVERSIONINFOW);
    auto rtlGetVersion =
        reinterpret_cast<RtlGetVersionFn>(GetProcAddress(ntdll, "RtlGetVersion"));
    if (!rtlGetVersion)
    {
        PrintLastError(L"GetProcAddress(RtlGetVersion)");
        return false;
    }

    RTL_OSVERSIONINFOW version = {};
    version.dwOSVersionInfoSize = sizeof(version);
    const LONG status = rtlGetVersion(&version);
    if (status != 0)
    {
        wprintf(L"RtlGetVersion failed. NTSTATUS = 0x%08lX\n",
                static_cast<unsigned long>(status));
        return false;
    }

    if (version.dwMajorVersion < 10)
    {
        wprintf(L"Private loader labs currently target modern Windows 10/11 x64. "
                L"Detected version %lu.%lu build %lu.\n",
                version.dwMajorVersion,
                version.dwMinorVersion,
                version.dwBuildNumber);
        return false;
    }

    buildNumber = version.dwBuildNumber;
    return true;
}

bool ValidatePrivateLoaderBuild(LoadMethod loadMethod)
{
    ULONG buildNumber = 0;
    if (!GetWindowsBuildNumber(buildNumber))
    {
        return false;
    }

    // These private loader routines changed call shape across Windows builds.
    // This lab only implements the modern x64 signatures:
    // - LdrpLoadDll: Windows 10 1809+ removed the extra boolean argument.
    // - LdrpLoadDllInternal: the implemented context/stub matches the modern
    //   Windows 10/11 private path used after preprocessing the DLL name.
    if ((loadMethod == LoadMethod::LdrpLoadDll ||
         loadMethod == LoadMethod::LdrpLoadDllInternal) &&
        buildNumber < kWindows10Build1809)
    {
        wprintf(L"Private loader methods in this lab use Windows 10 1809+ private signatures. "
                L"Detected build %lu.\n",
                buildNumber);
        return false;
    }

    wprintf(L"Detected Windows build %lu for private loader call layout.\n", buildNumber);
    return true;
}

bool ResolveRemoteNtdllPrivateSymbol(DWORD targetPid,
                                     const char* symbolName,
                                     std::uintptr_t& remoteAddress)
{
    remoteAddress = 0;

    std::uintptr_t rva = 0;
    if (!ResolveNtdllSymbolRva(symbolName, rva))
    {
        return false;
    }

    const std::uintptr_t remoteNtdll = FindRemoteModuleBase(targetPid, L"ntdll.dll");
    if (remoteNtdll == 0)
    {
        return false;
    }

    remoteAddress = remoteNtdll + rva;
    wprintf(L"Remote ntdll!%S address: 0x%p.\n",
            symbolName,
            reinterpret_cast<void*>(remoteAddress));
    return true;
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

bool ThreadBelongsToProcess(DWORD targetPid, DWORD threadId)
{
    const std::vector<DWORD> targetThreadIds = EnumerateThreadIdsForProcess(targetPid);
    return std::find(targetThreadIds.begin(), targetThreadIds.end(), threadId) != targetThreadIds.end();
}

bool ReleaseRemoteAllocation(HANDLE process, LPVOID allocation, const wchar_t* name);

bool QueueRemoteRoutineApc(DWORD targetPid,
                           const wchar_t* dllPath,
                           LPTHREAD_START_ROUTINE startRoutine,
                           LPVOID argument,
                           DWORD apcThreadId,
                           bool& canReleaseRemoteArgument)
{
    wprintf(L"Queueing remote routine APCs with QueueUserAPC.\n");

    canReleaseRemoteArgument = true;

    const std::vector<DWORD> targetThreadIds = EnumerateThreadIdsForProcess(targetPid);
    if (targetThreadIds.empty())
    {
        wprintf(L"No target threads found for PID %lu.\n", targetPid);
        return false;
    }

    std::vector<DWORD> threadIds;
    if (apcThreadId != 0)
    {
        if (std::find(targetThreadIds.begin(), targetThreadIds.end(), apcThreadId) == targetThreadIds.end())
        {
            wprintf(L"Requested APC thread %lu does not belong to target PID %lu.\n",
                    apcThreadId,
                    targetPid);
            return false;
        }

        threadIds.push_back(apcThreadId);
        wprintf(L"Using requested target thread %lu for this APC launch.\n", apcThreadId);
    }
    else
    {
        threadIds = targetThreadIds;
        wprintf(L"No --apc-thread specified; queueing to all %zu target thread(s).\n",
                threadIds.size());
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

    const bool singleThreadApc = apcThreadId != 0;
    if (WaitForRemoteModuleLoad(targetPid, dllPath))
    {
        if (singleThreadApc)
        {
            wprintf(L"Leaving the remote APC argument allocated because QueueUserAPC does not provide a completion handle for the APC routine.\n");
        }
        else
        {
            wprintf(L"Leaving the remote APC argument allocated because other queued APCs may dispatch later.\n");
        }
        return true;
    }

    wprintf(L"DLL load was not observed. QueueUserAPC only runs when a target thread enters an alertable wait.\n");
    if (singleThreadApc)
    {
        wprintf(L"Leaving the remote APC argument allocated because the requested APC may still dispatch later.\n");
    }
    else
    {
        wprintf(L"Leaving the remote APC argument allocated because a queued APC may still dispatch later.\n");
    }
    return false;
}

bool LaunchWithThreadHijack(HANDLE process,
                            DWORD targetPid,
                            const wchar_t* dllPath,
                            LPTHREAD_START_ROUTINE startRoutine,
                            LPVOID argument,
                            DWORD hijackThreadId,
                            bool& canReleaseRemoteArgument)
{
    wprintf(L"Hijacking an existing target thread with SuspendThread/GetThreadContext/SetThreadContext.\n");

    canReleaseRemoteArgument = true;

    if (hijackThreadId == 0)
    {
        wprintf(L"ThreadHijack requires --hijack-thread <tid>.\n");
        return false;
    }

    if (!ThreadBelongsToProcess(targetPid, hijackThreadId))
    {
        wprintf(L"Requested hijack thread %lu does not belong to target PID %lu.\n",
                hijackThreadId,
                targetPid);
        return false;
    }

    LPTHREAD_START_ROUTINE remoteNtContinue =
        ResolveRemoteProcAddress(targetPid, L"ntdll.dll", "NtContinue");
    if (!remoteNtContinue)
    {
        return false;
    }

    LPVOID remoteStub = VirtualAllocEx(process,
                                       nullptr,
                                       sizeof(kThreadHijackStub),
                                       MEM_COMMIT | MEM_RESERVE,
                                       PAGE_READWRITE);
    if (!remoteStub)
    {
        PrintLastError(L"VirtualAllocEx(thread-hijack stub)");
        return false;
    }

    LPVOID remoteContext = VirtualAllocEx(process,
                                          nullptr,
                                          sizeof(HijackRemoteContext),
                                          MEM_COMMIT | MEM_RESERVE,
                                          PAGE_READWRITE);
    if (!remoteContext)
    {
        PrintLastError(L"VirtualAllocEx(thread-hijack context)");
        ReleaseRemoteAllocation(process, remoteStub, L"VirtualFreeEx(thread-hijack stub)");
        return false;
    }

    if (!WriteProcessMemory(process,
                            remoteStub,
                            kThreadHijackStub,
                            sizeof(kThreadHijackStub),
                            nullptr))
    {
        PrintLastError(L"WriteProcessMemory(thread-hijack stub)");
        ReleaseRemoteAllocation(process, remoteContext, L"VirtualFreeEx(thread-hijack context)");
        ReleaseRemoteAllocation(process, remoteStub, L"VirtualFreeEx(thread-hijack stub)");
        return false;
    }

    DWORD oldProtect = 0;
    if (!VirtualProtectEx(process,
                          remoteStub,
                          sizeof(kThreadHijackStub),
                          PAGE_EXECUTE_READ,
                          &oldProtect))
    {
        PrintLastError(L"VirtualProtectEx(thread-hijack stub)");
        ReleaseRemoteAllocation(process, remoteContext, L"VirtualFreeEx(thread-hijack context)");
        ReleaseRemoteAllocation(process, remoteStub, L"VirtualFreeEx(thread-hijack stub)");
        return false;
    }

    FlushInstructionCache(process, remoteStub, sizeof(kThreadHijackStub));

    UniqueHandle thread(OpenThread(THREAD_SUSPEND_RESUME |
                                       THREAD_GET_CONTEXT |
                                       THREAD_SET_CONTEXT |
                                       THREAD_QUERY_INFORMATION,
                                   FALSE,
                                   hijackThreadId));
    if (!thread.valid())
    {
        PrintLastError(L"OpenThread(thread hijack)");
        ReleaseRemoteAllocation(process, remoteContext, L"VirtualFreeEx(thread-hijack context)");
        ReleaseRemoteAllocation(process, remoteStub, L"VirtualFreeEx(thread-hijack stub)");
        return false;
    }

    const DWORD previousSuspendCount = SuspendThread(thread.get());
    if (previousSuspendCount == static_cast<DWORD>(-1))
    {
        PrintLastError(L"SuspendThread");
        ReleaseRemoteAllocation(process, remoteContext, L"VirtualFreeEx(thread-hijack context)");
        ReleaseRemoteAllocation(process, remoteStub, L"VirtualFreeEx(thread-hijack stub)");
        return false;
    }

    CONTEXT originalContext = {};
    originalContext.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(thread.get(), &originalContext))
    {
        PrintLastError(L"GetThreadContext");
        ResumeThread(thread.get());
        ReleaseRemoteAllocation(process, remoteContext, L"VirtualFreeEx(thread-hijack context)");
        ReleaseRemoteAllocation(process, remoteStub, L"VirtualFreeEx(thread-hijack stub)");
        return false;
    }

    HijackRemoteContext hijackContext = {};
    hijackContext.start_routine = reinterpret_cast<std::uintptr_t>(startRoutine);
    hijackContext.argument = reinterpret_cast<std::uintptr_t>(argument);
    hijackContext.nt_continue = reinterpret_cast<std::uintptr_t>(remoteNtContinue);
    hijackContext.original_context = originalContext;

    if (!WriteProcessMemory(process,
                            remoteContext,
                            &hijackContext,
                            sizeof(hijackContext),
                            nullptr))
    {
        PrintLastError(L"WriteProcessMemory(thread-hijack context)");
        ResumeThread(thread.get());
        ReleaseRemoteAllocation(process, remoteContext, L"VirtualFreeEx(thread-hijack context)");
        ReleaseRemoteAllocation(process, remoteStub, L"VirtualFreeEx(thread-hijack stub)");
        return false;
    }

    CONTEXT redirectContext = originalContext;
    redirectContext.Rip = reinterpret_cast<DWORD64>(remoteStub);
    redirectContext.Rcx = reinterpret_cast<DWORD64>(remoteContext);
    redirectContext.ContextFlags = CONTEXT_FULL;

    if (!SetThreadContext(thread.get(), &redirectContext))
    {
        PrintLastError(L"SetThreadContext");
        ResumeThread(thread.get());
        ReleaseRemoteAllocation(process, remoteContext, L"VirtualFreeEx(thread-hijack context)");
        ReleaseRemoteAllocation(process, remoteStub, L"VirtualFreeEx(thread-hijack stub)");
        return false;
    }

    if (ResumeThread(thread.get()) == static_cast<DWORD>(-1))
    {
        PrintLastError(L"ResumeThread");
        SetThreadContext(thread.get(), &originalContext);
        ReleaseRemoteAllocation(process, remoteContext, L"VirtualFreeEx(thread-hijack context)");
        ReleaseRemoteAllocation(process, remoteStub, L"VirtualFreeEx(thread-hijack stub)");
        return false;
    }

    canReleaseRemoteArgument = false;

    wprintf(L"Redirected thread %lu to stub 0x%p with context 0x%p.\n",
            hijackThreadId,
            remoteStub,
            remoteContext);

    const bool observedLoad = WaitForRemoteModuleLoad(targetPid, dllPath);
    wprintf(L"Leaving the remote thread-hijack stub and context allocated for observation.\n");

    if (!observedLoad)
    {
        wprintf(L"DLL load was not observed after the hijacked thread resumed.\n");
        return false;
    }

    return true;
}

bool LaunchRemoteRoutine(HANDLE process,
                         DWORD targetPid,
                         const wchar_t* dllPath,
                         LPTHREAD_START_ROUTINE startRoutine,
                         LPVOID argument,
                         const InjectorConfig& config,
                         bool& canReleaseRemoteArgument)
{
    canReleaseRemoteArgument = true;

    switch (config.launchMethod)
    {
    case LaunchMethod::CreateRemoteThread:
        return LaunchWithCreateRemoteThread(process, startRoutine, argument);

    case LaunchMethod::NtCreateThreadEx:
        return LaunchWithNtCreateThreadEx(process, startRoutine, argument);

    case LaunchMethod::QueueUserAPC:
        return QueueRemoteRoutineApc(targetPid,
                                     dllPath,
                                     startRoutine,
                                     argument,
                                     config.queueUserApc.threadId,
                                     canReleaseRemoteArgument);

    case LaunchMethod::ThreadHijack:
        return LaunchWithThreadHijack(process,
                                      targetPid,
                                      dllPath,
                                      startRoutine,
                                      argument,
                                      config.threadHijack.threadId,
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
    case LaunchMethod::ThreadHijack:
        return L"ThreadHijack";
    default:
        return L"unknown";
    }
}

const wchar_t* LoadMethodName(LoadMethod loadMethod)
{
    switch (loadMethod)
    {
    case LoadMethod::LoadLibraryW:
        return L"LoadLibraryW";
    case LoadMethod::LdrLoadDll:
        return L"LdrLoadDll";
    case LoadMethod::LdrpLoadDll:
        return L"LdrpLoadDll";
    case LoadMethod::LdrpLoadDllInternal:
        return L"LdrpLoadDllInternal";
    default:
        return L"unknown";
    }
}

UniqueHandle OpenTargetProcessForInjection(DWORD targetPid)
{
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
    }

    return process;
}

bool ReleaseRemoteAllocation(HANDLE process, LPVOID allocation, const wchar_t* name)
{
    if (allocation == nullptr)
    {
        return true;
    }

    if (!VirtualFreeEx(process, allocation, 0, MEM_RELEASE))
    {
        PrintLastError(name);
        return false;
    }

    return true;
}

LPVOID StageRemoteExecutableStub(HANDLE process,
                                 const unsigned char* stubBytes,
                                 std::size_t stubSize,
                                 const wchar_t* label)
{
    LPVOID remoteStub = VirtualAllocEx(process,
                                       nullptr,
                                       stubSize,
                                       MEM_COMMIT | MEM_RESERVE,
                                       PAGE_READWRITE);
    if (!remoteStub)
    {
        wprintf(L"VirtualAllocEx(%s stub) failed. GetLastError() = %lu\n",
                label,
                GetLastError());
        return nullptr;
    }

    if (!WriteProcessMemory(process, remoteStub, stubBytes, stubSize, nullptr))
    {
        wprintf(L"WriteProcessMemory(%s stub) failed. GetLastError() = %lu\n",
                label,
                GetLastError());
        ReleaseRemoteAllocation(process, remoteStub, L"VirtualFreeEx(stub)");
        return nullptr;
    }

    DWORD oldProtect = 0;
    if (!VirtualProtectEx(process, remoteStub, stubSize, PAGE_EXECUTE_READ, &oldProtect))
    {
        wprintf(L"VirtualProtectEx(%s stub) failed. GetLastError() = %lu\n",
                label,
                GetLastError());
        ReleaseRemoteAllocation(process, remoteStub, L"VirtualFreeEx(stub)");
        return nullptr;
    }

    FlushInstructionCache(process, remoteStub, stubSize);
    return remoteStub;
}

bool InjectDllWithLoadLibraryInternal(DWORD targetPid,
                                      const wchar_t* dllPath,
                                      const InjectorConfig& config)
{
    UniqueHandle process = OpenTargetProcessForInjection(targetPid);
    if (!process.valid())
    {
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
    if (!LaunchRemoteRoutine(process.get(),
                             targetPid,
                             dllPath,
                             remoteLoadLibraryW,
                             remoteDllPath,
                             config,
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
    else if (config.launchMethod == LaunchMethod::ThreadHijack)
    {
        wprintf(L"Leaving the remote LoadLibraryW argument allocated because the hijacked thread has no completion handle.\n");
    }

    wprintf(L"Remote LoadLibraryW launched with %s finished. "
            L"Check TargetApp for detection rows and the message box.\n",
            LaunchMethodName(config.launchMethod));
    return true;
}

bool PrepareLdrLoadDllContext(DWORD targetPid,
                              const wchar_t* dllPath,
                              std::uintptr_t remoteContextAddress,
                              LdrLoadDllRemoteContext& context)
{
    LPTHREAD_START_ROUTINE remoteLdrLoadDll =
        ResolveRemoteProcAddress(targetPid, L"ntdll.dll", "LdrLoadDll");
    if (!remoteLdrLoadDll)
    {
        return false;
    }

    const std::size_t pathCharacterCount = wcslen(dllPath) + 1;
    if (pathCharacterCount > _countof(context.dll_path))
    {
        wprintf(L"DLL path is too long for the beginner LdrLoadDll context.\n");
        return false;
    }

    const std::size_t pathBytesWithoutNull = (pathCharacterCount - 1) * sizeof(wchar_t);
    const std::size_t pathBytesWithNull = pathCharacterCount * sizeof(wchar_t);
    if (pathBytesWithNull > USHRT_MAX)
    {
        wprintf(L"DLL path is too long for UNICODE_STRING in this lab.\n");
        return false;
    }

    context = {};
    context.ldr_load_dll = reinterpret_cast<std::uintptr_t>(remoteLdrLoadDll);
    context.dll_name.length = static_cast<USHORT>(pathBytesWithoutNull);
    context.dll_name.maximum_length = static_cast<USHORT>(pathBytesWithNull);
    context.dll_name.buffer =
        remoteContextAddress + offsetof(LdrLoadDllRemoteContext, dll_path);

    if (wcscpy_s(context.dll_path, _countof(context.dll_path), dllPath) != 0)
    {
        wprintf(L"Failed to copy DLL path into LdrLoadDll context.\n");
        return false;
    }

    return true;
}

bool PrepareLdrpLoadDllContext(DWORD targetPid,
                               const wchar_t* dllPath,
                               std::uintptr_t remoteContextAddress,
                               LdrpLoadDllRemoteContext& context)
{
    if (!ValidatePrivateLoaderBuild(LoadMethod::LdrpLoadDll))
    {
        return false;
    }

    std::uintptr_t remoteLdrpLoadDll = 0;
    if (!ResolveRemoteNtdllPrivateSymbol(targetPid, "LdrpLoadDll", remoteLdrpLoadDll))
    {
        return false;
    }

    std::uintptr_t remoteLdrpDereferenceModule = 0;
    if (!ResolveRemoteNtdllPrivateSymbol(targetPid,
                                         "LdrpDereferenceModule",
                                         remoteLdrpDereferenceModule))
    {
        return false;
    }

    const std::size_t pathCharacterCount = wcslen(dllPath) + 1;
    if (pathCharacterCount > _countof(context.dll_path))
    {
        wprintf(L"DLL path is too long for the LdrpLoadDll context.\n");
        return false;
    }

    const std::size_t pathBytesWithoutNull = (pathCharacterCount - 1) * sizeof(wchar_t);
    const std::size_t pathBytesWithNull = pathCharacterCount * sizeof(wchar_t);
    if (pathBytesWithNull > USHRT_MAX)
    {
        wprintf(L"DLL path is too long for UNICODE_STRING in this lab.\n");
        return false;
    }

    context = {};
    const std::uintptr_t remoteDllPath =
        remoteContextAddress + offsetof(LdrpLoadDllRemoteContext, dll_path);

    context.ldrp_load_dll = remoteLdrpLoadDll;
    context.ldrp_dereference_module = remoteLdrpDereferenceModule;
    context.dll_name.length = static_cast<USHORT>(pathBytesWithoutNull);
    context.dll_name.maximum_length = static_cast<USHORT>(pathBytesWithNull);
    context.dll_name.buffer = remoteDllPath;
    context.search_context.original_full_dll_name = remoteDllPath;

    if (wcscpy_s(context.dll_path, _countof(context.dll_path), dllPath) != 0)
    {
        wprintf(L"Failed to copy DLL path into LdrpLoadDll context.\n");
        return false;
    }

    return true;
}

bool PrepareLdrpLoadDllInternalContext(DWORD targetPid,
                                       const wchar_t* dllPath,
                                       std::uintptr_t remoteContextAddress,
                                       LdrpLoadDllInternalRemoteContext& context)
{
    if (!ValidatePrivateLoaderBuild(LoadMethod::LdrpLoadDllInternal))
    {
        return false;
    }

    std::uintptr_t remoteLdrpPreprocessDllName = 0;
    if (!ResolveRemoteNtdllPrivateSymbol(targetPid,
                                         "LdrpPreprocessDllName",
                                         remoteLdrpPreprocessDllName))
    {
        return false;
    }

    std::uintptr_t remoteLdrpLoadDllInternal = 0;
    if (!ResolveRemoteNtdllPrivateSymbol(targetPid,
                                         "LdrpLoadDllInternal",
                                         remoteLdrpLoadDllInternal))
    {
        return false;
    }

    std::uintptr_t remoteLdrpDereferenceModule = 0;
    if (!ResolveRemoteNtdllPrivateSymbol(targetPid,
                                         "LdrpDereferenceModule",
                                         remoteLdrpDereferenceModule))
    {
        return false;
    }

    const std::size_t pathCharacterCount = wcslen(dllPath) + 1;
    if (pathCharacterCount > _countof(context.dll_path))
    {
        wprintf(L"DLL path is too long for the LdrpLoadDllInternal context.\n");
        return false;
    }

    const std::size_t pathBytesWithoutNull = (pathCharacterCount - 1) * sizeof(wchar_t);
    const std::size_t pathBytesWithNull = pathCharacterCount * sizeof(wchar_t);
    if (pathBytesWithNull > USHRT_MAX)
    {
        wprintf(L"DLL path is too long for UNICODE_STRING in this lab.\n");
        return false;
    }

    context = {};
    const std::uintptr_t remoteDllPath =
        remoteContextAddress + offsetof(LdrpLoadDllInternalRemoteContext, dll_path);
    const std::uintptr_t remoteBundleStaticBuffer =
        remoteContextAddress +
        offsetof(LdrpLoadDllInternalRemoteContext, preprocessed_name) +
        offsetof(LdrpUnicodeStringBundle, static_buffer);

    context.ldrp_preprocess_dll_name = remoteLdrpPreprocessDllName;
    context.ldrp_load_dll_internal = remoteLdrpLoadDllInternal;
    context.ldrp_dereference_module = remoteLdrpDereferenceModule;
    context.dll_name.length = static_cast<USHORT>(pathBytesWithoutNull);
    context.dll_name.maximum_length = static_cast<USHORT>(pathBytesWithNull);
    context.dll_name.buffer = remoteDllPath;
    context.preprocessed_name.string.maximum_length =
        static_cast<USHORT>(sizeof(context.preprocessed_name.static_buffer));
    context.preprocessed_name.string.buffer = remoteBundleStaticBuffer;
    context.search_context.original_full_dll_name = remoteDllPath;

    if (wcscpy_s(context.dll_path, _countof(context.dll_path), dllPath) != 0)
    {
        wprintf(L"Failed to copy DLL path into LdrpLoadDllInternal context.\n");
        return false;
    }

    return true;
}

bool InjectDllWithLdrLoadDll(DWORD targetPid,
                             const wchar_t* dllPath,
                             const InjectorConfig& config)
{
    UniqueHandle process = OpenTargetProcessForInjection(targetPid);
    if (!process.valid())
    {
        return false;
    }

    LPVOID remoteStub = VirtualAllocEx(process.get(),
                                       nullptr,
                                       sizeof(kLdrLoadDllStub),
                                       MEM_COMMIT | MEM_RESERVE,
                                       PAGE_READWRITE);
    if (!remoteStub)
    {
        PrintLastError(L"VirtualAllocEx(LdrLoadDll stub)");
        return false;
    }

    if (!WriteProcessMemory(process.get(),
                            remoteStub,
                            kLdrLoadDllStub,
                            sizeof(kLdrLoadDllStub),
                            nullptr))
    {
        PrintLastError(L"WriteProcessMemory(LdrLoadDll stub)");
        ReleaseRemoteAllocation(process.get(), remoteStub, L"VirtualFreeEx(LdrLoadDll stub)");
        return false;
    }

    DWORD oldProtect = 0;
    if (!VirtualProtectEx(process.get(),
                          remoteStub,
                          sizeof(kLdrLoadDllStub),
                          PAGE_EXECUTE_READ,
                          &oldProtect))
    {
        PrintLastError(L"VirtualProtectEx(LdrLoadDll stub)");
        ReleaseRemoteAllocation(process.get(), remoteStub, L"VirtualFreeEx(LdrLoadDll stub)");
        return false;
    }

    LPVOID remoteContext = VirtualAllocEx(process.get(),
                                          nullptr,
                                          sizeof(LdrLoadDllRemoteContext),
                                          MEM_COMMIT | MEM_RESERVE,
                                          PAGE_READWRITE);
    if (!remoteContext)
    {
        PrintLastError(L"VirtualAllocEx(LdrLoadDll context)");
        ReleaseRemoteAllocation(process.get(), remoteStub, L"VirtualFreeEx(LdrLoadDll stub)");
        return false;
    }

    LdrLoadDllRemoteContext context = {};
    if (!PrepareLdrLoadDllContext(targetPid,
                                  dllPath,
                                  reinterpret_cast<std::uintptr_t>(remoteContext),
                                  context))
    {
        ReleaseRemoteAllocation(process.get(), remoteContext, L"VirtualFreeEx(LdrLoadDll context)");
        ReleaseRemoteAllocation(process.get(), remoteStub, L"VirtualFreeEx(LdrLoadDll stub)");
        return false;
    }

    if (!WriteProcessMemory(process.get(),
                            remoteContext,
                            &context,
                            sizeof(context),
                            nullptr))
    {
        PrintLastError(L"WriteProcessMemory(LdrLoadDll context)");
        ReleaseRemoteAllocation(process.get(), remoteContext, L"VirtualFreeEx(LdrLoadDll context)");
        ReleaseRemoteAllocation(process.get(), remoteStub, L"VirtualFreeEx(LdrLoadDll stub)");
        return false;
    }

    wprintf(L"Staged LdrLoadDll context at 0x%p and x64 adapter stub at 0x%p.\n",
            remoteContext,
            remoteStub);

    bool canReleaseRemoteState = true;
    if (!LaunchRemoteRoutine(process.get(),
                             targetPid,
                             dllPath,
                             reinterpret_cast<LPTHREAD_START_ROUTINE>(remoteStub),
                             remoteContext,
                             config,
                             canReleaseRemoteState))
    {
        if (canReleaseRemoteState)
        {
            ReleaseRemoteAllocation(process.get(), remoteContext, L"VirtualFreeEx(LdrLoadDll context)");
            ReleaseRemoteAllocation(process.get(), remoteStub, L"VirtualFreeEx(LdrLoadDll stub)");
        }
        return false;
    }

    LdrLoadDllRemoteContext completedContext = {};
    if (ReadProcessMemory(process.get(),
                          remoteContext,
                          &completedContext,
                          sizeof(completedContext),
                          nullptr))
    {
        wprintf(L"LdrLoadDll returned NTSTATUS 0x%08lX, module handle 0x%p.\n",
                static_cast<unsigned long>(completedContext.status),
                reinterpret_cast<void*>(completedContext.module_handle));

        if (!NtSuccess(completedContext.status))
        {
            PrintNtStatus(L"remote LdrLoadDll", completedContext.status);
            if (canReleaseRemoteState)
            {
                ReleaseRemoteAllocation(process.get(), remoteContext, L"VirtualFreeEx(LdrLoadDll context)");
                ReleaseRemoteAllocation(process.get(), remoteStub, L"VirtualFreeEx(LdrLoadDll stub)");
            }
            return false;
        }
    }
    else
    {
        PrintLastError(L"ReadProcessMemory(LdrLoadDll context)");
    }

    if (canReleaseRemoteState)
    {
        ReleaseRemoteAllocation(process.get(), remoteContext, L"VirtualFreeEx(LdrLoadDll context)");
        ReleaseRemoteAllocation(process.get(), remoteStub, L"VirtualFreeEx(LdrLoadDll stub)");
    }
    else
    {
        if (config.launchMethod == LaunchMethod::ThreadHijack)
        {
            wprintf(L"Leaving the remote LdrLoadDll stub and context allocated because the hijacked thread has no completion handle.\n");
        }
        else if (config.queueUserApc.threadId != 0)
        {
            wprintf(L"Leaving the remote LdrLoadDll stub and context allocated because QueueUserAPC does not provide a completion handle for the APC routine.\n");
        }
        else
        {
            wprintf(L"Leaving the remote LdrLoadDll stub and context allocated because queued APCs may dispatch later.\n");
        }
    }

    wprintf(L"Remote LdrLoadDll launched with %s finished. "
            L"Check TargetApp for detection rows and the message box.\n",
            LaunchMethodName(config.launchMethod));
    return true;
}

void ReleaseOrExplainRemoteLoaderState(HANDLE process,
                                       LPVOID remoteContext,
                                       LPVOID remoteStub,
                                       const wchar_t* methodName,
                                       const InjectorConfig& config,
                                       bool canReleaseRemoteState)
{
    wchar_t contextLabel[96] = {};
    wchar_t stubLabel[96] = {};
    swprintf_s(contextLabel, L"VirtualFreeEx(%s context)", methodName);
    swprintf_s(stubLabel, L"VirtualFreeEx(%s stub)", methodName);

    if (canReleaseRemoteState)
    {
        ReleaseRemoteAllocation(process, remoteContext, contextLabel);
        ReleaseRemoteAllocation(process, remoteStub, stubLabel);
        return;
    }

    if (config.launchMethod == LaunchMethod::ThreadHijack)
    {
        wprintf(L"Leaving the remote %s stub and context allocated because the hijacked thread has no completion handle.\n",
                methodName);
    }
    else if (config.queueUserApc.threadId != 0)
    {
        wprintf(L"Leaving the remote %s stub and context allocated because QueueUserAPC does not provide a completion handle for the APC routine.\n",
                methodName);
    }
    else
    {
        wprintf(L"Leaving the remote %s stub and context allocated because queued APCs may dispatch later.\n",
                methodName);
    }
}

bool InjectDllWithLdrpLoadDll(DWORD targetPid,
                              const wchar_t* dllPath,
                              const InjectorConfig& config)
{
    UniqueHandle process = OpenTargetProcessForInjection(targetPid);
    if (!process.valid())
    {
        return false;
    }

    LPVOID remoteStub = StageRemoteExecutableStub(process.get(),
                                                 kLdrpLoadDllStub,
                                                 sizeof(kLdrpLoadDllStub),
                                                 L"LdrpLoadDll");
    if (!remoteStub)
    {
        return false;
    }

    LPVOID remoteContext = VirtualAllocEx(process.get(),
                                          nullptr,
                                          sizeof(LdrpLoadDllRemoteContext),
                                          MEM_COMMIT | MEM_RESERVE,
                                          PAGE_READWRITE);
    if (!remoteContext)
    {
        PrintLastError(L"VirtualAllocEx(LdrpLoadDll context)");
        ReleaseRemoteAllocation(process.get(), remoteStub, L"VirtualFreeEx(LdrpLoadDll stub)");
        return false;
    }

    LdrpLoadDllRemoteContext context = {};
    if (!PrepareLdrpLoadDllContext(targetPid,
                                   dllPath,
                                   reinterpret_cast<std::uintptr_t>(remoteContext),
                                   context))
    {
        ReleaseRemoteAllocation(process.get(), remoteContext, L"VirtualFreeEx(LdrpLoadDll context)");
        ReleaseRemoteAllocation(process.get(), remoteStub, L"VirtualFreeEx(LdrpLoadDll stub)");
        return false;
    }

    if (!WriteProcessMemory(process.get(),
                            remoteContext,
                            &context,
                            sizeof(context),
                            nullptr))
    {
        PrintLastError(L"WriteProcessMemory(LdrpLoadDll context)");
        ReleaseRemoteAllocation(process.get(), remoteContext, L"VirtualFreeEx(LdrpLoadDll context)");
        ReleaseRemoteAllocation(process.get(), remoteStub, L"VirtualFreeEx(LdrpLoadDll stub)");
        return false;
    }

    wprintf(L"Staged LdrpLoadDll context at 0x%p and x64 adapter stub at 0x%p.\n",
            remoteContext,
            remoteStub);

    bool canReleaseRemoteState = true;
    if (!LaunchRemoteRoutine(process.get(),
                             targetPid,
                             dllPath,
                             reinterpret_cast<LPTHREAD_START_ROUTINE>(remoteStub),
                             remoteContext,
                             config,
                             canReleaseRemoteState))
    {
        if (canReleaseRemoteState)
        {
            ReleaseRemoteAllocation(process.get(), remoteContext, L"VirtualFreeEx(LdrpLoadDll context)");
            ReleaseRemoteAllocation(process.get(), remoteStub, L"VirtualFreeEx(LdrpLoadDll stub)");
        }
        return false;
    }

    LdrpLoadDllRemoteContext completedContext = {};
    if (ReadProcessMemory(process.get(),
                          remoteContext,
                          &completedContext,
                          sizeof(completedContext),
                          nullptr))
    {
        wprintf(L"LdrpLoadDll returned NTSTATUS 0x%08lX, loader entry 0x%p.\n",
                static_cast<unsigned long>(completedContext.status),
                reinterpret_cast<void*>(completedContext.entry));

        if (!NtSuccess(completedContext.status) || completedContext.entry == 0)
        {
            if (!NtSuccess(completedContext.status))
            {
                PrintNtStatus(L"remote LdrpLoadDll", completedContext.status);
            }
            else
            {
                wprintf(L"remote LdrpLoadDll succeeded but returned a null loader entry.\n");
            }

            if (canReleaseRemoteState)
            {
                ReleaseRemoteAllocation(process.get(), remoteContext, L"VirtualFreeEx(LdrpLoadDll context)");
                ReleaseRemoteAllocation(process.get(), remoteStub, L"VirtualFreeEx(LdrpLoadDll stub)");
            }
            return false;
        }
    }
    else
    {
        PrintLastError(L"ReadProcessMemory(LdrpLoadDll context)");
    }

    std::uintptr_t loadedBase = 0;
    if (FindRemoteModuleByPath(targetPid, dllPath, loadedBase))
    {
        wprintf(L"Observed DLL loaded in target at 0x%p.\n",
                reinterpret_cast<void*>(loadedBase));
    }

    ReleaseOrExplainRemoteLoaderState(process.get(),
                                      remoteContext,
                                      remoteStub,
                                      L"LdrpLoadDll",
                                      config,
                                      canReleaseRemoteState);

    wprintf(L"Remote LdrpLoadDll launched with %s finished. "
            L"Check TargetApp for detection rows and the message box.\n",
            LaunchMethodName(config.launchMethod));
    return true;
}

bool InjectDllWithLdrpLoadDllInternal(DWORD targetPid,
                                      const wchar_t* dllPath,
                                      const InjectorConfig& config)
{
    UniqueHandle process = OpenTargetProcessForInjection(targetPid);
    if (!process.valid())
    {
        return false;
    }

    LPVOID remoteStub = StageRemoteExecutableStub(process.get(),
                                                 kLdrpLoadDllInternalStub,
                                                 sizeof(kLdrpLoadDllInternalStub),
                                                 L"LdrpLoadDllInternal");
    if (!remoteStub)
    {
        return false;
    }

    LPVOID remoteContext = VirtualAllocEx(process.get(),
                                          nullptr,
                                          sizeof(LdrpLoadDllInternalRemoteContext),
                                          MEM_COMMIT | MEM_RESERVE,
                                          PAGE_READWRITE);
    if (!remoteContext)
    {
        PrintLastError(L"VirtualAllocEx(LdrpLoadDllInternal context)");
        ReleaseRemoteAllocation(process.get(), remoteStub, L"VirtualFreeEx(LdrpLoadDllInternal stub)");
        return false;
    }

    LdrpLoadDllInternalRemoteContext context = {};
    if (!PrepareLdrpLoadDllInternalContext(targetPid,
                                           dllPath,
                                           reinterpret_cast<std::uintptr_t>(remoteContext),
                                           context))
    {
        ReleaseRemoteAllocation(process.get(), remoteContext, L"VirtualFreeEx(LdrpLoadDllInternal context)");
        ReleaseRemoteAllocation(process.get(), remoteStub, L"VirtualFreeEx(LdrpLoadDllInternal stub)");
        return false;
    }

    if (!WriteProcessMemory(process.get(),
                            remoteContext,
                            &context,
                            sizeof(context),
                            nullptr))
    {
        PrintLastError(L"WriteProcessMemory(LdrpLoadDllInternal context)");
        ReleaseRemoteAllocation(process.get(), remoteContext, L"VirtualFreeEx(LdrpLoadDllInternal context)");
        ReleaseRemoteAllocation(process.get(), remoteStub, L"VirtualFreeEx(LdrpLoadDllInternal stub)");
        return false;
    }

    wprintf(L"Staged LdrpLoadDllInternal context at 0x%p and x64 adapter stub at 0x%p.\n",
            remoteContext,
            remoteStub);

    bool canReleaseRemoteState = true;
    if (!LaunchRemoteRoutine(process.get(),
                             targetPid,
                             dllPath,
                             reinterpret_cast<LPTHREAD_START_ROUTINE>(remoteStub),
                             remoteContext,
                             config,
                             canReleaseRemoteState))
    {
        if (canReleaseRemoteState)
        {
            ReleaseRemoteAllocation(process.get(), remoteContext, L"VirtualFreeEx(LdrpLoadDllInternal context)");
            ReleaseRemoteAllocation(process.get(), remoteStub, L"VirtualFreeEx(LdrpLoadDllInternal stub)");
        }
        return false;
    }

    LdrpLoadDllInternalRemoteContext completedContext = {};
    if (ReadProcessMemory(process.get(),
                          remoteContext,
                          &completedContext,
                          sizeof(completedContext),
                          nullptr))
    {
        wprintf(L"LdrpLoadDllInternal returned NTSTATUS 0x%08lX, loader entry 0x%p.\n",
                static_cast<unsigned long>(completedContext.status),
                reinterpret_cast<void*>(completedContext.entry));

        if (!NtSuccess(completedContext.status) || completedContext.entry == 0)
        {
            if (!NtSuccess(completedContext.status))
            {
                PrintNtStatus(L"remote LdrpLoadDllInternal", completedContext.status);
            }
            else
            {
                wprintf(L"remote LdrpLoadDllInternal succeeded but returned a null loader entry.\n");
            }

            if (canReleaseRemoteState)
            {
                ReleaseRemoteAllocation(process.get(), remoteContext, L"VirtualFreeEx(LdrpLoadDllInternal context)");
                ReleaseRemoteAllocation(process.get(), remoteStub, L"VirtualFreeEx(LdrpLoadDllInternal stub)");
            }
            return false;
        }
    }
    else
    {
        PrintLastError(L"ReadProcessMemory(LdrpLoadDllInternal context)");
    }

    std::uintptr_t loadedBase = 0;
    if (FindRemoteModuleByPath(targetPid, dllPath, loadedBase))
    {
        wprintf(L"Observed DLL loaded in target at 0x%p.\n",
                reinterpret_cast<void*>(loadedBase));
    }

    ReleaseOrExplainRemoteLoaderState(process.get(),
                                      remoteContext,
                                      remoteStub,
                                      L"LdrpLoadDllInternal",
                                      config,
                                      canReleaseRemoteState);

    wprintf(L"Remote LdrpLoadDllInternal launched with %s finished. "
            L"Check TargetApp for detection rows and the message box.\n",
            LaunchMethodName(config.launchMethod));
    return true;
}
}

bool InjectDll(DWORD targetPid,
               const wchar_t* dllPath,
               const InjectorConfig& config)
{
    std::uintptr_t existingModule = 0;
    if (FindRemoteModuleByPath(targetPid, dllPath, existingModule))
    {
        wprintf(L"%s is already loaded in the target at 0x%p.\n",
                dllPath,
                reinterpret_cast<void*>(existingModule));
        wprintf(L"%s would only increment the loader reference count; "
                L"DllMain(DLL_PROCESS_ATTACH) will not run again.\n",
                LoadMethodName(config.loadMethod));
        wprintf(L"Restart TargetApp to repeat the visible MessageBox demo.\n");
        return true;
    }

    switch (config.loadMethod)
    {
    case LoadMethod::LoadLibraryW:
        return InjectDllWithLoadLibraryInternal(targetPid, dllPath, config);

    case LoadMethod::LdrLoadDll:
        return InjectDllWithLdrLoadDll(targetPid, dllPath, config);

    case LoadMethod::LdrpLoadDll:
        return InjectDllWithLdrpLoadDll(targetPid, dllPath, config);

    case LoadMethod::LdrpLoadDllInternal:
        return InjectDllWithLdrpLoadDllInternal(targetPid, dllPath, config);

    default:
        wprintf(L"Unsupported load method.\n");
        return false;
    }
}

}
