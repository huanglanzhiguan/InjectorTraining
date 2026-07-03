#include "ProcessInspection.h"

#include <tlhelp32.h>

#include <algorithm>
#include <cwctype>
#include <sstream>
#include <utility>

namespace target
{
namespace
{
using NtQueryInformationThreadFn = LONG(NTAPI*)(HANDLE, LONG, PVOID, ULONG, PULONG);

template <typename HandleValue>
class UniqueHandle
{
public:
    explicit UniqueHandle(HandleValue handle = nullptr)
        : handle_(handle)
    {
    }

    ~UniqueHandle()
    {
        if (valid())
        {
            CloseHandle(handle_);
        }
    }

    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;

    bool valid() const
    {
        return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
    }

    HandleValue get() const
    {
        return handle_;
    }

private:
    HandleValue handle_;
};

NtQueryInformationThreadFn ResolveNtQueryInformationThread()
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr)
    {
        return nullptr;
    }

    return reinterpret_cast<NtQueryInformationThreadFn>(
        GetProcAddress(ntdll, "NtQueryInformationThread"));
}
}

std::vector<ModuleInfo> EnumerateCurrentModules()
{
    std::vector<ModuleInfo> modules;
    UniqueHandle<HANDLE> snapshot(CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
        GetCurrentProcessId()));

    if (!snapshot.valid())
    {
        return modules;
    }

    MODULEENTRY32W entry = {};
    entry.dwSize = sizeof(entry);

    if (!Module32FirstW(snapshot.get(), &entry))
    {
        return modules;
    }

    do
    {
        ModuleInfo module;
        module.name = entry.szModule;
        module.path = entry.szExePath;
        module.base = reinterpret_cast<std::uintptr_t>(entry.modBaseAddr);
        module.size = entry.modBaseSize;
        modules.push_back(std::move(module));
    } while (Module32NextW(snapshot.get(), &entry));

    return modules;
}

std::vector<ThreadInfo> EnumerateCurrentThreads()
{
    std::vector<ThreadInfo> threads;
    const auto nt_query_information_thread = ResolveNtQueryInformationThread();
    if (nt_query_information_thread == nullptr)
    {
        return threads;
    }

    const DWORD current_pid = GetCurrentProcessId();
    UniqueHandle<HANDLE> snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
    if (!snapshot.valid())
    {
        return threads;
    }

    THREADENTRY32 entry = {};
    entry.dwSize = sizeof(entry);

    if (!Thread32First(snapshot.get(), &entry))
    {
        return threads;
    }

    do
    {
        if (entry.th32OwnerProcessID != current_pid)
        {
            continue;
        }

        UniqueHandle<HANDLE> thread(OpenThread(THREAD_QUERY_INFORMATION, FALSE, entry.th32ThreadID));
        if (!thread.valid())
        {
            continue;
        }

        PVOID start_address = nullptr;
        const LONG status = nt_query_information_thread(
            thread.get(),
            9,
            &start_address,
            sizeof(start_address),
            nullptr);

        if (status < 0)
        {
            continue;
        }

        threads.push_back({ entry.th32ThreadID, reinterpret_cast<std::uintptr_t>(start_address) });
    } while (Thread32Next(snapshot.get(), &entry));

    return threads;
}

std::wstring ToLower(std::wstring value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(std::towlower(ch));
    });
    return value;
}

std::wstring FileNameFromPath(std::wstring_view path)
{
    const std::size_t slash = path.find_last_of(L"\\/");
    if (slash == std::wstring_view::npos)
    {
        return std::wstring(path);
    }

    return std::wstring(path.substr(slash + 1));
}

std::wstring CompactPath(std::wstring_view path)
{
    const std::wstring value(path);
    const std::wstring file_name = FileNameFromPath(value);
    const std::size_t slash = value.find_last_of(L"\\/");
    if (slash == std::wstring::npos)
    {
        return file_name;
    }

    const std::size_t previous_slash = value.find_last_of(L"\\/", slash == 0 ? 0 : slash - 1);
    if (previous_slash == std::wstring::npos)
    {
        return value;
    }

    return value.substr(previous_slash + 1);
}

std::wstring HexAddress(std::uintptr_t value)
{
    std::wstringstream stream;
    stream << L"0x" << std::hex << std::uppercase << value;
    return stream.str();
}

std::wstring ProtectionText(DWORD protect)
{
    const DWORD base_protect = protect & 0xFF;
    switch (base_protect)
    {
    case PAGE_EXECUTE:
        return L"PAGE_EXECUTE";
    case PAGE_EXECUTE_READ:
        return L"PAGE_EXECUTE_READ";
    case PAGE_EXECUTE_READWRITE:
        return L"PAGE_EXECUTE_READWRITE";
    case PAGE_EXECUTE_WRITECOPY:
        return L"PAGE_EXECUTE_WRITECOPY";
    case PAGE_READONLY:
        return L"PAGE_READONLY";
    case PAGE_READWRITE:
        return L"PAGE_READWRITE";
    case PAGE_WRITECOPY:
        return L"PAGE_WRITECOPY";
    case PAGE_NOACCESS:
        return L"PAGE_NOACCESS";
    default:
        return L"protect=" + std::to_wstring(protect);
    }
}

const ModuleInfo* FindContainingModule(const std::vector<ModuleInfo>& modules, std::uintptr_t address)
{
    for (const ModuleInfo& module : modules)
    {
        const std::uintptr_t end = module.base + module.size;
        if (address >= module.base && address < end)
        {
            return &module;
        }
    }

    return nullptr;
}

bool IsExecutableProtection(DWORD protect)
{
    if ((protect & PAGE_GUARD) != 0 || (protect & PAGE_NOACCESS) != 0)
    {
        return false;
    }

    const DWORD base_protect = protect & 0xFF;
    return base_protect == PAGE_EXECUTE ||
        base_protect == PAGE_EXECUTE_READ ||
        base_protect == PAGE_EXECUTE_READWRITE ||
        base_protect == PAGE_EXECUTE_WRITECOPY;
}
}
