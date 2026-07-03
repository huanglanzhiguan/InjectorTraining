#include "LoaderMechanisms.h"

#include "../Core/MechanismRegistry.h"

#include <algorithm>
#include <cwchar>
#include <sstream>

namespace target
{
namespace
{
constexpr ULONG kLdrDllNotificationReasonLoaded = 1;

struct UnicodeString
{
    USHORT length;
    USHORT maximum_length;
    PWSTR buffer;
};

struct LdrDllLoadedNotificationData
{
    ULONG flags;
    const UnicodeString* full_dll_name;
    const UnicodeString* base_dll_name;
    void* dll_base;
    ULONG size_of_image;
};

union LdrDllNotificationData
{
    LdrDllLoadedNotificationData loaded;
};

using LdrRegisterDllNotificationFn = LONG(NTAPI*)(ULONG, void(NTAPI*)(ULONG, const void*, void*), void*, void**);
using LdrUnregisterDllNotificationFn = LONG(NTAPI*)(void*);

std::wstring StringFromUnicodeString(const UnicodeString* value)
{
    if (value == nullptr || value->buffer == nullptr || value->length == 0)
    {
        return {};
    }

    return std::wstring(value->buffer, value->length / sizeof(wchar_t));
}

LdrRegisterDllNotificationFn ResolveLdrRegisterDllNotification()
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr)
    {
        return nullptr;
    }

    return reinterpret_cast<LdrRegisterDllNotificationFn>(
        GetProcAddress(ntdll, "LdrRegisterDllNotification"));
}

LdrUnregisterDllNotificationFn ResolveLdrUnregisterDllNotification()
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr)
    {
        return nullptr;
    }

    return reinterpret_cast<LdrUnregisterDllNotificationFn>(
        GetProcAddress(ntdll, "LdrUnregisterDllNotification"));
}

std::wstring ModuleCountText(std::size_t count)
{
    return std::to_wstring(count) + L" module(s)";
}
}

ModuleBaselineMechanism::ModuleBaselineMechanism()
{
    CaptureBaseline();
}

std::wstring_view ModuleBaselineMechanism::Id() const noexcept
{
    return L"loader.module_baseline";
}

std::wstring_view ModuleBaselineMechanism::Name() const noexcept
{
    return L"New loader-visible module";
}

std::wstring_view ModuleBaselineMechanism::Category() const noexcept
{
    return L"Loader";
}

std::wstring_view ModuleBaselineMechanism::Description() const noexcept
{
    return L"Records startup modules and flags any module that appears later in loader enumeration.";
}

DetectionResult ModuleBaselineMechanism::Run()
{
    const std::vector<ModuleInfo> modules = EnumerateCurrentModules();
    for (const ModuleInfo& module : modules)
    {
        const std::wstring path = ToLower(module.path);
        if (baseline_paths_.find(path) == baseline_paths_.end())
        {
            return DetectionResult::Detected(L"new module: " + CompactPath(module.path));
        }
    }

    return DetectionResult::Clean(L"baseline unchanged: " + ModuleCountText(modules.size()));
}

void ModuleBaselineMechanism::Reset()
{
    CaptureBaseline();
}

void ModuleBaselineMechanism::CaptureBaseline()
{
    baseline_paths_.clear();
    for (const ModuleInfo& module : EnumerateCurrentModules())
    {
        baseline_paths_.insert(ToLower(module.path));
    }
}

DllNotificationMechanism::DllNotificationMechanism()
{
    InitializeCriticalSection(&lock_);

    const auto ldr_register_dll_notification = ResolveLdrRegisterDllNotification();
    if (ldr_register_dll_notification == nullptr)
    {
        return;
    }

    available_ = ldr_register_dll_notification(0, &NotificationCallback, this, &cookie_) >= 0;
}

DllNotificationMechanism::~DllNotificationMechanism()
{
    if (cookie_ != nullptr)
    {
        const auto ldr_unregister_dll_notification = ResolveLdrUnregisterDllNotification();
        if (ldr_unregister_dll_notification != nullptr)
        {
            ldr_unregister_dll_notification(cookie_);
        }
    }

    DeleteCriticalSection(&lock_);
}

std::wstring_view DllNotificationMechanism::Id() const noexcept
{
    return L"loader.dll_notification";
}

std::wstring_view DllNotificationMechanism::Name() const noexcept
{
    return L"Loader DLL notification";
}

std::wstring_view DllNotificationMechanism::Category() const noexcept
{
    return L"Loader";
}

std::wstring_view DllNotificationMechanism::Description() const noexcept
{
    return L"Uses LdrRegisterDllNotification to observe DLL load events.";
}

DetectionResult DllNotificationMechanism::Run()
{
    if (!available_)
    {
        return DetectionResult::Error(L"LdrRegisterDllNotification is unavailable");
    }

    EnterCriticalSection(&lock_);
    const DWORD load_count = load_count_;
    const std::wstring last_path(last_path_);
    LeaveCriticalSection(&lock_);

    if (load_count == 0)
    {
        return DetectionResult::Clean(L"no loader DLL notification after baseline");
    }

    return DetectionResult::Detected(L"load #" + std::to_wstring(load_count) +
                                     L": " + CompactPath(last_path));
}

void DllNotificationMechanism::Reset()
{
    EnterCriticalSection(&lock_);
    load_count_ = 0;
    last_path_[0] = L'\0';
    LeaveCriticalSection(&lock_);
}

void NTAPI DllNotificationMechanism::NotificationCallback(ULONG reason, const void* data, void* context)
{
    if (reason != kLdrDllNotificationReasonLoaded || data == nullptr || context == nullptr)
    {
        return;
    }

    const auto* notification = static_cast<const LdrDllNotificationData*>(data);
    static_cast<DllNotificationMechanism*>(context)->RecordLoad(
        StringFromUnicodeString(notification->loaded.full_dll_name));
}

void DllNotificationMechanism::RecordLoad(std::wstring_view full_path)
{
    EnterCriticalSection(&lock_);
    ++load_count_;

    const std::size_t copy_count = (std::min)(full_path.size(), static_cast<std::size_t>(MAX_PATH - 1));
    std::wmemcpy(last_path_, full_path.data(), copy_count);
    last_path_[copy_count] = L'\0';

    LeaveCriticalSection(&lock_);
}

ThreadStartModuleMechanism::ThreadStartModuleMechanism()
{
    CaptureBaseline();
}

std::wstring_view ThreadStartModuleMechanism::Id() const noexcept
{
    return L"thread.start_module";
}

std::wstring_view ThreadStartModuleMechanism::Name() const noexcept
{
    return L"Thread starts in new module";
}

std::wstring_view ThreadStartModuleMechanism::Category() const noexcept
{
    return L"Thread";
}

std::wstring_view ThreadStartModuleMechanism::Description() const noexcept
{
    return L"Flags threads whose start address belongs to a module loaded after baseline.";
}

DetectionResult ThreadStartModuleMechanism::Run()
{
    const std::vector<ModuleInfo> modules = EnumerateCurrentModules();
    const std::vector<ThreadInfo> threads = EnumerateCurrentThreads();

    if (threads.empty())
    {
        return DetectionResult::Error(L"unable to query thread start addresses");
    }

    for (const ThreadInfo& thread : threads)
    {
        const ModuleInfo* module = FindContainingModule(modules, thread.start_address);
        if (module == nullptr)
        {
            return DetectionResult::Suspicious(L"thread " + std::to_wstring(thread.thread_id) +
                                               L" starts outside loaded modules at " +
                                               HexAddress(thread.start_address));
        }

        if (baseline_module_paths_.find(ToLower(module->path)) == baseline_module_paths_.end())
        {
            return DetectionResult::Detected(L"thread " + std::to_wstring(thread.thread_id) +
                                             L" starts in new module " + module->name);
        }
    }

    return DetectionResult::Clean(std::to_wstring(threads.size()) + L" thread(s), starts in baseline modules");
}

void ThreadStartModuleMechanism::Reset()
{
    CaptureBaseline();
}

void ThreadStartModuleMechanism::CaptureBaseline()
{
    baseline_module_paths_.clear();
    for (const ModuleInfo& module : EnumerateCurrentModules())
    {
        baseline_module_paths_.insert(ToLower(module.path));
    }
}

PrivateExecutableMemoryMechanism::PrivateExecutableMemoryMechanism()
{
    CaptureBaseline();
}

std::wstring_view PrivateExecutableMemoryMechanism::Id() const noexcept
{
    return L"memory.private_executable";
}

std::wstring_view PrivateExecutableMemoryMechanism::Name() const noexcept
{
    return L"New private executable memory";
}

std::wstring_view PrivateExecutableMemoryMechanism::Category() const noexcept
{
    return L"Memory";
}

std::wstring_view PrivateExecutableMemoryMechanism::Description() const noexcept
{
    return L"Scans this process for executable MEM_PRIVATE regions.";
}

DetectionResult PrivateExecutableMemoryMechanism::Run()
{
    MEMORY_BASIC_INFORMATION memory = {};
    auto* address = static_cast<unsigned char*>(nullptr);

    while (VirtualQuery(address, &memory, sizeof(memory)) == sizeof(memory))
    {
        if (memory.State == MEM_COMMIT &&
            memory.Type == MEM_PRIVATE &&
            IsExecutableProtection(memory.Protect))
        {
            const auto base = reinterpret_cast<std::uintptr_t>(memory.BaseAddress);
            if (baseline_region_bases_.find(base) == baseline_region_bases_.end())
            {
                return DetectionResult::Suspicious(L"new private executable region at " +
                                                   HexAddress(base) +
                                                   L", size " + std::to_wstring(memory.RegionSize) +
                                                   L", " + ProtectionText(memory.Protect));
            }
        }

        auto* next = address + memory.RegionSize;
        if (next <= address)
        {
            break;
        }

        address = next;
    }

    return DetectionResult::Clean(L"no new executable MEM_PRIVATE regions");
}

void PrivateExecutableMemoryMechanism::Reset()
{
    CaptureBaseline();
}

void PrivateExecutableMemoryMechanism::CaptureBaseline()
{
    baseline_region_bases_.clear();

    MEMORY_BASIC_INFORMATION memory = {};
    auto* address = static_cast<unsigned char*>(nullptr);

    while (VirtualQuery(address, &memory, sizeof(memory)) == sizeof(memory))
    {
        if (memory.State == MEM_COMMIT &&
            memory.Type == MEM_PRIVATE &&
            IsExecutableProtection(memory.Protect))
        {
            baseline_region_bases_.insert(reinterpret_cast<std::uintptr_t>(memory.BaseAddress));
        }

        auto* next = address + memory.RegionSize;
        if (next <= address)
        {
            break;
        }

        address = next;
    }
}
}

TARGET_REGISTER_MECHANISM(target::ModuleBaselineMechanism)
TARGET_REGISTER_MECHANISM(target::DllNotificationMechanism)
TARGET_REGISTER_MECHANISM(target::ThreadStartModuleMechanism)
TARGET_REGISTER_MECHANISM(target::PrivateExecutableMemoryMechanism)
