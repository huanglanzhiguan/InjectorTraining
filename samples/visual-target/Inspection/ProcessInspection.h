#pragma once

#include <windows.h>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace target
{
// Loader-visible module snapshot entry.
//
// These values come from Toolhelp module enumeration. They describe modules the
// Windows loader knows about, which is exactly why classic LoadLibrary-based
// injection appears here and manual mapping may not.
struct ModuleInfo
{
    std::wstring name;
    std::wstring path;
    std::uintptr_t base = 0;
    std::size_t size = 0;
};

// Thread snapshot entry with the thread's original start address.
//
// The start address is queried through NtQueryInformationThread. It is useful
// for teaching because a thread that starts inside a newly loaded module often
// means the injected DLL created a worker thread.
struct ThreadInfo
{
    DWORD thread_id = 0;
    std::uintptr_t start_address = 0;
};

// Enumerate modules currently visible through the normal loader/module view.
std::vector<ModuleInfo> EnumerateCurrentModules();

// Enumerate current process threads and their start addresses.
std::vector<ThreadInfo> EnumerateCurrentThreads();

std::wstring ToLower(std::wstring value);
std::wstring FileNameFromPath(std::wstring_view path);
std::wstring CompactPath(std::wstring_view path);
std::wstring HexAddress(std::uintptr_t value);
std::wstring ProtectionText(DWORD protect);

const ModuleInfo* FindContainingModule(const std::vector<ModuleInfo>& modules, std::uintptr_t address);

// True for page protections that allow execution. This is intentionally a broad
// helper; the mechanism decides whether executable memory is suspicious in
// context.
bool IsExecutableProtection(DWORD protect);
}
