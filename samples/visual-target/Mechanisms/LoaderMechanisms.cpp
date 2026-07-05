#include "LoaderMechanisms.h"

#include "../Core/MechanismRegistry.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cwchar>
#include <limits>
#include <set>
#include <sstream>
#include <utility>
#include <vector>

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

constexpr LONG kMaximumPeHeaderOffset = 0x1000;
constexpr WORD kMaximumReasonableSectionCount = 96;
constexpr DWORD kMinimumReasonableImageSize = 0x1000;
constexpr DWORD kMaximumReasonableImageSize = 512 * 1024 * 1024;
constexpr std::uintptr_t kNtFileHeaderOffset = sizeof(DWORD);
constexpr std::uintptr_t kNtOptionalHeaderOffset = sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);

struct AllocationSummary
{
    std::size_t extent = 0;
    bool has_executable_page = false;
};

struct PrivatePeImageCandidate
{
    std::uintptr_t allocation_base = 0;
    DWORD size_of_image = 0;
    WORD section_count = 0;
    DWORD executable_page_protection = 0;
};

struct ExecutablePrivateRegion
{
    std::uintptr_t base = 0;
    std::size_t size = 0;
    DWORD protection = 0;
};

struct PrivateExecutableAllocation
{
    std::uintptr_t allocation_base = 0;
    std::vector<ExecutablePrivateRegion> executable_regions;
};

struct ClaimedExecutableRange
{
    std::uintptr_t begin = 0;
    std::uintptr_t end = 0;
};

struct PeHeaderClaims
{
    DWORD size_of_image = 0;
    WORD section_count = 0;
    std::vector<ClaimedExecutableRange> executable_ranges;
    std::wstring failure_detail;
};

struct PrivateHeaderMismatchCandidate
{
    std::uintptr_t allocation_base = 0;
    std::uintptr_t executable_region = 0;
    DWORD executable_page_protection = 0;
    std::wstring detail;
};

bool AddOffset(std::uintptr_t base, std::uintptr_t offset, std::uintptr_t& result)
{
    if (offset > (std::numeric_limits<std::uintptr_t>::max)() - base)
    {
        return false;
    }

    result = base + offset;
    return true;
}

template <typename Value>
bool ReadCurrentProcessValue(std::uintptr_t address, Value& value)
{
    SIZE_T bytes_read = 0;
    return ReadProcessMemory(
        GetCurrentProcess(),
        reinterpret_cast<const void*>(address),
        &value,
        sizeof(value),
        &bytes_read) != FALSE &&
        bytes_read == sizeof(value);
}

AllocationSummary SummarizePrivateAllocation(std::uintptr_t allocation_base)
{
    AllocationSummary summary;
    MEMORY_BASIC_INFORMATION memory = {};
    auto* address = reinterpret_cast<unsigned char*>(allocation_base);
    const auto* allocation = reinterpret_cast<const void*>(allocation_base);

    while (VirtualQuery(address, &memory, sizeof(memory)) == sizeof(memory))
    {
        if (memory.AllocationBase != allocation)
        {
            break;
        }

        const auto region_base = reinterpret_cast<std::uintptr_t>(memory.BaseAddress);
        const auto region_size = static_cast<std::uintptr_t>(memory.RegionSize);
        std::uintptr_t region_end = 0;
        if (!AddOffset(region_base, region_size, region_end))
        {
            break;
        }

        if (region_end > allocation_base)
        {
            summary.extent = (std::max)(
                summary.extent,
                static_cast<std::size_t>(region_end - allocation_base));
        }

        if (memory.State == MEM_COMMIT &&
            memory.Type == MEM_PRIVATE &&
            IsExecutableProtection(memory.Protect))
        {
            summary.has_executable_page = true;
        }

        if (region_end <= reinterpret_cast<std::uintptr_t>(address))
        {
            break;
        }

        address = reinterpret_cast<unsigned char*>(region_end);
    }

    return summary;
}

bool ValidatePeSectionTable(std::uintptr_t section_table_address, WORD section_count, DWORD size_of_image)
{
    bool has_executable_section = false;

    for (WORD index = 0; index < section_count; ++index)
    {
        IMAGE_SECTION_HEADER section = {};
        std::uintptr_t section_address = 0;
        if (!AddOffset(section_table_address, static_cast<std::uintptr_t>(index) * sizeof(section), section_address) ||
            !ReadCurrentProcessValue(section_address, section))
        {
            return false;
        }

        if (section.VirtualAddress == 0 || section.VirtualAddress >= size_of_image)
        {
            return false;
        }

        const DWORD virtual_size = section.Misc.VirtualSize != 0
            ? section.Misc.VirtualSize
            : section.SizeOfRawData;
        if (virtual_size != 0 &&
            static_cast<unsigned long long>(section.VirtualAddress) + virtual_size > size_of_image)
        {
            return false;
        }

        if ((section.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0)
        {
            has_executable_section = true;
        }
    }

    return has_executable_section;
}

bool LooksLikePrivatePeImage(PrivatePeImageCandidate& candidate)
{
    MEMORY_BASIC_INFORMATION first_page = {};
    if (VirtualQuery(
        reinterpret_cast<const void*>(candidate.allocation_base),
        &first_page,
        sizeof(first_page)) != sizeof(first_page))
    {
        return false;
    }

    if (first_page.State != MEM_COMMIT || first_page.Type != MEM_PRIVATE)
    {
        return false;
    }

    IMAGE_DOS_HEADER dos_header = {};
    if (!ReadCurrentProcessValue(candidate.allocation_base, dos_header) ||
        dos_header.e_magic != IMAGE_DOS_SIGNATURE ||
        dos_header.e_lfanew < static_cast<LONG>(sizeof(IMAGE_DOS_HEADER)) ||
        dos_header.e_lfanew > kMaximumPeHeaderOffset)
    {
        return false;
    }

    std::uintptr_t nt_headers_address = 0;
    if (!AddOffset(candidate.allocation_base, static_cast<std::uintptr_t>(dos_header.e_lfanew), nt_headers_address))
    {
        return false;
    }

    DWORD nt_signature = 0;
    if (!ReadCurrentProcessValue(nt_headers_address, nt_signature) ||
        nt_signature != IMAGE_NT_SIGNATURE)
    {
        return false;
    }

    IMAGE_FILE_HEADER file_header = {};
    if (!ReadCurrentProcessValue(nt_headers_address + kNtFileHeaderOffset, file_header) ||
        file_header.NumberOfSections == 0 ||
        file_header.NumberOfSections > kMaximumReasonableSectionCount ||
        file_header.SizeOfOptionalHeader < sizeof(WORD))
    {
        return false;
    }

    std::uintptr_t optional_header_address = 0;
    if (!AddOffset(nt_headers_address, kNtOptionalHeaderOffset, optional_header_address))
    {
        return false;
    }

    WORD optional_magic = 0;
    if (!ReadCurrentProcessValue(optional_header_address, optional_magic))
    {
        return false;
    }

    DWORD size_of_image = 0;
    DWORD size_of_headers = 0;
    if (optional_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        constexpr WORD kMinimumOptionalHeaderSize =
            static_cast<WORD>(offsetof(IMAGE_OPTIONAL_HEADER64, SizeOfHeaders) + sizeof(DWORD));
        IMAGE_OPTIONAL_HEADER64 optional_header = {};
        if (file_header.SizeOfOptionalHeader < kMinimumOptionalHeaderSize ||
            !ReadCurrentProcessValue(optional_header_address, optional_header))
        {
            return false;
        }

        size_of_image = optional_header.SizeOfImage;
        size_of_headers = optional_header.SizeOfHeaders;
    }
    else if (optional_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        constexpr WORD kMinimumOptionalHeaderSize =
            static_cast<WORD>(offsetof(IMAGE_OPTIONAL_HEADER32, SizeOfHeaders) + sizeof(DWORD));
        IMAGE_OPTIONAL_HEADER32 optional_header = {};
        if (file_header.SizeOfOptionalHeader < kMinimumOptionalHeaderSize ||
            !ReadCurrentProcessValue(optional_header_address, optional_header))
        {
            return false;
        }

        size_of_image = optional_header.SizeOfImage;
        size_of_headers = optional_header.SizeOfHeaders;
    }
    else
    {
        return false;
    }

    if (size_of_image < kMinimumReasonableImageSize ||
        size_of_image > kMaximumReasonableImageSize ||
        size_of_headers == 0 ||
        size_of_headers > size_of_image)
    {
        return false;
    }

    const AllocationSummary allocation = SummarizePrivateAllocation(candidate.allocation_base);
    if (!allocation.has_executable_page || allocation.extent < size_of_image)
    {
        return false;
    }

    std::uintptr_t section_table_address = 0;
    if (!AddOffset(optional_header_address, file_header.SizeOfOptionalHeader, section_table_address) ||
        !ValidatePeSectionTable(section_table_address, file_header.NumberOfSections, size_of_image))
    {
        return false;
    }

    candidate.size_of_image = size_of_image;
    candidate.section_count = file_header.NumberOfSections;
    return true;
}

std::vector<PrivatePeImageCandidate> EnumeratePrivatePeLikeImages()
{
    std::vector<PrivatePeImageCandidate> candidates;
    std::set<std::uintptr_t> visited_allocations;
    MEMORY_BASIC_INFORMATION memory = {};
    auto* address = static_cast<unsigned char*>(nullptr);

    while (VirtualQuery(address, &memory, sizeof(memory)) == sizeof(memory))
    {
        if (memory.State == MEM_COMMIT &&
            memory.Type == MEM_PRIVATE &&
            IsExecutableProtection(memory.Protect))
        {
            PrivatePeImageCandidate candidate;
            candidate.allocation_base = reinterpret_cast<std::uintptr_t>(memory.AllocationBase);
            candidate.executable_page_protection = memory.Protect;

            if (visited_allocations.insert(candidate.allocation_base).second &&
                LooksLikePrivatePeImage(candidate))
            {
                candidates.push_back(candidate);
            }
        }

        const auto region_base = reinterpret_cast<std::uintptr_t>(memory.BaseAddress);
        const auto region_size = static_cast<std::uintptr_t>(memory.RegionSize);
        std::uintptr_t next = 0;
        if (!AddOffset(region_base, region_size, next) ||
            next <= reinterpret_cast<std::uintptr_t>(address))
        {
            break;
        }

        address = reinterpret_cast<unsigned char*>(next);
    }

    return candidates;
}

PrivateExecutableAllocation DescribePrivateExecutableAllocation(std::uintptr_t allocation_base)
{
    PrivateExecutableAllocation allocation;
    allocation.allocation_base = allocation_base;

    MEMORY_BASIC_INFORMATION memory = {};
    auto* address = reinterpret_cast<unsigned char*>(allocation_base);
    const auto* allocation_base_pointer = reinterpret_cast<const void*>(allocation_base);

    while (VirtualQuery(address, &memory, sizeof(memory)) == sizeof(memory))
    {
        if (memory.AllocationBase != allocation_base_pointer)
        {
            break;
        }

        if (memory.State == MEM_COMMIT &&
            memory.Type == MEM_PRIVATE &&
            IsExecutableProtection(memory.Protect))
        {
            allocation.executable_regions.push_back({
                reinterpret_cast<std::uintptr_t>(memory.BaseAddress),
                memory.RegionSize,
                memory.Protect
            });
        }

        const auto region_base = reinterpret_cast<std::uintptr_t>(memory.BaseAddress);
        const auto region_size = static_cast<std::uintptr_t>(memory.RegionSize);
        std::uintptr_t next = 0;
        if (!AddOffset(region_base, region_size, next) ||
            next <= reinterpret_cast<std::uintptr_t>(address))
        {
            break;
        }

        address = reinterpret_cast<unsigned char*>(next);
    }

    return allocation;
}

std::vector<PrivateExecutableAllocation> EnumeratePrivateExecutableAllocations()
{
    std::vector<PrivateExecutableAllocation> allocations;
    std::set<std::uintptr_t> visited_allocations;
    MEMORY_BASIC_INFORMATION memory = {};
    auto* address = static_cast<unsigned char*>(nullptr);

    while (VirtualQuery(address, &memory, sizeof(memory)) == sizeof(memory))
    {
        if (memory.State == MEM_COMMIT &&
            memory.Type == MEM_PRIVATE &&
            IsExecutableProtection(memory.Protect))
        {
            const auto allocation_base =
                reinterpret_cast<std::uintptr_t>(memory.AllocationBase);
            if (visited_allocations.insert(allocation_base).second)
            {
                PrivateExecutableAllocation allocation =
                    DescribePrivateExecutableAllocation(allocation_base);
                if (!allocation.executable_regions.empty())
                {
                    allocations.push_back(std::move(allocation));
                }
            }
        }

        const auto region_base = reinterpret_cast<std::uintptr_t>(memory.BaseAddress);
        const auto region_size = static_cast<std::uintptr_t>(memory.RegionSize);
        std::uintptr_t next = 0;
        if (!AddOffset(region_base, region_size, next) ||
            next <= reinterpret_cast<std::uintptr_t>(address))
        {
            break;
        }

        address = reinterpret_cast<unsigned char*>(next);
    }

    return allocations;
}

bool ReadPeHeaderClaims(std::uintptr_t allocation_base, PeHeaderClaims& claims)
{
    claims = {};

    IMAGE_DOS_HEADER dos_header = {};
    if (!ReadCurrentProcessValue(allocation_base, dos_header) ||
        dos_header.e_magic != IMAGE_DOS_SIGNATURE)
    {
        claims.failure_detail = L"no valid MZ header";
        return false;
    }

    if (dos_header.e_lfanew < static_cast<LONG>(sizeof(IMAGE_DOS_HEADER)) ||
        dos_header.e_lfanew > kMaximumPeHeaderOffset)
    {
        claims.failure_detail = L"invalid e_lfanew";
        return false;
    }

    std::uintptr_t nt_headers_address = 0;
    if (!AddOffset(allocation_base, static_cast<std::uintptr_t>(dos_header.e_lfanew), nt_headers_address))
    {
        claims.failure_detail = L"NT header address overflow";
        return false;
    }

    DWORD nt_signature = 0;
    if (!ReadCurrentProcessValue(nt_headers_address, nt_signature) ||
        nt_signature != IMAGE_NT_SIGNATURE)
    {
        claims.failure_detail = L"no valid PE signature";
        return false;
    }

    IMAGE_FILE_HEADER file_header = {};
    if (!ReadCurrentProcessValue(nt_headers_address + kNtFileHeaderOffset, file_header) ||
        file_header.NumberOfSections == 0 ||
        file_header.NumberOfSections > kMaximumReasonableSectionCount ||
        file_header.SizeOfOptionalHeader < sizeof(WORD))
    {
        claims.failure_detail = L"invalid PE file header";
        return false;
    }

    std::uintptr_t optional_header_address = 0;
    if (!AddOffset(nt_headers_address, kNtOptionalHeaderOffset, optional_header_address))
    {
        claims.failure_detail = L"optional header address overflow";
        return false;
    }

    WORD optional_magic = 0;
    if (!ReadCurrentProcessValue(optional_header_address, optional_magic))
    {
        claims.failure_detail = L"unreadable optional header";
        return false;
    }

    DWORD size_of_headers = 0;
    if (optional_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        constexpr WORD kMinimumOptionalHeaderSize =
            static_cast<WORD>(offsetof(IMAGE_OPTIONAL_HEADER64, SizeOfHeaders) + sizeof(DWORD));
        IMAGE_OPTIONAL_HEADER64 optional_header = {};
        if (file_header.SizeOfOptionalHeader < kMinimumOptionalHeaderSize ||
            !ReadCurrentProcessValue(optional_header_address, optional_header))
        {
            claims.failure_detail = L"invalid PE64 optional header";
            return false;
        }

        claims.size_of_image = optional_header.SizeOfImage;
        size_of_headers = optional_header.SizeOfHeaders;
    }
    else if (optional_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        constexpr WORD kMinimumOptionalHeaderSize =
            static_cast<WORD>(offsetof(IMAGE_OPTIONAL_HEADER32, SizeOfHeaders) + sizeof(DWORD));
        IMAGE_OPTIONAL_HEADER32 optional_header = {};
        if (file_header.SizeOfOptionalHeader < kMinimumOptionalHeaderSize ||
            !ReadCurrentProcessValue(optional_header_address, optional_header))
        {
            claims.failure_detail = L"invalid PE32 optional header";
            return false;
        }

        claims.size_of_image = optional_header.SizeOfImage;
        size_of_headers = optional_header.SizeOfHeaders;
    }
    else
    {
        claims.failure_detail = L"unsupported optional header magic";
        return false;
    }

    if (claims.size_of_image < kMinimumReasonableImageSize ||
        claims.size_of_image > kMaximumReasonableImageSize ||
        size_of_headers == 0 ||
        size_of_headers > claims.size_of_image)
    {
        claims.failure_detail = L"implausible PE image size";
        return false;
    }

    std::uintptr_t section_table_address = 0;
    if (!AddOffset(optional_header_address, file_header.SizeOfOptionalHeader, section_table_address))
    {
        claims.failure_detail = L"section table address overflow";
        return false;
    }

    for (WORD index = 0; index < file_header.NumberOfSections; ++index)
    {
        IMAGE_SECTION_HEADER section = {};
        std::uintptr_t section_address = 0;
        if (!AddOffset(section_table_address, static_cast<std::uintptr_t>(index) * sizeof(section), section_address) ||
            !ReadCurrentProcessValue(section_address, section))
        {
            claims.failure_detail = L"unreadable PE section table";
            return false;
        }

        if (section.VirtualAddress == 0 || section.VirtualAddress >= claims.size_of_image)
        {
            claims.failure_detail = L"invalid PE section RVA";
            return false;
        }

        const DWORD virtual_size = (std::max)(section.Misc.VirtualSize, section.SizeOfRawData);
        if (virtual_size != 0 &&
            static_cast<unsigned long long>(section.VirtualAddress) + virtual_size > claims.size_of_image)
        {
            claims.failure_detail = L"invalid PE section bounds";
            return false;
        }

        if ((section.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 && virtual_size != 0)
        {
            std::uintptr_t begin = 0;
            std::uintptr_t end = 0;
            if (!AddOffset(allocation_base, section.VirtualAddress, begin) ||
                !AddOffset(begin, virtual_size, end))
            {
                claims.failure_detail = L"executable section address overflow";
                return false;
            }

            claims.executable_ranges.push_back({ begin, end });
        }
    }

    claims.section_count = file_header.NumberOfSections;
    return true;
}

bool RegionOverlapsRange(const ExecutablePrivateRegion& region, const ClaimedExecutableRange& range)
{
    std::uintptr_t region_end = 0;
    if (!AddOffset(region.base, static_cast<std::uintptr_t>(region.size), region_end))
    {
        return false;
    }

    return region.base < range.end && region_end > range.begin;
}

bool HeaderCoversExecutableRegion(const PeHeaderClaims& claims, const ExecutablePrivateRegion& region)
{
    for (const ClaimedExecutableRange& range : claims.executable_ranges)
    {
        if (RegionOverlapsRange(region, range))
        {
            return true;
        }
    }

    return false;
}

bool TryFindHeaderMismatch(const PrivateExecutableAllocation& allocation,
                           PrivateHeaderMismatchCandidate& candidate)
{
    if (allocation.executable_regions.empty())
    {
        return false;
    }

    const ExecutablePrivateRegion& first_executable_region = allocation.executable_regions.front();
    PeHeaderClaims claims = {};
    candidate = {};
    candidate.allocation_base = allocation.allocation_base;
    candidate.executable_region = first_executable_region.base;
    candidate.executable_page_protection = first_executable_region.protection;

    if (!ReadPeHeaderClaims(allocation.allocation_base, claims))
    {
        candidate.detail = L"executable private allocation has " +
            claims.failure_detail +
            L" at " +
            HexAddress(allocation.allocation_base);
        return true;
    }

    if (claims.executable_ranges.empty())
    {
        candidate.detail = L"PE header has " +
            std::to_wstring(claims.section_count) +
            L" section(s) but none marked executable";
        return true;
    }

    for (const ExecutablePrivateRegion& region : allocation.executable_regions)
    {
        if (!HeaderCoversExecutableRegion(claims, region))
        {
            candidate.executable_region = region.base;
            candidate.executable_page_protection = region.protection;
            candidate.detail = L"executable page at " +
                HexAddress(region.base) +
                L" is outside PE executable sections";
            return true;
        }
    }

    return false;
}

std::vector<PrivateHeaderMismatchCandidate> EnumeratePrivateHeaderMismatches()
{
    std::vector<PrivateHeaderMismatchCandidate> candidates;

    for (const PrivateExecutableAllocation& allocation : EnumeratePrivateExecutableAllocations())
    {
        PrivateHeaderMismatchCandidate candidate = {};
        if (TryFindHeaderMismatch(allocation, candidate))
        {
            candidates.push_back(std::move(candidate));
        }
    }

    return candidates;
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

PrivatePeImageMechanism::PrivatePeImageMechanism()
{
    CaptureBaseline();
}

std::wstring_view PrivatePeImageMechanism::Id() const noexcept
{
    return L"memory.private_pe_image";
}

std::wstring_view PrivatePeImageMechanism::Name() const noexcept
{
    return L"Private PE-like image";
}

std::wstring_view PrivatePeImageMechanism::Category() const noexcept
{
    return L"Memory";
}

std::wstring_view PrivatePeImageMechanism::Description() const noexcept
{
    return L"Looks for MEM_PRIVATE allocations that still resemble an in-memory PE image.";
}

DetectionResult PrivatePeImageMechanism::Run()
{
    for (const PrivatePeImageCandidate& candidate : EnumeratePrivatePeLikeImages())
    {
        if (baseline_allocation_bases_.find(candidate.allocation_base) == baseline_allocation_bases_.end())
        {
            return DetectionResult::Detected(L"private PE image at " +
                                             HexAddress(candidate.allocation_base) +
                                             L", image size " +
                                             HexAddress(candidate.size_of_image) +
                                             L", " +
                                             std::to_wstring(candidate.section_count) +
                                             L" section(s), " +
                                             ProtectionText(candidate.executable_page_protection));
        }
    }

    return DetectionResult::Clean(L"no private PE-like image regions");
}

void PrivatePeImageMechanism::Reset()
{
    CaptureBaseline();
}

void PrivatePeImageMechanism::CaptureBaseline()
{
    baseline_allocation_bases_.clear();

    for (const PrivatePeImageCandidate& candidate : EnumeratePrivatePeLikeImages())
    {
        baseline_allocation_bases_.insert(candidate.allocation_base);
    }
}

PrivateHeaderMismatchMechanism::PrivateHeaderMismatchMechanism()
{
    CaptureBaseline();
}

std::wstring_view PrivateHeaderMismatchMechanism::Id() const noexcept
{
    return L"memory.private_header_mismatch";
}

std::wstring_view PrivateHeaderMismatchMechanism::Name() const noexcept
{
    return L"Private header mismatch";
}

std::wstring_view PrivateHeaderMismatchMechanism::Category() const noexcept
{
    return L"Memory";
}

std::wstring_view PrivateHeaderMismatchMechanism::Description() const noexcept
{
    return L"Compares PE header claims with executable MEM_PRIVATE page protections.";
}

DetectionResult PrivateHeaderMismatchMechanism::Run()
{
    for (const PrivateHeaderMismatchCandidate& candidate : EnumeratePrivateHeaderMismatches())
    {
        if (baseline_allocation_bases_.find(candidate.allocation_base) == baseline_allocation_bases_.end())
        {
            return DetectionResult::Suspicious(candidate.detail +
                                               L"; allocation " +
                                               HexAddress(candidate.allocation_base) +
                                               L", executable page " +
                                               HexAddress(candidate.executable_region) +
                                               L", " +
                                               ProtectionText(candidate.executable_page_protection));
        }
    }

    return DetectionResult::Clean(L"private executable pages match PE header claims");
}

void PrivateHeaderMismatchMechanism::Reset()
{
    CaptureBaseline();
}

void PrivateHeaderMismatchMechanism::CaptureBaseline()
{
    baseline_allocation_bases_.clear();

    for (const PrivateHeaderMismatchCandidate& candidate : EnumeratePrivateHeaderMismatches())
    {
        baseline_allocation_bases_.insert(candidate.allocation_base);
    }
}
}

TARGET_REGISTER_MECHANISM(target::ModuleBaselineMechanism)
TARGET_REGISTER_MECHANISM(target::DllNotificationMechanism)
TARGET_REGISTER_MECHANISM(target::ThreadStartModuleMechanism)
TARGET_REGISTER_MECHANISM(target::PrivateExecutableMemoryMechanism)
TARGET_REGISTER_MECHANISM(target::PrivatePeImageMechanism)
TARGET_REGISTER_MECHANISM(target::PrivateHeaderMismatchMechanism)
