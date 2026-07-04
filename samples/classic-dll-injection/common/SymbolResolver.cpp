#include "SymbolResolver.h"

#include "Handle.h"
#include "Win32Helpers.h"

#include <windows.h>
#include <dbghelp.h>
#include <urlmon.h>

#include <cstdio>
#include <cwchar>
#include <mutex>
#include <string>

namespace lab
{
namespace
{
// Modern PE CodeView debug records start with the ASCII bytes "RSDS".
// Interpreted as a little-endian DWORD, those bytes become 0x53445352.
constexpr DWORD kCodeViewRsdsSignature = 0x53445352;

struct CodeViewRsdsInfo
{
    DWORD signature = 0;
    GUID guid = {};
    DWORD age = 0;
    char pdb_file_name[1] = {};
};

struct PdbIdentity
{
    std::wstring file_name;
    std::wstring guid_age;
};

std::mutex g_dbghelpMutex;

bool ExtractNtdllPdbIdentity(HMODULE module, PdbIdentity& identity)
{
    identity = {};

    const auto* base = reinterpret_cast<const unsigned char*>(module);
    const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        wprintf(L"Loaded ntdll.dll has an invalid DOS header.\n");
        return false;
    }

    const auto* ntHeaders =
        reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        wprintf(L"Loaded ntdll.dll has an invalid NT header.\n");
        return false;
    }

    const IMAGE_DATA_DIRECTORY& debugDirectory =
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    if (debugDirectory.VirtualAddress == 0 ||
        debugDirectory.Size < sizeof(IMAGE_DEBUG_DIRECTORY))
    {
        wprintf(L"Loaded ntdll.dll does not expose CodeView debug data.\n");
        return false;
    }

    const auto* debugEntries =
        reinterpret_cast<const IMAGE_DEBUG_DIRECTORY*>(base + debugDirectory.VirtualAddress);
    const DWORD debugEntryCount =
        debugDirectory.Size / static_cast<DWORD>(sizeof(IMAGE_DEBUG_DIRECTORY));

    const CodeViewRsdsInfo* rsds = nullptr;
    for (DWORD index = 0; index < debugEntryCount; ++index)
    {
        if (debugEntries[index].Type != IMAGE_DEBUG_TYPE_CODEVIEW ||
            debugEntries[index].AddressOfRawData == 0)
        {
            continue;
        }

        const auto* candidate =
            reinterpret_cast<const CodeViewRsdsInfo*>(base + debugEntries[index].AddressOfRawData);
        if (candidate->signature == kCodeViewRsdsSignature)
        {
            rsds = candidate;
            break;
        }
    }

    if (rsds == nullptr)
    {
        wprintf(L"Loaded ntdll.dll does not contain an RSDS CodeView record.\n");
        return false;
    }

    wchar_t guidText[64] = {};
    if (StringFromGUID2(rsds->guid, guidText, _countof(guidText)) == 0)
    {
        PrintLastError(L"StringFromGUID2");
        return false;
    }

    for (const wchar_t* current = guidText; *current != L'\0'; ++current)
    {
        if ((*current >= L'0' && *current <= L'9') ||
            (*current >= L'A' && *current <= L'F') ||
            (*current >= L'a' && *current <= L'f'))
        {
            identity.guid_age += *current;
        }
    }
    identity.guid_age += std::to_wstring(rsds->age);

    const int fileNameLength =
        MultiByteToWideChar(CP_UTF8, 0, rsds->pdb_file_name, -1, nullptr, 0);
    if (fileNameLength <= 1)
    {
        wprintf(L"Failed to convert PDB file name from the RSDS record.\n");
        return false;
    }

    std::wstring convertedFileName(fileNameLength, L'\0');
    MultiByteToWideChar(CP_UTF8,
                        0,
                        rsds->pdb_file_name,
                        -1,
                        &convertedFileName[0],
                        fileNameLength);
    identity.file_name.assign(convertedFileName.c_str());

    const std::size_t slash = identity.file_name.find_last_of(L"\\/");
    if (slash != std::wstring::npos)
    {
        identity.file_name.erase(0, slash + 1);
    }

    wprintf(L"ntdll CodeView record: %s\\%s\\%s\n",
            identity.file_name.c_str(),
            identity.guid_age.c_str(),
            identity.file_name.c_str());
    return true;
}

bool EnsureDirectoryExists(const std::wstring& path)
{
    if (CreateDirectoryW(path.c_str(), nullptr))
    {
        return true;
    }

    if (GetLastError() == ERROR_ALREADY_EXISTS)
    {
        return true;
    }

    wprintf(L"CreateDirectoryW(%s) failed. GetLastError() = %lu\n",
            path.c_str(),
            GetLastError());
    return false;
}

bool BuildPdbCachePath(const PdbIdentity& identity, std::wstring& pdbPath)
{
    wchar_t root[MAX_PATH] = {};
    const DWORD length = GetFullPathNameW(L".symbols", _countof(root), root, nullptr);
    if (length == 0 || length >= _countof(root))
    {
        PrintLastError(L"GetFullPathNameW(.symbols)");
        return false;
    }

    std::wstring rootPath = root;
    if (!EnsureDirectoryExists(rootPath))
    {
        return false;
    }

    std::wstring pdbDirectory = rootPath + L"\\" + identity.file_name;
    if (!EnsureDirectoryExists(pdbDirectory))
    {
        return false;
    }

    pdbDirectory += L"\\" + identity.guid_age;
    if (!EnsureDirectoryExists(pdbDirectory))
    {
        return false;
    }

    pdbPath = pdbDirectory + L"\\" + identity.file_name;
    return true;
}

bool EnsurePdbDownloaded(const PdbIdentity& identity, const std::wstring& pdbPath)
{
    WIN32_FILE_ATTRIBUTE_DATA attributes = {};
    if (GetFileAttributesExW(pdbPath.c_str(), GetFileExInfoStandard, &attributes))
    {
        return true;
    }

    std::wstring url = L"https://msdl.microsoft.com/download/symbols/";
    url += identity.file_name;
    url += L"/";
    url += identity.guid_age;
    url += L"/";
    url += identity.file_name;

    wprintf(L"Downloading %s\n", url.c_str());
    const HRESULT hr = URLDownloadToFileW(nullptr, url.c_str(), pdbPath.c_str(), 0, nullptr);
    if (FAILED(hr))
    {
        wprintf(L"URLDownloadToFileW failed. HRESULT = 0x%08lX\n",
                static_cast<unsigned long>(hr));
        return false;
    }

    return true;
}

bool GetFileSizeForSymbolLoad(const std::wstring& path, DWORD& fileSize)
{
    WIN32_FILE_ATTRIBUTE_DATA attributes = {};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &attributes))
    {
        wprintf(L"GetFileAttributesExW(%s) failed. GetLastError() = %lu\n",
                path.c_str(),
                GetLastError());
        return false;
    }

    if (attributes.nFileSizeHigh != 0)
    {
        wprintf(L"PDB is larger than this beginner resolver expects.\n");
        return false;
    }

    fileSize = attributes.nFileSizeLow;
    return true;
}
}

bool ResolveNtdllSymbolRva(const char* symbolName, std::uintptr_t& rva)
{
    rva = 0;

    if (symbolName == nullptr || symbolName[0] == '\0')
    {
        wprintf(L"ResolveNtdllSymbolRva received an empty symbol name.\n");
        return false;
    }

    std::lock_guard<std::mutex> lock(g_dbghelpMutex);

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
    {
        PrintLastError(L"GetModuleHandleW(ntdll.dll)");
        return false;
    }

    PdbIdentity identity;
    if (!ExtractNtdllPdbIdentity(ntdll, identity))
    {
        return false;
    }

    std::wstring pdbPath;
    if (!BuildPdbCachePath(identity, pdbPath))
    {
        return false;
    }

    if (!EnsurePdbDownloaded(identity, pdbPath))
    {
        return false;
    }

    DWORD pdbFileSize = 0;
    if (!GetFileSizeForSymbolLoad(pdbPath, pdbFileSize))
    {
        return false;
    }

    UniqueHandle dbghelpProcess(
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId()));
    if (!dbghelpProcess.valid())
    {
        PrintLastError(L"OpenProcess(current process for DbgHelp)");
        return false;
    }

    SymSetOptions(SYMOPT_UNDNAME |
                  SYMOPT_DEFERRED_LOADS |
                  SYMOPT_AUTO_PUBLICS |
                  SYMOPT_FAIL_CRITICAL_ERRORS |
                  SYMOPT_EXACT_SYMBOLS);

    if (!SymInitializeW(dbghelpProcess.get(), nullptr, FALSE))
    {
        PrintLastError(L"SymInitializeW");
        return false;
    }

    const DWORD64 loadedBase =
        SymLoadModuleExW(dbghelpProcess.get(),
                         nullptr,
                         pdbPath.c_str(),
                         L"ntdll",
                         0x10000000,
                         pdbFileSize,
                         nullptr,
                         0);
    if (loadedBase == 0)
    {
        PrintLastError(L"SymLoadModuleExW(ntdll.pdb)");
        SymCleanup(dbghelpProcess.get());
        return false;
    }

    SYMBOL_INFO_PACKAGE symbol = {};
    symbol.si.SizeOfStruct = sizeof(SYMBOL_INFO);
    symbol.si.MaxNameLen = MAX_SYM_NAME;

    bool found = SymFromName(dbghelpProcess.get(), symbolName, &symbol.si) == TRUE;
    std::string qualifiedName;
    if (!found)
    {
        qualifiedName = "ntdll!";
        qualifiedName += symbolName;
        found = SymFromName(dbghelpProcess.get(), qualifiedName.c_str(), &symbol.si) == TRUE;
    }

    if (!found)
    {
        wprintf(L"SymFromName(%S) failed. GetLastError() = %lu\n",
                symbolName,
                GetLastError());
        SymUnloadModule64(dbghelpProcess.get(), loadedBase);
        SymCleanup(dbghelpProcess.get());
        return false;
    }

    rva = static_cast<std::uintptr_t>(symbol.si.Address - symbol.si.ModBase);
    wprintf(L"Resolved ntdll!%S from %s at RVA 0x%Ix.\n",
            symbolName,
            identity.file_name.c_str(),
            rva);

    SymUnloadModule64(dbghelpProcess.get(), loadedBase);
    SymCleanup(dbghelpProcess.get());
    return true;
}
}
