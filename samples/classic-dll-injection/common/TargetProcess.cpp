#include "TargetProcess.h"

#include "Handle.h"
#include "Win32Helpers.h"

#include <tlhelp32.h>

#include <cstdio>
#include <vector>

namespace lab
{
bool FindExistingProcessByImageName(const wchar_t* imageName, DWORD& pid)
{
    pid = 0;

    UniqueHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snapshot.valid())
    {
        PrintLastError(L"CreateToolhelp32Snapshot");
        return false;
    }

    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(entry);

    if (!Process32FirstW(snapshot.get(), &entry))
    {
        PrintLastError(L"Process32FirstW");
        return false;
    }

    DWORD matchCount = 0;
    do
    {
        if (_wcsicmp(entry.szExeFile, imageName) == 0)
        {
            ++matchCount;
            if (pid == 0)
            {
                pid = entry.th32ProcessID;
            }

            wprintf(L"Found %s PID %lu\n", imageName, entry.th32ProcessID);
        }
    } while (Process32NextW(snapshot.get(), &entry));

    if (pid == 0)
    {
        wprintf(L"No %s process found. Start the target process, then run the injector again.\n", imageName);
        return false;
    }

    if (matchCount > 1)
    {
        wprintf(L"Multiple %s processes found. Using PID %lu for this beginner lab.\n", imageName, pid);
    }

    wprintf(L"Using %s PID %lu\n", imageName, pid);
    return true;
}

std::vector<DWORD> EnumerateThreadIdsForProcess(DWORD pid)
{
    std::vector<DWORD> threadIds;

    UniqueHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
    if (!snapshot.valid())
    {
        PrintLastError(L"CreateToolhelp32Snapshot(threads)");
        return threadIds;
    }

    THREADENTRY32 entry = {};
    entry.dwSize = sizeof(entry);

    if (!Thread32First(snapshot.get(), &entry))
    {
        PrintLastError(L"Thread32First");
        return threadIds;
    }

    do
    {
        if (entry.th32OwnerProcessID == pid)
        {
            threadIds.push_back(entry.th32ThreadID);
        }
    } while (Thread32Next(snapshot.get(), &entry));

    return threadIds;
}
}
