#include "common/TargetProcess.h"
#include "common/Win32Helpers.h"
#include "impl/LoadLibraryRemoteThread.h"

#include <windows.h>

#include <cstdio>

int wmain(int argc, wchar_t** argv)
{
    if (argc != 2)
    {
        wprintf(L"Usage: %s <full-or-relative-path-to-TrainingDll.dll>\n", argv[0]);
        return 1;
    }

    wchar_t dllPath[MAX_PATH] = {};
    if (!lab::GetFullFilePath(argv[1], dllPath, _countof(dllPath)))
    {
        return 1;
    }

    DWORD targetPid = 0;
    if (!lab::FindExistingTargetApp(targetPid))
    {
        return 1;
    }

    if (!lab::InjectDllWithLoadLibraryRemoteThread(targetPid, dllPath))
    {
        return 1;
    }

    return 0;
}
