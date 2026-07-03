#pragma once

#include <windows.h>

namespace lab
{
bool InjectDllWithLoadLibraryRemoteThread(DWORD targetPid, const wchar_t* dllPath);
}

