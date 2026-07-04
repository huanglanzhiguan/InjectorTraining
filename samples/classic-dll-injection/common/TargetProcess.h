#pragma once

#include <windows.h>

#include <vector>

namespace lab
{
bool FindExistingProcessByImageName(const wchar_t* imageName, DWORD& pid);
std::vector<DWORD> EnumerateThreadIdsForProcess(DWORD pid);
}
