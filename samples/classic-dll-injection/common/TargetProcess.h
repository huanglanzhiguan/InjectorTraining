#pragma once

#include <windows.h>

namespace lab
{
bool FindExistingProcessByImageName(const wchar_t* imageName, DWORD& pid);
}
