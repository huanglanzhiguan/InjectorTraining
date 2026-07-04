#pragma once

#include <cstdint>

namespace lab
{
bool ResolveNtdllSymbolRva(const char* symbolName, std::uintptr_t& rva);
}
