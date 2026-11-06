#pragma once

#include <windows.h>
#include <cstdio>
#include <string_view>

namespace cfx::compat
{
enum class MappingFileOperation { Create, Open };

inline wchar_t FoldMappingAscii(wchar_t character)
{
    return (character >= L'A' && character <= L'Z') ? character + (L'a' - L'A') : character;
}

inline bool ContainsFoldedMappingFragment(std::wstring_view requested, std::wstring_view fragment)
{
    if (requested.size() < fragment.size()) return false;
    for (size_t start = 0; start <= requested.size() - fragment.size(); ++start)
    {
        size_t index = 0;
        while (index < fragment.size() &&
               FoldMappingAscii(requested[start + index]) == FoldMappingAscii(fragment[index])) ++index;
        if (index == fragment.size()) return true;
    }
    return false;
}

inline bool TraceMappingFilePolicy(MappingFileOperation operation, std::wstring_view requested, bool allowed)
{
#ifdef CFX_CORE_MAPPING_DIAGNOSTICS
    const auto savedError = GetLastError();
    constexpr std::wstring_view filename = L"socialclub.dll";
    constexpr std::wstring_view fragment = L"Files\\Rockstar Games\\Social Club";
    const auto separator = requested.find_last_of(L"\\/");
    const auto basename = requested.substr(separator == std::wstring_view::npos ? 0 : separator + 1);
    bool matches = basename.size() == filename.size();
    for (size_t index = 0; matches && index < filename.size(); ++index)
        matches = FoldMappingAscii(basename[index]) == filename[index];
    const char* operationName = operation == MappingFileOperation::Create ? "create" :
                                operation == MappingFileOperation::Open ? "open" : nullptr;
    if (matches && operationName)
    {
        const bool canonical = requested.find(fragment) != std::wstring_view::npos;
        const bool folded = ContainsFoldedMappingFragment(requested, fragment);
        const bool ntPrefix = requested.size() >= 4 && requested.substr(0, 4) == L"\\??\\";
        char line[192];
        std::snprintf(line, sizeof(line),
                      "[CFX_MAPPING_FILE] pid=%lu operation=%s allowed=%u canonical_fragment=%u folded_fragment=%u nt_prefix=%u\n",
                      GetCurrentProcessId(), operationName, static_cast<unsigned>(allowed),
                      static_cast<unsigned>(canonical), static_cast<unsigned>(folded), static_cast<unsigned>(ntPrefix));
        OutputDebugStringA(line);
    }
    SetLastError(savedError);
#endif
    return allowed;
}
}
