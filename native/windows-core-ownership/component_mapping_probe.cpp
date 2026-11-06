#include <windows.h>

#include <cstdio>
#include <cstring>
#include <cwchar>
#include <string>
#include <string_view>

static constexpr unsigned long SourceMarker = 0x46585231;
static constexpr unsigned long TargetMarker = 0x46585232;

static std::wstring sourcePath;
static std::wstring targetPath;
static volatile LONG matchingCount;
static unsigned mode;

static void Emit(unsigned phase, unsigned long marker, LONG hits)
{
    std::printf("OWN_COMPONENT_MAPPING phase=%u pid=%lu mode=%u marker=0x%08lx hits=%ld\n",
        phase, GetCurrentProcessId(), mode, marker, hits);
}

static wchar_t* MapOwnFixture(const wchar_t* name, void* (*allocator)(size_t))
{
    const wchar_t* comparison = name;
    if (std::wcsncmp(comparison, L"\\??\\", 4) == 0)
    {
        comparison += 4;
    }
    const bool match = _wcsicmp(comparison, sourcePath.c_str()) == 0;
    if (match)
    {
        InterlockedIncrement(&matchingCount);
    }
    const wchar_t* result = match ? targetPath.c_str() : name;
    const auto bytes = (std::wcslen(result) + 1) * sizeof(wchar_t);
    auto copy = static_cast<wchar_t*>(allocator(bytes));
    if (!copy)
    {
        ExitProcess(90);
    }
    std::memcpy(copy, result, bytes);
    return copy;
}

static unsigned long LoadOwnMarker(unsigned phase, bool expectMapping)
{
    const auto before = matchingCount;
    const auto module = LoadLibraryW(sourcePath.c_str());
    if (!module)
    {
        ExitProcess(91);
    }
    const auto marker = reinterpret_cast<unsigned long (*)()>(GetProcAddress(module, "MappingMarker"));
    if (!marker)
    {
        ExitProcess(92);
    }
    const auto value = marker();
    const auto hits = matchingCount - before;
    Emit(phase, value, hits);
    if (!FreeLibrary(module))
    {
        ExitProcess(93);
    }
    if (GetModuleHandleW(L"ownership-source.exe") || GetModuleHandleW(L"ownership-target.dll"))
    {
        ExitProcess(94);
    }
    if ((expectMapping && hits <= 0) || (!expectMapping && hits != 0))
    {
        ExitProcess(95);
    }
    return value;
}

int wmain(int argc, wchar_t** argv)
{
    if (argc != 2 || (std::wcscmp(argv[1], L"--baseline") != 0 && std::wcscmp(argv[1], L"--fixed") != 0))
    {
        return 2;
    }
    mode = std::wcscmp(argv[1], L"--fixed") == 0;
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    if (!GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "wine_get_version"))
    {
        return 3;
    }

    wchar_t ownPath[32768];
    const auto length = GetModuleFileNameW(nullptr, ownPath, _countof(ownPath));
    if (!length || length >= _countof(ownPath))
    {
        return 4;
    }
    const auto separator = std::wcsrchr(ownPath, L'\\');
    if (!separator)
    {
        return 5;
    }
    const std::wstring directory(ownPath, separator - ownPath + 1);
    sourcePath = directory + L"ownership-source.exe";
    targetPath = directory + L"ownership-target.dll";
    if (LoadOwnMarker(1, false) != SourceMarker)
    {
        ExitProcess(6);
    }

    const auto core = LoadLibraryW((directory + L"CoreRT.dll").c_str());
    if (!core)
    {
        ExitProcess(7);
    }
    using Mapping = wchar_t* (*)(const wchar_t*, void* (*)(size_t));
    const auto setup = reinterpret_cast<void (*)(Mapping)>(GetProcAddress(core, "CoreSetMappingFunction"));
    const auto get = reinterpret_cast<void* (*)()>(GetProcAddress(core, "?GetInstance@ComponentLoader@@SA@XZ"));
    // The Windows x64 member-call ABI passes this before the public string_view argument.
    const auto initialize = reinterpret_cast<void (*)(void*, std::string_view)>(GetProcAddress(core,
        "?InitializeWithString@ComponentLoader@@QEAAXV?$basic_string_view@DU?$char_traits@D@std@@@std@@@Z"));
    if (!setup || !get || !initialize)
    {
        ExitProcess(8);
    }
    setup(&MapOwnFixture);
    if (LoadOwnMarker(2, true) != TargetMarker)
    {
        ExitProcess(9);
    }

    const auto loader = get();
    if (!loader)
    {
        ExitProcess(10);
    }
    Emit(3, 0, matchingCount);
    initialize(loader, R"(["windows-fixture"])");
    if (!GetModuleHandleW(L"windows-fixture.dll"))
    {
        ExitProcess(11);
    }
    Emit(4, 0, matchingCount);
    const auto value = LoadOwnMarker(5, mode != 0);
    const auto expected = mode ? TargetMarker : SourceMarker;
    if (value != expected)
    {
        ExitProcess(12);
    }
    Emit(6, value, matchingCount);
    ExitProcess(0);
}
