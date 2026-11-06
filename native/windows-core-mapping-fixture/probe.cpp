#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winternl.h>
#include <array>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <string>
#include "role_config.h"

namespace {
using Ldr = NTSTATUS(NTAPI*)(PWSTR, PULONG, PUNICODE_STRING, PHANDLE);
using Create = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
    PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
using Open = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);
using Provider = wchar_t* (*)(const wchar_t*, void* (*)(size_t));
using Mapping = void (*)(Provider);
using Bytes = std::array<unsigned char, 21>;
constexpr DWORD rvas[] = {0x15b50, 0xf420, 0xefe0};
std::array<void*, 3> entries{};
std::array<Bytes, 3> first{}, setup{};
bool firstValid[3]{}, setupValid[3]{};
bool executionSafe[3]{};
HMODULE ntdll = nullptr;
HANDLE selfRead = nullptr;
const wchar_t sourcePath[] = CFX_CORE_OWN_ROOT L"\\Program Files\\Rockstar Games\\Social Club\\socialclub.dll";
const wchar_t targetPath[] = CFX_CORE_OWN_ROOT L"\\Program Files\\Rockstar Games\\Social Club\\mapping-target.dll";
volatile LONG providerCalls = 0, providerHits = 0;
unsigned closeFailures = 0;

DWORD Atomic(volatile LONG& value) { return static_cast<DWORD>(InterlockedCompareExchange(&value, 0, 0)); }
bool TargetsSafe() { return executionSafe[0] && executionSafe[1] && executionSafe[2]; }
bool Same(const std::wstring& a, const std::wstring& b) {
    return CompareStringOrdinal(a.c_str(), -1, b.c_str(), -1, TRUE) == CSTR_EQUAL;
}
bool ModuleAt(HMODULE module, const std::wstring& expected) {
    wchar_t path[32768];
    const DWORD size = module ? GetModuleFileNameW(module, path, 32768) : 0;
    return size && size < 32768 && Same(std::wstring(path, size), expected);
}
wchar_t* MapOwnFixture(const wchar_t* name, void* (*allocator)(size_t)) {
    InterlockedIncrement(&providerCalls);
    const wchar_t* normalized = name;
    if (!std::wcsncmp(normalized, L"\\??\\", 4)) normalized += 4;
    const bool match = !_wcsicmp(normalized, sourcePath);
    if (match) InterlockedIncrement(&providerHits);
    const wchar_t* result = match ? targetPath : normalized;
    const size_t size = (std::wcslen(result) + 1) * sizeof(wchar_t);
    auto copy = static_cast<wchar_t*>(allocator(size));
    if (!copy) ExitProcess(90);
    std::memcpy(copy, result, size);
    return copy;
}
UNICODE_STRING Unicode(std::wstring& value) {
    UNICODE_STRING result{};
    if (value.size() > 32766) return result;
    result.Buffer = value.data();
    result.Length = static_cast<USHORT>(value.size() * sizeof(wchar_t));
    result.MaximumLength = static_cast<USHORT>(result.Length + sizeof(wchar_t));
    return result;
}
bool FileIdentity(HANDLE file, BY_HANDLE_FILE_INFORMATION& identity) {
    return file && file != INVALID_HANDLE_VALUE && GetFileInformationByHandle(file, &identity);
}
bool SameIdentity(const BY_HANDLE_FILE_INFORMATION& a, const BY_HANDLE_FILE_INFORMATION& b) {
    return a.dwVolumeSerialNumber == b.dwVolumeSerialNumber && a.nFileIndexHigh == b.nFileIndexHigh && a.nFileIndexLow == b.nFileIndexLow;
}
bool Remember(const std::wstring& name, BY_HANDLE_FILE_INFORMATION& identity) {
    const HANDLE file = CreateFileW(name.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    const bool identified = FileIdentity(file, identity);
    const bool closed = file && file != INVALID_HANDLE_VALUE && CloseHandle(file);
    if (file && file != INVALID_HANDLE_VALUE && !closed) ++closeFailures;
    return identified && closed;
}
unsigned LocalRead(unsigned api, Bytes& result) {
    const auto pointer = reinterpret_cast<ULONG_PTR>(entries[api]);
    const auto base = reinterpret_cast<ULONG_PTR>(ntdll);
    if (pointer < base + 5 || pointer - base != rvas[api] || pointer - base > 4349952 - 16) return 1;
    const auto start = pointer - 5;
    MEMORY_BASIC_INFORMATION before{}, after{};
    if (VirtualQuery(reinterpret_cast<void*>(start), &before, sizeof(before)) != sizeof(before)) return 2;
    const auto region = reinterpret_cast<ULONG_PTR>(before.BaseAddress);
    const DWORD protection = before.Protect & 0xff;
    const bool executable = protection == PAGE_EXECUTE || protection == PAGE_EXECUTE_READ
        || protection == PAGE_EXECUTE_READWRITE || protection == PAGE_EXECUTE_WRITECOPY;
    if (before.State != MEM_COMMIT || before.Type != MEM_IMAGE || before.AllocationBase != ntdll
        || !executable || (before.Protect & PAGE_GUARD) || start < region
        || start - region > before.RegionSize || 21 > before.RegionSize - (start - region)) return 3;
    std::memcpy(result.data(), reinterpret_cast<void*>(start), result.size());
    if (VirtualQuery(reinterpret_cast<void*>(start), &after, sizeof(after)) != sizeof(after)
        || before.BaseAddress != after.BaseAddress || before.AllocationBase != after.AllocationBase
        || before.RegionSize != after.RegionSize || before.State != after.State || before.Protect != after.Protect
        || before.Type != after.Type || GetModuleHandleW(L"ntdll.dll") != ntdll) return 4;
    return 0;
}
unsigned Jump(const Bytes& value) {
    return value[5] == 0xe9 ? 1 : value[5] == 0xeb && value[6] == 0xf9 && value[0] == 0xe9 ? 2 : 0;
}
bool Snapshot(unsigned phase) {
    bool good = true;
    for (unsigned api = 0; api < 3; ++api) {
        Bytes local{}, remote{}, after{};
        unsigned status = LocalRead(api, local);
        const bool attempted = status == 0;
        SIZE_T count = 0; BOOL ok = FALSE; DWORD error = 0; bool stable = false;
        if (attempted) {
            SetLastError(ERROR_SUCCESS);
            ok = ReadProcessMemory(selfRead, reinterpret_cast<const char*>(entries[api]) - 5, remote.data(), remote.size(), &count);
            error = GetLastError();
            const unsigned later = LocalRead(api, after);
            stable = !later && local == after;
            if (later) status = later; else if (!stable) status = 5;
        }
        const bool known = !status && ok && count == 21 && stable;
        executionSafe[api] = !status && stable;
        const bool equal = known && local == remote;
        if (phase == 0 && known) { first[api] = local; firstValid[api] = true; }
        if (phase == 1 && known) { setup[api] = local; setupValid[api] = true; }
        std::printf("{\"event\":\"sample\",\"phase\":%u,\"api\":%u,\"read_status\":%u,\"equal_first\":%s,"
                    "\"equal_setup\":%s,\"jump_kind\":%u,\"rpm_attempted\":%s,\"rpm_ok\":%s,\"rpm_bytes\":%llu,"
                    "\"rpm_error\":%lu,\"local_stable\":%s,\"rpm_equal_local\":%s,\"provider_calls\":%lu,\"provider_hits\":%lu}\n",
            phase, api + 1, status, !known || !firstValid[api] ? "null" : local == first[api] ? "true" : "false",
            !known || !setupValid[api] ? "null" : local == setup[api] ? "true" : "false", Jump(local),
            attempted ? "true" : "false", ok ? "true" : "false", static_cast<unsigned long long>(count), error,
            stable ? "true" : "false", !known ? "null" : equal ? "true" : "false", Atomic(providerCalls), Atomic(providerHits));
        good = good && equal;
    }
    std::fflush(stdout);
    return good;
}
DWORD Marker(HMODULE module) {
    using Function = DWORD (*)();
    const auto function = reinterpret_cast<Function>(GetProcAddress(module, "MappingMarker"));
    return function ? function() : 0;
}
bool Exercise(unsigned phase, bool mapped, const BY_HANDLE_FILE_INFORMATION& source, const BY_HANDLE_FILE_INFORMATION& target) {
    std::wstring path = std::wstring(L"\\??\\") + sourcePath;
    auto name = Unicode(path);
    OBJECT_ATTRIBUTES attributes{};
    attributes.Length = sizeof(attributes); attributes.ObjectName = &name; attributes.Attributes = 0x40;
    bool all = name.Buffer != nullptr;
    for (unsigned api : {1u, 2u, 0u}) {
        HANDLE handle = nullptr; IO_STATUS_BLOCK io{};
        const DWORD beforeCalls = Atomic(providerCalls), beforeHits = Atomic(providerHits);
        NTSTATUS status;
        const bool attempted = TargetsSafe();
        if (!attempted) status = 0;
        else if (api == 1) status = reinterpret_cast<Create>(entries[api])(&handle, FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            &attributes, &io, nullptr, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 1, 0x60, nullptr, 0);
        else if (api == 2) status = reinterpret_cast<Open>(entries[api])(&handle, FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            &attributes, &io, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0x60);
        else {
            std::wstring dll = sourcePath; auto module = Unicode(dll);
            status = reinterpret_cast<Ldr>(entries[api])(nullptr, nullptr, &module, &handle);
        }
        const DWORD calls = Atomic(providerCalls) - beforeCalls, hits = Atomic(providerHits) - beforeHits;
        bool isSource = false, isTarget = false; DWORD marker = 0;
        const bool valid = handle && handle != INVALID_HANDLE_VALUE;
        if (valid && api != 0) {
            BY_HANDLE_FILE_INFORMATION opened{};
            if (FileIdentity(handle, opened)) { isSource = SameIdentity(source, opened); isTarget = SameIdentity(target, opened); }
        } else if (valid) {
            wchar_t loaded[32768]; const DWORD size = GetModuleFileNameW(reinterpret_cast<HMODULE>(handle), loaded, 32768);
            if (size && size < 32768) { isSource = Same(std::wstring(loaded, size), sourcePath); isTarget = Same(std::wstring(loaded, size), targetPath); }
            marker = Marker(reinterpret_cast<HMODULE>(handle));
        }
        const bool closed = valid && (api == 0 ? FreeLibrary(reinterpret_cast<HMODULE>(handle)) : CloseHandle(handle));
        if (valid && !closed) ++closeFailures;
        char statusText[16];
        if (attempted) std::snprintf(statusText, sizeof(statusText), "%lu", static_cast<DWORD>(status));
        else std::memcpy(statusText, "null", 5);
        std::printf("{\"event\":\"call\",\"phase\":%u,\"api\":%u,\"attempted\":%s,\"status\":%s,\"source_identity\":%s,\"target_identity\":%s,"
                    "\"provider_calls_delta\":%lu,\"provider_hits_delta\":%lu,\"marker\":%lu,\"close_ok\":%s}\n",
            phase, api + 1, attempted ? "true" : "false", statusText, isSource ? "true" : "false", isTarget ? "true" : "false", calls, hits, marker, closed ? "true" : "false");
        all = all && status == 0 && closed && isSource == !mapped && isTarget == mapped
            && (api != 0 || marker == (mapped ? 0x46585232u : 0x46585231u)) && (mapped ? hits > 0 : calls == 0 && hits == 0);
    }
    return all;
}
}

int wmain(int argc, wchar_t** argv) {
    if (argc != 2) return 2;
    const unsigned mode = !std::wcscmp(argv[1], L"--baseline") ? 0 : !std::wcscmp(argv[1], L"--core-load-only") ? 1
        : !std::wcscmp(argv[1], L"--core-mapping") ? 2 : 3;
    if (mode == 3) return 2;
    const std::wstring root = CFX_CORE_OWN_ROOT;
    HMODULE core = nullptr, tbb = nullptr, library = nullptr;
    DWORD coreError = 0, tbbError = 0, exportError = 0;
    bool mapped = false, coreLoaded = mode == 0, safe = true, functional = true;
    unsigned checks = 0;
    SetLastError(ERROR_SUCCESS);
    selfRead = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE, FALSE, GetCurrentProcessId());
    const DWORD selfError = GetLastError();
    const bool selfReal = selfRead && selfRead != GetCurrentProcess() && GetProcessId(selfRead) == GetCurrentProcessId();
    std::printf("{\"event\":\"ready\",\"mode\":%u,\"pid\":%lu,\"self_handle_real\":%s,\"self_handle_error\":%lu}\n",
        mode, GetCurrentProcessId(), selfReal ? "true" : "false", selfError);
    const bool prepared = [&]() {
        wchar_t image[32768]; const DWORD size = GetModuleFileNameW(nullptr, image, 32768);
        if (!selfReal || !size || size >= 32768 || !Same(std::wstring(image, size), root + L"\\core_mapping_fixture.exe")) return false;
        if (GetModuleHandleW(L"CoreRT.dll") || GetModuleHandleW(L"tbb12.dll")) return false;
        ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) return false;
        const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(ntdll);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 || dos->e_lfanew > 4096) return false;
        const auto pe = reinterpret_cast<const IMAGE_NT_HEADERS64*>(reinterpret_cast<const char*>(ntdll) + dos->e_lfanew);
        if (pe->Signature != IMAGE_NT_SIGNATURE || pe->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64
            || pe->OptionalHeader.SizeOfImage != 4349952) return false;
        const char* names[] = {"LdrLoadDll", "NtCreateFile", "NtOpenFile"};
        for (unsigned api = 0; api < 3; ++api) {
            entries[api] = reinterpret_cast<void*>(GetProcAddress(ntdll, names[api]));
            if (reinterpret_cast<ULONG_PTR>(entries[api]) - reinterpret_cast<ULONG_PTR>(ntdll) != rvas[api]) return false;
        }
        return true;
    }();
    BY_HANDLE_FILE_INFORMATION source{}, target{};
    safe = prepared && Remember(sourcePath, source) && Remember(targetPath, target) && !SameIdentity(source, target);
    if (safe) {
        const auto snapshot = [&](unsigned phase) { const bool ok = Snapshot(phase); ++checks; functional = functional && ok; };
        snapshot(0);
        if (mode && TargetsSafe()) {
            SetLastError(ERROR_SUCCESS);
            tbb = LoadLibraryExW((root + L"\\tbb12.dll").c_str(), nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
            tbbError = GetLastError();
            if (ModuleAt(tbb, root + L"\\tbb12.dll")) {
                SetLastError(ERROR_SUCCESS);
                core = LoadLibraryExW((root + L"\\CoreRT.dll").c_str(), nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
                coreError = GetLastError();
            }
            coreLoaded = ModuleAt(core, root + L"\\CoreRT.dll");
            if (coreLoaded && mode == 2) {
                SetLastError(ERROR_SUCCESS);
                const auto mapping = reinterpret_cast<Mapping>(GetProcAddress(core, "CoreSetMappingFunction"));
                exportError = GetLastError();
                if (mapping) { mapping(&MapOwnFixture); mapped = true; }
            }
        }
        std::printf("{\"event\":\"core\",\"mode\":%u,\"tbb_loaded\":%s,\"tbb_error\":%lu,\"core_loaded\":%s,"
                    "\"core_error\":%lu,\"export_error\":%lu,\"mapping_returned\":%s}\n", mode,
            tbb ? "true" : "false", tbbError, core ? "true" : "false", coreError, exportError, mapped ? "true" : "false");
        snapshot(1);
        functional = Exercise(2, mode == 2, source, target) && functional; snapshot(2);
        const bool loadAttempted = TargetsSafe();
        if (loadAttempted) library = LoadLibraryW(sourcePath);
        const DWORD marker = library ? Marker(library) : 0;
        std::printf("{\"event\":\"library\",\"operation\":1,\"attempted\":%s,\"ok\":%s,\"marker\":%lu}\n",
            loadAttempted ? "true" : "false", library ? "true" : "false", marker);
        functional = library && marker == (mode == 2 ? 0x46585232u : 0x46585231u) && functional; snapshot(3);
        Sleep(250); snapshot(4);
        const bool freeAttempted = library != nullptr;
        const bool freed = freeAttempted && FreeLibrary(library);
        if (freed) library = nullptr; else if (library) ++closeFailures;
        std::printf("{\"event\":\"library\",\"operation\":2,\"attempted\":%s,\"ok\":%s,\"marker\":0}\n",
            freeAttempted ? "true" : "false", freed ? "true" : "false");
        functional = functional && freed; snapshot(5);
        snapshot(6);
        functional = Exercise(7, mode == 2, source, target) && functional; snapshot(7);
    }
    if (library && !FreeLibrary(library)) ++closeFailures;
    const bool held = mode == 0 ? !core && !tbb : core && tbb && GetModuleHandleW(L"CoreRT.dll") == core && GetModuleHandleW(L"tbb12.dll") == tbb;
    const bool selfClosed = selfRead && selfRead != GetCurrentProcess() && CloseHandle(selfRead);
    if (selfRead && selfRead != GetCurrentProcess() && !selfClosed) ++closeFailures;
    const int exit = safe && functional && coreLoaded && (mode != 2 || mapped) && held && selfClosed && checks == 8 && !closeFailures ? 0 : 1;
    // Core/TBB remain referenced until process exit: Core registered DLL notifications.
    std::printf("{\"event\":\"completed\",\"mode\":%u,\"checkpoints\":%u,\"core_references_held\":%s,"
                "\"self_handle_closed\":%s,\"close_failures\":%u,\"exit\":%d}\n", mode, checks, held ? "true" : "false", selfClosed ? "true" : "false", closeFailures, exit);
    std::fflush(stdout);
    return exit;
}
