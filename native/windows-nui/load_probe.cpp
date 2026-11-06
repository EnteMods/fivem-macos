#include <windows.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <include/cef_api_hash.h>
#include <include/cef_version.h>

static HMODULE Load(const wchar_t* path, const char* label)
{
    const auto module = LoadLibraryExW(path, nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!module)
    {
        std::printf("NUI_LOAD_FAILED module=%s error=%lu\n", label, GetLastError());
    }
    else
    {
        std::printf("NUI_MODULE_LOADED module=%s\n", label);
    }
    std::fflush(stdout);
    return module;
}

int main()
{
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    wchar_t root[32768] = {};
    const auto length = GetCurrentDirectoryW(32768, root);
    if (!length || length >= 32768) return 20;
    const std::wstring directory(root);
    SetDllDirectoryW((directory + L"\\bin").c_str());
    const auto core = Load((directory + L"\\CoreRT.dll").c_str(), "CoreRT.dll");
    if (!core) return 21;
    const auto cef = Load((directory + L"\\bin\\libcef.dll").c_str(), "bin/libcef.dll");
    if (!cef) return 22;
#if CEF_VERSION_MAJOR == 103
    using ApiHash = const char*(__cdecl*)(int);
    const auto hash = reinterpret_cast<ApiHash>(GetProcAddress(cef, "cef_api_hash"));
    if (!hash) return 23;
    const auto actual = hash(0);
    const auto universal = hash(1);
    if (!actual || std::strcmp(actual, CEF_API_HASH_PLATFORM) ||
        !universal || std::strcmp(universal, CEF_API_HASH_UNIVERSAL)) return 24;
    std::printf("NUI_CEF_API_MATCH version=%d hash=%s\n", CEF_VERSION_MAJOR, actual);
#else
    using ApiHash = const char*(__cdecl*)(int, int);
    const auto hash = reinterpret_cast<ApiHash>(GetProcAddress(cef, "cef_api_hash"));
    if (!hash) return 23;
    const auto actual = hash(CEF_API_VERSION, 0);
    if (!actual || std::strcmp(actual, CEF_API_HASH_PLATFORM)) return 24;
    std::printf("NUI_CEF_API_MATCH version=%d hash=%s\n", CEF_API_VERSION, actual);
#endif
    std::fflush(stdout);
    const auto nui = Load((directory + L"\\nui-core.dll").c_str(), "nui-core.dll");
    if (!nui) return 25;
    if (!GetProcAddress(nui, "CreateComponent")) return 26;
    const auto resource = FindResourceA(nui, "FXCOMPONENT", MAKEINTRESOURCEA(115));
    if (!resource) return 27;
    const auto resource_size = SizeofResource(nui, resource);
    const auto resource_handle = LoadResource(nui, resource);
    const auto bytes = resource_handle ? static_cast<const char*>(LockResource(resource_handle)) : nullptr;
    if (!bytes || !resource_size) return 28;
    const std::string manifest(bytes, resource_size);
    if (manifest.find("nui:core") == std::string::npos || manifest.find("legitimacy") == std::string::npos) return 29;
    std::printf("NUI_LOAD_PROBE_OK manifest_bytes=%lu original_vendor_imports=1 component_created=0 preinit_called=0 browser_initialized=0\n", resource_size);
    std::fflush(stdout);
    return 0;
}
