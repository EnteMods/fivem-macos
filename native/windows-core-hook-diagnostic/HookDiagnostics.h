#pragma once

#include <windows.h>
#include <cstdio>

namespace cfx::compat
{
enum class MappingHookPhase
{
    NtCreateFile,
    NtOpenFile,
    NtDeleteFile,
    NtQueryAttributesFile,
    NtQueryFullAttributesFile,
    NtSetInformationFile,
    LdrLoadDll,
    LdrGetProcedureAddress,
    RtlGetFullPathNameU,
    GetFileVersionInfoSizeW,
    GetFileVersionInfoSizeA,
    GetFileVersionInfoW,
    GetFileVersionInfoA,
    VerQueryValueW,
    RegOpenKeyExW,
    GetFileAttributesExW,
    GetProcAddressForCaller,
    Kernel32CreateThread,
    KernelbaseCreateThread,
    CoUninitialize,
    EnableAll
};

inline const char* MappingHookPhaseName(MappingHookPhase phase)
{
    switch (phase)
    {
        case MappingHookPhase::NtCreateFile: return "create.ntdll.NtCreateFile";
        case MappingHookPhase::NtOpenFile: return "create.ntdll.NtOpenFile";
        case MappingHookPhase::NtDeleteFile: return "create.ntdll.NtDeleteFile";
        case MappingHookPhase::NtQueryAttributesFile: return "create.ntdll.NtQueryAttributesFile";
        case MappingHookPhase::NtQueryFullAttributesFile: return "create.ntdll.NtQueryFullAttributesFile";
        case MappingHookPhase::NtSetInformationFile: return "create.ntdll.NtSetInformationFile";
        case MappingHookPhase::LdrLoadDll: return "create.ntdll.LdrLoadDll";
        case MappingHookPhase::LdrGetProcedureAddress: return "create.ntdll.LdrGetProcedureAddress";
        case MappingHookPhase::RtlGetFullPathNameU: return "create.ntdll.RtlGetFullPathName_U";
        case MappingHookPhase::GetFileVersionInfoSizeW: return "create.version.GetFileVersionInfoSizeW";
        case MappingHookPhase::GetFileVersionInfoSizeA: return "create.version.GetFileVersionInfoSizeA";
        case MappingHookPhase::GetFileVersionInfoW: return "create.version.GetFileVersionInfoW";
        case MappingHookPhase::GetFileVersionInfoA: return "create.version.GetFileVersionInfoA";
        case MappingHookPhase::VerQueryValueW: return "create.version.VerQueryValueW";
        case MappingHookPhase::RegOpenKeyExW: return "create.kernelbase.RegOpenKeyExW";
        case MappingHookPhase::GetFileAttributesExW: return "create.kernelbase.GetFileAttributesExW";
        case MappingHookPhase::GetProcAddressForCaller: return "create.kernelbase.GetProcAddressForCaller";
        case MappingHookPhase::Kernel32CreateThread: return "create.kernel32.CreateThread";
        case MappingHookPhase::KernelbaseCreateThread: return "create.kernelbase.CreateThread";
        case MappingHookPhase::CoUninitialize: return "create.combase.CoUninitialize";
        case MappingHookPhase::EnableAll: return "enable.all";
    }
    return "unknown";
}

inline void TraceMappingHookStatus(MappingHookPhase phase, int status)
{
#ifdef CFX_CORE_MAPPING_DIAGNOSTICS
    const auto savedError = GetLastError();
    const auto boundedStatus = (status >= -1 && status <= 12) ? status : -1;
    char line[192];
    std::snprintf(line, sizeof(line), "[CFX_MAPPING_HOOK] pid=%lu phase=%s status=%d\n",
                  GetCurrentProcessId(), MappingHookPhaseName(phase), boundedStatus);
    OutputDebugStringA(line);
    SetLastError(savedError);
#endif
}

template<typename Operation>
inline auto TraceMappingHook(MappingHookPhase phase, Operation&& operation) -> decltype(operation())
{
    const auto status = operation();
    TraceMappingHookStatus(phase, static_cast<int>(status));
    return status;
}
}
