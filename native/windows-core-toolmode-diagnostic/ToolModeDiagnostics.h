#pragma once

#include <windows.h>
#include <cstdio>

namespace cfx::compat
{
enum class ToolModePhase
{
    Enter,
    LoaderBefore, LoaderAfter,
    InstancesBefore, InstanceBefore, InstanceResult, InstancesAfter,
    DiscoveryBefore, DiscoveryAfter,
    GlobalParserBefore, GlobalParserAfter,
    CommandMissing, CommandMatched,
    DependenciesBefore, DependenciesResult,
    ToolCastBefore, ToolCastAfter,
    CommandBefore, CommandAfter,
    CommandParserBefore, CommandParserAfter,
    InvokeBefore, InvokeAfter,
    UnknownCommand, RequiredOption, OptionsError,
    Return
};

inline const char* ToolModePhaseName(ToolModePhase phase)
{
    switch (phase)
    {
    case ToolModePhase::Enter: return "enter";
    case ToolModePhase::LoaderBefore: return "loader.before";
    case ToolModePhase::LoaderAfter: return "loader.after";
    case ToolModePhase::InstancesBefore: return "instances.before";
    case ToolModePhase::InstanceBefore: return "instance.before";
    case ToolModePhase::InstanceResult: return "instance.result";
    case ToolModePhase::InstancesAfter: return "instances.after";
    case ToolModePhase::DiscoveryBefore: return "discovery.before";
    case ToolModePhase::DiscoveryAfter: return "discovery.after";
    case ToolModePhase::GlobalParserBefore: return "global-parser.before";
    case ToolModePhase::GlobalParserAfter: return "global-parser.after";
    case ToolModePhase::CommandMissing: return "command.missing";
    case ToolModePhase::CommandMatched: return "command.matched";
    case ToolModePhase::DependenciesBefore: return "dependencies.before";
    case ToolModePhase::DependenciesResult: return "dependencies.result";
    case ToolModePhase::ToolCastBefore: return "tool-cast.before";
    case ToolModePhase::ToolCastAfter: return "tool-cast.after";
    case ToolModePhase::CommandBefore: return "command.before";
    case ToolModePhase::CommandAfter: return "command.after";
    case ToolModePhase::CommandParserBefore: return "command-parser.before";
    case ToolModePhase::CommandParserAfter: return "command-parser.after";
    case ToolModePhase::InvokeBefore: return "invoke.before";
    case ToolModePhase::InvokeAfter: return "invoke.after";
    case ToolModePhase::UnknownCommand: return "command.unknown";
    case ToolModePhase::RequiredOption: return "exception.required-option";
    case ToolModePhase::OptionsError: return "exception.options-error";
    case ToolModePhase::Return: return "return";
    }
    return nullptr;
}

inline void TraceToolMode(ToolModePhase phase, bool value = false)
{
#ifdef CFX_CORE_TOOLMODE_DIAGNOSTICS
    const auto savedError = GetLastError();
    const char* name = ToolModePhaseName(phase);
    if (name)
    {
        char line[128];
        std::snprintf(line, sizeof(line), "[CFX_TOOLMODE] pid=%lu phase=%s value=%u\n",
                      GetCurrentProcessId(), name, static_cast<unsigned>(value));
        OutputDebugStringA(line);
    }
    SetLastError(savedError);
#endif
}

inline bool TraceToolModeResult(ToolModePhase phase, bool value)
{
    TraceToolMode(phase, value);
    return value;
}
}
