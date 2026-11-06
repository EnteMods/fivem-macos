"""Native execution of the real header and original/overlay ToolMode, without Wine."""
import hashlib
import importlib.util
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SPEC = importlib.util.spec_from_file_location('own_toolmode_builder_under_test', HERE / 'build.py')
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)

WINDOWS = '''#pragma once
unsigned long GetLastError();
void SetLastError(unsigned long);
unsigned long GetCurrentProcessId();
void OutputDebugStringA(const char*);
const wchar_t* GetCommandLine();
'''

STDINC = r'''#pragma once
#include <windows.h>
#include <cstdio>
#include <vector>
#include <string>
#include <map>
#include <set>
#include <functional>
#include <cassert>
#define DLL_EXPORT
#define CORE_EXPORT
#define EXPORTED_TYPE
struct fwRefCountable { virtual ~fwRefCountable() = default; };
template<class T> struct fwRefContainer {
    T* pointer = nullptr;
    fwRefContainer() = default;
    fwRefContainer(T* value) : pointer(value) {}
    T* GetRef() const { return pointer; }
    T* operator->() const { return pointer; }
};
template<class T, class U> T dynamic_component_cast(U* value) { return dynamic_cast<T>(value); }
struct OwnConfiguration {
    bool missing = false, unknown = false, dependency_result = true;
    int global_error = 0, command_error = 0;
    bool invoke_exit = false;
};
extern OwnConfiguration configuration;
extern unsigned long lastError;
extern int loaderCalls, initializeCalls, manualCalls, namesCalls, commandCalls;
extern int setupCalls, invokeCalls, parserRuns, stores, dependencyReads;
'''

COMPONENT_LOADER = r'''#pragma once
#include "StdInc.h"
class Component : public fwRefCountable {
public:
    virtual bool Initialize() { ++initializeCalls; lastError = 201; return configuration.dependency_result; }
};
class ComponentData : public fwRefCountable {
public:
    std::vector<fwRefContainer<Component>> instances;
    std::vector<fwRefContainer<ComponentData>> dependencies;
    std::string name;
    auto& GetInstances() { return instances; }
    const auto& GetDependencyDataList() { ++dependencyReads; return dependencies; }
    const std::string& GetName() { return name; }
    fwRefContainer<Component> CreateManualInstance() { ++manualCalls; lastError = 202; return instances[0]; }
};
class ComponentLoader {
public:
    std::vector<fwRefContainer<ComponentData>> components;
    static ComponentLoader* GetInstance();
    void Initialize() { ++loaderCalls; lastError = 200; }
    template<class Callback> void ForAllComponents(Callback cb) {
        for (auto component : components) cb(component);
    }
};
'''

BOOST = r'''#pragma once
#include <exception>
#include <type_traits>
#include "StdInc.h"
namespace boost::program_options {
struct error : std::exception { const char* what() const noexcept override { return "PRIVATE_OPTION_ERROR"; } };
struct required_option : error {};
struct value_semantic {};
template<class T> value_semantic* value() { static value_semantic v; return &v; }
template<class T> value_semantic* wvalue() { return value<T>(); }
struct options_description {
    explicit options_description(const char*) {}
    struct adder {
        adder& operator()(const char*, value_semantic*, const char*) { return *this; }
    };
    adder add_options() { return {}; }
};
struct positional_options_description {
    positional_options_description& add(const char*, int) { return *this; }
};
struct variable_value {
    template<class T> T as() const {
        static_assert(std::is_same_v<T, std::string>);
        return configuration.unknown ? "PRIVATE_UNKNOWN_COMMAND" : "own-fixture";
    }
};
using variables_map = std::map<std::string, variable_value>;
struct wparsed_options { std::vector<int> options; bool global = false; };
struct wcommand_line_parser {
    bool global = false;
    explicit wcommand_line_parser(const std::vector<std::wstring>&) {}
    wcommand_line_parser& options(const options_description&) { global = true; return *this; }
    wcommand_line_parser& positional(const positional_options_description&) { return *this; }
    wcommand_line_parser& allow_unregistered() { return *this; }
    wparsed_options run() {
        ++parserRuns; lastError = 205;
        if (global && configuration.global_error == 1) throw required_option();
        if (global && configuration.global_error == 2) throw error();
        return {{}, global};
    }
};
inline void store(const wparsed_options& options, variables_map& vars) {
    ++stores; lastError = 206;
    if (options.global && !configuration.missing) vars["command"] = {};
}
inline std::vector<std::wstring> split_winmain(const wchar_t*) {
    return {L"own-fixture.exe", L"PRIVATE_COMMAND_ARGUMENT"};
}
enum { include_positional = 1 };
inline std::vector<std::wstring> collect_unrecognized(const std::vector<int>&, int) {
    return {L"own-fixture", L"PRIVATE_RESOURCE_ARGUMENT"};
}
}
'''

DRIVER = r'''
#include "ToolMode.Win32.cpp"
#include <string>
#include <iostream>
OwnConfiguration configuration;
unsigned long lastError = 101;
int loaderCalls, initializeCalls, manualCalls, namesCalls, commandCalls;
int setupCalls, invokeCalls, parserRuns, stores, dependencyReads;
static std::string diagnosticOutput;
unsigned long GetLastError() { return lastError; }
void SetLastError(unsigned long value) { lastError = value; }
unsigned long GetCurrentProcessId() { lastError = 888; return 42; }
void OutputDebugStringA(const char* value) { diagnosticOutput += value; lastError = 999; }
const wchar_t* GetCommandLine() { lastError = 203; return L"PRIVATE_COMMAND_LINE"; }
static ComponentLoader loader;
ComponentLoader* ComponentLoader::GetInstance() { return &loader; }
struct OwnExit { int status; };
struct Command : ToolCommand {
    void SetupCommandLineParser(boost::program_options::wcommand_line_parser& parser,
                                std::function<void(boost::program_options::wcommand_line_parser&)> callback) override {
        ++setupCalls; lastError = 207;
        if (configuration.command_error == 1) throw boost::program_options::required_option();
        if (configuration.command_error == 2) throw boost::program_options::error();
        callback(parser);
    }
    void InvokeCommand(const boost::program_options::variables_map&) override {
        ++invokeCalls; lastError = 208;
        if (configuration.invoke_exit) throw OwnExit{1};
    }
};
static Command command;
struct Tool : Component, ToolComponent {
    std::vector<std::string> GetCommandNames() override {
        ++namesCalls; lastError = 204; return {"own-fixture"};
    }
    fwRefContainer<ToolCommand> GetCommand(const std::string&) override {
        ++commandCalls; lastError = 209; return &command;
    }
};
int main(int argc, char** argv) {
    const int mode = argc > 1 ? std::stoi(argv[1]) : 0;
    configuration.missing = mode == 1;
    configuration.unknown = mode == 2;
    configuration.dependency_result = mode != 3;
    configuration.global_error = mode == 4 ? 1 : mode == 5 ? 2 : 0;
    configuration.command_error = mode == 6 ? 1 : mode == 7 ? 2 : 0;
    configuration.invoke_exit = mode == 8;
    Tool tool;
    Component dependency;
    ComponentData toolData, dependencyData;
    toolData.name = "PRIVATE_COMPONENT";
    dependencyData.name = "PRIVATE_DEPENDENCY";
    toolData.instances = {&tool};
    dependencyData.instances = {&dependency};
    toolData.dependencies = {&dependencyData};
    loader.components = {&toolData, &dependencyData};
    int outcome = 0;
    try { ToolMode_Init(); }
    catch (const OwnExit& exit) { outcome = exit.status; }
    std::cout << "OWN_RESULT mode=" << mode << " outcome=" << outcome << " error=" << lastError
              << " loader=" << loaderCalls << " initialize=" << initializeCalls
              << " manual=" << manualCalls << " names=" << namesCalls << " command=" << commandCalls
              << " setup=" << setupCalls << " invoke=" << invokeCalls << " parsers=" << parserRuns
              << " stores=" << stores << " dependencies=" << dependencyReads << '\n';
    std::cout << diagnosticOutput;
}
'''


class ToolModeDiagnosticsTests(unittest.TestCase):
    def compile(self, directory, source, *, enabled=False, real_toolmode=False):
        folder = Path(directory)
        (folder / 'windows.h').write_text(WINDOWS)
        command = ['/usr/bin/clang++', '-std=c++17', '-I', str(folder), '-I', str(HERE)]
        if enabled:
            command.append('-DCFX_CORE_TOOLMODE_DIAGNOSTICS')
        if real_toolmode:
            command.extend(['-DCOMPILING_CORE', '-I', str(ROOT / 'port/fivem/code/client/citicore')])
            (folder / 'StdInc.h').write_text(STDINC)
            (folder / 'ComponentLoader.h').write_text(COMPONENT_LOADER)
            (folder / 'boost').mkdir()
            (folder / 'boost/program_options.hpp').write_text(BOOST)
            (folder / 'ToolMode.Win32.cpp').write_bytes(source)
            source = DRIVER
        (folder / 'test.cpp').write_text(source)
        command.extend([str(folder / 'test.cpp'), '-o', str(folder / 'own-test')])
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return folder / 'own-test'

    def run_header(self, enabled):
        source = r'''
#include <ToolModeDiagnostics.h>
#include <string>
#include <type_traits>
static unsigned long error = 123;
static int getErrors, sets, pids, outputs, expressions;
static std::string diagnosticLog;
unsigned long GetLastError() { ++getErrors; return error; }
void SetLastError(unsigned long value) { ++sets; error = value; }
unsigned long GetCurrentProcessId() { ++pids; error = 888; return 42; }
void OutputDebugStringA(const char* value) { ++outputs; diagnosticLog += value; error = 999; }
int main() {
    using namespace cfx::compat;
    for (int original = 0; original != 2; ++original) {
        auto result = TraceToolModeResult(ToolModePhase::DependenciesResult, [&]() {
            ++expressions; error = 707; return original != 0;
        }());
        static_assert(std::is_same_v<decltype(result), bool>);
        if (result != (original != 0) || error != 707) return 1;
    }
    if (expressions != 2) return 2;
    TraceToolMode(ToolModePhase::InvokeBefore);
    TraceToolMode(static_cast<ToolModePhase>(999), true);
    if (error != 707) return 3;
#ifdef CFX_CORE_TOOLMODE_DIAGNOSTICS
    if (getErrors != 4 || sets != 4 || outputs != 3 || pids != 3) return 4;
    if (diagnosticLog != "[CFX_TOOLMODE] pid=42 phase=dependencies.result value=0\n"
               "[CFX_TOOLMODE] pid=42 phase=dependencies.result value=1\n"
               "[CFX_TOOLMODE] pid=42 phase=invoke.before value=0\n") return 5;
#else
    if (getErrors || sets || pids || outputs || !diagnosticLog.empty()) return 6;
#endif
}
'''
        with tempfile.TemporaryDirectory(prefix='cfx-own-toolmode-header-') as temp:
            binary = self.compile(temp, source, enabled=enabled)
            result = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_enabled_header_preserves_last_error_bool_and_single_evaluation(self):
        self.run_header(True)

    def test_disabled_header_makes_no_winapi_calls(self):
        self.run_header(False)

    def test_toolmode_and_cmake_strip_to_exact_pinned_inputs(self):
        original = (ROOT / builder.ORIGINAL).read_bytes()
        cmake = (ROOT / builder.BASE_CMAKE).read_bytes()
        self.assertEqual(hashlib.sha256(original).hexdigest(), builder.ORIGINAL_SHA)
        self.assertEqual(hashlib.sha256(cmake).hexdigest(), builder.BASE_FILES['CMakeLists.txt'])
        self.assertEqual(builder.strip_toolmode(builder.wrap_toolmode(original)), original)
        self.assertEqual(builder.strip_cmake(builder.wrap_cmake(cmake)), cmake)

    def test_original_invocations_conditions_catches_and_arguments_are_unchanged(self):
        original = (ROOT / builder.ORIGINAL).read_bytes()
        overlay = builder.wrap_toolmode(original)
        for call in (b'instance->Initialize()', b'componentLoader->Initialize()', b'CreateManualInstance()',
                     b'GetCommandNames()', b'initDeps(componentData)', b'globalVars.find("command")',
                     b'it != toolCommands.end()', b'tool->GetCommand(command)', b'SetupCommandLineParser(parser,',
                     b'commandImpl->InvokeCommand(vm)', b'e.what()', b'GetCommandLine()', b'GetInstances()[0]'):
            self.assertEqual(overlay.count(call), original.count(call), call)
        self.assertIn(builder.wrap_result(b'initDeps(componentData)', 'DependenciesResult') + b';', overlay)
        self.assertNotIn(b'if (' + builder.wrap_result(b'initDeps(componentData)', 'DependenciesResult'), overlay)
        self.assertEqual(overlay.count(b'catch ('), original.count(b'catch ('))

    def test_changed_expression_or_diagnostic_inventory_is_rejected(self):
        original = (ROOT / builder.ORIGINAL).read_bytes()
        for before in (builder.ANCHOR, b'commandImpl->InvokeCommand(vm)', b'it != toolCommands.end()'):
            with self.subTest(before=before), self.assertRaises(RuntimeError):
                builder.wrap_toolmode(original.replace(before, b'UNEXPECTED', 1))
        overlay = builder.wrap_toolmode(original)
        with self.assertRaises(RuntimeError):
            builder.strip_toolmode(overlay.replace(b'ToolModePhase::InvokeAfter', b'ToolModePhase::InvokeBefore', 1))
        with self.assertRaises(RuntimeError):
            builder.strip_toolmode(overlay + b'cfx::compat::Unexpected();\r\n')

    def test_header_has_only_fixed_phase_and_bool_payload_inputs(self):
        header = (HERE / 'ToolModeDiagnostics.h').read_text()
        phases = builder.toolmode_phase_names()
        self.assertEqual(len(phases), 27)
        self.assertEqual(len(phases), len(set(phases)))
        self.assertIn('TraceToolMode(ToolModePhase phase, bool value = false)', header)
        self.assertIn('[CFX_TOOLMODE] pid=%lu phase=%s value=%u\\n', header)
        self.assertEqual(header.count('OutputDebugStringA('), 1)
        for forbidden in ('GetCommandLine', 'GetModule', 'GetProcAddress', 'LoadLibrary', 'CreateFile',
                          'what()', 'ToolComponent', 'std::string', 'const wchar_t*', 'const void*'):
            self.assertNotIn(forbidden, header)

    def test_real_original_and_overlay_toolmode_match_across_nine_own_lifecycle_cases(self):
        original = (ROOT / builder.ORIGINAL).read_bytes()
        with tempfile.TemporaryDirectory(prefix='cfx-own-toolmode-body-') as temp:
            temp = Path(temp)
            binaries = []
            for name, source, enabled in (('original', original, False),
                                          ('diagnostics-off', builder.wrap_toolmode(original), False),
                                          ('diagnostics-on', builder.wrap_toolmode(original), True)):
                folder = temp / name
                folder.mkdir()
                binaries.append(self.compile(folder, source, enabled=enabled, real_toolmode=True))
            for mode in range(9):
                with self.subTest(mode=mode):
                    outputs = []
                    for binary in binaries:
                        result = subprocess.run([str(binary), str(mode)], capture_output=True, text=True)
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                        lines = result.stdout.splitlines()
                        metadata = [line for line in lines if line.startswith('OWN_RESULT ')]
                        self.assertEqual(len(metadata), 1)
                        outputs.append((metadata[0], [line for line in lines if line.startswith('[CFX_TOOLMODE]')]))
                    self.assertEqual(outputs[0][0], outputs[1][0])
                    self.assertEqual(outputs[0][0], outputs[2][0])
                    self.assertFalse(outputs[0][1])
                    self.assertFalse(outputs[1][1])
                    events = outputs[2][1]
                    self.assertTrue(events)
                    for event in events:
                        self.assertRegex(event, r'^\[CFX_TOOLMODE\] pid=42 phase=[a-z.-]+ value=[01]$')
                        self.assertNotIn('PRIVATE', event)
                    joined = '\n'.join(events)
                    if mode in (0, 3, 8):
                        self.assertIn('phase=invoke.before', joined)
                        self.assertEqual('phase=invoke.after' in joined, mode != 8)
                        self.assertIn('invoke=1', outputs[2][0])
                    if mode == 3:
                        self.assertIn('phase=dependencies.result value=0', joined)
                    if mode in (4, 6):
                        self.assertIn('phase=exception.required-option', joined)
                    if mode in (5, 7):
                        self.assertIn('phase=exception.options-error', joined)

    def test_v7_mapping_hooks_and_policies_are_exact_independent_inputs(self):
        for name, digest in builder.BASE_FILES.items():
            path = ROOT / 'build/windows-core-file-policy-diagnostic/overlay' / name
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
        cmake = builder.wrap_cmake((ROOT / builder.BASE_CMAKE).read_bytes())
        self.assertEqual(cmake.count(b'list(APPEND coreSources "${CMAKE_CURRENT_SOURCE_DIR}/ToolMode.Win32.cpp")'), 1)
        self.assertEqual(cmake.count(b'list(APPEND coreSources "${CMAKE_CURRENT_SOURCE_DIR}/FileMapping.Win32.cpp")'), 1)
        self.assertIn(b'option(CFX_CORE_TOOLMODE_DIAGNOSTICS "Emit fixed-field public ToolMode diagnostics" OFF)', cmake)


if __name__ == '__main__':
    unittest.main()
