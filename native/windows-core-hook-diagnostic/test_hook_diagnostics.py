"""Compile the own status header and verify reversible source overlays; no Wine."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SPEC = importlib.util.spec_from_file_location('own_hook_build_under_test', HERE / 'build.py')
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


class HookDiagnosticsTests(unittest.TestCase):
    def run_header(self, enabled):
        with tempfile.TemporaryDirectory(prefix='cfx-own-hook-trace-') as directory:
            folder = Path(directory)
            (folder / 'windows.h').write_text('''#pragma once
unsigned long GetLastError();
void SetLastError(unsigned long);
unsigned long GetCurrentProcessId();
void OutputDebugStringA(const char*);
''')
            (folder / 'test.cpp').write_text(r'''
#include <string>
#include <type_traits>
#include <HookDiagnostics.h>
static unsigned long lastError = 123;
static int invocations = 0;
static int getErrorCalls = 0;
static int setErrorCalls = 0;
static int getPidCalls = 0;
static int outputCalls = 0;
static std::string output;
unsigned long GetLastError() { ++getErrorCalls; return lastError; }
void SetLastError(unsigned long value) { ++setErrorCalls; lastError = value; }
unsigned long GetCurrentProcessId() { ++getPidCalls; lastError = 888; return 42; }
void OutputDebugStringA(const char* value) { ++outputCalls; output += value; lastError = 999; }
enum class OwnStatus : int { Value = 8 };
int main()
{
    using namespace cfx::compat;
    auto status = TraceMappingHook(MappingHookPhase::NtOpenFile, [&]() {
        ++invocations;
        if (lastError != 123) return static_cast<OwnStatus>(99);
        lastError = 707;
        return OwnStatus::Value;
    });
    static_assert(std::is_same_v<decltype(status), OwnStatus>);
    if (status != OwnStatus::Value || invocations != 1 || lastError != 707) return 1;
    const int cases[] = {-42, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};
    for (int value : cases)
    {
        const auto returned = TraceMappingHook(MappingHookPhase::EnableAll, [&]() {
            ++invocations;
            if (lastError != 707) return 987;
            return value;
        });
        if (returned != value || lastError != 707) return 2;
    }
    if (invocations != 17) return 3;
#ifdef CFX_CORE_MAPPING_DIAGNOSTICS
    const std::string expected = R"([CFX_MAPPING_HOOK] pid=42 phase=create.ntdll.NtOpenFile status=8
[CFX_MAPPING_HOOK] pid=42 phase=enable.all status=-1
[CFX_MAPPING_HOOK] pid=42 phase=enable.all status=-1
[CFX_MAPPING_HOOK] pid=42 phase=enable.all status=0
[CFX_MAPPING_HOOK] pid=42 phase=enable.all status=1
[CFX_MAPPING_HOOK] pid=42 phase=enable.all status=2
[CFX_MAPPING_HOOK] pid=42 phase=enable.all status=3
[CFX_MAPPING_HOOK] pid=42 phase=enable.all status=4
[CFX_MAPPING_HOOK] pid=42 phase=enable.all status=5
[CFX_MAPPING_HOOK] pid=42 phase=enable.all status=6
[CFX_MAPPING_HOOK] pid=42 phase=enable.all status=7
[CFX_MAPPING_HOOK] pid=42 phase=enable.all status=8
[CFX_MAPPING_HOOK] pid=42 phase=enable.all status=9
[CFX_MAPPING_HOOK] pid=42 phase=enable.all status=10
[CFX_MAPPING_HOOK] pid=42 phase=enable.all status=11
[CFX_MAPPING_HOOK] pid=42 phase=enable.all status=12
[CFX_MAPPING_HOOK] pid=42 phase=enable.all status=-1
)";
    if (output != expected || getErrorCalls != 17 || setErrorCalls != 17 || getPidCalls != 17 || outputCalls != 17) return 4;
#else
    if (!output.empty() || getErrorCalls || setErrorCalls || getPidCalls || outputCalls) return 5;
#endif
    if (std::string(MappingHookPhaseName(static_cast<MappingHookPhase>(999))) != "unknown") return 6;
}
''')
            command = ['/usr/bin/clang++', '-std=c++17', '-I', str(folder), '-I', str(HERE),
                       str(folder / 'test.cpp'), '-o', str(folder / 'own-header-test')]
            if enabled:
                command.insert(1, '-DCFX_CORE_MAPPING_DIAGNOSTICS')
            compiled = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            tested = subprocess.run([str(folder / 'own-header-test')], capture_output=True, text=True)
            self.assertEqual(tested.returncode, 0, tested.stdout + tested.stderr)

    def test_enabled_fixed_status_payload_preserves_original_return_last_error_and_evaluation(self):
        self.run_header(True)

    def test_disabled_no_winapi_or_output_preserves_original_return_last_error_and_evaluation(self):
        self.run_header(False)

    def test_mapping_overlay_reverses_to_exact_v5_bytes(self):
        original = (ROOT / 'port/fivem/code/client/citicore/FileMapping.Win32.cpp').read_bytes()
        overlay = builder.wrap_mapping(original)
        self.assertEqual(builder.strip_mapping(overlay), original)
        self.assertEqual(len(list(builder.WRAPPED_LINE.finditer(overlay))), 21)
        self.assertEqual(overlay.count(builder.HOOK_INCLUDE), 1)
        self.assertEqual(overlay.count(b'MH_CreateHookApi('), original.count(b'MH_CreateHookApi('))
        self.assertEqual(overlay.count(b'MH_EnableHook('), original.count(b'MH_EnableHook('))

    def test_cmake_overlay_changes_only_the_mapping_source_selection(self):
        original = (ROOT / 'native/windows-core/CMakeLists.txt').read_bytes()
        overlay = builder.overlay_cmake(original)
        self.assertEqual(overlay.replace(builder.CMAKE_OVERLAY, b'', 1), original)
        self.assertEqual(overlay.count(builder.CMAKE_ANCHOR), 1)
        self.assertIn(b'"${CFX_SOURCE_DIR}/code/client/citicore"', overlay)

    def test_changed_hook_inventory_and_overlay_are_rejected(self):
        original = (ROOT / 'port/fivem/code/client/citicore/FileMapping.Win32.cpp').read_bytes()
        for changed in (original.replace(b'"NtCreateFile"', b'"UnexpectedApi"', 1),
                        original.replace(b'\tMH_EnableHook(MH_ALL_HOOKS);', b'', 1),
                        original + b'\tMH_EnableHook(MH_ALL_HOOKS);\r\n'):
            with self.subTest(changed_bytes=len(changed)):
                with self.assertRaises(RuntimeError):
                    builder.wrap_mapping(changed)
        overlay = builder.wrap_mapping(original)
        with self.assertRaises(RuntimeError):
            builder.strip_mapping(overlay.replace(b'::NtCreateFile,', b'::NtOpenFile,', 1))


if __name__ == '__main__':
    unittest.main()
