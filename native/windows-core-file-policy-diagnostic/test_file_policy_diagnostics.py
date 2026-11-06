"""Compile the actual own header and check reversible overlays without Wine."""
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SPEC = importlib.util.spec_from_file_location('own_file_policy_builder_under_test', HERE / 'build.py')
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


class FilePolicyDiagnosticsTests(unittest.TestCase):
    def run_header(self, enabled):
        with tempfile.TemporaryDirectory(prefix='cfx-own-file-policy-') as directory:
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
#include <FilePolicyDiagnostics.h>
static unsigned long lastError = 123;
static int predicates, getErrors, setErrors, getPids, outputs;
static std::string output;
unsigned long GetLastError() { ++getErrors; return lastError; }
void SetLastError(unsigned long value) { ++setErrors; lastError = value; }
unsigned long GetCurrentProcessId() { ++getPids; lastError = 888; return 42; }
void OutputDebugStringA(const char* value) { ++outputs; output += value; lastError = 999; }
static bool check(cfx::compat::MappingFileOperation operation, std::wstring_view path, bool original)
{
    const int before = predicates;
    auto result = cfx::compat::TraceMappingFilePolicy(operation, path, [&]() {
        ++predicates;
        lastError = 707;
        return original;
    }());
    static_assert(std::is_same_v<decltype(result), bool>);
    return result == original && predicates == before + 1 && lastError == 707;
}
int main()
{
    using Operation = cfx::compat::MappingFileOperation;
    if (!check(Operation::Create, LR"(\??\C:\Program Files\Rockstar Games\Social Club\socialclub.dll)", true)) return 1;
    if (!check(Operation::Open, LR"(\??\C:\program files\rockstar games\social club\SOCIALCLUB.DLL)", false)) return 2;
    if (!check(Operation::Open, LR"(Z:\own\socialclub.dll)", false)) return 3;
    if (!check(Operation::Create, LR"(C:\Program Files\Rockstar Games\Social Club\socialclub.dll)", false)) return 4;
    if (!check(Operation::Open, L"socialclub.dll", true)) return 5;
    if (!check(Operation::Create, L"Z:/Program Files/Rockstar Games/Social Club/socialclub.dll", true)) return 6;
    if (!check(Operation::Open, LR"(C:\Program FILES\Rockstar Games\Social Club\SocialClub.DlL)", true)) return 7;
    if (!check(Operation::Open, LR"(C:\Program Fİles\Rockstar Games\Social Club\socialclub.dll)", false)) return 8;
    if (!check(Operation::Create, LR"(Z:\own\socialclub.dll.extra)", false)) return 9;
    if (!check(Operation::Open, LR"(Z:\own\SocialClubHelper.exe)", true)) return 10;
    if (!check(Operation::Open, LR"(Z:\own\socialclub.dll\child)", false)) return 11;
    if (!check(Operation::Create, LR"(Z:\own\mysocialclub.dll)", true)) return 12;
    if (!check(static_cast<Operation>(999), L"socialclub.dll", false)) return 13;
    if (predicates != 13) return 14;
#ifdef CFX_CORE_MAPPING_DIAGNOSTICS
    const std::string expected = R"([CFX_MAPPING_FILE] pid=42 operation=create allowed=1 canonical_fragment=1 folded_fragment=1 nt_prefix=1
[CFX_MAPPING_FILE] pid=42 operation=open allowed=0 canonical_fragment=0 folded_fragment=1 nt_prefix=1
[CFX_MAPPING_FILE] pid=42 operation=open allowed=0 canonical_fragment=0 folded_fragment=0 nt_prefix=0
[CFX_MAPPING_FILE] pid=42 operation=create allowed=0 canonical_fragment=1 folded_fragment=1 nt_prefix=0
[CFX_MAPPING_FILE] pid=42 operation=open allowed=1 canonical_fragment=0 folded_fragment=0 nt_prefix=0
[CFX_MAPPING_FILE] pid=42 operation=create allowed=1 canonical_fragment=0 folded_fragment=0 nt_prefix=0
[CFX_MAPPING_FILE] pid=42 operation=open allowed=1 canonical_fragment=0 folded_fragment=1 nt_prefix=0
[CFX_MAPPING_FILE] pid=42 operation=open allowed=0 canonical_fragment=0 folded_fragment=0 nt_prefix=0
)";
    if (output != expected || getErrors != 13 || setErrors != 13 || getPids != 8 || outputs != 8) return 15;
    for (const char* forbidden : {"Z:", "C:", "own", "Rockstar", "socialclub", "Program", "PRIVATE"})
        if (output.find(forbidden) != std::string::npos) return 16;
#else
    if (!output.empty() || getErrors || setErrors || getPids || outputs) return 17;
#endif
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

    def test_enabled_header_exact_private_free_fields_and_original_predicate_contract(self):
        self.run_header(True)

    def test_disabled_header_preserves_boolean_and_error_without_winapi_calls(self):
        self.run_header(False)

    def test_overlay_removes_to_exact_pinned_v6_bytes(self):
        original = (ROOT / builder.BASE_MAPPING).read_bytes()
        self.assertEqual(hashlib.sha256(original).hexdigest(), builder.BASE_MAPPING_SHA)
        overlay = builder.wrap_mapping(original)
        self.assertEqual(builder.strip_mapping(overlay), original)
        self.assertEqual(overlay.count(builder.INCLUDE), 1)
        self.assertEqual(overlay.count(b'cfx::compat::TraceMappingFilePolicy('), 2)

    def test_only_two_original_predicates_are_wrapped_and_hook_tls_code_unchanged(self):
        original = (ROOT / builder.BASE_MAPPING).read_bytes()
        overlay = builder.wrap_mapping(original)
        self.assertEqual(overlay.count(builder.PREDICATE), original.count(builder.PREDICATE))
        for unchanged in (b'cfx::compat::TraceMappingHook(', b'GetTls()', b'tls->inOpenFile',
                          b'tls->inCreateFile', b'MapRedirectedNtFilename('):
            self.assertEqual(overlay.count(unchanged), original.count(unchanged))
        for start, end, operation in builder.FUNCTIONS:
            _, _, before = builder._section(original, start, end)
            _, _, after = builder._section(overlay, start, end)
            self.assertEqual(after.replace(builder.WRAPPERS[operation], builder.PREDICATE), before)

    def test_changed_target_inventory_or_operation_is_rejected(self):
        original = (ROOT / builder.BASE_MAPPING).read_bytes()
        for changed in (original.replace(b'NTSTATUS WINAPI NtOpenFileStub(', b'NTSTATUS WINAPI OtherStub(', 1),
                        original.replace(b'\t\tif (IsMappedFilename(moduleNameStr))\r\n', b'\t\tif (true)\r\n', 1),
                        original.replace(builder.ANCHOR, b'', 1), original + builder.INCLUDE):
            with self.subTest(changed_bytes=len(changed)), self.assertRaises(RuntimeError):
                builder.wrap_mapping(changed)
        overlay = builder.wrap_mapping(original)
        with self.assertRaises(RuntimeError):
            builder.strip_mapping(overlay.replace(b'MappingFileOperation::Create,', b'MappingFileOperation::Open,', 1))

    def test_cmake_and_existing_hook_header_are_reused_with_exact_pins(self):
        for name, expected in ((builder.BASE_CMAKE, builder.BASE_CMAKE_SHA),
                               (builder.BASE_HEADER, builder.BASE_HEADER_SHA)):
            self.assertEqual(hashlib.sha256((ROOT / name).read_bytes()).hexdigest(), expected)
        cmake = (ROOT / builder.BASE_CMAKE).read_bytes()
        self.assertEqual(cmake.count(b'list(APPEND coreSources "${CMAKE_CURRENT_SOURCE_DIR}/FileMapping.Win32.cpp")'), 1)
        self.assertIn(b'"${CFX_SOURCE_DIR}/code/client/citicore"', cmake)


if __name__ == '__main__':
    unittest.main()
