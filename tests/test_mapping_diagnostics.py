"""Compile the real mapping trace header with own test-only WinAPI functions; no Wine."""
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
INCLUDE = ROOT / 'port/fivem/code/client/citicore'


class MappingDiagnosticsTests(unittest.TestCase):
    def run_header(self, enabled):
        with tempfile.TemporaryDirectory(prefix='cfx-mapping-trace-') as directory:
            path = pathlib.Path(directory)
            (path / 'windows.h').write_text('''#pragma once
unsigned long GetLastError();
void SetLastError(unsigned long);
unsigned long GetCurrentProcessId();
void OutputDebugStringA(const char*);
''')
            (path / 'test.cpp').write_text(r'''
#include <string>
#include <MappingDiagnostics.h>
static unsigned long error = 123;
static std::string output;
unsigned long GetLastError() { return error; }
void SetLastError(unsigned long value) { error = value; }
unsigned long GetCurrentProcessId() { return 42; }
void OutputDebugStringA(const char* value) { output += value; error = 999; }
int main()
{
    using namespace cfx::compat;
    TraceMappingProvider("setup.enter", false);
    TraceSocialClubMapping("ldr.enter", LR"(Z:\own\SOCIALCLUB.DLL)", {}, true);
    TraceSocialClubMapping("provider.after", LR"(Z:\own\socialclub.dll)", LR"(Z:\own\target.dll)", true, true);
    TraceSocialClubMapping("provider.same", LR"(Z:\own\socialclub.dll)", LR"(Z:\own\socialclub.dll)", true, true);
    TraceSocialClubMapping("ignored", LR"(Z:\own\socialclub.dll.extra)", {}, true);
    TraceSocialClubMapping("ignored", LR"(Z:\own\SocialClubHelper.exe)", {}, true);
    TraceSocialClubMapping("ignored", LR"(Z:\own\socialclub.dll\child)", {}, true);
    if (error != 123) return 1;
#ifdef CFX_CORE_MAPPING_DIAGNOSTICS
    const std::string expected = R"([CFX_MAPPING] pid=42 phase=setup.enter provider_set=0 provider_called=0 return_changed=0
[CFX_MAPPING] pid=42 phase=ldr.enter provider_set=1 provider_called=0 return_changed=0
[CFX_MAPPING] pid=42 phase=provider.after provider_set=1 provider_called=1 return_changed=1
[CFX_MAPPING] pid=42 phase=provider.same provider_set=1 provider_called=1 return_changed=0
)";
    if (output != expected) return 2;
    if (output.find("own") != std::string::npos || output.find("target.dll") != std::string::npos) return 3;
#else
    if (!output.empty()) return 4;
#endif
}
''')
            source = path / 'test.cpp'
            source.write_text(source.read_text().replace('\\\\n', '\\n'))
            command = ['/usr/bin/clang++', '-std=c++17', '-I', str(path), '-I', str(INCLUDE),
                       str(source), '-o', str(path / 'header-test')]
            if enabled:
                command.insert(1, '-DCFX_CORE_MAPPING_DIAGNOSTICS')
            compiled = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            result = subprocess.run([str(path / 'header-test')], capture_output=True)
            self.assertEqual(result.returncode, 0)

    def test_opt_in_exact_filename_fixed_fields_and_last_error(self):
        self.run_header(True)

    def test_default_off_emits_nothing(self):
        self.run_header(False)


if __name__ == '__main__':
    unittest.main()
