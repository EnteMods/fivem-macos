import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
HEADER_DIR = ROOT / "port/fivem/code/client/shared"


class StartupPhaseTraceTests(unittest.TestCase):
    def _run(self, enabled):
        with tempfile.TemporaryDirectory(prefix="cfx-public-phase-test-") as directory:
            path = pathlib.Path(directory)
            (path / "windows.h").write_text("""
#pragma once
unsigned long GetLastError();
void SetLastError(unsigned long);
unsigned long GetCurrentProcessId();
unsigned long GetCurrentThreadId();
void OutputDebugStringA(const char*);
""")
            (path / "test.cpp").write_text(r'''
#include <string>
#include <StartupPhaseTrace.h>
static unsigned long lastError = 0;
static std::string output;
unsigned long GetLastError() { return lastError; }
void SetLastError(unsigned long error) { lastError = error; }
unsigned long GetCurrentProcessId() { return 42; }
unsigned long GetCurrentThreadId() { return 7; }
void OutputDebugStringA(const char* text) { output += text; lastError = 9999; }
int main()
{
    lastError = 123;
    CfxSourceStartupPhase("fixed.phase", 88);
    if (lastError != 123) return 1;
    CfxSourceStartupComponentPhase("fixed.component", "nui:core\nC:/private? \xc3\xbc");
    if (lastError != 123) return 2;
#ifdef CFX_SOURCE_STARTUP_DIAGNOSTICS
    const std::string expected =
        "[CFX_SOURCE_PHASE] pid=42 tid=7 phase=fixed.phase value=88\n"
        "[CFX_SOURCE_COMPONENT] pid=42 tid=7 phase=fixed.component component=nui:core_C:_private____\n";
    if (output != expected) return 3;
    output.clear();
    const std::string longName(300, 'x');
    CfxSourceStartupComponentPhase("fixed.bounded", longName.c_str());
    if (output != "[CFX_SOURCE_COMPONENT] pid=42 tid=7 phase=fixed.bounded component=" + std::string(96, 'x') + "\n") return 4;
    if (lastError != 123) return 5;
#else
    if (!output.empty()) return 6;
#endif
}
''')
            command = ["/usr/bin/clang++", "-std=c++17", "-I", str(path), "-I", str(HEADER_DIR),
                       str(path / "test.cpp"), "-o", str(path / "trace-test")]
            if enabled:
                command.insert(1, "-DCFX_SOURCE_STARTUP_DIAGNOSTICS")
            subprocess.run(command, check=True, capture_output=True, text=True)
            result = subprocess.run([str(path / "trace-test")], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_component_names_are_bounded_sanitized_and_last_error_is_preserved(self):
        self._run(True)

    def test_default_build_emits_nothing(self):
        self._run(False)


if __name__ == "__main__":
    unittest.main()
