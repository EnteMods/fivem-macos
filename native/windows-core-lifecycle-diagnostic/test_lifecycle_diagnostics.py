"""Native doubles exercise only the public InitMHWrapper bodies; no Wine or CRT-runtime claim."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
spec = importlib.util.spec_from_file_location('own_lifecycle_builder', HERE / 'build.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class LifecycleTests(unittest.TestCase):
    def native(self, enabled):
        original = (ROOT / builder.ORIGINAL).read_bytes()
        wrapped = builder.wrap_seh(original)
        body = wrapped[wrapped.index(b'struct InitMHWrapper'):wrapped.index(b'InitMHWrapper mh;')].decode()
        with tempfile.TemporaryDirectory(prefix='cfx-lifecycle-own-') as temporary:
            folder = Path(temporary)
            (folder / 'windows.h').write_text('''#pragma once
using DWORD = unsigned int;
DWORD GetLastError(); void SetLastError(DWORD); DWORD GetCurrentProcessId();
DWORD GetCurrentThreadId(); void OutputDebugStringA(const char*);
''')
            code = r'''
#include <string>
#include <cerrno>
#include "LifecycleDiagnostics.h"
static unsigned int error = 11, queries = 0, outputs = 0, initCount = 0, finiCount = 0;
static std::string text;
unsigned int GetLastError() { ++queries; return error; }
void SetLastError(unsigned int value) { error = value; }
unsigned int GetCurrentProcessId() { error=999; errno=999; return 4294967295u; }
unsigned int GetCurrentThreadId() { error=998; errno=998; return 77; }
void OutputDebugStringA(const char* value) { ++outputs; text += value; error=997; errno=997; }
int MH_Initialize() { ++initCount; if(error!=11 || errno!=12) return 99; error=21; errno=22; return 1; }
int MH_Uninitialize() { ++finiCount; if(error!=31 || errno!=32) return 99; error=41; errno=42; return 0; }
''' + body + r'''
int main() {
 errno=12;
 { InitMHWrapper own; if(error!=21 || errno!=22 || initCount!=1) return 1; error=31; errno=32; }
 if(error!=41 || errno!=42 || finiCount!=1) return 2;
#ifdef CFX_CORE_LIFECYCLE_DIAGNOSTICS
 const std::string expected = "[CFX_CORE_MH] pid=4294967295 tid=77 phase=1 status_valid=0 status=-1\n"
  "[CFX_CORE_MH] pid=4294967295 tid=77 phase=2 status_valid=1 status=1\n"
  "[CFX_CORE_MH] pid=4294967295 tid=77 phase=3 status_valid=0 status=-1\n"
  "[CFX_CORE_MH] pid=4294967295 tid=77 phase=4 status_valid=1 status=0\n";
 if(text!=expected || queries!=4 || outputs!=4) return 3;
 text.clear();
 cfx::compat::TraceCoreMH(2,true,99);
 cfx::compat::TraceCoreMH(4,true,-99);
 if(text!="[CFX_CORE_MH] pid=4294967295 tid=77 phase=2 status_valid=1 status=-1\n"
          "[CFX_CORE_MH] pid=4294967295 tid=77 phase=4 status_valid=1 status=-1\n") return 4;
#else
 if(!text.empty() || queries || outputs) return 5;
#endif
 if(error!=41 || errno!=42) return 6;
 return 0;
}
'''
            source = folder / 'test.cpp'
            source.write_text(code)
            command = ['/usr/bin/clang++', '-std=c++17', '-Wall', '-Wextra', '-Werror', '-I', str(folder),
                       '-I', str(HERE), str(source), '-o', str(folder / 'test')]
            if enabled:
                command.insert(1, '-DCFX_CORE_LIFECYCLE_DIAGNOSTICS')
            compiled = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            tested = subprocess.run([str(folder / 'test')], capture_output=True, text=True)
            self.assertEqual(tested.returncode, 0, tested.stdout + tested.stderr)

    def test_native_enabled_preserves_call_counts_error_states_and_fixed_fields(self):
        self.native(True)

    def test_native_disabled_performs_no_logging_or_query_calls(self):
        self.native(False)

    def test_original_source_and_v8_cmake_recover_exactly(self):
        original = (ROOT / builder.ORIGINAL).read_bytes()
        wrapped = builder.wrap_seh(original)
        self.assertEqual(builder.strip_seh(wrapped), original)
        self.assertEqual(wrapped.count(b'TraceCoreMH('), 4)
        for call in (b'MH_Initialize()', b'MH_Uninitialize()'):
            self.assertEqual(wrapped.count(call), original.count(call))
        cmake = (ROOT / builder.BASE / 'CMakeLists.txt').read_bytes()
        self.assertEqual(builder.strip_cmake(builder.wrap_cmake(cmake)), cmake)
        with self.assertRaises(RuntimeError): builder.wrap_seh(wrapped)
        with self.assertRaises(RuntimeError): builder.wrap_seh(original.replace(b'MH_Uninitialize();', b'ChangedCall();'))
        with self.assertRaises(RuntimeError): builder.strip_seh(wrapped + b'cfx::compat::TraceCoreMH(1,false,-1);')


if __name__ == '__main__':
    unittest.main()
