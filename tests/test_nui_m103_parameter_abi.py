from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'native/windows-nui'))
import build_m103
import prepare_cef

LLVM = Path('/opt/homebrew/opt/llvm/bin')
CLANG = LLVM / 'clang-cl'
OBJDUMP = LLVM / 'llvm-objdump'
MSVC = ROOT / 'toolchains/msvc-2022'
SDK = MSVC / 'Windows Kits/10/Include/10.0.26100.0'
HEADERS = [MSVC / 'VC/Tools/MSVC/14.44.35207/include',
           *(SDK / name for name in ('ucrt', 'shared', 'um', 'winrt'))]
ARCHIVE = ROOT / 'downloads/cef' / (build_m103.CEF_BUILD + '.zip')

FIXTURE = '''
#include "include/base/cef_scoped_refptr.h"

struct Factory
{
    void AddRef() const;
    void Release() const;
};

extern "C" __declspec(dllexport) Factory* Receive(void*, void*, scoped_refptr<Factory> factory)
{
    return factory.get();
}
'''


@unittest.skipUnless(all(path.exists() for path in (CLANG, OBJDUMP, ARCHIVE, *HEADERS)),
                     'Windows x64 Clang toolchain and the official CEF 103 package are required')
class NuiM103ParameterAbiTest(unittest.TestCase):
    def test_stock_msvc_caller_passes_scoped_refptr_by_address(self):
        self.assertEqual(prepare_cef.sha(ARCHIVE), build_m103.CEF_SHA256)
        with tempfile.TemporaryDirectory() as folder:
            workspace = Path(folder)
            cef = workspace / 'cef'
            with patch.object(prepare_cef, 'ROOT', workspace):
                prepare_cef.extract_build_inputs(ARCHIVE, cef, build_m103.CEF_BUILD, {})
            source = workspace / 'parameter.cpp'
            source.write_text(FIXTURE)

            original = self.compile_and_disassemble(source, cef)
            build_m103.use_stock_msvc_parameter_abi(cef)
            adapted = self.compile_and_disassemble(source, cef)

        direct = r'\bmov\s+r\w+,\s*r8\s*$'
        indirect = r'\bmov\s+r\w+,\s*qword ptr \[r8\]'
        self.assertRegex(original, r'(?m)' + direct)
        self.assertNotRegex(original, indirect)
        self.assertRegex(adapted, indirect)

    def compile_and_disassemble(self, source, cef):
        obj = source.with_suffix('.obj')
        compile_result = subprocess.run([
            str(CLANG), '--target=x86_64-pc-windows-msvc', '/nologo', '/c', '/O2',
            '/std:c++17', '/EHsc', '/Zc:__cplusplus', *(f'/I{path}' for path in [cef, *HEADERS]),
            f'/Fo{obj}', str(source),
        ], capture_output=True, text=True, timeout=30)
        self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
        disassembly = subprocess.check_output([
            str(OBJDUMP), '-d', '--x86-asm-syntax=intel', '--disassemble-symbols=Receive', str(obj),
        ], text=True, timeout=10)
        self.assertIn('<Receive>:', disassembly)
        return disassembly
