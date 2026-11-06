"""Pure overlay scope and native own WinAPI doubles; no Wine or desktop queries."""
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import types
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SPEC = importlib.util.spec_from_file_location('graphics_window_overlay', HERE / 'overlay.py')
overlay = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(overlay)


def v11_input():
    path = ROOT / 'native/windows-graphics-diagnostics/overlay.py'
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != '803f754dca4ca4fa1ec432e1ecaf92eeb984e514e223bcd9c28fbd4222a87533':
        raise RuntimeError('Frozen preceding pure overlay changed')
    previous = types.ModuleType('preceding_graphics_overlay')
    exec(compile(raw, str(path), 'exec'), previous.__dict__)
    return previous.apply((ROOT / previous.ORIGINAL).read_bytes())[0]


class WindowOverlayTests(unittest.TestCase):
    def test_roundtrip_exact_v11_and_original_call_diagnostic_order(self):
        original = v11_input()
        patched, proof = overlay.apply(original)
        self.assertEqual(overlay.strip(patched), original)
        self.assertEqual(proof['replacement_count'], 6)
        for call in (overlay._NORMAL, overlay._REVERSE):
            self.assertEqual(patched.count(call), 1)
            self.assertIn(call + overlay._CAPTURE, patched)
        self.assertIn(overlay._NORMAL + overlay._CAPTURE + overlay._NORMAL_METADATA, patched)
        self.assertIn(overlay._REVERSE + overlay._CAPTURE + overlay._REVERSE_METADATA, patched)
        self.assertIn(b'cfxWindowError, cfxWindowStyle, dwExStyle, cfxWindowParentNonnull)', patched)
        self.assertEqual(patched.count(b'if (initState->isReverseGame)'), original.count(b'if (initState->isReverseGame)'))
        self.assertEqual(patched.count(b'CreateSwapChainForHwnd('), original.count(b'CreateSwapChainForHwnd('))
        qi = b'\t\t\t\tswapChain1->QueryInterface(__uuidof(IDXGISwapChain), (void**)ppSwapChain);\r\n'
        self.assertEqual(patched.count(qi), 1)
        self.assertIn(overlay.CHANGES[5][1], patched)
        self.assertIn(b'TraceGraphicsWindowAvailability(ppSwapChain != nullptr);', patched)
        self.assertIn(overlay.CHANGES[4][1], patched)
        self.assertEqual(patched.count(b'\r\n'), patched.count(b'\n'))
        for call in (b'CoreGetGameWindow(', b'FindWindowW('):
            self.assertEqual(patched.count(call), original.count(call))

    def test_changed_input_duplicate_overlay_and_extra_edits_rejected(self):
        original = v11_input();patched, _ = overlay.apply(original)
        for data in (patched, original + b'\n', original.replace(b'CoreSetGameWindow(w)', b'OtherCall(w)')):
            with self.assertRaises(ValueError): overlay.apply(data)
        for data in (original, patched + b'// extra\n', patched.replace(b'cfxWindowError', b'changedError', 1)):
            with self.assertRaises(ValueError): overlay.strip(data)

    def test_native_on_off_ownership_class_liveness_caps_and_error_preservation(self):
        header = (HERE / 'GraphicsWindowDiagnostics.h').read_bytes()
        with tempfile.TemporaryDirectory(prefix='own-graphics-window-') as temporary:
            folder = Path(temporary)
            (folder / 'GraphicsWindowDiagnostics.h').write_bytes(header)
            (folder / 'windows.h').write_text('#pragma once\n#include <cstdint>\n'
                'using DWORD=unsigned int;using BOOL=int;using HWND=void*;using LPARAM=std::intptr_t;\n'
                '#define CALLBACK\n#define TRUE 1\n#define FALSE 0\n'
                'DWORD GetLastError();void SetLastError(DWORD);DWORD GetCurrentProcessId();DWORD GetCurrentThreadId();\n'
                'void OutputDebugStringA(const char*);BOOL EnumWindows(BOOL(*)(HWND,LPARAM),LPARAM);\n'
                'DWORD GetWindowThreadProcessId(HWND,DWORD*);BOOL IsWindow(HWND);int GetClassNameW(HWND,wchar_t*,int);\n')
            source = folder / 'test.cpp'
            source.write_text(r'''
#include "GraphicsWindowDiagnostics.h"
#include <cstdlib>
#include <string>
#include <vector>
struct Window { DWORD owner; const wchar_t* name; bool valid=true; };
static std::vector<Window> windows;
static std::vector<std::string> lines;
static DWORD errorValue=123;
static DWORD ownPid=0xffffffffu, ownTid=0xfffffffeu;
static unsigned calls, classCalls, foreignClassCalls;
static bool enumFailure;
DWORD GetLastError() { ++calls; return errorValue; }
void SetLastError(DWORD value) { ++calls; errorValue=value; }
DWORD GetCurrentProcessId() { ++calls; errorValue=91;errno=92;return ownPid; }
DWORD GetCurrentThreadId() { ++calls;errorValue=93;errno=94;return ownTid; }
void OutputDebugStringA(const char* text) {
 ++calls;lines.emplace_back(text);if(lines.back().size()>=256)std::abort();errorValue=95;errno=96;
}
BOOL EnumWindows(BOOL(*callback)(HWND,LPARAM),LPARAM parameter) {
 ++calls;errorValue=97;errno=98;if(enumFailure)return FALSE;
 for(auto& window:windows)if(!callback(&window,parameter))return FALSE;
 return TRUE;
}
DWORD GetWindowThreadProcessId(HWND handle,DWORD* pid) {
 ++calls;auto& window=*static_cast<Window*>(handle);*pid=window.owner;errorValue=99;errno=100;return 11;
}
BOOL IsWindow(HWND handle) { ++calls;return static_cast<Window*>(handle)->valid; }
int GetClassNameW(HWND handle,wchar_t* output,int capacity) {
 ++calls;++classCalls;auto& window=*static_cast<Window*>(handle);
 if(window.owner!=77)++foreignClassCalls;
 if(capacity!=16)std::abort();int count=0;
 while(window.name[count]&&count<capacity-1){output[count]=window.name[count];++count;}
 output[count]=0;errorValue=101;errno=102;return count;
}
int main() {
 errno=456;
 const DWORD captured=cfx::compat::CaptureGraphicsWindowError();
 cfx::compat::TraceGraphicsWindowResult(false,0xffffffffu,0xffffffffu,0xffffffffu,true);
 if(errorValue!=123||errno!=456)return 1;
 cfx::compat::TraceGraphicsWindowResult(true,0,0,0,false);
 if(errorValue!=123||errno!=456)return 2;
 ownPid=77;ownTid=88;
 windows={{77,L"grcWindow"},{99,L"grcWindow"},{77,L"OtherClass"},
          {77,L"grcWindowTooLong"},{77,L"grcWindow",false},{77,L"grcWindow"}};
 cfx::compat::TraceGraphicsWindowAvailability(true);
 if(errorValue!=123||errno!=456)return 3;
#ifdef CFX_GRAPHICS_WINDOW_DIAGNOSTICS
 if(captured!=123||foreignClassCalls||classCalls!=4)return 4;
 if(lines[0]!="[CFX_GRAPHICS_WND] pid=4294967295 tid=4294967294 phase=1 returned=0 error=4294967295 style=4294967295 exstyle=4294967295 parent_nonnull=1\n")return 5;
 if(lines[1]!="[CFX_GRAPHICS_WND] pid=4294967295 tid=4294967294 phase=1 returned=1 error=0 style=0 exstyle=0 parent_nonnull=0\n")return 6;
 if(lines[2]!="[CFX_GRAPHICS_WND] pid=77 tid=88 phase=2 swapchain_requested=1 count=2 capped=0 enum_ok=1 query_failures=1\n")return 7;
 windows.assign(300,Window{77,L"grcWindow"});classCalls=0;
 cfx::compat::TraceGraphicsWindowAvailability(false);
 if(classCalls!=256||lines.back()!="[CFX_GRAPHICS_WND] pid=77 tid=88 phase=2 swapchain_requested=0 count=256 capped=1 enum_ok=0 query_failures=0\n")return 8;
 enumFailure=true;cfx::compat::TraceGraphicsWindowAvailability(true);
 if(lines.back()!="[CFX_GRAPHICS_WND] pid=77 tid=88 phase=2 swapchain_requested=1 count=0 capped=0 enum_ok=0 query_failures=0\n")return 9;
 if(errorValue!=123||errno!=456)return 10;
 for(auto& line:lines)if(line.find("grcWindow")!=std::string::npos)return 11;
#else
 if(captured||calls||classCalls||!lines.empty())return 12;
#endif
 return 0;
}
''')
            for enabled in (False, True):
                binary = folder / ('on' if enabled else 'off')
                command = ['/usr/bin/clang++', '-std=c++17', '-Wall', '-Wextra', '-Werror',
                           '-I', str(folder), str(source), '-o', str(binary)]
                if enabled: command.insert(1, '-DCFX_GRAPHICS_WINDOW_DIAGNOSTICS=1')
                result = subprocess.run(command, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                result = subprocess.run([str(binary)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual((HERE / 'GraphicsWindowDiagnostics.h').read_bytes(), header)


if __name__ == '__main__':
    unittest.main()
