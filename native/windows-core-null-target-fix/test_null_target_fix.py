"""Native own doubles compare the exact original/fixed MH statements; no Wine."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
spec = importlib.util.spec_from_file_location('own_null_target_builder', HERE / 'build.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class NullTargetTests(unittest.TestCase):
    def test_native_original_vs_fixed_missing_valid_and_unowned_targets(self):
        original = (ROOT / builder.ORIGINAL).read_bytes()
        fixed = builder.wrap_component(original)

        def scope(name, source, owned):
            start = source.index(b'\t\tMH_Initialize();')
            end = source.index(b'\r\n\t}', start)
            ctor = source[start:end].decode()
            start = source.index(b'\t\tDisableToolHelpScope thScope;', source.index(b'\t~HardErrorScope()'))
            start = source.index(b'\r\n', start) + 2
            end = source.index(b'\r\n\t\tif (m_oldLdrFlags)', start)
            dtor = source[start:end].decode()
            fields = builder.CHANGES[2][1 if owned else 0].decode()
            return f'struct {name} {{\n{fields}\n{name}(void* a, void* b):m_target(a),m_target2(b) {{\n{ctor}\n}}\n~{name}() {{\n{dtor}\n}}\n}};\n'

        code = r'''
#include <array>
#include <cstdlib>
constexpr int MH_OK=0, ALREADY_CREATED=3, NOT_CREATED=4, NOT_EXECUTABLE=7;
static int objects[5];
static std::array<bool,5> created, enabled;
static std::array<unsigned,5> creates, enables, disables, removes;
static int resultA, resultB;
static unsigned initCalls, allEnable, allDisable, nullCreate, nullRemove;
static void* g_origRtlRaiseException;
static void* g_origZwQueryDebugFilterState;
void RtlRaiseExceptionStub() {}
void ZwQueryDebugFilterStateStub() {}
int index(void* target) {
 for(int i=0;i<5;++i) if(target==&objects[i]) return i;
 std::abort();
}
int MH_Initialize() { ++initCalls; return 1; }
int MH_CreateHook(void* target, void(*)(), void**) {
 if(!target) { ++nullCreate; return NOT_EXECUTABLE; }
 int i=index(target); ++creates[i]; int status=i==3?resultA:resultB;
 if(status==MH_OK) created[i]=true;
 return status;
}
int MH_EnableHook(void* target) {
 if(!target) { ++allEnable; for(int i=0;i<5;++i) if(created[i]) enabled[i]=true; return 0; }
 int i=index(target); ++enables[i]; if(!created[i]) return NOT_CREATED; enabled[i]=true; return 0;
}
int MH_DisableHook(void* target) {
 if(!target) { ++allDisable; enabled.fill(false); return 0; }
 int i=index(target); ++disables[i]; if(!created[i]) return NOT_CREATED; enabled[i]=false; return 0;
}
int MH_RemoveHook(void* target) {
 if(!target) { ++nullRemove; return NOT_CREATED; }
 int i=index(target); ++removes[i]; if(!created[i]) return NOT_CREATED; created[i]=enabled[i]=false; return 0;
}
void reset(int a, int b) {
 resultA=a; resultB=b; created.fill(false); enabled.fill(false);
 creates.fill(0); enables.fill(0); disables.fill(0); removes.fill(0);
 for(int i=0;i<3;++i) created[i]=enabled[i]=true;
 if(a==ALREADY_CREATED) created[3]=enabled[3]=true;
 if(b==ALREADY_CREATED) created[4]=enabled[4]=true;
 initCalls=allEnable=allDisable=nullCreate=nullRemove=0;
}
bool mappingActive() { return enabled[0]&&enabled[1]&&enabled[2]; }
''' + scope('OriginalScope', original, False) + scope('FixedScope', fixed, True) + r'''
bool fixedCase(bool first, bool second, int a, int b) {
 reset(a,b);
 { FixedScope own(first?&objects[3]:nullptr,second?&objects[4]:nullptr); if(!mappingActive()) return false; }
 if(!mappingActive()||initCalls!=1||allEnable||allDisable||nullCreate||nullRemove) return false;
 for(int i=3;i<5;++i) {
  bool present=i==3?first:second; int status=i==3?a:b; bool owned=present&&status==MH_OK;
  if(creates[i]!=unsigned(present)||enables[i]!=unsigned(owned)||disables[i]!=unsigned(owned)||removes[i]!=unsigned(owned)) return false;
  if(status==ALREADY_CREATED&&(!created[i]||!enabled[i])) return false;
  if(owned&&created[i]) return false;
 }
 return true;
}
int main() {
 reset(0,0); { OriginalScope original(&objects[3],nullptr); }
 if(mappingActive()||initCalls!=1||allEnable!=1||allDisable!=1||nullCreate!=1||nullRemove!=1) return 1;
 reset(0,0); { OriginalScope original(&objects[3],&objects[4]); }
 if(!mappingActive()||initCalls!=1||allEnable||allDisable) return 2;
 if(!fixedCase(true,false,0,0)||!fixedCase(false,true,0,0)||!fixedCase(false,false,0,0)) return 3;
 if(!fixedCase(true,true,0,0)) return 4;
 if(!fixedCase(true,true,3,3)||!fixedCase(true,true,0,3)) return 5;
 if(!fixedCase(true,true,7,8)||!fixedCase(true,true,7,0)) return 6;
 return 0;
}
'''
        with tempfile.TemporaryDirectory(prefix='cfx-null-target-own-') as temporary:
            folder = Path(temporary)
            source, binary = folder / 'test.cpp', folder / 'test'
            source.write_text(code)
            compiled = subprocess.run(['/usr/bin/clang++', '-std=c++17', '-Wall', '-Wextra', '-Werror',
                str(source), '-o', str(binary)], capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            tested = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(tested.returncode, 0, tested.stdout + tested.stderr)

    def test_original_source_cmake_and_minhook_call_inventory_recover_exactly(self):
        original = (ROOT / builder.ORIGINAL).read_bytes()
        fixed = builder.wrap_component(original)
        self.assertEqual(builder.strip_component(fixed), original)
        for call in (b'MH_Initialize(', b'MH_CreateHook(', b'MH_EnableHook(', b'MH_DisableHook(', b'MH_RemoveHook('):
            self.assertEqual(fixed.count(call), original.count(call))
        self.assertNotIn(b'MH_Uninitialize(', fixed)
        cmake = (ROOT / builder.BASE / 'CMakeLists.txt').read_bytes()
        wrapped = builder.wrap_cmake(cmake)
        self.assertEqual(builder.strip_cmake(wrapped), cmake)
        self.assertIn(b'list(INSERT coreSources ${nullTargetComponentIndex}', wrapped)
        self.assertNotIn(b'list(APPEND coreSources "${CMAKE_CURRENT_SOURCE_DIR}/DllGameComponent.Win32.cpp")', wrapped)

    def test_changed_sources_or_unrecognized_extra_edits_are_rejected(self):
        original = (ROOT / builder.ORIGINAL).read_bytes()
        fixed = builder.wrap_component(original)
        for raw in (fixed, original.replace(b'MH_Initialize();', b'ChangedCall();')):
            with self.assertRaises(RuntimeError): builder.wrap_component(raw)
        with self.assertRaises(RuntimeError): builder.strip_component(fixed + b'// extra edit\n')
        cmake = (ROOT / builder.BASE / 'CMakeLists.txt').read_bytes()
        with self.assertRaises(RuntimeError): builder.wrap_cmake(builder.wrap_cmake(cmake))
        with self.assertRaises(RuntimeError): builder.strip_cmake(builder.wrap_cmake(cmake) + b'# extra edit\n')


if __name__ == '__main__':
    unittest.main()
