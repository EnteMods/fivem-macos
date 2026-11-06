#!/usr/bin/env python3
"""Build a separate four-marker Core9 candidate from the frozen Core8 overlay; no Wine."""
import hashlib
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
BUILD = ROOT / 'build/windows-core-lifecycle-diagnostic'
OVERLAY = BUILD / 'overlay'
RECORD = ROOT / 'research/core-lifecycle-diagnostic-build.json'
BASE = 'build/windows-core-toolmode-diagnostic/overlay/'
BASE_RECORD = 'research/core-toolmode-diagnostic-build.json'
ORIGINAL = 'port/fivem/code/client/citicore/SEHTableHandler.Win32.cpp'
ORIGINAL_SHA = '5205e85793a7232819dee4773aef4bce190ba681134f4808797623906e81bb27'
BASE_FILES = {
    'CMakeLists.txt': 'd7cb88f70a2afb0fab2293e5c62a4af969f0179df2ebc1b99b02157070b5c010',
    'ToolMode.Win32.cpp': 'f468552c49618b6f0c01c103e0c21b40f058fa50b0d225ed71128aa374ae8e82',
    'ToolModeDiagnostics.h': '400a9cd2b87b047018935639defc0ca19f3f9281a5d72ebac0a36f2f8e12ca30',
    'FileMapping.Win32.cpp': '06c62a368aabf0abf3e249f98272b1bb2466fe63dc92b927c49497f97566f156',
    'HookDiagnostics.h': 'ab71b69fa81864d10ad12d08f3fd82b2251e29684e5cac81f5c9a1060140b59d',
    'FilePolicyDiagnostics.h': 'dbd834cd1d94e89886d898c51e3d4946f18c6c071b315cf01e12dcf60d234feb'}
PINS = {BASE + name: digest for name, digest in BASE_FILES.items()}
PINS.update({BASE_RECORD: 'a702672af931818322c2cc9fd888ff231c051e52643d2c902759c5ea3391d09c',
    ORIGINAL: ORIGINAL_SHA,
    'build/windows-core-toolmode-diagnostic/CoreRT.dll': '0dd03dfff845d3a154f2e3c1a0d90374b57fb5a25e0bdc2d489d96920d847650',
    'build/windows-core-toolmode-diagnostic/clang_23.1_cxx17_64_md_relwithdebinfo/tbb12.dll':
        '2231daa77496b6676e33fd01269b2154ab904e692de5b525b04e551c69170e0e'})
INCLUDE = b'#include "LifecycleDiagnostics.h"\r\n'
ANCHOR = b'#include <MinHook.h>\r\n'
CHANGES = (
    (b'\tInitMHWrapper()\r\n\t{\r\n\t\tMH_Initialize();\r\n\t}',
     b'\tInitMHWrapper()\r\n\t{\r\n\t\tcfx::compat::TraceCoreMH(1, false, -1);\r\n'
     b'\t\tconst auto cfx_mh_ctor_status = MH_Initialize();\r\n'
     b'\t\tcfx::compat::TraceCoreMH(2, true, static_cast<int>(cfx_mh_ctor_status));\r\n\t}'),
    (b'\t~InitMHWrapper()\r\n\t{\r\n\t\tMH_Uninitialize();\r\n\t}',
     b'\t~InitMHWrapper()\r\n\t{\r\n\t\tcfx::compat::TraceCoreMH(3, false, -1);\r\n'
     b'\t\tconst auto cfx_mh_dtor_status = MH_Uninitialize();\r\n'
     b'\t\tcfx::compat::TraceCoreMH(4, true, static_cast<int>(cfx_mh_dtor_status));\r\n\t}'))
CMAKE_SELECTION = (b'list(FIND coreSources "${CFX_SOURCE_DIR}/code/client/citicore/SEHTableHandler.Win32.cpp" lifecycleSehIndex)\n'
    b'if(lifecycleSehIndex LESS 0)\n  message(FATAL_ERROR "Original SEH source must occur in the existing Core source selection")\nendif()\n'
    b'list(REMOVE_AT coreSources ${lifecycleSehIndex})\n'
    b'list(INSERT coreSources ${lifecycleSehIndex} "${CMAKE_CURRENT_SOURCE_DIR}/SEHTableHandler.Win32.cpp")\n')
CMAKE_OPTION = (b'option(CFX_CORE_LIFECYCLE_DIAGNOSTICS "Emit fixed-field Core MinHook lifecycle diagnostics" OFF)\n'
    b'if(CFX_CORE_LIFECYCLE_DIAGNOSTICS)\n  target_compile_definitions(CoreRT PRIVATE CFX_CORE_LIFECYCLE_DIAGNOSTICS)\nendif()\n')
TEST_COUNT = 3
sys.path.insert(0, str(ROOT / 'scripts'))
from probe_environment import _plain_path


def regular(path):
    _plain_path(path, ROOT)
    value = path.lstat()
    if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1:
        raise RuntimeError('Require regular single-link lifecycle code/evidence files')
    return value


def sha(path):
    regular(path)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def identity(path):
    return {'path': path.relative_to(ROOT).as_posix(), 'bytes': regular(path).st_size, 'sha256': sha(path)}


def wrap_seh(original):
    if original.count(ANCHOR) != 1 or INCLUDE in original or b'TraceCoreMH' in original:
        raise RuntimeError('Require the exact original SEH source scope')
    result = original.replace(ANCHOR, ANCHOR + INCLUDE, 1)
    for before, after in CHANGES:
        if result.count(before) != 1:
            raise RuntimeError('Changed global InitMHWrapper source inventory')
        result = result.replace(before, after, 1)
    if strip_seh(result) != original:
        raise RuntimeError('Lifecycle removal did not restore original SEH bytes')
    return result


def strip_seh(overlay):
    if overlay.count(INCLUDE) != 1:
        raise RuntimeError('Changed lifecycle include inventory')
    result = overlay.replace(INCLUDE, b'', 1)
    for before, after in reversed(CHANGES):
        if result.count(after) != 1:
            raise RuntimeError('Changed lifecycle wrapper inventory')
        result = result.replace(after, before, 1)
    if b'TraceCoreMH' in result:
        raise RuntimeError('Unrecognized lifecycle expressions remain')
    return result


def wrap_cmake(original):
    anchor = b'add_library(CoreRT SHARED ${coreSources})\n'
    if original.count(anchor) != 1 or b'CFX_CORE_LIFECYCLE_DIAGNOSTICS' in original:
        raise RuntimeError('Require the unchanged v8 CMake overlay')
    return original.replace(anchor, CMAKE_SELECTION + anchor + CMAKE_OPTION, 1)


def strip_cmake(overlay):
    if overlay.count(CMAKE_SELECTION) != 1 or overlay.count(CMAKE_OPTION) != 1:
        raise RuntimeError('Changed lifecycle CMake scope')
    return overlay.replace(CMAKE_SELECTION, b'', 1).replace(CMAKE_OPTION, b'', 1)


def main():
    if RECORD.exists() or RECORD.is_symlink():
        raise RuntimeError('Preserve the existing completed lifecycle build report')
    for name, digest in PINS.items():
        if sha(ROOT / name) != digest:
            raise RuntimeError('A pinned original/Core8 input changed: ' + name)
    _plain_path(BUILD, ROOT)
    marker = BUILD / '.lifecycle-diagnostic-build'
    if BUILD.exists():
        if not BUILD.is_dir() or sha(marker) != hashlib.sha256(b'Separate Core lifecycle diagnostics\n').hexdigest():
            raise RuntimeError('Existing lifecycle build directory is not owned')
        for base, folders, files in os.walk(BUILD, followlinks=False):
            for name in folders:
                _plain_path(Path(base) / name, ROOT)
            for name in files:
                regular(Path(base) / name)
    else:
        BUILD.mkdir(parents=True)
        marker.write_bytes(b'Separate Core lifecycle diagnostics\n')
    OVERLAY.mkdir(exist_ok=True)
    generated = {name: (ROOT / BASE / name).read_bytes() for name in BASE_FILES}
    original = (ROOT / ORIGINAL).read_bytes()
    generated['CMakeLists.txt'] = wrap_cmake(generated['CMakeLists.txt'])
    generated['SEHTableHandler.Win32.cpp'] = wrap_seh(original)
    generated['LifecycleDiagnostics.h'] = (HERE / 'LifecycleDiagnostics.h').read_bytes()
    for name, raw in generated.items():
        target = OVERLAY / name
        _plain_path(target, ROOT)
        if target.exists(): regular(target)
        target.write_bytes(raw)
    test_command = [sys.executable, '-B', '-m', 'unittest', 'discover', '-s', str(HERE), '-p', 'test_lifecycle_diagnostics.py', '-v']
    test_log = BUILD / 'header-tests.log'
    with test_log.open('w') as output:
        tested = subprocess.run(test_command, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT)
    if tested.returncode != 0 or f'Ran {TEST_COUNT} tests' not in test_log.read_text() or '\nOK\n' not in test_log.read_text():
        raise RuntimeError('Require all native lifecycle/header/strip tests')
    toolchain = ROOT / 'native/windows-core/toolchain.cmake'
    commands = [['cmake', '-S', str(OVERLAY), '-B', str(BUILD), '-G', 'Ninja',
        '-DCMAKE_TOOLCHAIN_FILE=' + str(toolchain), '-DCMAKE_POLICY_VERSION_MINIMUM=3.5',
        '-DCMAKE_BUILD_TYPE=RelWithDebInfo', '-DCFX_SOURCE_DIR=' + str(ROOT / 'port/fivem'),
        '-DCFX_CORE_MAPPING_DIAGNOSTICS=ON', '-DCFX_CORE_TOOLMODE_DIAGNOSTICS=ON',
        '-DCFX_CORE_LIFECYCLE_DIAGNOSTICS=ON', '-DCFX_CORE_ACCOUNT_FREE_TESTS=OFF', '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON'],
        ['cmake', '--build', str(BUILD), '--target', 'CoreRT', '--parallel', '4']]
    log = BUILD / 'build.log'
    with log.open('w') as output:
        for command in commands:
            if subprocess.run(command, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT).returncode:
                raise RuntimeError('Separate lifecycle Core build failed; preserve its log')
    compiled = json.loads((BUILD / 'compile_commands.json').read_bytes())
    for name in ('SEHTableHandler.Win32.cpp', 'FileMapping.Win32.cpp', 'ToolMode.Win32.cpp'):
        matches = [item for item in compiled if Path(item['file']).name == name]
        if len(matches) != 1 or Path(matches[0]['file']) != OVERLAY / name:
            raise RuntimeError('Require the exact selected separate Core overlays')
        flags = set(shlex.split(matches[0]['command']))
        if (not flags.intersection(('/MD', '-MD')) or flags.intersection(('/MT', '-MT', '/MDd', '-MDd', '/MTd', '-MTd'))
                or not all(value in matches[0]['command'] for value in (
                'CFX_CORE_MAPPING_DIAGNOSTICS', 'CFX_CORE_TOOLMODE_DIAGNOSTICS', 'CFX_CORE_LIFECYCLE_DIAGNOSTICS', 'COMPILING_CORE'))):
            raise RuntimeError('Require actual /MD and all three diagnostic compile flags')
    if any('CFX_CORE_ACCOUNT_FREE_TESTS' in item['command'] or 'IS_FXSERVER' in item['command'] for item in compiled):
        raise RuntimeError('No account-free or server code may enter this Core')
    if any(sha(ROOT / name) != digest for name, digest in PINS.items()):
        raise RuntimeError('Original or Core8 inputs changed during the separate build')
    tbb = list(BUILD.glob('*/tbb12.dll'))
    if len(tbb) != 1:
        raise RuntimeError('Require one actually built TBB artifact')
    settings = dict(directory=BUILD.relative_to(ROOT).as_posix(), commands=commands, exit=0, CFX_SOURCE_DIR='port/fivem',
        CFX_CORE_MAPPING_DIAGNOSTICS='ON', CFX_CORE_TOOLMODE_DIAGNOSTICS='ON', CFX_CORE_LIFECYCLE_DIAGNOSTICS='ON',
        CFX_CORE_ACCOUNT_FREE_TESTS='OFF', runtime='/MD', target='AMD64 Windows CoreRT', toolchain=identity(toolchain),
        log=identity(log), compile_commands=identity(BUILD / 'compile_commands.json'), source_scope=identity(BUILD / 'source-scope.txt'))
    scope = dict.fromkeys(('stripped_seh_equals_exact_original_bytes', 'stripped_cmake_equals_exact_v8_bytes',
        'v8_mapping_toolmode_and_headers_byte_identical', 'original_calls_evaluated_once',
        'original_statuses_and_controlflow_preserved', 'last_error_and_errno_preserved'), True)
    scope.update(dict.fromkeys(('dllmain_added', 'original_auth_security_or_mapping_policy_changed',
        'additional_minhook_calls', 'addresses_stacks_or_authentication_values_logged'), False))
    scope.update(stripped_seh_sha256=hashlib.sha256(strip_seh(generated['SEHTableHandler.Win32.cpp'])).hexdigest(),
                 stripped_cmake_sha256=hashlib.sha256(strip_cmake(generated['CMakeLists.txt'])).hexdigest())
    report = dict(compiled=True, source_revision=json.loads((ROOT / BASE_RECORD).read_bytes())['source_revision'],
        artifact=identity(BUILD / 'CoreRT.dll'), tbb_artifact=identity(tbb[0]), base_v8_build_record=identity(ROOT / BASE_RECORD),
        base_v8_overlay=[identity(ROOT / BASE / name) for name in BASE_FILES], original_seh=identity(ROOT / ORIGINAL),
        source_evidence=[identity(HERE / name) for name in ('build.py', 'LifecycleDiagnostics.h', 'test_lifecycle_diagnostics.py')],
        generated_overlay=[identity(OVERLAY / name) for name in generated], build=settings, scope_proof=scope,
        header_and_overlay_tests=dict(command=test_command, exit=0, passed=TEST_COUNT, log=identity(test_log)),
        payload=dict(fixed_prefix='CFX_CORE_MH', fields=['pid', 'tid', 'phase', 'status_valid', 'status'],
            phase_range=[1, 4], status_valid_range=[0, 1], status_range=[-1, 12], default='OFF',
            paths_addresses_stacks_arguments_authentication_or_profile_values_logged=False),
        preserved_original_and_v8_input_sha256=PINS, wine_client_or_game_started=False, stage_or_prefix_accessed=False,
        existing_patch_queue_changed=False, runtime_tested=False)
    RECORD.write_bytes((json.dumps(report, indent=2) + '\n').encode())
    print('Separate Core lifecycle candidate built; no stage, prefix or Wine action')


if __name__ == '__main__':
    main()
