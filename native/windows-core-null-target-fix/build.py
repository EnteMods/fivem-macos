#!/usr/bin/env python3
"""Build a separate Core10 with ownership guards for optional loader-diagnostic hooks."""
import copy
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
BUILD = ROOT / 'build/windows-core-null-target-fix'
OVERLAY = BUILD / 'overlay'
RECORD = ROOT / 'research/core-null-target-fix-build.json'
BASE = 'build/windows-core-lifecycle-diagnostic/overlay/'
BASE_RECORD = 'research/core-lifecycle-diagnostic-build.json'
ORIGINAL = 'port/fivem/code/client/citicore/DllGameComponent.Win32.cpp'
BASE_FILES = {
    'CMakeLists.txt': 'cb1a7886f4d91c0f46fc2b676fc4c57c55eba97a5b26e43459d8bc792063b31c',
    'ToolMode.Win32.cpp': 'f468552c49618b6f0c01c103e0c21b40f058fa50b0d225ed71128aa374ae8e82',
    'ToolModeDiagnostics.h': '400a9cd2b87b047018935639defc0ca19f3f9281a5d72ebac0a36f2f8e12ca30',
    'FileMapping.Win32.cpp': '06c62a368aabf0abf3e249f98272b1bb2466fe63dc92b927c49497f97566f156',
    'HookDiagnostics.h': 'ab71b69fa81864d10ad12d08f3fd82b2251e29684e5cac81f5c9a1060140b59d',
    'FilePolicyDiagnostics.h': 'dbd834cd1d94e89886d898c51e3d4946f18c6c071b315cf01e12dcf60d234feb',
    'SEHTableHandler.Win32.cpp': 'f4c248c5517aa9359274cfb80802dfe48b5f81c27ae3b49b8f1300cc0a5cec33',
    'LifecycleDiagnostics.h': '7e3625b73e0d44e008d0a3c6dc10dd2a01f67c41a546699c75d9a2fb67aa61ef'}
PINS = {BASE + name: digest for name, digest in BASE_FILES.items()}
PINS.update({BASE_RECORD: 'bb309c253a6c1e77d1ed520ffe04a81668728801f722437ab9d42944299511ae',
    ORIGINAL: 'e6cdafd33575617581727744a37b8a41ed258590f2d1e08a839ffeb9f3f0c9ce',
    'build/windows-core-lifecycle-diagnostic/CoreRT.dll': '51b7d6432f8a32b404144d19a5abf0a16bcadc764971e99e6fcb12e708a16396',
    'build/windows-core-lifecycle-diagnostic/clang_23.1_cxx17_64_md_relwithdebinfo/tbb12.dll':
        'c3931068206dc672fc8a070285b8623804d45c051d1ac73f33a13c6497e33038'})
CHANGES = (
    (b'\t\tMH_Initialize();\r\n'
     b'\t\tMH_CreateHook(m_target, RtlRaiseExceptionStub, (void**)&g_origRtlRaiseException);\r\n'
     b'\t\tMH_EnableHook(m_target);\r\n\r\n'
     b'\t\tMH_CreateHook(m_target2, ZwQueryDebugFilterStateStub, (void**)&g_origZwQueryDebugFilterState);\r\n'
     b'\t\tMH_EnableHook(m_target2);',
     b'\t\tMH_Initialize();\r\n'
     b'\t\tm_ownsTarget = m_target && MH_CreateHook(m_target, RtlRaiseExceptionStub, (void**)&g_origRtlRaiseException) == MH_OK;\r\n'
     b'\t\tif (m_ownsTarget)\r\n\t\t{\r\n\t\t\tMH_EnableHook(m_target);\r\n\t\t}\r\n\r\n'
     b'\t\tm_ownsTarget2 = m_target2 && MH_CreateHook(m_target2, ZwQueryDebugFilterStateStub, (void**)&g_origZwQueryDebugFilterState) == MH_OK;\r\n'
     b'\t\tif (m_ownsTarget2)\r\n\t\t{\r\n\t\t\tMH_EnableHook(m_target2);\r\n\t\t}'),
    (b'\t\tMH_DisableHook(m_target);\r\n\t\tMH_RemoveHook(m_target);\r\n\r\n'
     b'\t\tMH_DisableHook(m_target2);\r\n\t\tMH_RemoveHook(m_target2);',
     b'\t\tif (m_ownsTarget)\r\n\t\t{\r\n\t\t\tMH_DisableHook(m_target);\r\n\t\t\tMH_RemoveHook(m_target);\r\n\t\t}\r\n\r\n'
     b'\t\tif (m_ownsTarget2)\r\n\t\t{\r\n\t\t\tMH_DisableHook(m_target2);\r\n\t\t\tMH_RemoveHook(m_target2);\r\n\t\t}'),
    (b'\tvoid* m_target;\r\n\tvoid* m_target2;\r\n',
     b'\tvoid* m_target;\r\n\tvoid* m_target2;\r\n\tbool m_ownsTarget = false;\r\n\tbool m_ownsTarget2 = false;\r\n'))
CMAKE_SELECTION = (
    b'list(FIND coreSources "${CFX_SOURCE_DIR}/code/client/citicore/DllGameComponent.Win32.cpp" nullTargetComponentIndex)\n'
    b'if(nullTargetComponentIndex LESS 0)\n  message(FATAL_ERROR "Original component source must occur in Core source selection")\nendif()\n'
    b'list(REMOVE_AT coreSources ${nullTargetComponentIndex})\n'
    b'list(INSERT coreSources ${nullTargetComponentIndex} "${CMAKE_CURRENT_SOURCE_DIR}/DllGameComponent.Win32.cpp")\n')
TEST_COUNT = 3
sys.path.insert(0, str(ROOT / 'scripts'))
from probe_environment import _plain_path


def regular(path):
    _plain_path(path, ROOT)
    value = path.lstat()
    if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1:
        raise RuntimeError('Require regular single-link Core code/evidence files')
    return value


def identity(path):
    regular(path)
    raw = path.read_bytes()
    return {'path': path.relative_to(ROOT).as_posix(), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def wrap_component(original):
    if hashlib.sha256(original).hexdigest() != PINS[ORIGINAL]:
        raise RuntimeError('Require the exact public original component source')
    result = original
    for before, after in CHANGES:
        if result.count(before) != 1 or after in result:
            raise RuntimeError('Changed HardErrorScope inventory')
        result = result.replace(before, after, 1)
    if strip_component(result) != original:
        raise RuntimeError('Ownership removal did not restore the original source')
    return result


def strip_component(overlay):
    result = overlay
    for before, after in reversed(CHANGES):
        if result.count(after) != 1:
            raise RuntimeError('Changed ownership-guard inventory')
        result = result.replace(after, before, 1)
    if hashlib.sha256(result).hexdigest() != PINS[ORIGINAL]:
        raise RuntimeError('Unexpected edits outside the owned-target guards')
    return result


def wrap_cmake(original):
    anchor = b'add_library(CoreRT SHARED ${coreSources})\n'
    if hashlib.sha256(original).hexdigest() != BASE_FILES['CMakeLists.txt'] or original.count(anchor) != 1:
        raise RuntimeError('Require the exact Core9 CMake overlay')
    return original.replace(anchor, CMAKE_SELECTION + anchor, 1)


def strip_cmake(overlay):
    if overlay.count(CMAKE_SELECTION) != 1:
        raise RuntimeError('Changed same-index component source selection')
    result = overlay.replace(CMAKE_SELECTION, b'', 1)
    if hashlib.sha256(result).hexdigest() != BASE_FILES['CMakeLists.txt']:
        raise RuntimeError('Unexpected edits outside the CMake source selection')
    return result


def main():
    if sys.argv[1:]:
        raise RuntimeError('Only the fixed separate Core10 build is accepted')
    if RECORD.exists() or RECORD.is_symlink():
        raise RuntimeError('Preserve the existing completed Core10 build report')
    captured, before = {}, {}
    for name, digest in PINS.items():
        regular(ROOT / name)
        raw = (ROOT / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != digest:
            raise RuntimeError('A fixed original/Core9 input changed')
        captured[name] = raw
        before[name] = dict(path=name, bytes=len(raw), sha256=digest)
    previous = json.loads(captured[BASE_RECORD])
    expected = {BASE + name for name in BASE_FILES}
    if (previous.get('compiled') is not True or previous['build']['exit'] != 0
            or len(previous['generated_overlay']) != len(expected)
            or {item['path'] for item in previous['generated_overlay']} != expected
            or any(item != before[item['path']] for item in previous['generated_overlay'])):
        raise RuntimeError('Require the actual complete Core9 overlay record')
    _plain_path(BUILD, ROOT)
    marker = BUILD / '.null-target-fix-build'
    if BUILD.exists():
        if not BUILD.is_dir() or identity(marker)['sha256'] != hashlib.sha256(b'Separate Core null-target ownership fix\n').hexdigest():
            raise RuntimeError('Existing Core10 build directory is not owned')
        for base, folders, files in os.walk(BUILD, followlinks=False):
            for name in folders: _plain_path(Path(base) / name, ROOT)
            for name in files: regular(Path(base) / name)
    else:
        BUILD.mkdir(parents=True)
        marker.write_bytes(b'Separate Core null-target ownership fix\n')
    OVERLAY.mkdir(exist_ok=True)
    generated = {name: captured[BASE + name] for name in BASE_FILES}
    generated['CMakeLists.txt'] = wrap_cmake(generated['CMakeLists.txt'])
    generated['DllGameComponent.Win32.cpp'] = wrap_component(captured[ORIGINAL])
    sources = [identity(HERE / name) for name in ('build.py', 'test_null_target_fix.py')]
    for name, raw in generated.items():
        target = OVERLAY / name
        _plain_path(target, ROOT)
        if target.exists(): regular(target)
        target.write_bytes(raw)
    tested_command = [sys.executable, '-B', '-m', 'unittest', 'discover', '-s', str(HERE), '-p', 'test_null_target_fix.py', '-v']
    test_log = BUILD / 'native-tests.log'
    with test_log.open('w') as output:
        tested = subprocess.run(tested_command, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT)
    if tested.returncode or f'Ran {TEST_COUNT} tests' not in test_log.read_text() or '\nOK\n' not in test_log.read_text():
        raise RuntimeError('Require the native ownership and exact-strip checks')
    commands = copy.deepcopy(previous['build']['commands'])
    replacements = {str(ROOT / BASE).rstrip('/'): str(OVERLAY), str(ROOT / previous['build']['directory']): str(BUILD)}
    seen = {name: 0 for name in replacements}
    for command in commands:
        for index, value in enumerate(command):
            if value in replacements:
                seen[value] += 1
                command[index] = replacements[value]
    if len(commands) != 2 or sorted(seen.values()) != [1, 2]:
        raise RuntimeError('Changed fixed Core9 configure/build command roles')
    log = BUILD / 'build.log'
    with log.open('w') as output:
        for command in commands:
            if subprocess.run(command, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT).returncode:
                raise RuntimeError('Separate Core10 build failed; preserve its log')
    compiled = json.loads((BUILD / 'compile_commands.json').read_bytes())
    for name in ('DllGameComponent.Win32.cpp', 'SEHTableHandler.Win32.cpp', 'FileMapping.Win32.cpp', 'ToolMode.Win32.cpp'):
        matches = [item for item in compiled if Path(item['file']).name == name]
        if len(matches) != 1 or Path(matches[0]['file']) != OVERLAY / name:
            raise RuntimeError('Require exactly the separate selected Core10 source')
        flags = set(shlex.split(matches[0]['command']))
        if (not flags.intersection(('/MD', '-MD')) or flags.intersection(('/MT', '-MT', '/MDd', '-MDd', '/MTd', '-MTd'))
                or not all(value in matches[0]['command'] for value in ('COMPILING_CORE', 'CFX_CORE_MAPPING_DIAGNOSTICS',
                    'CFX_CORE_TOOLMODE_DIAGNOSTICS', 'CFX_CORE_LIFECYCLE_DIAGNOSTICS'))):
            raise RuntimeError('Require original /MD Core diagnostic definitions')
    if any('CFX_CORE_ACCOUNT_FREE_TESTS' in item['command'] or 'IS_FXSERVER' in item['command'] for item in compiled):
        raise RuntimeError('No server/test code may enter this Core')
    if before != {name: identity(ROOT / name) for name in PINS} or sources != [identity(HERE / name) for name in ('build.py', 'test_null_target_fix.py')]:
        raise RuntimeError('Original, Core9, or own recipe inputs changed during build')
    if any((OVERLAY / name).read_bytes() != raw for name, raw in generated.items()):
        raise RuntimeError('Generated overlay changed during build')
    tbb = list(BUILD.glob('*/tbb12.dll'))
    if len(tbb) != 1: raise RuntimeError('Require one actually built TBB artifact')
    scope = dict.fromkeys(('stripped_component_equals_exact_original_bytes', 'stripped_cmake_equals_exact_v9_bytes',
        'v9_other_seven_overlay_files_byte_identical', 'mh_initialize_call_unchanged',
        'nonnull_and_successful_create_required_for_owned_targets', 'enable_disable_remove_only_for_owned_targets',
        'failed_or_already_created_targets_not_modified', 'other_original_branches_and_calls_byte_identical'), True)
    scope.update(dict.fromkeys(('dllmain_added', 'original_auth_security_or_mapping_policy_changed',
        'global_minhook_uninitialize_added', 'additional_minhook_calls', 'addresses_stacks_or_authentication_values_logged'), False))
    scope.update(stripped_component_sha256=hashlib.sha256(strip_component(generated['DllGameComponent.Win32.cpp'])).hexdigest(),
        stripped_cmake_sha256=hashlib.sha256(strip_cmake(generated['CMakeLists.txt'])).hexdigest())
    settings = {key: copy.deepcopy(value) for key, value in previous['build'].items() if key not in
        ('directory', 'commands', 'log', 'compile_commands', 'source_scope')}
    settings.update(directory=BUILD.relative_to(ROOT).as_posix(), commands=commands, log=identity(log),
        compile_commands=identity(BUILD / 'compile_commands.json'), source_scope=identity(BUILD / 'source-scope.txt'))
    report = dict(compiled=True, source_revision=previous['source_revision'], artifact=identity(BUILD / 'CoreRT.dll'),
        tbb_artifact=identity(tbb[0]), base_v9_build_record=before[BASE_RECORD],
        base_v9_overlay=[before[BASE + name] for name in BASE_FILES], original_component=before[ORIGINAL],
        source_evidence=sources, generated_overlay=[identity(OVERLAY / name) for name in generated], build=settings,
        scope_proof=scope, native_and_overlay_tests=dict(command=tested_command, exit=0, passed=TEST_COUNT,
            log=identity(test_log), scope='Native original/fixed MinHook doubles and exact source/CMake reversal; no Wine/client claim'),
        preserved_original_and_v9_input_sha256=PINS, wine_client_or_game_started=False, stage_or_prefix_accessed=False,
        existing_patch_queue_changed=False, runtime_tested=False)
    with RECORD.open('x') as output:
        json.dump(report, output, indent=2)
        output.write('\n')
    print('Separate Core10 ownership fix built; no stage, prefix, or Wine action')


if __name__ == '__main__':
    main()
