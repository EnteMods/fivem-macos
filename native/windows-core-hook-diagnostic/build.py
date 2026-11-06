#!/usr/bin/env python3
"""Build a reversible own CoreRT hook-status overlay; never stage or start Wine."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
BUILD = ROOT / 'build/windows-core-hook-diagnostic'
OVERLAY = BUILD / 'overlay'
SOURCE = ROOT / 'port/fivem'
V5_RECORD = ROOT / 'research/core-mapping-diagnostic-build.json'
RECORD = ROOT / 'research/core-hook-diagnostic-build.json'
PINNED_SOURCES = {
    'port/fivem/code/client/citicore/FileMapping.Win32.cpp': '1e2e23846410586e27117716ba8ea4ee8be3681469d50015391c4f10ce2e3053',
    'port/fivem/code/client/citicore/MappingDiagnostics.h': '9cab07670dfcbd4134d5d60af5d28e745c753576c12107b270b0a8f3df033b31',
    'native/windows-core/CMakeLists.txt': '37ed38171fcaf4b02ead24e53ac05a7f7579f360cb74343ce9abab164f79bbac',
}
CORE_SHA = 'a9f4262d7f0d35b7e87e89d84cb00ed2007ca2dd297a0ae802d2c6877738f0a0'
TBB_SHA = 'facbb8c13497defb47191774081fba51fb421991da7eecbb828f9eb493b1d97c'
PHASES = (
    ('ntdll.dll', 'NtCreateFile', 'NtCreateFile'),
    ('ntdll.dll', 'NtOpenFile', 'NtOpenFile'),
    ('ntdll.dll', 'NtDeleteFile', 'NtDeleteFile'),
    ('ntdll.dll', 'NtQueryAttributesFile', 'NtQueryAttributesFile'),
    ('ntdll.dll', 'NtQueryFullAttributesFile', 'NtQueryFullAttributesFile'),
    ('ntdll.dll', 'NtSetInformationFile', 'NtSetInformationFile'),
    ('ntdll.dll', 'LdrLoadDll', 'LdrLoadDll'),
    ('ntdll.dll', 'LdrGetProcedureAddress', 'LdrGetProcedureAddress'),
    ('ntdll.dll', 'RtlGetFullPathName_U', 'RtlGetFullPathNameU'),
    ('version.dll', 'GetFileVersionInfoSizeW', 'GetFileVersionInfoSizeW'),
    ('version.dll', 'GetFileVersionInfoSizeA', 'GetFileVersionInfoSizeA'),
    ('version.dll', 'GetFileVersionInfoW', 'GetFileVersionInfoW'),
    ('version.dll', 'GetFileVersionInfoA', 'GetFileVersionInfoA'),
    ('version.dll', 'VerQueryValueW', 'VerQueryValueW'),
    ('kernelbase.dll', 'RegOpenKeyExW', 'RegOpenKeyExW'),
    ('kernelbase.dll', 'GetFileAttributesExW', 'GetFileAttributesExW'),
    ('kernelbase.dll', 'GetProcAddressForCaller', 'GetProcAddressForCaller'),
    ('kernel32.dll', 'CreateThread', 'Kernel32CreateThread'),
    ('kernelbase.dll', 'CreateThread', 'KernelbaseCreateThread'),
    ('combase.dll', 'CoUninitialize', 'CoUninitialize'),
)
HOOK_LINE = re.compile(rb'(?m)^\t(MH_CreateHookApi\([^\r\n]*\)|MH_EnableHook\(MH_ALL_HOOKS\));(?=\r?$)')
WRAPPED_LINE = re.compile(
    rb'(?m)^\tcfx::compat::TraceMappingHook\(cfx::compat::MappingHookPhase::([A-Za-z0-9]+), '
    rb'\[&\]\(\) \{ return (MH_CreateHookApi\([^\r\n]*\)|MH_EnableHook\(MH_ALL_HOOKS\)); \}\);(?=\r?$)')
INCLUDE_ANCHOR = b'#include "MappingDiagnostics.h"\r\n'
HOOK_INCLUDE = b'#include "HookDiagnostics.h"\r\n'
CMAKE_ANCHOR = b'add_library(CoreRT SHARED ${coreSources})\n'
CMAKE_OVERLAY = (
    b'list(FILTER coreSources EXCLUDE REGEX "/FileMapping[.]Win32[.]cpp$")\n'
    b'list(APPEND coreSources "${CMAKE_CURRENT_SOURCE_DIR}/FileMapping.Win32.cpp")\n')
sys.path.insert(0, str(ROOT / 'scripts'))
from probe_environment import _plain_path


def regular_file(path, *, allow_missing=False):
    _plain_path(path, ROOT)
    try:
        info = path.lstat()
    except FileNotFoundError:
        if allow_missing:
            return
        raise
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise RuntimeError('Require local regular single-link input/output: ' + str(path))
    return info


def sha(path):
    regular_file(path)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def identity(path):
    digest = sha(path)
    return {'path': str(path.relative_to(ROOT)), 'bytes': path.stat().st_size, 'sha256': digest}


def wrap_mapping(original):
    expressions = list(HOOK_LINE.finditer(original))
    if len(expressions) != 21 or original.count(INCLUDE_ANCHOR) != 1:
        raise RuntimeError('Require exact v5 hook inventory and include anchor')
    phases = []
    for index, match in enumerate(expressions):
        expression = match.group(1)
        if index < 20:
            api = re.match(rb'MH_CreateHookApi\(L"([^"]+)", "([^"]+)"', expression)
            if not api or (api[1].decode(), api[2].decode()) != PHASES[index][:2]:
                raise RuntimeError('Unexpected hook expression or order')
            phases.append(PHASES[index][2])
        elif expression != b'MH_EnableHook(MH_ALL_HOOKS)':
            raise RuntimeError('Require existing single EnableHook-all call')
        else:
            phases.append('EnableAll')
    iterator = iter(phases)

    def replace(match):
        return (b'\tcfx::compat::TraceMappingHook(cfx::compat::MappingHookPhase::'
                + next(iterator).encode() + b', [&]() { return ' + match.group(1) + b'; });')

    result = HOOK_LINE.sub(replace, original)
    result = result.replace(INCLUDE_ANCHOR, INCLUDE_ANCHOR + HOOK_INCLUDE, 1)
    if strip_mapping(result) != original:
        raise RuntimeError('Removing hook diagnostics does not reproduce exact v5 bytes')
    return result


def strip_mapping(overlay):
    matches = list(WRAPPED_LINE.finditer(overlay))
    expected = [phase[2] for phase in PHASES] + ['EnableAll']
    if [match[1].decode() for match in matches] != expected or overlay.count(HOOK_INCLUDE) != 1:
        raise RuntimeError('Unexpected overlay wrappers or include')
    return WRAPPED_LINE.sub(lambda match: b'\t' + match[2] + b';', overlay).replace(HOOK_INCLUDE, b'', 1)


def overlay_cmake(original):
    if original.count(CMAKE_ANCHOR) != 1:
        raise RuntimeError('Require exact CoreRT CMake anchor')
    result = original.replace(CMAKE_ANCHOR, CMAKE_OVERLAY + CMAKE_ANCHOR, 1)
    if result.replace(CMAKE_OVERLAY, b'', 1) != original:
        raise RuntimeError('CMake overlay must be reversible')
    return result


def safe_write(path, data):
    if not path.is_relative_to(BUILD) and path != RECORD:
        raise RuntimeError('Write outside isolated hook build or its report')
    regular_file(path, allow_missing=True)
    path.write_bytes(data)


def check_build_tree():
    _plain_path(BUILD, ROOT)
    if BUILD.exists():
        if not BUILD.is_dir():
            raise RuntimeError('Hook build must be a local directory')
        marker = BUILD / '.hook-diagnostic-build'
        if not marker.is_file() or sha(marker) != hashlib.sha256(b'Own compile-only hook diagnostic overlay\n').hexdigest():
            raise RuntimeError('Existing hook build has no exact own marker')
        for directory, folders, files in os.walk(BUILD, followlinks=False):
            for name in folders:
                _plain_path(Path(directory) / name, ROOT)
            for name in files:
                regular_file(Path(directory) / name)
    else:
        BUILD.mkdir(parents=True)
        safe_write(BUILD / '.hook-diagnostic-build', b'Own compile-only hook diagnostic overlay\n')


def main():
    # This fixed report is checked before any path from its contents is used.
    v5_identity = identity(V5_RECORD)
    v5 = json.loads(V5_RECORD.read_text())
    if ({item['path']: item['sha256'] for item in v5['source_evidence']} != PINNED_SOURCES
            or len(v5['source_evidence']) != 3):
        raise RuntimeError('Require the reviewed three-input v5 build record')
    for path, digest in PINNED_SOURCES.items():
        if sha(ROOT / path) != digest:
            raise RuntimeError('Pinned v5 source changed: ' + path)
    ordinary_core = ROOT / 'build/windows-core/CoreRT.dll'
    ordinary_tbb = ROOT / 'build/windows-core/clang_23.1_cxx17_64_md_relwithdebinfo/tbb12.dll'
    v5_core = ROOT / 'build/windows-core-mapping-diagnostic/CoreRT.dll'
    if sha(ordinary_core) != CORE_SHA or sha(ordinary_tbb) != TBB_SHA:
        raise RuntimeError('Require unchanged ordinary CoreRT and TBB')
    if (v5['diagnostic_artifact']['path'] != str(v5_core.relative_to(ROOT))
            or sha(v5_core) != v5['diagnostic_artifact']['sha256']):
        raise RuntimeError('Require unchanged v5 diagnostic CoreRT')
    preserved = {item['path']: item['sha256'] for item in [v5_identity,
        identity(ordinary_core), identity(ordinary_tbb), identity(v5_core)]}
    preserved.update(PINNED_SOURCES)
    mapping = ROOT / 'port/fivem/code/client/citicore/FileMapping.Win32.cpp'
    cmake = ROOT / 'native/windows-core/CMakeLists.txt'
    mapping_bytes = mapping.read_bytes()
    cmake_bytes = cmake.read_bytes()
    overlay_bytes = wrap_mapping(mapping_bytes)
    generated_cmake = overlay_cmake(cmake_bytes)
    check_build_tree()
    _plain_path(OVERLAY, ROOT)
    OVERLAY.mkdir(exist_ok=True)
    for name, content in (('FileMapping.Win32.cpp', overlay_bytes), ('CMakeLists.txt', generated_cmake),
                          ('HookDiagnostics.h', (HERE / 'HookDiagnostics.h').read_bytes())):
        safe_write(OVERLAY / name, content)
    test_log = BUILD / 'header-tests.log'
    regular_file(test_log, allow_missing=True)
    test_command = [sys.executable, '-m', 'unittest', 'discover', '-s', str(HERE), '-p', 'test_hook_diagnostics.py', '-v']
    with test_log.open('w') as output:
        tests = subprocess.run(test_command, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT)
    if tests.returncode != 0:
        raise RuntimeError('Own header/overlay tests failed; see ' + str(test_log))
    toolchain = ROOT / 'native/windows-core/toolchain.cmake'
    commands = [
        ['cmake', '-S', str(OVERLAY), '-B', str(BUILD), '-G', 'Ninja',
         '-DCMAKE_TOOLCHAIN_FILE=' + str(toolchain), '-DCMAKE_POLICY_VERSION_MINIMUM=3.5',
         '-DCMAKE_BUILD_TYPE=RelWithDebInfo', '-DCFX_SOURCE_DIR=' + str(SOURCE),
         '-DCFX_CORE_MAPPING_DIAGNOSTICS=ON', '-DCFX_CORE_ACCOUNT_FREE_TESTS=OFF',
         '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON'],
        ['cmake', '--build', str(BUILD), '--target', 'CoreRT', '--parallel', '4'],
    ]
    build_log = BUILD / 'build.log'
    regular_file(build_log, allow_missing=True)
    with build_log.open('w') as output:
        for command in commands:
            completed = subprocess.run(command, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT)
            if completed.returncode != 0:
                raise RuntimeError('Isolated hook diagnostic build failed; see ' + str(build_log))
    core = BUILD / 'CoreRT.dll'
    tbb = list(BUILD.glob('*/tbb12.dll'))
    if len(tbb) != 1:
        raise RuntimeError('Require one actually built TBB DLL')
    for binary in (core, tbb[0]):
        raw = binary.read_bytes()
        offset = struct.unpack_from('<I', raw, 60)[0]
        if (raw[offset:offset+4] != b'PE\0\0' or struct.unpack_from('<H', raw, offset+4)[0] != 0x8664
                or not struct.unpack_from('<H', raw, offset+22)[0] & 0x2000):
            raise RuntimeError('Require actual AMD64 PE DLL artifacts')
    compiled = json.loads((BUILD / 'compile_commands.json').read_text())
    mapping_commands = [item for item in compiled if Path(item['file']).name == 'FileMapping.Win32.cpp']
    if len(mapping_commands) != 1 or Path(mapping_commands[0]['file']) != OVERLAY / 'FileMapping.Win32.cpp':
        raise RuntimeError('Only the overlay FileMapping source must be compiled')
    command = mapping_commands[0]['command']
    flags = set(shlex.split(command))
    if (not flags.intersection(('/MD', '-MD'))
            or flags.intersection(('/MT', '-MT', '/MDd', '-MDd', '/MTd', '-MTd'))
            or not all(flag in command for flag in ('CFX_CORE_MAPPING_DIAGNOSTICS', 'COMPILING_CORE'))):
        raise RuntimeError('Require actual /MD diagnostic CoreRT compilation')
    if any('CFX_CORE_ACCOUNT_FREE_TESTS' in item['command'] or 'IS_FXSERVER' in item['command'] for item in compiled):
        raise RuntimeError('Unexpected account-free instrumentation or server definition')
    if preserved != {path: sha(ROOT / path) for path in preserved}:
        raise RuntimeError('Original v5 inputs/artifacts changed during separate build')
    report = {
        'at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'compiled': True,
        'source_revision': v5['source_revision'], 'base_v5_build_record': v5_identity,
        'artifact': identity(core), 'tbb_artifact': identity(tbb[0]),
        'source_evidence': [identity(HERE / name) for name in ('build.py', 'HookDiagnostics.h', 'test_hook_diagnostics.py')],
        'generated_overlay': [identity(OVERLAY / name) for name in ('CMakeLists.txt', 'FileMapping.Win32.cpp', 'HookDiagnostics.h')],
        'scope_proof': {'original_sources_pinned': PINNED_SOURCES,
            'stripped_mapping_sha256': hashlib.sha256(strip_mapping(overlay_bytes)).hexdigest(),
            'stripped_mapping_equals_exact_v5_bytes': strip_mapping(overlay_bytes) == mapping_bytes,
            'stripped_cmake_equals_exact_v5_bytes': generated_cmake.replace(CMAKE_OVERLAY, b'', 1) == cmake_bytes,
            'create_hook_api_wrappers': 20, 'enable_all_wrappers': 1,
            'original_hook_expressions_unchanged_and_evaluated_once': True,
            'status_controls_original_flow': False, 'mapping_callback_filter_or_return_changed': False,
            'additional_getmodulehandle_probes': False},
        'build': {'directory': str(BUILD.relative_to(ROOT)), 'commands': commands, 'exit': 0,
            'CFX_SOURCE_DIR': str(SOURCE.relative_to(ROOT)), 'CFX_CORE_MAPPING_DIAGNOSTICS': 'ON',
            'CFX_CORE_ACCOUNT_FREE_TESTS': 'OFF', 'runtime': '/MD', 'target': 'AMD64 Windows CoreRT',
            'toolchain': identity(toolchain), 'log': identity(build_log),
            'compile_commands': identity(BUILD / 'compile_commands.json'), 'source_scope': identity(BUILD / 'source-scope.txt')},
        'header_and_overlay_tests': {'command': test_command, 'exit': tests.returncode, 'log': identity(test_log),
            'scope': 'Header compiled ON/OFF with own WinAPI stubs; LastError, fixed fields, status bounds, original return and exactly one evaluation; reversible overlay'},
        'payload': {'fixed_prefix': 'CFX_MAPPING_HOOK', 'fields': ['pid', 'phase', 'status'],
            'phase_source': 'fixed enum only', 'status_range': [-1, 12], 'out_of_range_status_logged_as': -1,
            'paths_pointers_auth_or_profile_values_logged': False, 'last_error_preserved': True},
        'preserved_original_input_and_artifact_sha256': preserved,
        'wine_client_or_game_started': False, 'stage_or_prefix_accessed': False,
        'existing_patch_queue_changed': False, 'runtime_tested': False,
    }
    safe_write(RECORD, (json.dumps(report, indent=2) + '\n').encode())
    print('Separate hook-status CoreRT build and own ON/OFF tests PASS; no staging or Wine', flush=True)


if __name__ == '__main__':
    main()
