#!/usr/bin/env python3
"""Build a separate reversible file-policy diagnostic Core; no Wine or staging."""
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
BUILD = ROOT / 'build/windows-core-file-policy-diagnostic'
OVERLAY = BUILD / 'overlay'
RECORD = ROOT / 'research/core-file-policy-diagnostic-build.json'
BASE_RECORD = 'research/core-hook-diagnostic-build.json'
BASE_RECORD_SHA = '1a96402376a1df944cc8168efca993d533bdb2ae3cfa260c1cd8ae195ed259e8'
BASE_MAPPING = 'build/windows-core-hook-diagnostic/overlay/FileMapping.Win32.cpp'
BASE_MAPPING_SHA = '00cf57d5fe758d61ca67ebb1e6778bc28c240a26d66824c210aaa47c10e2a3c4'
BASE_CMAKE = 'build/windows-core-hook-diagnostic/overlay/CMakeLists.txt'
BASE_CMAKE_SHA = 'beb5907b6eea81f75c5435569a9edff74f820434a263ad97749f0ab12f759ca9'
BASE_HEADER = 'build/windows-core-hook-diagnostic/overlay/HookDiagnostics.h'
BASE_HEADER_SHA = 'ab71b69fa81864d10ad12d08f3fd82b2251e29684e5cac81f5c9a1060140b59d'
BASE_CORE = 'build/windows-core-hook-diagnostic/CoreRT.dll'
BASE_CORE_SHA = 'b8830fa5bc6103a976d217dba418d9cbf7f27fed5e2cdf4db4587447f5eb17b8'
BASE_TBB = 'build/windows-core-hook-diagnostic/clang_23.1_cxx17_64_md_relwithdebinfo/tbb12.dll'
BASE_TBB_SHA = '7692b31578fa9c390cf253ee6ecdabaea63839327f054d3ed179ab60eb64096c'
BASE_SOURCES = {'native/windows-core-hook-diagnostic/' + name for name in
                ('build.py', 'HookDiagnostics.h', 'test_hook_diagnostics.py')}
BASE_GENERATED = {BASE_MAPPING, BASE_CMAKE, BASE_HEADER}
PINNED_ORIGINAL = {
    'port/fivem/code/client/citicore/FileMapping.Win32.cpp': '1e2e23846410586e27117716ba8ea4ee8be3681469d50015391c4f10ce2e3053',
    'port/fivem/code/client/citicore/MappingDiagnostics.h': '9cab07670dfcbd4134d5d60af5d28e745c753576c12107b270b0a8f3df033b31',
    'native/windows-core/CMakeLists.txt': '37ed38171fcaf4b02ead24e53ac05a7f7579f360cb74343ce9abab164f79bbac',
    'research/core-mapping-diagnostic-build.json': 'ad15b0705afa4a488140c0afb76b2c421682cdc0983897ebf79c453846e4e326',
    'build/windows-core/CoreRT.dll': 'a9f4262d7f0d35b7e87e89d84cb00ed2007ca2dd297a0ae802d2c6877738f0a0',
    'build/windows-core/clang_23.1_cxx17_64_md_relwithdebinfo/tbb12.dll': 'facbb8c13497defb47191774081fba51fb421991da7eecbb828f9eb493b1d97c',
    'build/windows-core-mapping-diagnostic/CoreRT.dll': 'de1d88338377a1463cf9107656ba4a9669f1da087a136f2bcfad2a4eee031377',
}
INCLUDE = b'#include "FilePolicyDiagnostics.h"\r\n'
ANCHOR = b'#include "HookDiagnostics.h"\r\n'
PREDICATE = b'IsMappedFilename(moduleNameStr)'
FUNCTIONS = (
    (b'NTSTATUS WINAPI NtCreateFileStub(', b'NTSTATUS(WINAPI* g_origNtOpenFile)', 'Create'),
    (b'NTSTATUS WINAPI NtOpenFileStub(', b'typedef struct _FILE_RENAME_INFORMATION', 'Open'),
)
WRAPPERS = {operation: (b'cfx::compat::TraceMappingFilePolicy(cfx::compat::MappingFileOperation::'
                        + operation.encode() + b', moduleNameStr, ' + PREDICATE + b')')
            for _, _, operation in FUNCTIONS}
MARKER = b'Own compile-only file-policy diagnostic overlay\n'
TEST_COUNT = 6
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
        raise RuntimeError('Require a local regular single-link code/evidence file: ' + str(path))
    return info


def sha(path):
    regular_file(path)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def identity(path):
    digest = sha(path)
    return {'path': str(path.relative_to(ROOT)), 'bytes': path.stat().st_size, 'sha256': digest}


def _section(source, start, end):
    if source.count(start) != 1 or source.count(end) != 1:
        raise RuntimeError('Unexpected file-hook function boundary inventory')
    begin = source.index(start)
    finish = source.index(end, begin)
    return begin, finish, source[begin:finish]


def wrap_mapping(source):
    if source.count(ANCHOR) != 1 or INCLUDE in source:
        raise RuntimeError('Require the exact unmodified v6 hook-header include')
    overlay = source
    for start, end, operation in FUNCTIONS:
        begin, finish, body = _section(overlay, start, end)
        condition = b'\t\tif (' + PREDICATE + b')\r\n'
        if body.count(condition) != 1 or body.count(PREDICATE) != 1:
            raise RuntimeError('Require exactly one original predicate in each target NT file stub')
        changed = body.replace(condition, b'\t\tif (' + WRAPPERS[operation] + b')\r\n', 1)
        overlay = overlay[:begin] + changed + overlay[finish:]
    overlay = overlay.replace(ANCHOR, ANCHOR + INCLUDE, 1)
    if strip_mapping(overlay) != source:
        raise RuntimeError('Removing the two wrappers and include must recover exact v6 bytes')
    return overlay


def strip_mapping(overlay):
    if overlay.count(INCLUDE) != 1 or overlay.count(b'cfx::compat::TraceMappingFilePolicy(') != 2:
        raise RuntimeError('Unexpected file-policy overlay call/include inventory')
    result = overlay
    for start, end, operation in FUNCTIONS:
        begin, finish, body = _section(result, start, end)
        if body.count(WRAPPERS[operation]) != 1 or result.count(WRAPPERS[operation]) != 1:
            raise RuntimeError('Unexpected file-policy operation or target function')
        result = result[:begin] + body.replace(WRAPPERS[operation], PREDICATE, 1) + result[finish:]
    return result.replace(INCLUDE, b'', 1)


def safe_write(path, payload):
    if not path.is_relative_to(BUILD) and path != RECORD:
        raise RuntimeError('Write outside the separate file-policy build/report')
    regular_file(path, allow_missing=True)
    path.write_bytes(payload)


def check_build_tree():
    _plain_path(BUILD, ROOT)
    if BUILD.exists():
        if not BUILD.is_dir() or sha(BUILD / '.file-policy-diagnostic-build') != hashlib.sha256(MARKER).hexdigest():
            raise RuntimeError('Existing build directory has no exact own marker')
        for directory, folders, files in os.walk(BUILD, followlinks=False):
            for name in folders:
                _plain_path(Path(directory) / name, ROOT)
            for name in files:
                regular_file(Path(directory) / name)
    else:
        BUILD.mkdir(parents=True)
        safe_write(BUILD / '.file-policy-diagnostic-build', MARKER)


def main():
    pinned = {**PINNED_ORIGINAL, BASE_RECORD: BASE_RECORD_SHA, BASE_MAPPING: BASE_MAPPING_SHA,
              BASE_CMAKE: BASE_CMAKE_SHA, BASE_HEADER: BASE_HEADER_SHA, BASE_CORE: BASE_CORE_SHA, BASE_TBB: BASE_TBB_SHA}
    for name, digest in pinned.items():
        if sha(ROOT / name) != digest:
            raise RuntimeError('Pinned v6 or original code/evidence input changed: ' + name)
    v6 = json.loads((ROOT / BASE_RECORD).read_text())
    for items, expected in ((v6.get('source_evidence'), BASE_SOURCES), (v6.get('generated_overlay'), BASE_GENERATED)):
        if (not isinstance(items, list) or len(items) != len(expected)
                or any(not isinstance(item, dict) or type(item.get('path')) is not str for item in items)
                or {item['path'] for item in items} != expected):
            raise RuntimeError('Unexpected v6 source/overlay path set')
    for item in v6['source_evidence'] + v6['generated_overlay']:
        if sha(ROOT / item['path']) != item['sha256']:
            raise RuntimeError('Bound v6 source or overlay changed')
        pinned[item['path']] = item['sha256']
    base_mapping = (ROOT / BASE_MAPPING).read_bytes()
    overlay_mapping = wrap_mapping(base_mapping)
    check_build_tree()
    _plain_path(OVERLAY, ROOT)
    OVERLAY.mkdir(exist_ok=True)
    for name, payload in (
            ('FileMapping.Win32.cpp', overlay_mapping), ('CMakeLists.txt', (ROOT / BASE_CMAKE).read_bytes()),
            ('HookDiagnostics.h', (ROOT / BASE_HEADER).read_bytes()),
            ('FilePolicyDiagnostics.h', (HERE / 'FilePolicyDiagnostics.h').read_bytes())):
        safe_write(OVERLAY / name, payload)
    test_log = BUILD / 'header-tests.log'
    regular_file(test_log, allow_missing=True)
    test_command = [sys.executable, '-m', 'unittest', 'discover', '-s', str(HERE),
                    '-p', 'test_file_policy_diagnostics.py', '-v']
    with test_log.open('w') as output:
        tests = subprocess.run(test_command, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT)
    test_output = test_log.read_text()
    if tests.returncode != 0 or 'Ran 6 tests' not in test_output or re.search(r'(?m)^OK\s*$', test_output) is None:
        raise RuntimeError('Require all six real file-policy header/overlay checks')
    toolchain = ROOT / 'native/windows-core/toolchain.cmake'
    commands = [
        ['cmake', '-S', str(OVERLAY), '-B', str(BUILD), '-G', 'Ninja',
         '-DCMAKE_TOOLCHAIN_FILE=' + str(toolchain), '-DCMAKE_POLICY_VERSION_MINIMUM=3.5',
         '-DCMAKE_BUILD_TYPE=RelWithDebInfo', '-DCFX_SOURCE_DIR=' + str(ROOT / 'port/fivem'),
         '-DCFX_CORE_MAPPING_DIAGNOSTICS=ON', '-DCFX_CORE_ACCOUNT_FREE_TESTS=OFF',
         '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON'],
        ['cmake', '--build', str(BUILD), '--target', 'CoreRT', '--parallel', '4']]
    build_log = BUILD / 'build.log'
    regular_file(build_log, allow_missing=True)
    with build_log.open('w') as output:
        for command in commands:
            result = subprocess.run(command, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT)
            if result.returncode != 0:
                raise RuntimeError('Separate file-policy diagnostic Core build failed; see ' + str(build_log))
    core = BUILD / 'CoreRT.dll'
    tbb = list(BUILD.glob('*/tbb12.dll'))
    if len(tbb) != 1:
        raise RuntimeError('Require one actually built TBB DLL')
    for binary in (core, tbb[0]):
        raw = binary.read_bytes()
        offset = struct.unpack_from('<I', raw, 60)[0]
        if (raw[offset:offset + 4] != b'PE\0\0' or struct.unpack_from('<H', raw, offset + 4)[0] != 0x8664
                or not struct.unpack_from('<H', raw, offset + 22)[0] & 0x2000):
            raise RuntimeError('Require actual AMD64 PE DLL artifacts')
    compiled = json.loads((BUILD / 'compile_commands.json').read_text())
    mapping_commands = [item for item in compiled if Path(item['file']).name == 'FileMapping.Win32.cpp']
    if len(mapping_commands) != 1 or Path(mapping_commands[0]['file']) != OVERLAY / 'FileMapping.Win32.cpp':
        raise RuntimeError('Only the new separate mapping overlay must be compiled')
    command = mapping_commands[0]['command']
    flags = set(shlex.split(command))
    if (not flags.intersection(('/MD', '-MD'))
            or flags.intersection(('/MT', '-MT', '/MDd', '-MDd', '/MTd', '-MTd'))
            or not all(flag in command for flag in ('CFX_CORE_MAPPING_DIAGNOSTICS', 'COMPILING_CORE'))):
        raise RuntimeError('Require actual /MD diagnostic CoreRT compilation')
    if any('CFX_CORE_ACCOUNT_FREE_TESTS' in item['command'] or 'IS_FXSERVER' in item['command'] for item in compiled):
        raise RuntimeError('Unexpected test instrumentation or server definition')
    if pinned != {name: sha(ROOT / name) for name in pinned}:
        raise RuntimeError('Original or v6 inputs changed during separate compilation')
    report = {
        'at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'compiled': True,
        'source_revision': v6['source_revision'], 'base_v6_build_record': identity(ROOT / BASE_RECORD),
        'base_v6_overlay': identity(ROOT / BASE_MAPPING), 'artifact': identity(core), 'tbb_artifact': identity(tbb[0]),
        'source_evidence': [identity(HERE / name) for name in ('build.py', 'FilePolicyDiagnostics.h', 'test_file_policy_diagnostics.py')],
        'generated_overlay': [identity(OVERLAY / name) for name in
                              ('CMakeLists.txt', 'FileMapping.Win32.cpp', 'HookDiagnostics.h', 'FilePolicyDiagnostics.h')],
        'scope_proof': {'wrapper_count': 2, 'operations': ['create', 'open'],
            'original_predicate_evaluated_once': True, 'original_boolean_return_preserved': True,
            'stripped_mapping_sha256': hashlib.sha256(strip_mapping(overlay_mapping)).hexdigest(),
            'stripped_mapping_equals_exact_v6_bytes': strip_mapping(overlay_mapping) == base_mapping,
            'cmake_equals_exact_v6_bytes': sha(OVERLAY / 'CMakeLists.txt') == BASE_CMAKE_SHA,
            'hook_header_equals_exact_v6_bytes': sha(OVERLAY / 'HookDiagnostics.h') == BASE_HEADER_SHA,
            'existing_hook_expressions_tls_gates_callbacks_or_returns_changed': False,
            'mapping_filename_policy_changed': False, 'additional_module_or_file_api_probes': False},
        'build': {'directory': str(BUILD.relative_to(ROOT)), 'commands': commands, 'exit': 0,
            'CFX_SOURCE_DIR': 'port/fivem', 'CFX_CORE_MAPPING_DIAGNOSTICS': 'ON', 'CFX_CORE_ACCOUNT_FREE_TESTS': 'OFF',
            'runtime': '/MD', 'target': 'AMD64 Windows CoreRT', 'toolchain': identity(toolchain),
            'log': identity(build_log), 'compile_commands': identity(BUILD / 'compile_commands.json'),
            'source_scope': identity(BUILD / 'source-scope.txt')},
        'header_and_overlay_tests': {'command': test_command, 'exit': 0, 'passed': TEST_COUNT, 'log': identity(test_log),
            'scope': 'Real header ON/OFF with own WinAPI stubs; exact basename and ASCII fragments; preserved bool, predicate evaluation, LastError; exact reversible two-expression overlay'},
        'payload': {'fixed_prefix': 'CFX_MAPPING_FILE',
            'fields': ['pid', 'operation', 'allowed', 'canonical_fragment', 'folded_fragment', 'nt_prefix'],
            'operations': ['create', 'open'], 'filename_filter': 'exact socialclub.dll basename, ASCII case-insensitive',
            'canonical_fragment_literal': 'Files\\Rockstar Games\\Social Club', 'folding': 'ASCII A-Z only',
            'nt_prefix_literal': '\\??\\', 'paths_pointers_auth_or_profile_values_logged': False,
            'last_error_after_original_predicate_preserved': True, 'default': 'OFF'},
        'preserved_original_and_v6_input_sha256': pinned, 'wine_client_or_game_started': False,
        'stage_or_prefix_accessed': False, 'existing_patch_queue_changed': False, 'runtime_tested': False}
    safe_write(RECORD, (json.dumps(report, indent=2) + '\n').encode())
    print('Separate full Core file-policy diagnostic build and six header/overlay tests PASS; no staging or Wine', flush=True)


if __name__ == '__main__':
    main()
