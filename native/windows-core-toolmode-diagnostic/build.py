#!/usr/bin/env python3
"""Compile a separate reversible public ToolMode diagnostic Core, without Wine."""
import datetime
import hashlib
import importlib.util
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
BUILD = ROOT / 'build/windows-core-toolmode-diagnostic'
OVERLAY = BUILD / 'overlay'
RECORD = ROOT / 'research/core-toolmode-diagnostic-build.json'
BASE_RECORD = 'research/core-file-policy-diagnostic-build.json'
BASE_CMAKE = 'build/windows-core-file-policy-diagnostic/overlay/CMakeLists.txt'
BASE_FILES = {
    'CMakeLists.txt': 'beb5907b6eea81f75c5435569a9edff74f820434a263ad97749f0ab12f759ca9',
    'FileMapping.Win32.cpp': '06c62a368aabf0abf3e249f98272b1bb2466fe63dc92b927c49497f97566f156',
    'HookDiagnostics.h': 'ab71b69fa81864d10ad12d08f3fd82b2251e29684e5cac81f5c9a1060140b59d',
    'FilePolicyDiagnostics.h': 'dbd834cd1d94e89886d898c51e3d4946f18c6c071b315cf01e12dcf60d234feb',
}
ORIGINAL = 'port/fivem/code/client/citicore/ToolMode.Win32.cpp'
ORIGINAL_SHA = 'dfe069826208b2f4ce70a66e93b570de4b718125f990cca37efd8c22b86de15d'
PINNED = {
    BASE_RECORD: '14cc3a05f46351f47bc9e98e0bcb42cccffaf9b244d5b45e712ef22dc1f8467c',
    ORIGINAL: ORIGINAL_SHA,
    'build/windows-core-file-policy-diagnostic/CoreRT.dll': '6b895ac942eee539ece652462558144c4a10f8b7e22b4965ba1270008ceca16f',
    'build/windows-core-file-policy-diagnostic/clang_23.1_cxx17_64_md_relwithdebinfo/tbb12.dll':
        '4751126ff5387794ab99dc5ed4caeb0a0e33ab409623edc37728347ca310150e',
    'native/windows-core-file-policy-diagnostic/build.py': '8409623907142b5d7e48e4a1a44f11b2af53f101a8a1a6c8e53ca1ac7d0893cd',
    'native/windows-core-file-policy-diagnostic/FilePolicyDiagnostics.h': 'dbd834cd1d94e89886d898c51e3d4946f18c6c071b315cf01e12dcf60d234feb',
    'native/windows-core-file-policy-diagnostic/test_file_policy_diagnostics.py': 'f0417ec85f1a77ddffc6202ebac010616aa0f1208e0825ce25da606568467912',
}
PINNED.update({'build/windows-core-file-policy-diagnostic/overlay/' + name: digest
               for name, digest in BASE_FILES.items()})
MARKER = b'Own compile-only public ToolMode diagnostic overlay\n'
INCLUDE = b'#include "ToolModeDiagnostics.h"\r\n'
ANCHOR = b'#include "ToolComponent.h"\r\n'
PREFIX = b'cfx::compat::'


def trace(phase, indent=b'\t', value=None):
    argument = b'' if value is None else b', ' + value
    return indent + PREFIX + b'TraceToolMode(' + PREFIX + b'ToolModePhase::' + phase.encode() + argument + b');\r\n'


def wrap_result(expression, phase):
    return PREFIX + b'TraceToolModeResult(' + PREFIX + b'ToolModePhase::' + phase.encode() + b', ' + expression + b')'


REPLACEMENTS = (
    (b'extern "C" DLL_EXPORT void ToolMode_Init()\r\n{\r\n',
     b'extern "C" DLL_EXPORT void ToolMode_Init()\r\n{\r\n' + trace('Enter')),
    (b'\tcomponentLoader->Initialize();\r\n',
     trace('LoaderBefore') + b'\tcomponentLoader->Initialize();\r\n' + trace('LoaderAfter') + trace('InstancesBefore')),
    (b'            instance->Initialize();\r\n',
     trace('InstanceBefore', b'            ') + b'            ' + wrap_result(b'instance->Initialize()', 'InstanceResult') + b';\r\n'),
    (b'\t// instantiate all components, however do not initialize them - also save any components implementing tool functionality\r\n',
     trace('InstancesAfter') + trace('DiscoveryBefore') + b'\t// instantiate all components, however do not initialize them - also save any components implementing tool functionality\r\n'),
    (b'\t// parse program options\r\n', trace('DiscoveryAfter') + b'\t// parse program options\r\n'),
    (b'\t\tconst wchar_t* commandLine = GetCommandLine();\r\n',
     trace('GlobalParserBefore', b'\t\t') + b'\t\tconst wchar_t* commandLine = GetCommandLine();\r\n'),
    (b'\t\tbpo::store(result, globalVars);\r\n',
     b'\t\tbpo::store(result, globalVars);\r\n' + trace('GlobalParserAfter', b'\t\t')),
    (b'globalVars.find("command") == globalVars.end()',
     wrap_result(b'globalVars.find("command") == globalVars.end()', 'CommandMissing')),
    (b'it != toolCommands.end()', wrap_result(b'it != toolCommands.end()', 'CommandMatched')),
    (b'\t\t\tinitDeps(componentData);\r\n',
     trace('DependenciesBefore', b'\t\t\t') + b'\t\t\t' + wrap_result(b'initDeps(componentData)', 'DependenciesResult') + b';\r\n'),
    (b'\t\t\tToolComponent* tool = dynamic_component_cast<ToolComponent*>(component.GetRef());\r\n',
     trace('ToolCastBefore', b'\t\t\t') + b'\t\t\tToolComponent* tool = dynamic_component_cast<ToolComponent*>(component.GetRef());\r\n' +
     trace('ToolCastAfter', b'\t\t\t', b'tool != nullptr')),
    (b'\t\t\tfwRefContainer<ToolCommand> commandImpl = tool->GetCommand(command);\r\n',
     trace('CommandBefore', b'\t\t\t') + b'\t\t\tfwRefContainer<ToolCommand> commandImpl = tool->GetCommand(command);\r\n' +
     trace('CommandAfter', b'\t\t\t')),
    (b'\t\t\tcommandImpl->SetupCommandLineParser(parser,',
     trace('CommandParserBefore', b'\t\t\t') + b'\t\t\tcommandImpl->SetupCommandLineParser(parser,'),
    (b'\t\t\t// execute the command\r\n',
     trace('CommandParserAfter', b'\t\t\t') + b'\t\t\t// execute the command\r\n'),
    (b'\t\t\tcommandImpl->InvokeCommand(vm);\r\n',
     trace('InvokeBefore', b'\t\t\t') + b'\t\t\tcommandImpl->InvokeCommand(vm);\r\n' + trace('InvokeAfter', b'\t\t\t')),
    (b'\t\t\tprintf("Command [%s] is unknown to this tool.\\n", command.c_str());\r\n',
     trace('UnknownCommand', b'\t\t\t') + b'\t\t\tprintf("Command [%s] is unknown to this tool.\\n", command.c_str());\r\n'),
    (b'\t\tprintf("Required option missing: %s\\n", e.what());\r\n',
     trace('RequiredOption', b'\t\t') + b'\t\tprintf("Required option missing: %s\\n", e.what());\r\n'),
    (b'\t\tprintf("error: %s\\n", e.what());\r\n',
     trace('OptionsError', b'\t\t') + b'\t\tprintf("error: %s\\n", e.what());\r\n'),
    (b'\t}\r\n}\r\n\r\nstatic void(*g_gameFunction)',
     b'\t}\r\n' + trace('Return') + b'}\r\n\r\nstatic void(*g_gameFunction)'),
)
CMAKE_SELECTION = (b'list(FILTER coreSources EXCLUDE REGEX "/ToolMode[.]Win32[.]cpp$")\n'
                   b'list(APPEND coreSources "${CMAKE_CURRENT_SOURCE_DIR}/ToolMode.Win32.cpp")\n')
CMAKE_OPTION = (b'option(CFX_CORE_TOOLMODE_DIAGNOSTICS "Emit fixed-field public ToolMode diagnostics" OFF)\n'
                b'if(CFX_CORE_TOOLMODE_DIAGNOSTICS)\n'
                b'  target_compile_definitions(CoreRT PRIVATE CFX_CORE_TOOLMODE_DIAGNOSTICS)\n'
                b'endif()\n')
TEST_COUNT = 8
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
        raise RuntimeError('Require a regular single-link code/evidence file: ' + str(path))
    return info


def sha(path):
    regular_file(path)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def identity(path):
    digest = sha(path)
    return {'path': str(path.relative_to(ROOT)), 'bytes': path.stat().st_size, 'sha256': digest}


def wrap_toolmode(original):
    if original.count(ANCHOR) != 1 or INCLUDE in original or PREFIX in original:
        raise RuntimeError('Require the original public ToolMode source')
    result = original.replace(ANCHOR, ANCHOR + INCLUDE, 1)
    for before, after in REPLACEMENTS:
        if result.count(before) != 1:
            raise RuntimeError('Changed original ToolMode expression inventory: ' + repr(before))
        result = result.replace(before, after, 1)
    if strip_toolmode(result) != original:
        raise RuntimeError('ToolMode diagnostic removal must recover the exact original bytes')
    return result


def strip_toolmode(overlay):
    if overlay.count(INCLUDE) != 1:
        raise RuntimeError('Unexpected ToolMode diagnostic include inventory')
    result = overlay
    for before, after in reversed(REPLACEMENTS):
        if result.count(after) != 1:
            raise RuntimeError('Changed diagnostic expression inventory: ' + repr(after))
        result = result.replace(after, before, 1)
    result = result.replace(INCLUDE, b'', 1)
    if PREFIX in result:
        raise RuntimeError('Unrecognized ToolMode diagnostic expression')
    return result


def wrap_cmake(original):
    if b'CFX_CORE_TOOLMODE_DIAGNOSTICS' in original:
        raise RuntimeError('Require the unmodified v7 CMake overlay')
    before = b'add_library(CoreRT SHARED ${coreSources})\n'
    if original.count(before) != 1:
        raise RuntimeError('Unexpected CoreRT selection inventory')
    result = original.replace(before, CMAKE_SELECTION + before + CMAKE_OPTION, 1)
    if strip_cmake(result) != original:
        raise RuntimeError('CMake diagnostic removal must recover exact v7 bytes')
    return result


def strip_cmake(overlay):
    if overlay.count(CMAKE_SELECTION) != 1 or overlay.count(CMAKE_OPTION) != 1:
        raise RuntimeError('Unexpected ToolMode diagnostic CMake selection')
    return overlay.replace(CMAKE_SELECTION, b'', 1).replace(CMAKE_OPTION, b'', 1)


def safe_write(path, payload):
    if not path.is_relative_to(BUILD) and path != RECORD:
        raise RuntimeError('Write outside the separate ToolMode diagnostic build/report')
    regular_file(path, allow_missing=True)
    path.write_bytes(payload)


def check_build_tree():
    _plain_path(BUILD, ROOT)
    if BUILD.exists():
        if not BUILD.is_dir() or sha(BUILD / '.toolmode-diagnostic-build') != hashlib.sha256(MARKER).hexdigest():
            raise RuntimeError('Existing build directory lacks its exact own marker')
        for directory, folders, files in os.walk(BUILD, followlinks=False):
            for name in folders:
                _plain_path(Path(directory) / name, ROOT)
            for name in files:
                regular_file(Path(directory) / name)
    else:
        BUILD.mkdir(parents=True)
        safe_write(BUILD / '.toolmode-diagnostic-build', MARKER)


def main():
    for name, digest in PINNED.items():
        if sha(ROOT / name) != digest:
            raise RuntimeError('Pinned v7 or original ToolMode input changed: ' + name)
    previous = json.loads((ROOT / BASE_RECORD).read_text())
    expected_sources = {name for name in PINNED if name.startswith('native/windows-core-file-policy-diagnostic/')}
    expected_generated = {'build/windows-core-file-policy-diagnostic/overlay/' + name for name in BASE_FILES}
    for field, expected in (('source_evidence', expected_sources), ('generated_overlay', expected_generated)):
        items = previous.get(field)
        if (not isinstance(items, list) or len(items) != len(expected)
                or any(not isinstance(item, dict) or type(item.get('path')) is not str for item in items)
                or {item['path'] for item in items} != expected):
            raise RuntimeError('Unexpected v7 evidence path set')
        for item in items:
            if item.get('sha256') != PINNED[item['path']] or sha(ROOT / item['path']) != item['sha256']:
                raise RuntimeError('V7 identity does not match the fixed input')
    original = (ROOT / ORIGINAL).read_bytes()
    original_cmake = (ROOT / BASE_CMAKE).read_bytes()
    toolmode = wrap_toolmode(original)
    cmake = wrap_cmake(original_cmake)
    check_build_tree()
    _plain_path(OVERLAY, ROOT)
    OVERLAY.mkdir(exist_ok=True)
    generated = {'CMakeLists.txt': cmake, 'ToolMode.Win32.cpp': toolmode,
                 'ToolModeDiagnostics.h': (HERE / 'ToolModeDiagnostics.h').read_bytes()}
    for name in ('FileMapping.Win32.cpp', 'HookDiagnostics.h', 'FilePolicyDiagnostics.h'):
        generated[name] = (ROOT / 'build/windows-core-file-policy-diagnostic/overlay' / name).read_bytes()
    for name, payload in generated.items():
        safe_write(OVERLAY / name, payload)
    test_command = [sys.executable, '-m', 'unittest', 'discover', '-s', str(HERE), '-p', 'test_toolmode_diagnostics.py', '-v']
    test_log = BUILD / 'header-tests.log'
    regular_file(test_log, allow_missing=True)
    with test_log.open('w') as output:
        result = subprocess.run(test_command, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT)
    test_output = test_log.read_text()
    if result.returncode != 0 or f'Ran {TEST_COUNT} tests' not in test_output or re.search(r'(?m)^OK\s*$', test_output) is None:
        raise RuntimeError('Require all real ToolMode header/wrapper/scope checks')
    toolchain = ROOT / 'native/windows-core/toolchain.cmake'
    commands = [
        ['cmake', '-S', str(OVERLAY), '-B', str(BUILD), '-G', 'Ninja',
         '-DCMAKE_TOOLCHAIN_FILE=' + str(toolchain), '-DCMAKE_POLICY_VERSION_MINIMUM=3.5',
         '-DCMAKE_BUILD_TYPE=RelWithDebInfo', '-DCFX_SOURCE_DIR=' + str(ROOT / 'port/fivem'),
         '-DCFX_CORE_MAPPING_DIAGNOSTICS=ON', '-DCFX_CORE_TOOLMODE_DIAGNOSTICS=ON',
         '-DCFX_CORE_ACCOUNT_FREE_TESTS=OFF', '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON'],
        ['cmake', '--build', str(BUILD), '--target', 'CoreRT', '--parallel', '4']]
    build_log = BUILD / 'build.log'
    regular_file(build_log, allow_missing=True)
    with build_log.open('w') as output:
        for command in commands:
            built = subprocess.run(command, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT)
            if built.returncode != 0:
                raise RuntimeError('Separate ToolMode diagnostic Core build failed; see ' + str(build_log))
    core = BUILD / 'CoreRT.dll'
    tbb = list(BUILD.glob('*/tbb12.dll'))
    if len(tbb) != 1:
        raise RuntimeError('Require one actually built TBB DLL')
    for binary in (core, tbb[0]):
        regular_file(binary)
        raw = binary.read_bytes()
        offset = struct.unpack_from('<I', raw, 60)[0]
        if (raw[offset:offset + 4] != b'PE\0\0' or struct.unpack_from('<H', raw, offset + 4)[0] != 0x8664
                or not struct.unpack_from('<H', raw, offset + 22)[0] & 0x2000):
            raise RuntimeError('Require actual AMD64 PE DLL artifacts')
    compiled = json.loads((BUILD / 'compile_commands.json').read_text())
    overlay_commands = {}
    for name in ('FileMapping.Win32.cpp', 'ToolMode.Win32.cpp'):
        matches = [item for item in compiled if Path(item['file']).name == name]
        if len(matches) != 1 or Path(matches[0]['file']) != OVERLAY / name:
            raise RuntimeError('Require exactly the separate selected source overlay: ' + name)
        command = matches[0]['command']
        flags = set(shlex.split(command))
        if (not flags.intersection(('/MD', '-MD'))
                or flags.intersection(('/MT', '-MT', '/MDd', '-MDd', '/MTd', '-MTd'))
                or not all(flag in command for flag in ('CFX_CORE_TOOLMODE_DIAGNOSTICS', 'CFX_CORE_MAPPING_DIAGNOSTICS', 'COMPILING_CORE'))):
            raise RuntimeError('Require actual /MD opt-in diagnostic CoreRT compilation')
        overlay_commands[name] = command
    if any('CFX_CORE_ACCOUNT_FREE_TESTS' in item['command'] or 'IS_FXSERVER' in item['command'] for item in compiled):
        raise RuntimeError('Unexpected test instrumentation or server definition')
    if PINNED != {name: sha(ROOT / name) for name in PINNED}:
        raise RuntimeError('Original or v7 inputs changed during separate compilation')
    report = {
        'at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'compiled': True,
        'source_revision': previous['source_revision'], 'base_v7_build_record': identity(ROOT / BASE_RECORD),
        'base_v7_overlay': [identity(ROOT / 'build/windows-core-file-policy-diagnostic/overlay' / name) for name in BASE_FILES],
        'original_toolmode': identity(ROOT / ORIGINAL), 'artifact': identity(core), 'tbb_artifact': identity(tbb[0]),
        'source_evidence': [identity(HERE / name) for name in ('build.py', 'ToolModeDiagnostics.h', 'test_toolmode_diagnostics.py')],
        'generated_overlay': [identity(OVERLAY / name) for name in generated],
        'scope_proof': {
            'stripped_toolmode_equals_exact_original_bytes': strip_toolmode(toolmode) == original,
            'stripped_toolmode_sha256': hashlib.sha256(strip_toolmode(toolmode)).hexdigest(),
            'stripped_cmake_equals_exact_v7_bytes': strip_cmake(cmake) == original_cmake,
            'stripped_cmake_sha256': hashlib.sha256(strip_cmake(cmake)).hexdigest(),
            'v7_mapping_and_headers_byte_identical': all(sha(OVERLAY / name) == BASE_FILES[name] for name in
                                                       ('FileMapping.Win32.cpp', 'HookDiagnostics.h', 'FilePolicyDiagnostics.h')),
            'original_expressions_evaluated_once': True, 'original_boolean_results_preserved': True,
            'dependency_initialization_result_still_ignored': True,
            'original_toolmode_controlflow_catches_callbacks_and_arguments_changed': False,
            'private_mtl_invoke_implementation_changed': False,
            'auth_anticheat_integrity_or_filename_policy_changed': False},
        'build': {'directory': str(BUILD.relative_to(ROOT)), 'commands': commands, 'exit': 0,
                  'CFX_SOURCE_DIR': 'port/fivem', 'CFX_CORE_MAPPING_DIAGNOSTICS': 'ON',
                  'CFX_CORE_TOOLMODE_DIAGNOSTICS': 'ON', 'CFX_CORE_ACCOUNT_FREE_TESTS': 'OFF',
                  'runtime': '/MD', 'target': 'AMD64 Windows CoreRT', 'toolchain': identity(toolchain),
                  'log': identity(build_log), 'compile_commands': identity(BUILD / 'compile_commands.json'),
                  'source_scope': identity(BUILD / 'source-scope.txt'), 'overlay_compile_commands': overlay_commands},
        'header_and_overlay_tests': {'command': test_command, 'exit': 0, 'passed': TEST_COUNT,
                  'log': identity(test_log),
                  'scope': 'Actual header ON/OFF; fixed payload; bool/LastError/single evaluation; real original-vs-overlay ToolMode execution under own native dependency doubles; exact reversible source/CMake scope'},
        'payload': {'fixed_prefix': 'CFX_TOOLMODE', 'fields': ['pid', 'phase', 'value'],
                    'value_range': [0, 1], 'phase_vocabulary': toolmode_phase_names(),
                    'paths_pointers_commands_arguments_components_exceptions_auth_or_profile_values_logged': False,
                    'last_error_after_original_expression_preserved': True, 'default': 'OFF'},
        'preserved_original_and_v7_input_sha256': PINNED, 'wine_client_or_game_started': False,
        'stage_or_prefix_accessed': False, 'existing_patch_queue_changed': False, 'runtime_tested': False}
    safe_write(RECORD, (json.dumps(report, indent=2) + '\n').encode())
    print('Separate public ToolMode Core build and header/wrapper tests PASS; no staging or Wine', flush=True)


def toolmode_phase_names():
    raw = (HERE / 'ToolModeDiagnostics.h').read_text()
    return re.findall(r'case ToolModePhase::\w+: return "([a-z.-]+)";', raw)


if __name__ == '__main__':
    main()
