#!/usr/bin/env python3
"""Build the existing owned-hook correction against the isolated 88a4138 CoreRT inputs."""
import difflib
import hashlib
import importlib.util
import json
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'build/windows-main-candidate-27nal69i/source'
REVISION = '88a413835e9d7f56633f249880a13f42297153a2'
COMPONENT = 'code/client/citicore/DllGameComponent.Win32.cpp'
COMPONENT_SHA256 = 'e6cdafd33575617581727744a37b8a41ed258590f2d1e08a839ffeb9f3f0c9ce'
PREVIOUS = ROOT / 'native/windows-core-null-target-fix/build.py'
CMAKE = ROOT / 'native/windows-core/CMakeLists.txt'
TOOLCHAIN = ROOT / 'native/windows-core/toolchain.cmake'
FIXTURE = ROOT / 'native/windows-core-ownership/component_mapping_probe.cpp'
MARKER = ROOT / 'native/windows-mapping-fixture/marker.cpp'


def identity(path):
    data = path.read_bytes()
    return {'path': str(path.relative_to(ROOT)), 'bytes': len(data),
            'sha256': hashlib.sha256(data).hexdigest()}


def finish(folder, record):
    before = record['inputs']
    overlay = folder / 'overlay'
    if before != [identity(ROOT / row['path']) for row in before]:
        raise RuntimeError('A fixed source or build input changed')
    compile_commands = json.loads((folder / 'cmake/compile_commands.json').read_text())
    units = [unit for unit in compile_commands if Path(unit['file']).name == 'DllGameComponent.Win32.cpp']
    if len(units) != 1 or Path(units[0]['file']) != overlay / 'DllGameComponent.Win32.cpp':
        raise RuntimeError('Exactly the corrected source must be compiled')
    flags = set(shlex.split(units[0]['command']))
    if (not flags.intersection(('/MD', '-MD'))
            or flags.intersection(('/MT', '-MT', '/MDd', '-MDd', '/MTd', '-MTd'))
            or 'COMPILING_CORE' not in units[0]['command']):
        raise RuntimeError('Require the ordinary CoreRT /MD compilation')
    if any('CFX_CORE_ACCOUNT_FREE_TESTS' in unit['command'] or 'IS_FXSERVER' in unit['command']
            or 'CFX_CORE_MAPPING_DIAGNOSTICS' in unit['command'] for unit in compile_commands):
        raise RuntimeError('Test/server/mapping instrumentation must remain disabled')
    tbb = list((folder / 'cmake').glob('*/tbb12.dll'))
    if len(tbb) != 1:
        raise RuntimeError('Require one matching built TBB provider')
    fixture_files = [identity(folder / 'cmake/fixture' / name) for name in
        ('ownership_component_probe.exe', 'ownership-source.exe', 'ownership-target.dll', 'windows-fixture.dll')]
    record.update(artifact=identity(folder / 'cmake/CoreRT.dll'), tbb_artifact=identity(tbb[0]),
        fixture_inputs=fixture_files, compiled_source_sha256=identity(overlay / 'DllGameComponent.Win32.cpp')['sha256'],
        original_source_preserved=True, native_tests_passed=3, recipe=identity(Path(__file__)))
    (folder / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({'artifact': record['artifact'], 'tbb_artifact': record['tbb_artifact']}), flush=True)


def main():
    if sys.argv[1:]:
        raise ValueError('This recipe builds only the fixed isolated 88a4138 candidate')
    candidate_record = SOURCE.parent / 'result.json'
    candidate = json.loads(candidate_record.read_text())
    if (candidate.get('revision') != REVISION or candidate.get('build_exit') != 0
            or candidate.get('final_source_hashes_verified') != 26):
        raise RuntimeError('Require the verified isolated candidate source build')
    original = (SOURCE / COMPONENT).read_bytes()
    if hashlib.sha256(original).hexdigest() != COMPONENT_SHA256:
        raise RuntimeError('Candidate optional-hook source changed')
    spec = importlib.util.spec_from_file_location('previous_ownership_builder', PREVIOUS)
    previous = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(previous)
    corrected = previous.wrap_component(original)
    if previous.strip_component(corrected) != original:
        raise RuntimeError('The reused correction must strip to the candidate source')
    before = [identity(path) for path in (SOURCE / COMPONENT, PREVIOUS, CMAKE, TOOLCHAIN,
        candidate_record, FIXTURE, MARKER, ROOT / 'native/windows-tests/core_dll_fixture.cpp')]
    folder = Path(tempfile.mkdtemp(prefix='windows-core-ownership-', dir=ROOT / 'build'))
    overlay = folder / 'overlay'
    overlay.mkdir()
    (overlay / 'DllGameComponent.Win32.cpp').write_bytes(corrected)
    patch = ''.join(difflib.unified_diff(original.decode().splitlines(keepends=True),
        corrected.decode().splitlines(keepends=True), fromfile='a/' + COMPONENT, tofile='b/' + COMPONENT))
    patch_path = folder / 'optional-hook-ownership.patch'
    patch_path.write_bytes(patch.encode())
    subprocess.run(['git', '-C', str(SOURCE), 'apply', '--check', str(patch_path)], check=True)
    cmake = CMAKE.read_bytes()
    anchor = b'add_library(CoreRT SHARED ${coreSources})\n'
    if cmake.count(anchor) != 1:
        raise RuntimeError('Expected one complete CoreRT source selection')
    selection = previous.CMAKE_SELECTION
    fixture_cmake = f'''
add_executable(ownership_component_probe "{FIXTURE}")
add_library(ownership_source SHARED "{MARKER}")
add_library(ownership_target SHARED "{MARKER}")
target_compile_definitions(ownership_source PRIVATE FIXTURE_MARKER=0x46585231)
target_compile_definitions(ownership_target PRIVATE FIXTURE_MARKER=0x46585232)
set_target_properties(ownership_source PROPERTIES PREFIX "" OUTPUT_NAME "ownership-source" SUFFIX ".exe")
set_target_properties(ownership_target PROPERTIES PREFIX "" OUTPUT_NAME "ownership-target")
file(WRITE "${{CFX_GENERATED}}/ownership-fixture.json"
  "{{\\"name\\":\\"windows:fixture\\",\\"version\\":\\"1.2.3.0\\",\\"provides\\":[],\\"dependencies\\":[],\\"shouldAutoInstance\\":true}}")
file(WRITE "${{CFX_GENERATED}}/ownership-fixture.rc"
  "FXCOMPONENT 115 \\"${{CFX_GENERATED}}/ownership-fixture.json\\"\\n")
add_library(ownership_component_fixture SHARED "{ROOT / 'native/windows-tests/core_dll_fixture.cpp'}"
  "${{CFX_GENERATED}}/ownership-fixture.rc")
target_link_libraries(ownership_component_fixture PRIVATE Shared)
set_target_properties(ownership_component_fixture PROPERTIES PREFIX "" OUTPUT_NAME "windows-fixture")
foreach(target ownership_component_probe ownership_source ownership_target ownership_component_fixture)
  set_target_properties(${{target}} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${{CMAKE_BINARY_DIR}}/fixture"
    ARCHIVE_OUTPUT_DIRECTORY "${{CMAKE_BINARY_DIR}}/fixture" PDB_OUTPUT_DIRECTORY "${{CMAKE_BINARY_DIR}}/fixture")
endforeach()
'''
    (overlay / 'CMakeLists.txt').write_bytes(cmake.replace(anchor, selection + anchor, 1) + fixture_cmake.encode())
    record = {'source_revision': REVISION, 'source': str(SOURCE.relative_to(ROOT)),
        'build_directory': str(folder.relative_to(ROOT)), 'inputs': before,
        'corrected_source': identity(overlay / 'DllGameComponent.Win32.cpp'),
        'patch': identity(patch_path), 'recipe': identity(Path(__file__)),
        'ordinary_corert': True, 'account_free_test_instrumentation': False,
        'mapping_diagnostics_enabled': False, 'client_or_account_started': False,
        'source_or_active_stage_modified': False}
    commands = [
        [sys.executable, '-B', '-m', 'unittest', 'discover', '-s', str(PREVIOUS.parent),
            '-p', 'test_null_target_fix.py', '-v'],
        ['cmake', '-S', str(overlay), '-B', str(folder / 'cmake'), '-G', 'Ninja',
            '-DCFX_SOURCE_DIR=' + str(SOURCE), '-DCMAKE_TOOLCHAIN_FILE=' + str(TOOLCHAIN),
            '-DCMAKE_POLICY_VERSION_MINIMUM=3.5', '-DCMAKE_BUILD_TYPE=RelWithDebInfo',
            '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON', '-DCFX_CORE_ACCOUNT_FREE_TESTS=OFF',
            '-DCFX_CORE_MAPPING_DIAGNOSTICS=OFF'],
        ['cmake', '--build', str(folder / 'cmake'), '--target', 'CoreRT', 'ownership_component_probe',
            'ownership_source', 'ownership_target', 'ownership_component_fixture', '--parallel', '6']]
    print(folder, flush=True)
    record['commands'] = commands
    result_path = folder / 'result.json'
    result_path.write_text(json.dumps(record, indent=2) + '\n')
    for name, command in zip(('native-tests', 'configure', 'build'), commands):
        with (folder / (name + '.log')).open('x') as output:
            result = subprocess.run(command, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT)
        record[name + '_exit'] = result.returncode
        result_path.write_text(json.dumps(record, indent=2) + '\n')
        if result.returncode:
            raise RuntimeError(name + ' failed; preserve ' + str(folder))
    finish(folder, record)


if __name__ == '__main__':
    main()
