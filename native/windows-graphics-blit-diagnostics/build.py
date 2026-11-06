#!/usr/bin/env python3
"""Compile one diagnostic TU substitution against the frozen V12 graphics recipe."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import types

import overlay

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BASE = ROOT / 'build/windows-graphics-window-diagnostics'
BUILD = ROOT / 'build/windows-graphics-blit-diagnostics'
REPORT = ROOT / 'research/graphics-blit-diagnostics-build.json'
BASE_REPORT = ROOT / 'research/graphics-window-diagnostics-build.json'
BASE_REPORT_PIN = (70999, '83da0a6ae0e4576c85e7d1d6985eeb2de5b791e891b5b0d05cd9adeae5e6b0a6')
BASE_RECIPE = ROOT / 'native/windows-graphics-window-diagnostics/build.py'
BASE_RECIPE_PIN = (19862, 'a4699504225e7b368ce6afb76ab69cbf8445970230536da38ba1ffc9107f872c')


def load_module(path, payload):
    mod = types.ModuleType('_blit_' + path.stem)
    mod.__file__ = str(path)
    exec(compile(payload, str(path), 'exec'), mod.__dict__)
    return mod


def base_reader():
    if BASE_RECIPE.resolve(strict=True) != BASE_RECIPE or not BASE_RECIPE.is_file() or BASE_RECIPE.stat().st_nlink != 1:
        raise RuntimeError('Require regular frozen V12 builder')
    payload = BASE_RECIPE.read_bytes()
    if (len(payload), hashlib.sha256(payload).hexdigest()) != BASE_RECIPE_PIN:
        raise RuntimeError('Unexpected V12 builder identity')
    return load_module(BASE_RECIPE, payload)


def imports(inspection):
    return {
        re.search(r'^  Name: (.+)$', section, re.M)[1].casefold():
            sorted(re.findall(r'^  Symbol: (.*?) \(\d+\)$', section, re.M))
        for section in re.findall(r'^Import \{\n(.*?)^\}', inspection, re.M | re.S)
    }


def main():
    if sys.argv[1:]:
        raise ValueError('No configurable source or output roles')
    reader = base_reader()
    for path in (BUILD, REPORT):
        reader.plain(path)
        if path.exists():
            raise RuntimeError('Refusing to overwrite an existing candidate build or report')

    frozen_report = reader.bound(BASE_REPORT, BASE_REPORT_PIN)
    baseline = json.loads(frozen_report)
    if not baseline['compiled'] or not baseline['baseline_preserved'] or baseline['hresult_fix_applied']:
        raise RuntimeError('Require the completed trace-only V12 build')

    def verify(row):
        return reader.bound(ROOT / row['path'], (row['bytes'], row['sha256']))

    dependencies = {row['path']: row for row in (
        baseline['baseline_evidence'] + baseline['source_evidence'] + baseline['generated_overlay']
        + baseline['compiler_support_tools'] + [baseline[key] for key in (
            'artifact', 'generated_build_configuration', 'pe_inspection', 'source_recipe_source')])}
    for row in dependencies.values():
        verify(row)

    original = reader.bound(ROOT / overlay.SOURCE, overlay.SOURCE_PIN)
    patched = overlay.apply(original)
    if overlay.strip(patched) != original:
        raise RuntimeError('DrawCommands overlay is not reversible')
    candidate = BUILD / 'overlay/DrawCommands.cpp'
    old_token = f'"{ROOT / overlay.SOURCE}"'.encode()
    new_token = f'"{candidate}"'.encode()
    definition = f'set_source_files_properties({new_token.decode()} PROPERTIES COMPILE_DEFINITIONS "{overlay.DEFINE}=1")\n'.encode()
    base_cmake = verify(baseline['generated_build_configuration'])
    if base_cmake.count(old_token) != 1 or overlay.DEFINE.encode() in base_cmake:
        raise RuntimeError('Unexpected V12 CMake source scope')
    cmake = base_cmake.replace(old_token, new_token, 1) + definition
    if cmake[:-len(definition)].replace(new_token, old_token, 1) != base_cmake:
        raise RuntimeError('CMake derivation is not reversible')
    commands = baseline['build']['commands']
    if len(commands) != 2 or [cmd.count(str(BASE)) for cmd in commands] != [2, 1]:
        raise RuntimeError('Unexpected configure/build command roles')
    commands = [[str(BUILD) if arg == str(BASE) else arg for arg in cmd] for cmd in commands]
    local_sources = [reader.identity(HERE / name) for name in ('build.py', 'overlay.py', overlay.HEADER, 'test_overlay.py')]
    build_command = [sys.executable, '-B', '-m', 'unittest', 'discover', '-s', str(HERE), '-p', 'test_overlay.py', '-v']

    BUILD.mkdir()
    result = {
        'compiled': False, 'runtime_started': False, 'stage_or_prefix_modified': False,
        'source_revision': baseline['source_revision'], 'baseline_record': reader.identity(BASE_REPORT),
        'baseline_artifact': baseline['artifact'], 'frozen_input_count': len(dependencies),
        'source_evidence': local_sources, 'compile_commands_invoked': commands,
    }
    phase = 'overlay-tests'
    try:
        candidate.parent.mkdir()
        candidate.write_bytes(patched)
        header = candidate.parent / overlay.HEADER
        header.write_bytes(reader.read(HERE / overlay.HEADER))
        cmake_path = BUILD / 'CMakeLists.txt'
        cmake_path.write_bytes(cmake)
        with (BUILD / 'overlay-tests.log').open('x') as log:
            subprocess.run(build_command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, check=True)

        environment = dict(os.environ)
        for key in ('CL', '_CL_', 'CFLAGS', 'CXXFLAGS', 'CPPFLAGS', 'LDFLAGS', 'INCLUDE', 'LIB', 'LIBPATH'):
            environment.pop(key, None)
        with (BUILD / 'build.log').open('x') as log:
            for phase, command in zip(('configure', 'compile-link'), commands):
                subprocess.run(command, cwd=ROOT, env=environment, stdout=log, stderr=subprocess.STDOUT, check=True)

        phase = 'verify-output'
        binary = BUILD / 'rage-graphics-five.dll'
        inspection_path = BUILD / 'pe-inspection.txt'
        llvm = baseline['compiler_support_tools'][1]['path']
        inspection = subprocess.check_output([llvm, '--file-headers', '--coff-imports', '--coff-exports',
                                               '--coff-resources', str(binary)], text=True)
        inspection_path.write_text(inspection)
        source_recipe = baseline['source_recipe_source']
        helper = load_module(ROOT / source_recipe['path'], verify(source_recipe))
        exports = helper.export_index(reader.read(binary))
        export_signature = lambda table: {(row['name'], row['kind'], row['ordinal']) for row in table['exports']}
        before_imports = imports(verify(baseline['pe_inspection']).decode())
        after_imports = imports(inspection)
        if (len(exports['exports']) != 80 or export_signature(exports) != export_signature(baseline['export_metadata'])
                or not before_imports or before_imports != after_imports
                or 'IMAGE_FILE_MACHINE_AMD64' not in inspection or 'FXCOMPONENT' not in inspection.upper()):
            result['import_delta'] = {
                key: {'added': sorted(set(after_imports.get(key, ())) - set(before_imports.get(key, ()))),
                      'removed': sorted(set(before_imports.get(key, ())) - set(after_imports.get(key, ())))}
                for key in sorted(before_imports.keys() | after_imports.keys())
                if before_imports.get(key) != after_imports.get(key)
            }
            raise RuntimeError('Graphics PE export/import/resource verification failed')
        compile_db = BUILD / 'compile_commands.json'
        entries = json.loads(reader.read(compile_db))
        compiled = [entry for entry in entries if overlay.DEFINE in entry['command']]
        if len(entries) != 14 or len(compiled) != 1 or compiled[0]['file'] != str(candidate):
            raise RuntimeError('Require one translated diagnostics TU and the original source count')
        for row in list(dependencies.values()) + local_sources:
            verify(row)
        if reader.bound(BASE_REPORT, BASE_REPORT_PIN) != frozen_report:
            raise RuntimeError('V12 record changed during build')
        result.update(
            compiled=True, artifact=reader.identity(binary), baseline_preserved=True,
            generated_overlay=[reader.identity(path) for path in (candidate, header, cmake_path)],
            compile_database=reader.identity(compile_db), pe_inspection=reader.identity(inspection_path),
            exports_match_v12=80, import_symbols_match_v12=True,
            source_overlay_reverses_to_original=True, configuration_reverses_to_v12=True,
            export_instrumentation=['PushDrawBlitImShader', 'grcBegin', 'grcVertex', 'grcEnd', 'PopDrawBlitImShader'],
            checkpoint='glue_caller_origin_anchored_quad_before_drawImVertices',
            max_records_per_process=64, viewport_units_per_pixel=16, rtv_slot=0,
            menu_identity_proved=False, runtime_compatibility_proved=False,
        )
    except Exception as error:
        result.update(failure_phase=phase, failure_type=type(error).__name__, failure_message=str(error))
    for name in ('overlay-tests.log', 'build.log'):
        if (BUILD / name).is_file():
            result[name] = reader.identity(BUILD / name)
    result['at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with REPORT.open('x') as output:
        json.dump(result, output, indent=2)
        output.write('\n')
    print(json.dumps({'compiled': result['compiled'], 'report': reader.identity(REPORT)}))
    return 0 if result['compiled'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
