#!/usr/bin/env python3
"""Build a separate numeric window-diagnostic component from the verified V11 build."""
import builtins
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import types

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
BUILD = ROOT / 'build/windows-graphics-window-diagnostics'
REPORT = ROOT / 'research/graphics-window-diagnostics-build.json'
BASE_BUILD = ROOT / 'build/windows-graphics-diagnostics'
BASE_REPORT = 'research/graphics-swapchain-diagnostics-build.json'
BASE_PIN = (37218, 'a9705c9d54bcc886adae294f681c6144a8ff2b826c31fa9cd9072a99f34f0995')
BASE_ARTIFACT_PIN = (1232384, '2b405d25839176b8e8898344c9ea5e493887adef0fa78cf98d510cfe1ad1f7e7')
BASE_RECIPE = 'native/windows-graphics-diagnostics/build.py'
BASE_RECIPE_PIN = (16357, '64cf8bdba5f1eda30008ff8ec32d840bbee5ea62bdbd2c93439a136b54fa3c7e')
SOURCE_RECIPE = 'native/windows-graphics-source/build.py'
SOURCE_RECIPE_PIN = (21019, 'c3763de7580dbaa39126530a81300be3a27f1f81ae8944b87391679272b99065')
INPUT_PINS = {
    'GraphicsWindowDiagnostics.h': (4651, '672685d81827ab556fc7883ac858b2bf47ee2ea909f9eff4f945e27df4c67b42'),
    'overlay.py': (3730, '39ba84736982f6aa527c05d23383998f27e8c1b5403a020bff2c793b4ec9a172'),
    'test_overlay.py': (8318, 'bba092a05764498198d676f02e9a6a687634866a108e9a70070c5d8c020479ca'),
}
CONTEXT_PINS = {
    'file_policy_diagnostic_identity.py': (25298, 'a051da9cdb0aeeb850e9a553de804b8d9628c65294bf1c50b65c1f0703941f3a'),
    'graphics_diagnostic_identity.py': (16855, '61a9e144d0b94e76f14a86ed92e628b0d15b6a53b2e30da49da2417cba81f4a1'),
    'hook_diagnostic_identity.py': (19564, '58f3c2b7f89af0d3a12d2030a6603647fe36c4776ff8979f328fd2fe72daafd8'),
    'lifecycle_diagnostic_identity.py': (13214, 'ce2f31d62a37d80db0d8e7d72134466fdf1a55b38b2c9ca1d2fa3a9182fec895'),
    'null_target_fix_identity.py': (12369, '6d2a9b5c263063f20843ddc91573c2ec774489575b5fffce21cac3392a6c0705'),
    'run_main.py': (15813, 'e509d35e5ebaf13e95b859982062b484a41d54bdbe41296f87c7b427400094d0'),
    'source_code_identity.py': (15236, 'b707b8dd0cd7cbb20a922510d795bf4f7c02a23283a6ad18ed743a3d2151394b'),
    'toolmode_diagnostic_identity.py': (13663, '97487f2431948e830158a01d1909d8cb245beb37b26aa662d5a46d978881589b'),
}
SC_HEADER = 'GraphicsSwapChainDiagnostics.h'
SC_PIN = (2229, '87bade5b3de986fc0ab47ace967006f9284272fe417dcb454eab1782192b0d00')
RENDER_PIN = (42200, '39ab3f4966e9434894c004977914a39869782891b5d5ebd55c13f1be7d2d874e')
SC_DEFINE = b'target_compile_definitions(rage_graphics PRIVATE CFX_GRAPHICS_SWAPCHAIN_DIAGNOSTICS=1)\n'
DEFINE = b'target_compile_definitions(rage_graphics PRIVATE CFX_GRAPHICS_WINDOW_DIAGNOSTICS=1)\n'


def plain(path):
    if not path.is_absolute() or not path.is_relative_to(ROOT):
        raise RuntimeError('Require an exact project output/input role')
    current = ROOT
    for part in path.relative_to(ROOT).parts:
        current /= part
        if current.is_symlink():
            raise RuntimeError('Refusing a redirected build/input path')


def read(path):
    if path.is_relative_to(ROOT):
        plain(path)
    elif path.resolve(strict=True) != path:
        raise RuntimeError('Require a resolved compiler code path')
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise RuntimeError('Require regular single-link code/evidence')
    with path.open('rb') as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise RuntimeError('Code/evidence changed before open')
        data = stream.read()
        after = os.fstat(stream.fileno())
    end = path.lstat()
    stamp = lambda x: (x.st_dev, x.st_ino, x.st_size, x.st_mtime_ns, x.st_nlink, x.st_mode)
    if stamp(before) != stamp(after) or stamp(before) != stamp(end):
        raise RuntimeError('Code/evidence changed during read')
    return data


def digest(data):
    return hashlib.sha256(data).hexdigest()


def bound(path, pin):
    data = read(path)
    if pin is None or (len(data), digest(data)) != pin:
        raise RuntimeError('A frozen build input is missing or changed: ' + path.name)
    return data


def identity(path):
    data = read(path)
    return {'path': str(path.relative_to(ROOT)), 'bytes': len(data), 'sha256': digest(data)}


def module(data, path):
    value = types.ModuleType('_window_graphics_' + path.stem)
    value.__file__ = str(path)
    exec(compile(data, str(path), 'exec'), value.__dict__)
    return value


def support_context(payloads):
    """Execute only captured, preverified import bytes without changing sys.modules."""
    loaded = {}
    original_import = builtins.__import__

    def local_import(name, globals=None, locals=None, fromlist=(), level=0):
        filename = name + '.py'
        if level == 0 and filename in payloads:
            return get(filename)
        return original_import(name, globals, locals, fromlist, level)

    def get(filename):
        if filename not in loaded:
            value = types.ModuleType('_window_context_' + Path(filename).stem)
            value.__file__ = str(ROOT / 'native/windows-client' / filename)
            value.__dict__['__builtins__'] = dict(vars(builtins), __import__=local_import)
            loaded[filename] = value
            exec(compile(payloads[filename], value.__file__, 'exec'), value.__dict__)
        return loaded[filename]

    previous_path = list(sys.path)
    try:
        result = get('graphics_diagnostic_identity.py')
        if set(loaded) != set(CONTEXT_PINS):
            raise RuntimeError('Unexpected exact V11 import closure')
        return result
    finally:
        sys.path[:] = previous_path


def evidence(validator):
    refs = validator.validate_evidence(ROOT)
    unique = {}
    for item in refs:
        if (type(item) is not dict or set(item) != {'path', 'sha256'}
                or type(item['path']) is not str or type(item['sha256']) is not str):
            raise RuntimeError('Unexpected V11 evidence identity')
        relative = PurePosixPath(item['path'])
        if (relative.is_absolute() or str(relative) != item['path']
                or any(x in ('.', '..') for x in relative.parts)
                or relative.parts[0] not in {'build', 'native', 'port', 'research'}):
            raise RuntimeError('Refusing a non-code V11 evidence role')
        plain(ROOT / item['path'])
        if item['path'] in unique and unique[item['path']] != item['sha256']:
            raise RuntimeError('Conflicting V11 evidence identities')
        unique[item['path']] = item['sha256']
    if len(refs) != 296 or len(unique) != 194:
        raise RuntimeError('Unexpected fixed V11 evidence closure')
    rows = [identity(ROOT / name) for name in sorted(unique)]
    if any(row['sha256'] != unique[row['path']] for row in rows):
        raise RuntimeError('V11 evidence changed after its validator')
    return rows


def main():
    if sys.argv[1:]:
        raise RuntimeError('No arbitrary build/source/output arguments are accepted')
    for path in (BUILD, REPORT):
        plain(path)
    if BUILD.exists() or REPORT.exists():
        raise RuntimeError('Never overwrite an earlier build/report')
    BUILD.mkdir(parents=True)
    result = {'compiled': False, 'source_revision': '9f0e34e1cbdfc34fd05079416791f01938279097',
        'baseline_preserved': False, 'hresult_fix_applied': False,
        'stage_or_prefix_modified': False, 'runtime_started': False}
    phase = 'preflight'
    try:
        original = json.loads(bound(ROOT / BASE_REPORT, BASE_PIN))
        if original.get('compiled') is not True or original.get('hresult_fix_applied') is not False:
            raise RuntimeError('Require the completed trace-only V11 baseline')
        base_helper = module(bound(ROOT / BASE_RECIPE, BASE_RECIPE_PIN), ROOT / BASE_RECIPE)
        export_helper = module(bound(ROOT / SOURCE_RECIPE, SOURCE_RECIPE_PIN), ROOT / SOURCE_RECIPE)
        payloads = {name: bound(ROOT / 'native/windows-client' / name, pin) for name, pin in CONTEXT_PINS.items()}
        validator = support_context(payloads)
        preserved = evidence(validator)
        record_by_path = {row['path']: row for row in preserved}
        for key, expected in (('artifact', 'rage-graphics-five.dll'), ('generated_build_configuration', 'CMakeLists.txt')):
            row = original[key]
            base_helper.shape(row, str((BASE_BUILD / expected).relative_to(ROOT)))
            if record_by_path.get(row['path']) != row:
                raise RuntimeError('V11 generated input is outside verified evidence')
        bound(ROOT / original['artifact']['path'], BASE_ARTIFACT_PIN)
        render_before = bound(BASE_BUILD / 'overlay/RenderHooks.cpp', RENDER_PIN)
        old_header = bound(BASE_BUILD / 'overlay' / SC_HEADER, SC_PIN)
        cmake_before = read(ROOT / original['generated_build_configuration']['path'])
        source_inputs = [identity(HERE / 'build.py')]
        for name, pin in INPUT_PINS.items():
            bound(HERE / name, pin)
            source_inputs.append(identity(HERE / name))
        overlay = module(bound(HERE / 'overlay.py', INPUT_PINS['overlay.py']), HERE / 'overlay.py')
        patched, proof = overlay.apply(render_before)
        if overlay.strip(patched) != render_before:
            raise RuntimeError('Window overlay does not reverse to exact V11 input')
        inputs = BUILD / 'inputs';inputs.mkdir()
        snapshots = []
        for name, data in payloads.items():
            path = inputs / name;path.write_bytes(data)
            snapshots.append({'original_role': 'native/windows-client/' + name,
                'original_bytes': len(data), 'original_sha256': digest(data), 'snapshot': identity(path)})
        context_proof = {'original_live_requirement_after_build': False,
            'source_context_unchanged_during_build': True,
            'execution_from_preverified_captured_bytes': True, 'snapshots': snapshots}
        result.update(baseline_build_record=identity(ROOT / BASE_REPORT), baseline_artifact=original['artifact'],
            baseline_recipe_source=identity(ROOT / BASE_RECIPE), source_recipe_source=identity(ROOT / SOURCE_RECIPE),
            baseline_evidence=preserved, baseline_evidence_reference_count=296,
            support_context_before_after=context_proof, source_evidence=source_inputs)
        phase = 'overlay-tests'
        tests = [sys.executable, '-B', '-m', 'unittest', 'discover', '-s', str(HERE), '-p', 'test_overlay.py', '-v']
        with (BUILD / 'overlay-tests.log').open('x') as log:
            tested = subprocess.run(tests, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
        test_output = read(BUILD / 'overlay-tests.log').decode()
        if tested.returncode or 'Ran 3 tests' not in test_output or re.search(r'(?m)^OK\s*$', test_output) is None:
            raise RuntimeError('All three window overlay/native tests must pass before compilation')
        directory = BUILD / 'overlay';directory.mkdir()
        render = directory / 'RenderHooks.cpp';render.write_bytes(patched)
        window_header = directory / 'GraphicsWindowDiagnostics.h';window_header.write_bytes(read(HERE / window_header.name))
        sc_header = directory / SC_HEADER;sc_header.write_bytes(old_header)
        old_token = ('"' + str(BASE_BUILD / 'overlay/RenderHooks.cpp') + '"').encode()
        new_token = ('"' + str(render) + '"').encode()
        if cmake_before.count(old_token) != 1 or cmake_before.count(SC_DEFINE) != 1 or DEFINE in cmake_before:
            raise RuntimeError('Unexpected exact V11 CMake source/definition scope')
        cmake = cmake_before.replace(old_token, new_token, 1) + DEFINE
        if cmake[:-len(DEFINE)].replace(new_token, old_token, 1) != cmake_before:
            raise RuntimeError('CMake derivation is not exactly reversible')
        (BUILD / 'CMakeLists.txt').write_bytes(cmake)
        old_commands = original['build']['commands']
        if len(old_commands) != 2:
            raise RuntimeError('Require exactly configure and compile-link')
        commands = []
        for command, count in zip(old_commands, (2, 1)):
            if command.count(str(BASE_BUILD)) != count:
                raise RuntimeError('Unexpected V11 command output roles')
            commands.append([str(BUILD) if word == str(BASE_BUILD) else word for word in command])
        source_base = json.loads(read(ROOT / original['baseline_build_record']['path']))
        tools = source_base['compiler_support_tools']
        aliases = [('llvm', 'llvm-ar'), ('llvm', 'llvm-readobj'), ('llvm', 'clang-cl'), ('llvm', 'llvm-rc'), ('lld', 'lld-link')]
        if len(tools) != len(aliases):
            raise RuntimeError('Unexpected compiler support tool set')
        for row, (package, name) in zip(tools, aliases):
            expected = (Path('/opt/homebrew/opt') / package / 'bin' / name).resolve(strict=True)
            if row.get('path') != str(expected):
                raise RuntimeError('Unexpected compiler support tool role')
            bound(expected, (row['bytes'], row['sha256']))
        generated = [identity(path) for path in (render, sc_header, window_header)]
        result.update(generated_overlay=generated, generated_build_configuration=identity(BUILD / 'CMakeLists.txt'),
            compiler_support_tools=tools,
            scope_proof={'render_overlay': proof, 'cmake_reversed_equals_baseline': True,
                'replacement_tu_count': 1, 'no_new_translation_units': True,
                'definition': 'CFX_GRAPHICS_WINDOW_DIAGNOSTICS=1',
                'preserved_definition': 'CFX_GRAPHICS_SWAPCHAIN_DIAGNOSTICS=1',
                'previous_swapchain_header_preserved': True, 'hresult_fix_applied': False},
            overlay_tests={'command': tests, 'exit': 0, 'passed': 3, 'log': identity(BUILD / 'overlay-tests.log')})
        environment = dict(os.environ)
        for key in ('CL', '_CL_', 'CFLAGS', 'CXXFLAGS', 'CPPFLAGS', 'LDFLAGS', 'INCLUDE', 'LIB', 'LIBPATH'):
            environment.pop(key, None)
        with (BUILD / 'build.log').open('x') as log:
            for phase, command in zip(('configure', 'compile-link'), commands):
                done = subprocess.run(command, cwd=ROOT, env=environment, stdout=log, stderr=subprocess.STDOUT)
                if done.returncode:
                    raise RuntimeError(f'{phase} failed with exit {done.returncode}')
        phase = 'inspection'
        binary = BUILD / 'rage-graphics-five.dll';llvm = tools[1]['path']
        inspection_command = [llvm, '--file-headers', '--coff-imports', '--coff-exports', '--coff-resources', str(binary)]
        inspection = subprocess.check_output(inspection_command, text=True)
        (BUILD / 'pe-inspection.txt').write_text(inspection)
        exports = export_helper.export_index(read(binary))
        export_set = lambda rows: {(x['name'], x['kind'], x['ordinal']) for x in rows}
        dlls = re.findall(r'^\s+Name: (.+\.dll)$', inspection, re.M | re.I)
        if (len(exports['exports']) != 80 or export_set(exports['exports']) != export_set(original['export_metadata']['exports'])
                or {x.casefold() for x in dlls} != {x.casefold() for x in original['imports']}
                or 'IMAGE_FILE_MACHINE_AMD64' not in inspection or 'FXCOMPONENT' not in inspection.upper()
                or re.search(r'\b115\b', inspection) is None):
            raise RuntimeError('Component exports/imports/resource differ unexpectedly')
        object_root = BUILD / 'CMakeFiles/rage_graphics.dir'
        relocate = lambda row: BUILD / Path(row['path']).relative_to(BASE_BUILD.relative_to(ROOT))
        expected = {relocate(row) for row in original['objects']}
        objects = sorted(object_root.rglob('*.obj'))
        resource, manifest = relocate(original['resource_object']), relocate(original['cmake_manifest_resource'])
        if (len(objects) != 13 or set(objects) != expected
                or set(object_root.rglob('*.res')) != {resource, manifest}):
            raise RuntimeError('Unexpected complete translation-unit/resource output set')
        with (BUILD / 'object-directives.txt').open('x') as output:
            for obj in objects:
                directives = subprocess.check_output([llvm, '--coff-directives', str(obj)], text=True);output.write(directives)
                if (not ('RuntimeLibrary=MD_DynamicRelease' in directives or re.search(r'/DEFAULTLIB:msvcrt(?:\.lib)?\b', directives, re.I))
                        or re.search(r'/DEFAULTLIB:(?:libcmt|libcmtd|msvcrtd)(?:\.lib)?\b', directives, re.I)):
                    raise RuntimeError('Unexpected object CRT linkage')
        compile_commands = json.loads(read(BUILD / 'compile_commands.json'))
        cpp = [row for row in compile_commands if Path(row['file']).suffix == '.cpp']
        if (len(compile_commands) != 14 or len(cpp) != 13 or sum(Path(row['file']) == render for row in cpp) != 1
                or any(not re.search(r'(?:^|\s)[/-]D' + define + r'=1(?:\s|$)', row['command'])
                    for row in cpp for define in ('CFX_GRAPHICS_SWAPCHAIN_DIAGNOSTICS', 'CFX_GRAPHICS_WINDOW_DIAGNOSTICS'))):
            raise RuntimeError('Both diagnostic flags and exact replacement compilation are required')
        phase = 'preservation'
        if (evidence(validator) != preserved or identity(ROOT / BASE_REPORT) != result['baseline_build_record']
                or source_inputs != [identity(ROOT / row['path']) for row in source_inputs]
                or generated != [identity(path) for path in (render, sc_header, window_header)]
                or result['generated_build_configuration'] != identity(BUILD / 'CMakeLists.txt')
                or overlay.strip(read(render)) != render_before):
            raise RuntimeError('Baseline or diagnostic inputs changed during the build')
        for name, pin in CONTEXT_PINS.items():
            if bound(ROOT / 'native/windows-client' / name, pin) != payloads[name] or read(inputs / name) != payloads[name]:
                raise RuntimeError('Build-time support context or immutable snapshot changed')
        for row in tools:
            bound(Path(row['path']), (row['bytes'], row['sha256']))
        result.update(compiled=True, artifact=identity(binary), baseline_preserved=True,
            objects=[identity(path) for path in objects], resource_object=identity(resource), cmake_manifest_resource=identity(manifest),
            object_directives=identity(BUILD / 'object-directives.txt'), md_verified_object_count=13,
            imports=dlls, export_metadata=exports, exports_match_baseline=True,
            original_export_coverage_complete=True, pe_inspection=identity(BUILD / 'pe-inspection.txt'),
            inspection_command=inspection_command,
            build={'commands': commands, 'exit': 0, 'log': identity(BUILD / 'build.log'),
                'compile_commands': identity(BUILD / 'compile_commands.json')},
            deployment_or_runtime_compatibility_claimed=False)
    except Exception as error:
        result.update(failure_phase=phase, failure_type=type(error).__name__, failure_message=str(error))
        for name, key in (('build.log', 'failed_build_log'), ('overlay-tests.log', 'failed_overlay_test_log')):
            if (BUILD / name).exists():
                result[key] = identity(BUILD / name)
    result['at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    plain(REPORT)
    with REPORT.open('x') as output:
        json.dump(result, output, indent=2);output.write('\n')
    print(json.dumps({'compiled': result['compiled'], 'report': identity(REPORT), 'runtime_started': False}))
    return 0 if result['compiled'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
