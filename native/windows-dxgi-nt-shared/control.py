#!/usr/bin/env python3
"""Exercise own NT shared textures with the pinned DXMT and parity lifecycle."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
spec = importlib.util.spec_from_file_location('own_nt_shared_dxgi', ROOT / 'native/windows-dxgi-swapchain/run.py')
dxgi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dxgi)


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('Duplicate field')
        result[key] = value
    return result


def parse(lines, code, *, child=False, keyed=False):
    accepted = []
    try:
        if type(code) is not int or code not in (0, 1) or not 1 <= len(lines) <= 64:
            raise ValueError('Exit or count')
        for line in lines:
            if type(line) is not str or not line or len(line) > 512:
                raise ValueError('Line')
            row = json.loads(line, object_pairs_hook=pairs)
            if type(row) is not dict or set(row) != {'mode', 'pid', 'stage', 'hr', 'ok', 'value'}:
                raise ValueError('Schema')
            if any(type(row[key]) is not int or not 0 <= row[key] <= 0xffffffff
                   for key in ('mode', 'pid', 'stage', 'hr', 'value')):
                raise ValueError('Numeric field')
            if row['mode'] not in (1, 2, 3) or not row['pid'] or type(row['ok']) is not bool:
                raise ValueError('Role')
            accepted.append(row)
        producer = [1, 2, 3, 4, 5] + ([6, 7] if keyed else []) + [10, 11, 12] + ([8] if keyed else [])
        consumer = [20, 21, 22, 23, 24, 25] + ([26, 27] if keyed else []) + [30, 31, 32] + ([28] if keyed else [])
        expected = ({2: producer + [38, 39, 40, 41, 42, 43, 44, 90, 99], 3: consumer + [90, 99]}
                    if child else {1: producer + consumer + [90, 99]})
        valid = set(row['mode'] for row in accepted) == set(expected)
        pids = []
        for mode, stages in expected.items():
            selected = [row for row in accepted if row['mode'] == mode]
            valid = valid and [row['stage'] for row in selected] == stages
            mode_pids = {row['pid'] for row in selected}
            valid = valid and len(mode_pids) == 1
            pids.extend(mode_pids)
            values = {2: 2304 if keyed else 2050, 12: 64, 23: 8, 24: 8, 25: 87, 32: 64,
                      42: 17, 90: 0 if mode == 3 else 1, 99: 17 if mode == 3 else 0}
            valid = valid and all(row['ok'] and row['hr'] == 0
                                  and row['value'] == values.get(row['stage'], 0) for row in selected)
        valid = valid and len(set(pids)) == len(expected)
        return {'passed': code == 0 and valid, 'events': accepted,
                'first_rejection': next((row for row in accepted if not row['ok']), None)}
    except (ValueError, TypeError, KeyError):
        return {'passed': False, 'events': accepted, 'invalid_contract': True}


def main():
    graphics = dxgi.graphics()
    runner, runtime = graphics.runner, graphics.runtime
    expected_prefix = ROOT / 'prefixes/wine-parity-regression'
    if runner.PREFIX != expected_prefix or runtime.PREFIX != expected_prefix:
        raise RuntimeError('Require the fixed account-free parity prefix')
    build = Path(tempfile.mkdtemp(prefix='windows-dxgi-nt-shared-', dir=ROOT / 'build'))
    binary = build / 'nt_shared_probe.exe'
    source = HERE / 'probe.cpp'
    command = ['/opt/homebrew/bin/x86_64-w64-mingw32-g++', '-std=c++17', '-O2', '-Wall', '-Wextra',
               '-Werror', '-static', str(source), '-o', str(binary), '-ld3d11', '-luser32']
    with (build / 'build.log').open('x') as output:
        subprocess.run(command, check=True, timeout=45, stdout=output, stderr=subprocess.STDOUT)
    inputs = [runner.identity(path) for path in (source, Path(__file__).resolve(), ROOT / 'native/windows-dxgi-swapchain/run.py')]
    artifact = runner.identity(binary)
    fallback = {'DYLD_FALLBACK_LIBRARY_PATH': os.pathsep.join(map(str, (
        runtime.ENGINE / 'lib/wine/x86_64-unix', runtime.MOLTENVK.parent, runtime.FRAMEWORKS, runtime.GST_LIB))),
        'DYLD_FALLBACK_FRAMEWORK_PATH': str(runtime.FRAMEWORKS)}
    original_validate = runner.validate_environment

    def validate_environment(env):
        if 'DYLD_LIBRARY_PATH' in env or any(env.get(key) != value for key, value in fallback.items()):
            raise ValueError('Require the exact system-first library search')
        original_validate({key: value for key, value in env.items() if key not in fallback})

    def environment(verified):
        env = graphics.graphics_environment(verified)
        del env['DYLD_LIBRARY_PATH']
        env.update(fallback)
        return env

    def verify_inputs():
        if any(runner.identity(ROOT / row['path']) != row for row in (*inputs, artifact)):
            raise RuntimeError('Own NT texture fixture changed')
        return {'runtime_inputs': [artifact], 'source_inputs': inputs,
                'build_command': command, 'renderer': graphics.verify_renderer(), 'fallback': fallback,
                'texture_extent': [8, 8], 'texture_format': 87, 'present_called': False,
                'only_own_texture_pixels_read': True, 'child_scope': 'same-own-executable-inherited-own-NT-handle'}

    cases = []
    for name, argument, child, keyed in (
        ('same_process_no_mutex', '--same', False, False),
        ('same_process_keyed_mutex', '--same-keyed', False, True),
        ('child_no_mutex', '--child-roundtrip', True, False)):
        def output(lines, code, child=child, keyed=keyed):
            return parse(lines, code, child=child, keyed=keyed)
        cases.append({'name': name, 'binary': binary, 'cwd': build, 'arguments': [argument],
                      'parse_output': output, 'parse_diagnostics': graphics.parse_provider_diagnostics})
    runner.validate_environment = validate_environment
    return runner.run_cases(cases, verify_inputs=verify_inputs, role='dxgi-nt-shared',
                            environment_factory=environment, prepare_prefix=graphics.prepare_prefix)


if __name__ == '__main__':
    raise SystemExit(main())
