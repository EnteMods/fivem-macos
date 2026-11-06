#!/usr/bin/env python3
"""Compare known NUI-like source densities before Present in an account-free DXMT probe."""
from functools import partial
import json
import os
from pathlib import Path
import subprocess
import tempfile

from record_control import DXGI, HERE, ROOT, load


CASES = {'logical_480_320': (480, 320), 'logical_640_360': (640, 360)}


def parse_output(lines, code, *, dimensions):
    width, height = dimensions
    target = [2 * width, 2 * height]
    low = [width, height]
    expected = []
    for source, filter_name, period, levels, stripe in (
        (low, 'point', 4, [0, 255], [0, 0, 255, 255]),
        (low, 'linear', 4, [64, 191], [64, 64, 191, 191]),
        (target, 'point', 2, [0, 255], [0, 255, 0, 255]),
        (target, 'linear', 2, [0, 255], [0, 255, 0, 255]),
    ):
        expected.append({'source': source, 'target': target, 'filter': filter_name, 'period': period,
                         'interior': levels, 'contrast': levels[1] - levels[0], 'stripe': stripe,
                         'whole_target_exact': True})
    rows = [json.loads(line) for line in lines] if len(lines) <= 4 else []
    valid = rows == expected and all(
        all(type(row[key]) is type(value) and (type(value) is not list or all(type(x) is int for x in row[key]))
            for key, value in want.items()) for row, want in zip(rows, expected))
    return {'events': rows, 'passed': valid and code == 0}


def main():
    graphics = load(DXGI).graphics()
    runner, runtime = graphics.runner, graphics.runtime
    source = HERE / 'sharpness_probe.cpp'
    inputs = [runner.identity(path) for path in (source, Path(__file__).resolve(), DXGI, HERE / 'record_control.py')]
    build = Path(tempfile.mkdtemp(prefix='windows-dxgi-sharpness-', dir=ROOT / 'build'))
    compiled_source = build / source.name
    compiled_source.write_bytes(runtime.read_regular(source))
    compile_input = runner.identity(compiled_source)
    if compile_input['sha256'] != inputs[0]['sha256']:
        raise ValueError('Own sharpness source changed during compilation setup')
    binary = build / 'sharpness_probe.exe'
    command = ['/opt/homebrew/bin/x86_64-w64-mingw32-g++', '-std=c++17', '-O2', '-Wall', '-Wextra',
               '-Werror', '-static', str(compiled_source), '-o', str(binary), '-ld3d11', '-ld3dcompiler', '-luser32']
    subprocess.run(command, cwd=build, check=True)
    artifacts = [runner.identity(binary)]

    search = os.pathsep.join(map(str, (runtime.ENGINE / 'lib/wine/x86_64-unix', runtime.MOLTENVK.parent,
                                      runtime.FRAMEWORKS, runtime.GST_LIB)))
    fallback = {'DYLD_FALLBACK_LIBRARY_PATH': search, 'DYLD_FALLBACK_FRAMEWORK_PATH': str(runtime.FRAMEWORKS)}
    validate = runner.validate_environment

    def validate_environment(env):
        if 'DYLD_LIBRARY_PATH' in env or any(env.get(key) != value for key, value in fallback.items()):
            raise ValueError('Require exact system-first library selection')
        validate({key: value for key, value in env.items() if key not in fallback})

    def environment(verified):
        env = graphics.graphics_environment(verified)
        del env['DYLD_LIBRARY_PATH']
        env.update(fallback)
        return env

    def verify_inputs():
        if any(runner.identity(ROOT / item['path']) != item for item in (*inputs, compile_input, *artifacts)):
            raise ValueError('Own sharpness fixture input changed')
        return {'runtime_inputs': artifacts, 'source_inputs': inputs, 'compile_input': compile_input,
                'build_command': command, 'renderer': graphics.verify_renderer(), 'fallback': fallback,
                'logical_dimensions': CASES, 'present_called': False, 'only_own_offscreen_target_sampled': True}

    cases = [{'name': name, 'binary': binary, 'cwd': build, 'arguments': tuple(map(str, dimensions)),
              'parse_output': partial(parse_output, dimensions=dimensions),
              'parse_diagnostics': graphics.parse_provider_diagnostics} for name, dimensions in CASES.items()]
    runner.validate_environment = validate_environment
    try:
        return runner.run_cases(cases, verify_inputs=verify_inputs, role='dxgi-sharpness',
                                environment_factory=environment, prepare_prefix=graphics.prepare_prefix)
    finally:
        runner.validate_environment = validate


if __name__ == '__main__':
    raise SystemExit(main())
