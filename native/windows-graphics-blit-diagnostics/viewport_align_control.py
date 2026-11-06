#!/usr/bin/env python3
"""Run the scoped viewport pixel control on the account-free pinned DXMT stack."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from record_control import DXGI, HEADER, HERE, ROOT, bound, load


SOURCE = HERE / 'viewport_align_probe.cpp'
SCOPE = HERE / 'ViewportAlignProbe.h'
PINS = {
    SOURCE: 'e6cdcb4f859c1ace5698df399e014f7f7a7147a4db0823d3614ee45c9bad0831',
    SCOPE: 'd3b0421c0a39370815029945cffa28e0d9452f668a9655486753c8169417e13d',
}
EXPECTED = {
    'phase': 'complete', 'before': [0, 89, 1191, 982], 'before_pixels': 1063563,
    'within': [0, 0, 1512, 982], 'within_pixels': 1484784,
    'after': [0, 89, 1191, 982], 'after_pixels': 1063563,
    'scope_applied': True, 'restored': True, 'full_untouched': True, 'unrelated_untouched': True,
    'mismatch_untouched': True, 'multiple_untouched': True, 'scissor_declined': True, 'window_hidden': True,
}


def parse_output(lines, exit_code):
    rows = [json.loads(line) for line in lines]
    row = rows[0] if len(rows) == 1 and type(rows[0]) is dict else {}
    valid = (set(row) == {'pid', 'tid', *EXPECTED} and row['phase'] == 'complete'
             and all(type(row[name]) is int and 0 < row[name] <= 0xffffffff for name in ('pid', 'tid'))
             and all(type(row[name]) is type(value) for name, value in EXPECTED.items())
             and all(len(row[name]) == 4 and all(type(v) is int and 0 <= v <= 0xffffffff for v in row[name])
                     for name in ('before', 'within', 'after'))
             and all(0 <= row[name] <= 0xffffffff for name in ('before_pixels', 'within_pixels', 'after_pixels')))
    return {'events': [row] if valid else [],
            'passed': valid and exit_code == 0 and all(row[name] == value for name, value in EXPECTED.items())}


def main():
    graphics = load(DXGI).graphics()
    runner, runtime = graphics.runner, graphics.runtime
    inputs = [runner.identity(path) for path in (SOURCE, SCOPE, HEADER, DXGI, HERE / 'record_control.py', Path(__file__).resolve())]
    build = Path(tempfile.mkdtemp(prefix='windows-dxgi-viewport-align-', dir=ROOT / 'build'))
    for path, pin in PINS.items():
        data = runtime.read_regular(path)
        if hashlib.sha256(data).hexdigest() != pin:
            raise ValueError('Fixed own viewport source changed')
        (build / path.name).write_bytes(data)
    (build / HEADER.name).write_bytes(bound(HEADER))
    compile_inputs = [runner.identity(build / path.name) for path in (SOURCE, SCOPE, HEADER)]
    if [item['sha256'] for item in compile_inputs] != [item['sha256'] for item in inputs[:3]]:
        raise ValueError('Compiled input differs from the bound source')
    binary = build / 'viewport_align_probe.exe'
    command = ['/opt/homebrew/bin/x86_64-w64-mingw32-g++', '-std=c++17', '-O2', '-Wall', '-Wextra',
               '-Werror', '-static', str(build / SOURCE.name), '-o', str(binary), '-ld3d11', '-ld3dcompiler', '-luser32']
    subprocess.run(command, cwd=build, check=True)
    runtime_inputs = [runner.identity(binary)]

    search = os.pathsep.join(map(str, (runtime.ENGINE/'lib/wine/x86_64-unix', runtime.MOLTENVK.parent,
                                      runtime.FRAMEWORKS, runtime.GST_LIB)))
    fallback = {'DYLD_FALLBACK_LIBRARY_PATH': search, 'DYLD_FALLBACK_FRAMEWORK_PATH': str(runtime.FRAMEWORKS)}
    validate = runner.validate_environment

    def validate_environment(env):
        if 'DYLD_LIBRARY_PATH' in env or any(env.get(name) != value for name, value in fallback.items()):
            raise ValueError('Require the exact system-first library selection')
        validate({name: value for name, value in env.items() if name not in fallback})

    def environment(verified):
        env = graphics.graphics_environment(verified)
        del env['DYLD_LIBRARY_PATH']
        env.update(fallback)
        return env

    def verify_inputs():
        if any(runner.identity(ROOT / item['path']) != item for item in (*inputs, *compile_inputs, *runtime_inputs)):
            raise ValueError('Own viewport probe input changed')
        return {'runtime_inputs': runtime_inputs, 'source_inputs': inputs, 'compile_inputs': compile_inputs,
                'build_command': command, 'renderer': graphics.verify_renderer(), 'fallback': fallback,
                'present_called': False, 'only_own_render_target_sampled': True}

    case = {'name': 'scoped_viewport_readback', 'binary': binary, 'cwd': build,
            'parse_output': parse_output, 'parse_diagnostics': graphics.parse_provider_diagnostics}
    runner.validate_environment = validate_environment
    try:
        return runner.run_cases([case], verify_inputs=verify_inputs, role='dxgi-viewport-align',
                                environment_factory=environment, prepare_prefix=graphics.prepare_prefix)
    finally:
        runner.validate_environment = validate


if __name__ == '__main__':
    raise SystemExit(main())
