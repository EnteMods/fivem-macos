#!/usr/bin/env python3
"""Measure rendered viewport pixels with the pinned DXMT in the account-free prefix."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

import run as dxgi


def expected(phase, target, viewport):
    x, y, width, height = viewport
    return {'phase': phase, 'target': target, 'viewport': viewport,
            'red_bounds': [x, y, x + width, y + height], 'red_pixels': width * height}


def main():
    graphics = dxgi.graphics()
    runner, runtime = graphics.runner, graphics.runtime
    source = Path(__file__).with_name('viewport_probe.cpp').resolve()
    build = Path(tempfile.mkdtemp(prefix='windows-dxgi-viewport-', dir=dxgi.ROOT / 'build'))
    binary = build / 'viewport_probe.exe'
    subprocess.run(['/opt/homebrew/bin/x86_64-w64-mingw32-g++', '-std=c++17', '-O2', '-Wall', '-Wextra',
                    '-Werror', '-static', str(source), '-o', str(binary), '-ld3d11', '-ld3dcompiler', '-luser32'], check=True)

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
        return {'runtime_inputs': [runner.identity(binary)],
                'source_inputs': [runner.identity(path) for path in (source, Path(__file__).resolve())],
                'renderer': graphics.verify_renderer(), 'present_called': False,
                'only_test_textures_sampled': True, 'fallback': fallback}

    def output(lines, code):
        rows = [json.loads(line) for line in lines]
        full = [0, 0, 1512, 982]
        checks = [expected(1, [1512, 982], full), expected(2, [1190, 894], [0, 0, 1190, 894]),
                  expected(3, [1512, 982], [0, 88, 1190, 894]), expected(4, [1512, 982], full)]
        return {'passed': code == 0 and rows == checks, 'readback': rows}

    case = {'name': 'backbuffer_viewport_readback', 'binary': binary, 'cwd': build,
            'parse_output': output, 'parse_diagnostics': graphics.parse_provider_diagnostics}
    runner.validate_environment = validate_environment
    return runner.run_cases([case], verify_inputs=verify_inputs, role='dxgi-viewport',
                            environment_factory=environment, prepare_prefix=graphics.prepare_prefix)


if __name__ == '__main__':
    raise SystemExit(main())
