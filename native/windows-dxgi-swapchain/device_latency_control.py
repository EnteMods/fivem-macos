#!/usr/bin/env python3
"""Read, reduce and restore device frame latency in an isolated DXMT probe."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import uuid

import run as dxgi


def output(lines, code):
    if len(lines) != 1 or len(lines[0]) > 1024:
        return {'passed': False, 'events': []}
    try:
        event = json.loads(lines[0])
    except ValueError:
        return {'passed': False, 'events': []}
    expected = {
        'create': 0, 'query': 0, 'get_original': 0, 'set_low': 0, 'get_low': 0, 'set_original': 0, 'get_restored': 0,
        'original': 3, 'low': 1, 'restored': 3, 'same_device': True, 'hidden': True,
        'destroyed': True, 'unregistered': True,
    }
    valid = (type(event) is dict and set(event) == {'pid', *expected}
             and type(event['pid']) is int and 0 < event['pid'] <= 0xffffffff)
    passed = valid and code == 0 and all(type(event[key]) is type(value) and event[key] == value
                                        for key, value in expected.items())
    return {'passed': passed, 'events': [event] if valid else []}


def main():
    graphics = dxgi.graphics()
    runner, runtime = graphics.runner, graphics.runtime
    prefix = dxgi.ROOT / 'prefixes' / ('wine-parity-dxgi-device-latency-' + uuid.uuid4().hex[:12])
    if prefix.exists() or prefix.is_symlink():
        raise RuntimeError('Require a fresh probe prefix')
    runner.PREFIX = runtime.PREFIX = prefix

    source = Path(__file__).with_name('device_latency_probe.cpp').resolve()
    build = Path(tempfile.mkdtemp(prefix='windows-dxgi-device-latency-', dir=dxgi.ROOT / 'build'))
    binary = build / 'device_latency_probe.exe'
    inputs = [runner.identity(path) for path in (source, Path(__file__).resolve())]
    command = ['/opt/homebrew/bin/x86_64-w64-mingw32-g++', '-std=c++17', '-O2', '-Wall', '-Wextra',
               '-Werror', '-static', str(source), '-o', str(binary), '-ld3d11', '-luser32']
    subprocess.run(command, check=True, timeout=30)
    artifact = runner.identity(binary)

    fallback = {'DYLD_FALLBACK_LIBRARY_PATH': os.pathsep.join(map(str, (
        runtime.ENGINE / 'lib/wine/x86_64-unix', runtime.MOLTENVK.parent, runtime.FRAMEWORKS, runtime.GST_LIB,
    ))), 'DYLD_FALLBACK_FRAMEWORK_PATH': str(runtime.FRAMEWORKS)}
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
        if any(runner.identity(dxgi.ROOT / row['path']) != row for row in (*inputs, artifact)):
            raise RuntimeError('Probe source or executable changed')
        return {'runtime_inputs': [artifact], 'source_inputs': inputs, 'build_command': command,
                'renderer': graphics.verify_renderer(), 'present_called': False, 'fallback': fallback}

    case = {'name': 'device_frame_latency_round_trip', 'binary': binary, 'cwd': build,
            'parse_output': output, 'parse_diagnostics': graphics.parse_provider_diagnostics}
    runner.validate_environment = validate_environment
    return runner.run_cases([case], verify_inputs=verify_inputs, role='dxgi-device-latency',
                            environment_factory=environment, prepare_prefix=graphics.prepare_prefix)


if __name__ == '__main__':
    raise SystemExit(main())
