#!/usr/bin/env python3
"""Measure automatic DXMT backbuffer sizing in separate account-free Wine prefixes."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import uuid


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / 'native/windows-graphics-blit-diagnostics'))
from record_control import DXGI, load


LOGICAL_CLIENT = (480, 320)
REGISTRY_KEY = r'HKCU\Software\Wine\Mac Driver'
ARMS = {'standard': ('N', 1), 'retina': ('Y', 2)}


def host_display():
    source = '''
import CoreGraphics
let display = CGMainDisplayID()
guard let mode = CGDisplayCopyDisplayMode(display) else { fatalError("No main display mode") }
print(mode.width, mode.height, mode.pixelWidth, mode.pixelHeight)
'''
    width, height, pixel_width, pixel_height = map(int, subprocess.check_output(
        ['/usr/bin/swift', '-e', source], text=True, timeout=20).split())
    if min(width, height) < 640 or (pixel_width, pixel_height) != (2 * width, 2 * height):
        raise ValueError('Require a main display with a 2× macOS backing mode')
    return {'logical': [width, height], 'pixels': [pixel_width, pixel_height]}


def parse_output(lines, exitcode, display, expected_scale):
    if len(lines) != 1 or len(lines[0]) > 2048:
        return {'passed': False, 'events': []}
    row = json.loads(lines[0])
    physical_client = [value * expected_scale for value in LOGICAL_CLIENT]
    physical_screen = [value * expected_scale for value in display['logical']]
    expected = {'phase': 'complete', 'logical': list(LOGICAL_CLIENT), 'host_screen': display['logical'],
                'monitor': physical_screen, 'display_mode': physical_screen, 'scale': expected_scale,
                'expected_scale': expected_scale, 'client': physical_client, 'backbuffer': physical_client,
                'modules': 7, 'hidden': True, 'destroyed': True, 'unregistered': True, 'status': 0}
    valid = isinstance(row, dict) and set(row) == {*expected, 'pid', 'tid', 'monitor_dpi', 'client_dpi'}
    if valid:
        dpi = row['monitor_dpi']
        valid = (type(dpi) is list and len(dpi) == 2
                 and all(type(value) is int and 0 < value <= 0xffffffff
                         for value in (*dpi, row['pid'], row['tid'], row['client_dpi'])))
    return {'events': [row] if valid else [],
            'passed': valid and exitcode == 0 and all(type(row[key]) is type(value) and row[key] == value
                                                    for key, value in expected.items())}


def run_arm(name, display, build, artifact, inputs, command, run_id):
    setting, scale = ARMS[name]
    graphics = load(DXGI).graphics()
    runner, runtime = graphics.runner, graphics.runtime
    prefix = ROOT / 'prefixes' / f'wine-parity-retina-{name}-{run_id}'
    if prefix.exists() or prefix.is_symlink():
        raise RuntimeError('Retina arm requires a fresh independent prefix')
    runner.PREFIX = runtime.PREFIX = prefix
    binary = ROOT / artifact['path']
    fallback = {'DYLD_FALLBACK_LIBRARY_PATH': os.pathsep.join(map(str, (
        runtime.ENGINE / 'lib/wine/x86_64-unix', runtime.MOLTENVK.parent, runtime.FRAMEWORKS, runtime.GST_LIB))),
        'DYLD_FALLBACK_FRAMEWORK_PATH': str(runtime.FRAMEWORKS)}
    original_validate = runner.validate_environment

    def validate(env):
        if 'DYLD_LIBRARY_PATH' in env or any(env.get(key) != value for key, value in fallback.items()):
            raise ValueError('Require exact system-first library selection')
        original_validate({key: value for key, value in env.items() if key not in fallback})

    def environment(verified):
        env = graphics.graphics_environment(verified)
        del env['DYLD_LIBRARY_PATH']
        env.update(fallback)
        return env

    def prepare(verified, env):
        details = graphics.prepare_prefix(verified, env)
        if env['WINEPREFIX'] != str(prefix) or env['WINESERVER'] != str(runtime.ENGINE / 'bin/wineserver'):
            raise RuntimeError('Refusing to configure any other Wine session')
        setup = dict(env, WINEDEBUG='-all')
        setup.pop('DYLD_PRINT_LIBRARIES', None)
        wine = str(runtime.ENGINE / 'bin/wine')
        reg = [wine, str(runtime.ENGINE / 'lib/wine/x86_64-windows/reg.exe')]
        subprocess.run([*reg, 'add', REGISTRY_KEY, '/v', 'RetinaMode', '/t', 'REG_SZ', '/d', setting, '/f'],
                       env=setup, cwd=build, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=15)
        if graphics.verify_bridge_binding() != details['binding']:
            raise RuntimeError('Retina setup changed the bound graphics prefix')
        for flag in ('-k', '-w'):
            subprocess.run([env['WINESERVER'], flag], env=setup, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           check=True, timeout=15)
        result = subprocess.check_output([*reg, 'query', REGISTRY_KEY, '/v', 'RetinaMode'],
                                         env=setup, cwd=build, stderr=subprocess.DEVNULL, text=True, timeout=15)
        if not re.search(r'^\s*RetinaMode\s+REG_SZ\s+' + setting + r'\s*$', result, re.MULTILINE):
            raise RuntimeError('Wine did not persist the requested RetinaMode')
        if graphics.verify_bridge_binding() != details['binding']:
            raise RuntimeError('Retina setup changed the bound graphics prefix')
        return {**details, 'registry_retina_mode': setting, 'intermediate_cleanup': {'kill': 0, 'wait': 0},
                'log_pixels_changed': False}

    def verify_inputs():
        if any(runner.identity(ROOT / row['path']) != row for row in (*inputs, artifact)):
            raise RuntimeError('Retina fixture input changed')
        return {'runtime_inputs': [artifact], 'source_inputs': inputs, 'build_command': command,
                'renderer': graphics.verify_renderer(), 'host_display': display, 'logical_window': LOGICAL_CLIENT,
                'swapchain_dimensions_automatic': True, 'present_called': False, 'fallback': fallback}

    case = {'name': name, 'binary': binary, 'cwd': build,
            'arguments': tuple(map(str, (*LOGICAL_CLIENT, *display['logical'], scale))),
            'parse_output': lambda lines, code: parse_output(lines, code, display, scale),
            'parse_diagnostics': graphics.parse_provider_diagnostics}
    runner.validate_environment = validate
    return runner.run_cases([case], verify_inputs=verify_inputs, role=f'dxgi-retina-{name}',
                            environment_factory=environment, prepare_prefix=prepare)


def main():
    display = host_display()
    graphics = load(DXGI).graphics()
    runner, runtime = graphics.runner, graphics.runtime
    source = HERE / 'retina_probe.cpp'
    build = Path(tempfile.mkdtemp(prefix='windows-dxgi-retina-', dir=ROOT / 'build'))
    copied = build / source.name
    copied.write_bytes(runtime.read_regular(source))
    inputs = [runner.identity(path) for path in (source, copied, Path(__file__).resolve(), DXGI)]
    if inputs[0]['sha256'] != inputs[1]['sha256']:
        raise RuntimeError('Own Retina source changed during copy')
    binary = build / 'retina_probe.exe'
    command = ['/opt/homebrew/bin/x86_64-w64-mingw32-g++', '-std=c++17', '-O2', '-Wall', '-Wextra', '-Werror',
               '-static', str(copied), '-o', str(binary), '-ld3d11', '-luser32', '-lshcore']
    subprocess.run(command, cwd=build, check=True)
    artifact = runner.identity(binary)
    run_id = uuid.uuid4().hex[:12]
    results = [run_arm(arm, display, build, artifact, inputs, command, run_id) for arm in ARMS]
    return int(any(results))


if __name__ == '__main__':
    raise SystemExit(main())
