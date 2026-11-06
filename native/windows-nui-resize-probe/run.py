#!/usr/bin/env python3
"""Check software-frame backing replacement and bounded uploads on the pinned DXMT stack."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import uuid


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BLIT = ROOT / 'native/windows-graphics-blit-diagnostics'
sys.path.insert(0, str(BLIT))
from record_control import DXGI, load


BASE = BLIT / 'sharpness_probe.cpp'
BASE_SHA = '35e69a8687c9d65ca716f3726a9481c6fd46522c6383a23fe5458f5956789659'
START = [64, 48]


def derive(original):
    if hashlib.sha256(original).hexdigest() != BASE_SHA:
        raise ValueError('Expected the fixed own sharpness source')
    for first, after, replacement in (
        (b'static unsigned expected(', b'static int Run(', b'#include "probe.inc"\n\n'),
        (b'    const UINT width = logicalW * 2', b'    DXGI_SWAP_CHAIN_DESC', b''),
        (b'    D3D11_TEXTURE2D_DESC desc{};', b'    ComPtr<ID3DBlob>', b''),
        (b'    const D3D11_VIEWPORT viewport', b'    context->RSSetState', b''),
        (b'    bool exact = true;', b'static bool Dimension(',
         b'    return ResizeTest(window, device.Get(), context.Get(), logicalW, logicalH);\n}\n\n'),
    ):
        if original.count(first) != 1 or original.count(after) != 1:
            raise ValueError('Expected one sharpness fixture anchor')
        start = original.index(first)
        end = original.index(after, start)
        original = original[:start] + replacement + original[end:]
    return original.replace(b'OwnDxmtSharpnessProbe', b'OwnDxmtNuiResizeProbe')


def parse_output(lines, code):
    grown, shrunk = [128, 96], [80, 40]
    fields = (
        ('initial', START, START, 1, 12288, False),
        ('retained_grow', START, grown, 1, 12288, True),
        ('grow', grown, grown, 2, 61440, False),
        ('shrink', shrunk, shrunk, 3, 74240, True),
        ('short_frame', shrunk, shrunk, 3, 74240, True),
    )
    expected = [dict(phase=phase, backing=backing, target=target, maps=maps, bytes_written=written,
                     invalid_write_refused=refused, exact_pixels=True)
                for phase, backing, target, maps, written, refused in fields]
    rows = [json.loads(line) for line in lines] if len(lines) <= len(expected) else []
    valid = rows == expected and all(
        all(type(row[key]) is type(value) and (type(value) is not list or all(type(x) is int for x in row[key]))
            for key, value in want.items()) for row, want in zip(rows, expected))
    return {'events': rows, 'passed': code == 0 and valid}


def main():
    graphics = load(DXGI).graphics()
    runner, runtime = graphics.runner, graphics.runtime
    prefix = ROOT / 'prefixes' / f'wine-parity-nui-resize-{uuid.uuid4().hex[:12]}'
    if prefix.exists() or prefix.is_symlink():
        raise RuntimeError('Require a fresh independent prefix')
    runner.PREFIX = runtime.PREFIX = prefix

    fragment = HERE / 'probe.inc'
    inputs = [runner.identity(path) for path in (BASE, fragment, Path(__file__).resolve(), DXGI, BLIT / 'record_control.py')]
    build = Path(tempfile.mkdtemp(prefix='windows-dxgi-nui-resize-', dir=ROOT / 'build'))
    source, include = build / 'resize_probe.cpp', build / fragment.name
    source.write_bytes(derive(runtime.read_regular(BASE)))
    include.write_bytes(runtime.read_regular(fragment))
    compile_inputs = [runner.identity(path) for path in (source, include)]
    if compile_inputs[1]['sha256'] != inputs[1]['sha256']:
        raise RuntimeError('Own resize source changed during copy')
    binary = build / 'resize_probe.exe'
    command = ['/opt/homebrew/bin/x86_64-w64-mingw32-g++', '-std=c++17', '-O2', '-Wall', '-Wextra',
               '-Werror', '-static', str(source), '-o', str(binary), '-ld3d11', '-ld3dcompiler', '-luser32']
    subprocess.run(command, cwd=build, check=True)
    artifact = runner.identity(binary)

    search = os.pathsep.join(map(str, (runtime.ENGINE / 'lib/wine/x86_64-unix', runtime.MOLTENVK.parent,
                                      runtime.FRAMEWORKS, runtime.GST_LIB)))
    fallback = {'DYLD_FALLBACK_LIBRARY_PATH': search, 'DYLD_FALLBACK_FRAMEWORK_PATH': str(runtime.FRAMEWORKS)}
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

    def verify_inputs():
        if any(runner.identity(ROOT / row['path']) != row for row in (*inputs, *compile_inputs, artifact)):
            raise RuntimeError('Own resize probe input changed')
        return {'runtime_inputs': [artifact], 'source_inputs': inputs, 'compile_inputs': compile_inputs,
                'build_command': command, 'renderer': graphics.verify_renderer(), 'fallback': fallback,
                'fresh_prefix': True, 'present_called': False, 'cef_runtime_started': False}

    case = {'name': 'software_backing_resize', 'binary': binary, 'cwd': build, 'arguments': tuple(map(str, START)),
            'parse_output': parse_output, 'parse_diagnostics': graphics.parse_provider_diagnostics}
    runner.validate_environment = validate
    try:
        return runner.run_cases([case], verify_inputs=verify_inputs, role='dxgi-nui-resize',
                                environment_factory=environment, prepare_prefix=graphics.prepare_prefix)
    finally:
        runner.validate_environment = original_validate


if __name__ == '__main__':
    raise SystemExit(main())
