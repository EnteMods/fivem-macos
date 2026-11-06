#!/usr/bin/env python3
"""Exercise the production BLIT Record helper on an isolated real DXMT context."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import types


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DXGI = ROOT / 'native/windows-dxgi-swapchain/run.py'
PARSER = ROOT / 'native/windows-client/graphics_blit_metadata.py'
HEADER = HERE / 'GraphicsBlitDiagnostics.h'
PINS = {
    DXGI: '80a9f5078082a505824f9911cb08de13e3de614743eae00ac5188d5d9e288269',
    PARSER: '9b4ac6f265102ec5452a5c34436b948225ae938af9f9a4603cf79b31e66700f2',
    HEADER: '9841cca611f9a13d7081f7b642bd53f07e9faa1b7864cc78ca9471e2bb0ef9c5',
}
CHECKS = ('context_unchanged', 'last_error_preserved', 'errno_preserved', 'window_hidden')


def bound(path):
    if path.resolve(strict=True) != path or not path.is_file() or path.stat().st_nlink != 1:
        raise ValueError('Expected exact own control input path')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PINS[path]:
        raise ValueError('Reviewed own control input changed')
    return raw


def load(path):
    module = types.ModuleType('_own_blit_record_' + path.stem)
    module.__file__ = str(path)
    exec(compile(bound(path), str(path), 'exec'), module.__dict__)
    return module


def main():
    dxgi, parser = load(DXGI), load(PARSER)
    graphics = dxgi.graphics()
    runner, runtime = graphics.runner, graphics.runtime
    source = HERE / 'record_probe.cpp'
    source_inputs = [runner.identity(path) for path in (source, Path(__file__).resolve(), *PINS)]
    build = Path(tempfile.mkdtemp(prefix='windows-dxgi-blit-record-', dir=ROOT / 'build'))
    # Compile from the reviewed bytes that were read for this test.
    (build / HEADER.name).write_bytes(bound(HEADER))
    (build / source.name).write_bytes(runtime.read_regular(source))
    binary = build / 'blit_record_probe.exe'
    subprocess.run(['/opt/homebrew/bin/x86_64-w64-mingw32-g++', '-std=c++17', '-O2', '-Wall', '-Wextra',
                    '-Werror', '-static', str(build / source.name), '-o', str(binary), '-ld3d11', '-luser32'],
                   check=True)
    runtime_inputs = [runner.identity(binary)]
    compile_inputs = [runner.identity(build / path.name) for path in (source, HEADER)]
    if [item['sha256'] for item in compile_inputs] != [source_inputs[0]['sha256'], PINS[HEADER]]:
        raise ValueError('Compile input does not match the reviewed probe source')

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
        env['WINEDEBUG'] += ',+debugstr,+pid'
        return env

    def verify_inputs():
        if any(runner.identity(ROOT / item['path']) != item
                for item in (*source_inputs, *compile_inputs, *runtime_inputs)):
            raise ValueError('Own BLIT control input changed')
        return {'runtime_inputs': runtime_inputs, 'source_inputs': source_inputs, 'compile_inputs': compile_inputs,
                'renderer': graphics.verify_renderer(), 'present_called': False, 'fallback': fallback}

    identity = None

    def output(lines, code):
        nonlocal identity
        rows = [json.loads(line) for line in lines]
        row = rows[0] if len(rows) == 1 and type(rows[0]) is dict else {}
        valid = (set(row) == {'pid', 'tid', *CHECKS}
                 and all(type(row[name]) is int and 0 < row[name] <= 0xffffffff for name in ('pid', 'tid'))
                 and all(type(row[name]) is bool for name in CHECKS))
        if valid:
            identity = {'pid': row['pid'], 'tid': row['tid']}
        return {'passed': valid and code == 0 and all(row[name] for name in CHECKS), 'events': rows if valid else []}

    def diagnostics(lines, code):
        provider = graphics.parse_provider_diagnostics(lines, code)
        markers = parser.parse_lines(lines)
        expected = {**(identity or {}), 'quad_w': 1512, 'quad_h': 982, 'vp_count': 1, 'vp_valid': 1,
                    'vp_x16': 24, 'vp_y16': 36, 'vp_w16': 1928, 'vp_h16': 960, 'rt_w': 128, 'rt_h': 64}
        passed = (identity is not None and markers['events'] and not markers['rejected'] and not markers['capped']
                  and all(event == expected for event in markers['events']))
        return {'passed': bool(passed) and provider['passed'], 'marker_capture': markers, 'provider': provider}

    case = {'name': 'real_record_mip_rtv', 'binary': binary, 'cwd': build,
            'parse_output': output, 'parse_diagnostics': diagnostics}
    runner.validate_environment = validate_environment
    try:
        return runner.run_cases([case], verify_inputs=verify_inputs, role='dxgi-blit-record',
                                environment_factory=environment, prepare_prefix=graphics.prepare_prefix)
    finally:
        runner.validate_environment = validate


if __name__ == '__main__':
    raise SystemExit(main())
