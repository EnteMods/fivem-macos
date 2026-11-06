#!/usr/bin/env python3
"""Run the original viewport pixel test with three different owned geometries."""
import hashlib
import json
import os
from functools import partial
from pathlib import Path
import subprocess
import tempfile

from viewport_align_control import DXGI, EXPECTED, HEADER, HERE, PINS, ROOT, SCOPE, SOURCE, bound, load


CASES = {
    'baseline': (1512, 982, 1191, 893),
    'wide_16_9': (1280, 720, 800, 600),
    'wide_16_10': (1600, 1000, 1200, 900),
}

# Keep the earlier fixture and its GPU assertions byte-for-byte outside these geometry inputs.
EDITS = {
    b'#include <cstdio>': b'#include <charconv>\n#include <cstdio>',
    b'static constexpr UINT Width = 1512, Height = 982;': b'static UINT Width, Height, SubWidth, SubHeight;',
    b'const D3D11_VIEWPORT original{0, 89, 1191, 893, 0.125f, 0.875f};': (
        b'const auto y = Height - SubHeight;\n'
        b'    const D3D11_VIEWPORT original{0, float(y), float(SubWidth), float(SubHeight), 0.125f, 0.875f};'),
    b'const D3D11_VIEWPORT full{0, 0, Width, Height,': b'const D3D11_VIEWPORT full{0, 0, float(Width), float(Height),',
    b'const D3D11_VIEWPORT unrelated{1, 89, 1191, 893,': (
        b'const D3D11_VIEWPORT unrelated{1, original.TopLeftY, original.Width, original.Height,'),
    b'const D3D11_RECT scissor{0, 89, 1110, 982};': (
        b'const D3D11_RECT scissor{0, LONG(y), LONG(SubWidth - 1), LONG(Height)};'),
    b'before.Matches(0, 89, 1191, 893)': b'before.Matches(0, y, SubWidth, SubHeight)',
    b'after.Matches(0, 89, 1191, 893)': b'after.Matches(0, y, SubWidth, SubHeight)',
    b'int main(int argc, char**)\n{\n    if (argc != 1) return 1;': b'''int main(int argc, char** argv)
{
    if (argc != 5) return 1;
    UINT* dimensions[]{&Width, &Height, &SubWidth, &SubHeight};
    for (UINT i = 0; i < 4; ++i)
    {
        const auto* end = argv[i + 1] + std::strlen(argv[i + 1]);
        const auto parsed = std::from_chars(argv[i + 1], end, *dimensions[i]);
        if (parsed.ec != std::errc{} || parsed.ptr != end || !*dimensions[i] || *dimensions[i] > 4096)
            return 1;
    }
    if (SubWidth < 2 || SubWidth >= Width || SubHeight >= Height) return 1;''',
}


def derive(source):
    for original, replacement in EDITS.items():
        if source.count(original) != 1:
            raise ValueError('Expected one pinned geometry input')
        source = source.replace(original, replacement)
    return source


def parse_output(lines, exit_code, *, dimensions):
    width, height, sub_width, sub_height = dimensions
    clipped = [0, height - sub_height, sub_width, height]
    expected = dict(EXPECTED, before=clipped, after=clipped, within=[0, 0, width, height],
                    before_pixels=sub_width * sub_height, after_pixels=sub_width * sub_height,
                    within_pixels=width * height)
    rows = [json.loads(line) for line in lines]
    row = rows[0] if len(rows) == 1 and type(rows[0]) is dict else {}
    valid = (set(row) == {'pid', 'tid', *expected}
             and all(type(row[name]) is int and 0 < row[name] <= 0xffffffff for name in ('pid', 'tid'))
             and all(type(row[name]) is type(value) for name, value in expected.items())
             and all(all(type(value) is int for value in row[name]) for name in ('before', 'within', 'after')))
    return {'events': [row] if valid else [],
            'passed': valid and exit_code == 0 and all(row[name] == value for name, value in expected.items())}


def main():
    graphics = load(DXGI).graphics()
    runner, runtime = graphics.runner, graphics.runtime
    paths = (SOURCE, SCOPE, HEADER, DXGI, HERE / 'record_control.py', HERE / 'viewport_align_control.py',
             Path(__file__).resolve())
    inputs = [runner.identity(path) for path in paths]
    build = Path(tempfile.mkdtemp(prefix='windows-dxgi-viewport-align-matrix-', dir=ROOT / 'build'))
    source = build / 'viewport_align_matrix.cpp'
    probe, scope = (runtime.read_regular(path) for path in (SOURCE, SCOPE))
    if [hashlib.sha256(data).hexdigest() for data in (probe, scope)] != [PINS[SOURCE], PINS[SCOPE]]:
        raise ValueError('Fixed own viewport source changed')
    source.write_bytes(derive(probe))
    (build / SCOPE.name).write_bytes(scope)
    (build / HEADER.name).write_bytes(bound(HEADER))
    compile_inputs = [runner.identity(path) for path in (source, build / SCOPE.name, build / HEADER.name)]
    binary = build / 'viewport_align_matrix.exe'
    command = ['/opt/homebrew/bin/x86_64-w64-mingw32-g++', '-std=c++17', '-O2', '-Wall', '-Wextra',
               '-Werror', '-static', str(source), '-o', str(binary), '-ld3d11', '-ld3dcompiler', '-luser32']
    subprocess.run(command, cwd=build, check=True)
    runtime_inputs = [runner.identity(binary)]

    search = os.pathsep.join(map(str, (runtime.ENGINE / 'lib/wine/x86_64-unix', runtime.MOLTENVK.parent,
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
            raise ValueError('Own viewport matrix input changed')
        return {'runtime_inputs': runtime_inputs, 'source_inputs': inputs, 'compile_inputs': compile_inputs,
                'build_command': command, 'renderer': graphics.verify_renderer(), 'fallback': fallback,
                'geometry_argument_order': ['target_w', 'target_h', 'clipped_w', 'clipped_h'],
                'case_dimensions': CASES, 'present_called': False, 'only_own_render_target_sampled': True}

    cases = [{'name': name, 'binary': binary, 'cwd': build, 'arguments': tuple(map(str, dimensions)),
              'parse_output': partial(parse_output, dimensions=dimensions),
              'parse_diagnostics': graphics.parse_provider_diagnostics} for name, dimensions in CASES.items()]
    runner.validate_environment = validate_environment
    try:
        return runner.run_cases(cases, verify_inputs=verify_inputs, role='dxgi-viewport-align-matrix',
                                environment_factory=environment, prepare_prefix=graphics.prepare_prefix)
    finally:
        runner.validate_environment = validate


if __name__ == '__main__':
    raise SystemExit(main())
