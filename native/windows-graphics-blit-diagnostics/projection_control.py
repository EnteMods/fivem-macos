#!/usr/bin/env python3
"""Test the proposed fixed logical projection with a full DXMT viewport and scissor."""
from functools import partial
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

import viewport_align_matrix as matrix


CASES = {name: (*sizes[:2], 1920, 1080) for name, sizes in matrix.CASES.items()}
SHADER = br'''static constexpr char Shader[] = R"(
cbuffer Geometry : register(b0) { float2 logical; float2 quad; };
struct Vertex { float4 position : SV_Position; float2 uv : TEXCOORD; };
Vertex vertex(uint id : SV_VertexID)
{
    Vertex output;
    output.uv = float2(id & 1, id >> 1);
    const float2 xy = quad * float2(output.uv.x, 1 - output.uv.y);
    output.position = float4(2 * xy / logical - 1, 0, 1);
    return output;
}
float4 pixel(Vertex input) : SV_Target
{
    return input.uv.y < 0.5 ? float4(1, 0, 0, 1) : float4(0, 1, 0, 1);
}
)";

'''
MEASURE = br'''    const D3D11_VIEWPORT full{0, 0, float(Width), float(Height), 0.125f, 0.875f};
    const D3D11_RECT scissor{0, 0, LONG(Width), LONG(Height)};
    context->RSSetViewports(1, &full);
    context->RSSetScissorRects(1, &scissor);

    D3D11_BUFFER_DESC constantsDesc{};
    constantsDesc.ByteWidth = 4 * sizeof(float);
    constantsDesc.BindFlags = D3D11_BIND_CONSTANT_BUFFER;
    ComPtr<ID3D11Buffer> constants;
    if (FAILED(device->CreateBuffer(&constantsDesc, nullptr, constants.GetAddressOf())) || !constants) return 19;
    auto* cb = constants.Get();
    context->VSSetConstantBuffers(0, 1, &cb);
    const auto sameRaster = [&] {
        UINT count = 1;
        D3D11_RECT observed{};
        ComPtr<ID3D11RasterizerState> state;
        context->RSGetScissorRects(&count, &observed);
        context->RSGetState(state.GetAddressOf());
        return SameViewports(context.Get(), &full, 1) && count == 1 && state.Get() == rasterizer.Get()
            && !std::memcmp(&observed, &scissor, sizeof(scissor));
    };
    const auto sample = [&](UINT quadW, UINT quadH, Bounds& bounds) {
        const float values[]{float(LogicalWidth), float(LogicalHeight), float(quadW), float(quadH)};
        auto* view = targetView.Get();
        context->UpdateSubresource(cb, 0, nullptr, values, 0, 0);
        context->OMSetRenderTargets(1, &view, nullptr);
        Draw(context.Get(), view);
        return Readback(context.Get(), target.Get(), staging.Get(), bounds);
    };

    Bounds before, after;
    const bool initialState = sameRaster();
    if (!sample(Width, Height, before)) return 20;
    const bool beforeState = sameRaster();
    if (!sample(LogicalWidth, LogicalHeight, after)) return 21;
    const bool unchanged = initialState && beforeState && sameRaster();
    const bool orientation = before.firstRed && before.lastGreen && after.firstRed && after.lastGreen;
    const bool hidden = !IsWindowVisible(window);
    const auto nearest = [](UINT numerator, UINT denominator) { return (2 * numerator + denominator) / (2 * denominator); };
    const UINT right = nearest(Width * Width, LogicalWidth);
    const UINT top = nearest(Height * (LogicalHeight - Height), LogicalHeight);
    std::printf("{\"phase\":\"complete\",\"pid\":%lu,\"tid\":%lu", GetCurrentProcessId(), GetCurrentThreadId());
    PrintBounds("before", before);
    PrintBounds("after", after);
    std::printf(",\"raster_unchanged\":%s,\"y_orientation_preserved\":%s,\"window_hidden\":%s}\n",
                unchanged ? "true" : "false", orientation ? "true" : "false", hidden ? "true" : "false");
    return unchanged && orientation && hidden && before.Matches(0, top, right, Height - top)
        && after.Matches(0, 0, Width, Height) ? 0 : 23;
}

'''


def replace(source, original, replacement):
    if source.count(original) != 1:
        raise ValueError('Expected one pinned projection anchor')
    return source.replace(original, replacement, 1)


def region(source, first, after, replacement):
    if source.count(first) != 1 or source.count(after) != 1:
        raise ValueError('Expected unique projection region anchors')
    start = source.index(first)
    end = source.index(after, start)
    return source[:start] + replacement + source[end:]


def derive(original):
    source = matrix.derive(original).replace(b'SubWidth', b'LogicalWidth').replace(b'SubHeight', b'LogicalHeight')
    source = region(source, b'static constexpr char Shader[]', b'struct Bounds', SHADER)
    source = region(source, b'static bool Declines(', b'static void PrintBounds(', b'')
    source = region(source, b'    ComPtr<ID3D11RasterizerState> plain, clipped;', b'    context->VSSetShader(', br'''    raster.ScissorEnable = TRUE;
    ComPtr<ID3D11RasterizerState> rasterizer;
    if (FAILED(device->CreateRasterizerState(&raster, rasterizer.GetAddressOf())) || !rasterizer) return 18;
    context->RSSetState(rasterizer.Get());
    context->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLESTRIP);
''')
    source = region(source, b'    const auto y = Height - LogicalHeight;', b'int main(', MEASURE)
    for old, new in (
        (b'    bool Matches(', b'    bool firstRed = false, lastGreen = false;\n    bool Matches('),
        (b'context->Draw(3, 0);', b'context->Draw(4, 0);'),
        (b'            if (pixel[0] != 255 || pixel[1] || pixel[2] || pixel[3] != 255) continue;', br'''            const bool red = pixel[0] == 255 && !pixel[1];
            const bool green = !pixel[0] && pixel[1] == 255;
            if ((!red && !green) || pixel[2] || pixel[3] != 255) continue;
            if (!bounds.pixels) bounds.firstRed = red;
            bounds.lastGreen = green;'''),
        (b'LogicalWidth < 2 || LogicalWidth >= Width || LogicalHeight >= Height',
         b'Width >= LogicalWidth || Height >= LogicalHeight'),
        (b'OwnDxmtViewportAlignProbe', b'OwnDxmtProjectionProbe'),
    ):
        source = replace(source, old, new)
    return source


def parse_output(lines, code, *, dimensions):
    width, height, logical_w, logical_h = dimensions
    right = (2 * width * width + logical_w) // (2 * logical_w)
    top = (2 * height * (logical_h - height) + logical_h) // (2 * logical_h)
    expected = {'phase': 'complete', 'before': [0, top, right, height], 'before_pixels': right * (height - top),
                'after': [0, 0, width, height], 'after_pixels': width * height, 'raster_unchanged': True,
                'y_orientation_preserved': True, 'window_hidden': True}
    row = json.loads(lines[0]) if len(lines) == 1 else None
    valid = (type(row) is dict and set(row) == {'pid', 'tid', *expected}
             and all(type(row[name]) is int and 0 < row[name] <= 0xffffffff for name in ('pid', 'tid'))
             and all(type(row[name]) is type(value) for name, value in expected.items())
             and all(all(type(value) is int for value in row[name]) for name in ('before', 'after')))
    return {'events': [row] if valid else [],
            'passed': valid and code == 0 and all(row[name] == value for name, value in expected.items())}


def main():
    graphics = matrix.load(matrix.DXGI).graphics()
    runner, runtime = graphics.runner, graphics.runtime
    sources = [matrix.HERE / name for name in ('record_control.py', 'viewport_align_control.py', 'viewport_align_matrix.py')]
    inputs = [runner.identity(path) for path in (matrix.SOURCE, matrix.SCOPE, matrix.HEADER, matrix.DXGI,
                                                *sources, Path(__file__).resolve())]
    build = Path(tempfile.mkdtemp(prefix='windows-dxgi-projection-', dir=matrix.ROOT / 'build'))
    source = build / 'projection_probe.cpp'
    for original, dest in ((matrix.SOURCE, source), (matrix.SCOPE, build / matrix.SCOPE.name)):
        data = runtime.read_regular(original)
        if hashlib.sha256(data).hexdigest() != matrix.PINS[original]:
            raise ValueError('Pinned own fixture changed')
        dest.write_bytes(derive(data) if dest == source else data)
    (build / matrix.HEADER.name).write_bytes(matrix.bound(matrix.HEADER))
    compile_inputs = [runner.identity(path) for path in (source, build / matrix.SCOPE.name, build / matrix.HEADER.name)]
    binary = build / 'projection_probe.exe'
    command = ['/opt/homebrew/bin/x86_64-w64-mingw32-g++', '-std=c++17', '-O2', '-Wall', '-Wextra', '-Werror',
               '-static', str(source), '-o', str(binary), '-ld3d11', '-ld3dcompiler', '-luser32']
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
        if any(runner.identity(matrix.ROOT / item['path']) != item for item in (*inputs, *compile_inputs, *artifacts)):
            raise ValueError('Own projection fixture input changed')
        return {'runtime_inputs': artifacts, 'source_inputs': inputs, 'compile_inputs': compile_inputs,
                'build_command': command, 'renderer': graphics.verify_renderer(), 'fallback': fallback,
                'geometry_argument_order': ['target_w', 'target_h', 'logical_w', 'logical_h'],
                'case_dimensions': CASES, 'present_called': False, 'rage_projection_observed': False}

    cases = [{'name': name, 'binary': binary, 'cwd': build, 'arguments': tuple(map(str, dimensions)),
              'parse_output': partial(parse_output, dimensions=dimensions),
              'parse_diagnostics': graphics.parse_provider_diagnostics} for name, dimensions in CASES.items()]
    runner.validate_environment = validate_environment
    try:
        return runner.run_cases(cases, verify_inputs=verify_inputs, role='dxgi-projection',
                                environment_factory=environment, prepare_prefix=graphics.prepare_prefix)
    finally:
        runner.validate_environment = validate


if __name__ == '__main__':
    raise SystemExit(main())
