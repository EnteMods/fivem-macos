#!/usr/bin/env python3
"""Build the gated DrawCommands diagnostic separately from the live client."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import build as blit
import gate_overlay


HERE = Path(__file__).resolve().parent
ROOT = blit.ROOT
BLIT_REPORT_PIN = (4380, '588f7f20df8a5985e138a93e10d6e97db9fb702e16e7510979e42255abbc758a')
GATE_DEFINE = gate_overlay.DEFINE
Y_PROBE_OFFSET = 90
PROJECTION_UNIT_SHA = '1b2cec17d3a7fa415e20a6c706d52eaace73aff78e1ba38d154432b6b591c70b'
Y_ALIGNMENT = 'target_height_minus_reference_height'
NATIVE_EXTENTS = 'projection-sharpness-native-extents'
NATIVE_EXTENTS_FAST = 'projection-native-extents-fast'
RETINA_FULLSCREEN_Y = 'projection-retina-fullscreen-y'


def translate_projection_y(unit, offset):
    if hashlib.sha256(unit).hexdigest() != PROJECTION_UNIT_SHA:
        raise RuntimeError('Require the exact projection A/B translation unit')
    anchor = b'\t\t\tsize = {geometry.width, geometry.height};\r\n'
    edit = (b'\t\t{\r\n\t\t\tfor (auto& vertex : pending.vertices)\r\n'
            + f'\t\t\t\tvertex.y += {offset};\r\n'.encode('ascii')
            + anchor + b'\t\t}\r\n')
    if unit.count(anchor) != 1 or edit in unit:
        raise RuntimeError('Require exactly one successful projection branch')
    return unit.replace(anchor, edit, 1)


def main(variant='gates'):
    build = ROOT / f'build/windows-graphics-blit-{variant}'
    report_path = ROOT / f'research/graphics-blit-{variant}-build.json'
    fullscreen_y = variant == RETINA_FULLSCREEN_Y
    fast = variant == NATIVE_EXTENTS_FAST or fullscreen_y
    native_extents = variant == NATIVE_EXTENTS or fast
    sharpness_overlay_needed = variant == 'projection-sharpness' or native_extents
    sharpness = sharpness_overlay_needed and not fast
    aligned = variant == 'projection-aligned' or sharpness_overlay_needed
    projection = variant in ('projection', 'projection-y-probe') or aligned
    vertices = variant == 'vertices' or projection
    reader = blit.base_reader()
    for path in (build, report_path):
        reader.plain(path)
        if path.exists():
            raise RuntimeError('Preserve the existing gate build and report')
    report = json.loads(reader.bound(blit.REPORT, BLIT_REPORT_PIN))
    baseline = json.loads(reader.bound(blit.BASE_REPORT, blit.BASE_REPORT_PIN))
    if not report['compiled'] or report['source_revision'] != baseline['source_revision']:
        raise RuntimeError('Require the compiled blit baseline')

    def verify(row):
        return reader.bound(ROOT / row['path'], (row['bytes'], row['sha256']))

    frozen = [*report['generated_overlay'], *report['source_evidence'], report['artifact'], report['pe_inspection'],
              *baseline['baseline_evidence'], *baseline['source_evidence'], *baseline['generated_overlay'],
              *baseline['compiler_support_tools'], baseline['source_recipe_source']]
    frozen_by_path = {row['path']: row for row in frozen}
    for row in frozen_by_path.values():
        verify(row)
    source_row, header_row, cmake_row = report['generated_overlay']
    source, header, cmake = map(verify, (source_row, header_row, cmake_row))
    patched = gate_overlay.apply(source)
    if gate_overlay.strip(patched) != source:
        raise RuntimeError('Gate overlay must reverse to the frozen blit source')
    defines = [blit.overlay.DEFINE, GATE_DEFINE]
    extra_files = []
    tests_pattern = 'test_gate_overlay.py'
    if vertices:
        import vertex_overlay
        combined = vertex_overlay.apply(patched)
        if vertex_overlay.strip(combined) != patched:
            raise RuntimeError('Vertex overlay must reverse to the frozen gate source')
        patched = combined
        defines.append(vertex_overlay.DEFINE)
        extra_files = ['vertex_overlay.py', vertex_overlay.HEADER, 'test_vertex_overlay.py']
        tests_pattern = 'test_*overlay.py'
    if projection:
        import projection_overlay
        combined = projection_overlay.apply(patched)
        if projection_overlay.strip(combined) != patched:
            raise RuntimeError('Projection overlay must reverse to the frozen vertex source')
        patched = combined
        defines.append(projection_overlay.DEFINE)
        extra_files.extend(['projection_overlay.py', projection_overlay.HEADER,
                            'test_projection_overlay.py', 'test_projection_scale.py'])
        tests_pattern = 'test_*.py'
    if variant == 'projection-y-probe':
        patched = translate_projection_y(patched, f'{Y_PROBE_OFFSET}.0f')
    elif aligned:
        patched = translate_projection_y(patched, 'static_cast<float>(geometry.height) - ProjectionReferenceHeight')
    if sharpness_overlay_needed:
        import sharpness_overlay
        measured = sharpness_overlay.apply(patched)
        if sharpness_overlay.strip(measured) != patched:
            raise RuntimeError('Sharpness overlay must reverse to the aligned projection source')
        patched = measured
        if sharpness:
            defines.append(sharpness_overlay.DEFINE)
        extra_files.extend(['sharpness_overlay.py', 'test_sharpness_overlay.py'])
        if getattr(sharpness_overlay, 'HEADER', None):
            extra_files.append(sharpness_overlay.HEADER)
    if native_extents:
        import native_extents_overlay
        original_projection_header = reader.read(HERE / projection_overlay.HEADER)
        native_unit, native_header = native_extents_overlay.apply(patched, original_projection_header)
        if native_extents_overlay.strip(native_unit, native_header) != (patched, original_projection_header):
            raise RuntimeError('Native extents must reverse to the frozen sharpness source and projection header')
        patched = native_unit
        extra_files.extend(['native_extents_overlay.py', 'test_native_extents_overlay.py'])
    if fast:
        import native_extents_fast_overlay
        fast_unit = native_extents_fast_overlay.apply(patched)
        if native_extents_fast_overlay.strip(fast_unit) != patched:
            raise RuntimeError('Fast replay must reverse to the frozen native-extents source')
        patched = fast_unit
        extra_files.extend(['native_extents_fast_overlay.py', 'test_native_extents_fast_overlay.py'])
    if fullscreen_y:
        import fullscreen_y_overlay
        fullscreen_unit = fullscreen_y_overlay.apply(patched)
        if fullscreen_y_overlay.strip(fullscreen_unit) != patched:
            raise RuntimeError('Fullscreen Y must reverse to the frozen fast replay source')
        patched = fullscreen_unit
        extra_files.extend(['fullscreen_y_overlay.py', fullscreen_y_overlay.HEADER, 'test_fullscreen_y_overlay.py'])
    old_unit = str(ROOT / source_row['path']).encode()
    unit = build / 'overlay/DrawCommands.cpp'
    new_unit = str(unit).encode()
    old_define = f'COMPILE_DEFINITIONS "{blit.overlay.DEFINE}=1"'.encode()
    compile_defines = ';'.join(f'{name}=1' for name in defines)
    new_define = f'COMPILE_DEFINITIONS "{compile_defines}"'.encode()
    if cmake.count(old_unit) != 2 or cmake.count(old_define) != 1 or GATE_DEFINE.encode() in cmake:
        raise RuntimeError('Unexpected frozen blit CMake substitutions')
    cmake = cmake.replace(old_unit, new_unit).replace(old_define, new_define)
    commands = report['compile_commands_invoked']
    if len(commands) != 2 or [cmd.count(str(blit.BUILD)) for cmd in commands] != [2, 1]:
        raise RuntimeError('Unexpected frozen blit command roles')
    commands = [[str(build) if arg == str(blit.BUILD) else arg for arg in cmd] for cmd in commands]
    new_inputs = [reader.identity(HERE / name) for name in (
        'build_gates.py', 'gate_overlay.py', gate_overlay.HEADER, 'test_gate_overlay.py', *extra_files)]

    build.mkdir()
    unit.parent.mkdir()
    unit.write_bytes(patched)
    (unit.parent / Path(header_row['path']).name).write_bytes(header)
    for row in new_inputs:
        path = Path(row['path'])
        if path.suffix == '.h':
            payload = verify(row)
            if native_extents and path.name == projection_overlay.HEADER:
                if payload != original_projection_header:
                    raise RuntimeError('Projection header changed before the native-extents build')
                payload = native_header
            (unit.parent / path.name).write_bytes(payload)
    (build / 'CMakeLists.txt').write_bytes(cmake)
    environment = {name: value for name, value in os.environ.items() if name not in (
        'CL', '_CL_', 'CFLAGS', 'CXXFLAGS', 'CPPFLAGS', 'LDFLAGS', 'INCLUDE', 'LIB', 'LIBPATH')}
    log = build / 'build.log'
    with log.open('x') as output:
        tests = [sys.executable, '-B', '-m', 'unittest', 'discover', '-s', str(HERE), '-p', tests_pattern, '-v']
        for command in (tests, *commands):
            subprocess.run(command, cwd=ROOT, env=environment, stdout=output, stderr=subprocess.STDOUT, check=True)

    binary = build / 'rage-graphics-five.dll'
    llvm = baseline['compiler_support_tools'][1]['path']
    inspection = subprocess.check_output([llvm, '--file-headers', '--coff-imports', '--coff-exports',
                                          '--coff-resources', str(binary)], text=True)
    inspection_file = build / 'pe-inspection.txt'
    inspection_file.write_text(inspection)
    helper_row = baseline['source_recipe_source']
    helper = blit.load_module(ROOT / helper_row['path'], verify(helper_row))

    def export_signature(data):
        return {(row['name'], row['kind'], row['ordinal']) for row in helper.export_index(data)['exports']}

    exports = export_signature(reader.read(binary))
    original_imports = blit.imports(verify(report['pe_inspection']).decode())
    if (len(exports) != 80 or exports != export_signature(verify(report['artifact'])) or not original_imports
            or blit.imports(inspection) != original_imports or 'FXCOMPONENT' not in inspection.upper()):
        raise RuntimeError('Gate build must preserve the blit DLL export/import/resource boundary')
    entries = json.loads(reader.read(build / 'compile_commands.json'))
    if len(entries) != 14 or any([entry['file'] for entry in entries if define in entry['command']] != [str(unit)]
                                 for define in defines):
        raise RuntimeError('Require exactly one gate-instrumented translation unit')
    if fast and any(sharpness_overlay.DEFINE in entry['command'] for entry in entries):
        raise RuntimeError('Fast replay must compile without sharpness diagnostics')
    for row in [*frozen_by_path.values(), *new_inputs]:
        verify(row)

    result = {'compiled': True, 'runtime_started': False, 'stage_or_prefix_modified': False,
              'source_revision': report['source_revision'], 'baseline_report': reader.identity(blit.REPORT),
              'baseline_artifact': report['artifact'], 'artifact': reader.identity(binary),
              'source_evidence': new_inputs, 'frozen_input_count': len(frozen_by_path),
              'build_log': reader.identity(log), 'pe_inspection': reader.identity(inspection_file),
              'exports_match_blit': len(exports), 'import_symbols_match_blit': True,
              'compile_commands_invoked': commands}
    if vertices:
        result['vertex_measurement_enabled'] = True
    if projection:
        result['projection_ab_candidate'] = True
    if variant == 'projection-y-probe':
        result['projection_probe_y_offset'] = Y_PROBE_OFFSET
    if aligned:
        result['projection_y_alignment'] = Y_ALIGNMENT
    if sharpness:
        result['sharpness_texture_measurement'] = True
    if native_extents:
        result['native_extents_projection'] = True
        result['native_extents_generated_overlay'] = [reader.identity(unit),
                                                      reader.identity(unit.parent / projection_overlay.HEADER)]
    if fast:
        result['native_extents_fast_path'] = True
        result['sharpness_texture_measurement'] = False
    if fullscreen_y:
        result['retina_fullscreen_y_projection'] = True
        result['retina_fullscreen_y_source'] = reader.identity(unit.parent / fullscreen_y_overlay.HEADER)
    with report_path.open('x') as output:
        json.dump(result, output, indent=2)
        output.write('\n')
    print(json.dumps(result['artifact']))


if __name__ == '__main__':
    variants = ('vertices', 'projection', 'projection-y-probe', 'projection-aligned', 'projection-sharpness',
                NATIVE_EXTENTS, NATIVE_EXTENTS_FAST, RETINA_FULLSCREEN_Y)
    if len(sys.argv) > 2 or (len(sys.argv) == 2 and sys.argv[1] not in ['--' + item for item in variants]):
        raise SystemExit('Usage: build_gates.py [' + ' | '.join('--' + item for item in variants) + ']')
    main(sys.argv[1].removeprefix('--') if len(sys.argv) == 2 else 'gates')
