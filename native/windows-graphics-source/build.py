#!/usr/bin/env python3
"""Build the full unchanged public graphics component separately; never deploy or run it."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import types

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
SOURCE = ROOT / 'port/fivem'
BUILD = ROOT / 'build/windows-graphics-source-attempt3'
REPORT = ROOT / 'research/graphics-source-build-attempt3.json'
REVISION = '9f0e34e1cbdfc34fd05079416791f01938279097'
COMPONENT = 'code/components/rage-graphics-five'
CPP_NAMES = ('AMDDriverFixups', 'Component', 'DrawCommands', 'GameViewCapture', 'GfxFixups',
             'ReShadeFixups', 'RenderHooks', 'StubD3D11Device', 'ZOffThreadWindowing', 'dxerr', 'grcTexture')
CORE = 'build/windows-core-null-target-fix/'
ALLOCATOR = 'build/windows-source-integration/rage-allocator-five.dll'
ORIGINAL_GRAPHICS = 'build/windows-source-integration/rage-graphics-five.dll'
PINS = {
    ALLOCATOR: (175712, 'b581fda6d50f0cbbc095080a0c656fd054a393a9968a985da973020ec1761804'),
    ORIGINAL_GRAPHICS: (761952, 'edb22d90c4eea18c4ebbab31a0dfc89423ea43481ab25487dc7b11531debb58a'),
    'research/client-source-code-inputs-v10.json': (173844, '4dbaafc0a17f78f5b52ac48ace362fa843148586eb313b44f7a20064f3fbbf04'),
    'research/core-null-target-fix-build.json': (10556, '445bea6733b6a0b009a68fe0d8bac2741d38448e2033ed26cd6449d071901e5f'),
    'native/windows-core/toolchain.cmake': (2127, '15fa084f316f1a9f28ce49c8f2cd4de49a1236ebe32352d29a60d777ef0fee8b'),
    'native/windows-winhttp-probe/build.py': (10481, '4fe3acd14fe3a5ffdaf35ddcfd34ea80b1819640c4c31fbdc9a9a3a305bd4652'),
    CORE + 'CoreRT.lib': (28586, '1fa93d2300af60d6384ba35737a11284b34f826d1b9c9dab5a5d7cdd922d4026'),
    CORE + 'CoreRT.dll': (2365952, '04e4a47108a1f6d2c1459a28efb1e58575a91de042cf6e1e8cd4ccbe043eb88d'),
    CORE + 'Shared.lib': (3515946, '2d44cda9e5940058a10b2ae57d941e996692b019bd25e007c68e98a2901437dd'),
    CORE + 'cfx_minhook.lib': (171958, '3b2a74f4a0361e22d1ca897655701f94acef124057bf182c479caed1b06fe67d'),
    CORE + 'dependencies/fmt/fmt.lib': (1802902, '46d596c0531f113f95ead502fc9ccbf5234581027c37744a993f706d6346feb6'),
    CORE + 'clang_23.1_cxx17_64_md_relwithdebinfo/tbb12.lib': (43698, '7d202d17d89afd05d6bb3fe7b6f5a62f62bc89f75124293a748111e37e882af5'),
    CORE + 'clang_23.1_cxx17_64_md_relwithdebinfo/tbb12.dll': (402432, '76dc938842dce2d506d5f43f935efa62761df8b2ce89a66f11cec7c0c1ee7767'),
}
LIB_NAMES = ('CoreRT.lib', 'Shared.lib', 'cfx_minhook.lib', 'dependencies/fmt/fmt.lib',
             'clang_23.1_cxx17_64_md_relwithdebinfo/tbb12.lib')


def export_index(data):
    """Read PE export/section metadata only; classify CODE/DATA without reading function bodies."""
    def get(offset, form):
        size = struct.calcsize(form)
        if offset < 0 or offset + size > len(data): raise ValueError('PE metadata outside file')
        return struct.unpack_from(form, data, offset)
    if len(data) < 64 or data[:2] != b'MZ': raise ValueError('Expected PE image')
    pe, = get(60, '<I')
    if data[pe:pe + 4] != b'PE\0\0': raise ValueError('Expected PE signature')
    machine, count = get(pe + 4, '<HH')
    optional_size, = get(pe + 20, '<H')
    optional = pe + 24
    if machine != 0x8664 or not 1 <= count <= 96 or optional_size < 120 or get(optional, '<H')[0] != 0x20b:
        raise ValueError('Expected bounded AMD64 PE32+')
    if get(optional + 108, '<I')[0] < 1: raise ValueError('Missing export directory')
    export_rva, export_size = get(optional + 112, '<II')
    if not export_rva or export_size < 40 or export_rva + export_size > 1 << 32:
        raise ValueError('Invalid export directory')
    sections = []
    for index in range(count):
        at = optional + optional_size + index * 40
        virtual_size, rva, raw_size, raw_at = get(at + 8, '<IIII')
        flags, = get(at + 36, '<I')
        if rva + max(virtual_size, raw_size) > 1 << 32 or raw_at + raw_size > len(data):
            raise ValueError('Invalid PE section range')
        sections.append((rva, max(virtual_size, raw_size), raw_size, raw_at, flags))
    def section(rva, size=1):
        found = [row for row in sections if row[0] <= rva and rva - row[0] + size <= row[1]]
        if len(found) != 1: raise ValueError('Ambiguous or unmapped export RVA')
        return found[0]
    def offset(rva, size):
        row = section(rva, size)
        if rva - row[0] + size > row[2]: raise ValueError('Metadata is not file-backed')
        return row[3] + rva - row[0]
    def text(rva, limit=1024):
        row = section(rva)
        at = offset(rva, 1)
        end = data.find(b'\0', at, min(at + limit, row[3] + row[2]))
        if end < 0: raise ValueError('Unterminated export name')
        return data[at:end].decode('ascii')
    table = offset(export_rva, 40)
    _, _, _, _, name, ordinal_base, function_count, name_count, functions, names, ordinals = get(table, '<IIHHIIIIIII')
    if not 0 < name_count <= function_count <= 4096: raise ValueError('Unsupported export count')
    dll_name = text(name, 128)
    function_table = offset(functions, function_count * 4)
    name_table, ordinal_table = offset(names, name_count * 4), offset(ordinals, name_count * 2)
    rows, seen_names, named_ordinals = [], set(), set()
    for index in range(name_count):
        symbol = text(get(name_table + index * 4, '<I')[0])
        slot, = get(ordinal_table + index * 2, '<H')
        if slot >= function_count or symbol in seen_names or re.fullmatch(r'[A-Za-z0-9_?@$]+', symbol) is None:
            raise ValueError('Unsupported export name or ordinal')
        target, = get(function_table + slot * 4, '<I')
        if not target or export_rva <= target < export_rva + export_size:
            raise ValueError('Null or forwarded export cannot be classified')
        flags = section(target)[4]
        if not flags & 0xe0000000: raise ValueError('Export lacks executable or data-memory classification')
        ordinal = ordinal_base + slot
        if not 1 <= ordinal <= 65535: raise ValueError('Import ordinal outside PE range')
        rows.append({'name': symbol, 'ordinal': ordinal, 'rva': target,
                     'kind': 'function' if flags & 0x20000000 else 'data'})
        seen_names.add(symbol); named_ordinals.add(slot)
    if any(get(function_table + index * 4, '<I')[0] and index not in named_ordinals for index in range(function_count)):
        raise ValueError('Unnamed exports require explicit review')
    return {'dll_name': dll_name, 'exports': rows}


def object_inventory(build, sources, objects, resources):
    """Classify fixed CMake outputs from metadata lists without opening their contents."""
    directory = build / 'CMakeFiles/rage_graphics.dir'
    expected = {directory / (str(path).lstrip('/') + '.obj') for path in sources}
    component = directory / (str(SOURCE / COMPONENT / 'component.rc').lstrip('/') + '.res')
    manifest = directory / 'manifest.res'
    if (len(objects) != 13 or set(objects) != expected or len(resources) not in (1, 2)
            or component not in resources or not set(resources) <= {component, manifest}):
        raise RuntimeError('Expected thirteen exact C++ objects, component resource, and optional CMake manifest resource')
    return component, manifest if manifest in resources else None


def main():
    if sys.argv[1:]: raise RuntimeError('This builder accepts no path, source, or target arguments')
    helper_path = ROOT / 'native/windows-winhttp-probe/build.py'
    if helper_path.resolve(strict=True) != helper_path or helper_path.stat().st_nlink != 1:
        raise RuntimeError('Unexpected original compile helper')
    raw = helper_path.read_bytes()
    if (len(raw), hashlib.sha256(raw).hexdigest()) != PINS[str(helper_path.relative_to(ROOT))]:
        raise RuntimeError('Compile helper changed')
    helper = types.ModuleType('_graphics_source_compile_helper');helper.__file__ = str(helper_path)
    exec(compile(raw, str(helper_path), 'exec'), helper.__dict__)
    regular, identity = helper.regular, helper.identity
    for path in (BUILD, REPORT): helper._plain_path(path, ROOT)
    if BUILD.exists() or REPORT.exists(): raise RuntimeError('Use a fresh separate build; never overwrite prior artifacts')
    BUILD.mkdir(parents=True)
    (BUILD / '.graphics-source-build').write_text('Own public graphics component baseline; no deployment\n')
    record = {'compiled': False, 'source_revision': REVISION, 'baseline_public_source_unchanged': False,
              'hresult_fix_applied': False, 'stage_or_prefix_modified': False, 'runtime_started': False}
    phase = 'preflight'
    try:
        payloads, pinned = {}, []
        for name, pin in PINS.items():
            item = identity(ROOT / name)
            if (item['bytes'], item['sha256']) != pin: raise RuntimeError('Fixed existing code/build input changed')
            pinned.append(item);payloads[name] = (ROOT / name).read_bytes()
            if hashlib.sha256(payloads[name]).hexdigest() != pin[1]: raise RuntimeError('Input changed during capture')
        actual_revision = subprocess.check_output(['git', '-C', str(SOURCE), 'rev-parse', 'HEAD'], text=True).strip()
        if actual_revision != REVISION: raise RuntimeError('Wrong public source revision')
        clean_paths = [COMPONENT, 'code/client/common/StdInc.cpp', 'code/client/common/Error.cpp']
        if subprocess.run(['git', '-C', str(SOURCE), 'diff', '--quiet', REVISION, '--', *clean_paths]).returncode:
            raise RuntimeError('Baseline component or common source differs from the fixed revision')
        component = SOURCE / COMPONENT
        sources = [component / 'src' / (name + '.cpp') for name in CPP_NAMES]
        if {p.name for p in (component / 'src').glob('*.cpp')} != {p.name for p in sources}:
            raise RuntimeError('Unexpected complete graphics translation-unit set')
        sources += [SOURCE / 'code/client/common' / name for name in ('StdInc.cpp', 'Error.cpp')]
        baseline = sorted(p for p in component.rglob('*') if p.is_file()) + sources[-2:]
        source_inputs = [identity(path) for path in baseline]
        core_record = json.loads(payloads['research/core-null-target-fix-build.json'])
        if (core_record.get('compiled') is not True or core_record.get('source_revision') != REVISION
                or core_record['artifact'] != next(x for x in pinned if x['path'] == CORE + 'CoreRT.dll')
                or core_record['tbb_artifact'] != next(x for x in pinned if x['path'].endswith('/tbb12.dll'))):
            raise RuntimeError('Existing Core10 provenance does not match its fixed code')
        manifest = json.loads(payloads['research/client-source-code-inputs-v10.json'])
        for name in ('rage-allocator-five.dll', 'rage-graphics-five.dll'):
            found = [x for x in manifest['files'] if x['name'] == name]
            expected = PINS['build/windows-source-integration/' + name]
            if len(found) != 1 or (found[0]['bytes'], found[0]['sha256']) != expected:
                raise RuntimeError('Original stage component differs from Source10 code manifest')
        exports = export_index(payloads[ALLOCATOR])
        if exports['dll_name'].casefold() != 'rage-allocator-five.dll': raise RuntimeError('Wrong allocator module identity')
        definition = BUILD / 'rage-allocator-five.def'
        definition.write_text('LIBRARY rage-allocator-five.dll\nEXPORTS\n' + ''.join(
            f"  {row['name']} @{row['ordinal']}" + (' DATA' if row['kind'] == 'data' else '') + '\n'
            for row in exports['exports']))
        tools = {name: Path('/opt/homebrew/opt/llvm/bin') / name
                 for name in ('llvm-dlltool', 'llvm-readobj', 'clang-cl', 'llvm-rc')}
        tools['lld-link'] = Path('/opt/homebrew/opt/lld/bin/lld-link')
        tool_inputs = [{'path': str(path.resolve()), 'bytes': path.stat().st_size,
                        'sha256': hashlib.sha256(path.read_bytes()).hexdigest()} for path in tools.values()]
        commands = [[str(tools['llvm-dlltool']), '-m', 'i386:x86-64', '-d', str(definition), '-l', str(BUILD / 'rage-allocator-five.lib')]]
        include_roots = [SOURCE / x for x in ('code/client/shared', 'code/client/citicore', 'code/shared',
            'code/deplibs/include', COMPONENT + '/include', COMPONENT,
            'code/components/rage-allocator-five/include', 'vendor/rapidjson/include', 'vendor/utfcpp/source',
            'vendor/jitasm', 'vendor/minhook/include', 'vendor/udis86', 'vendor/tbb/include', 'vendor/fmtlib/include')]
        include_roots += [ROOT / CORE / 'generated/udis86', ROOT / CORE / 'generated/udis86/libudis86']
        include_roots += sorted(p / 'include' for p in (SOURCE / 'vendor/boost-submodules').iterdir() if (p / 'include').is_dir())
        if any(not path.is_dir() or path.resolve() != path for path in include_roots):
            raise RuntimeError('Missing or redirected existing component include directory')
        quote = lambda path: '"' + str(path).replace('\\', '/') + '"'
        cmake = BUILD / 'CMakeLists.txt'
        cmake.write_text('cmake_minimum_required(VERSION 3.25)\nproject(PublicGraphicsBaseline LANGUAGES CXX RC)\n'
            'set(CMAKE_CXX_STANDARD 17)\nset(CMAKE_CXX_STANDARD_REQUIRED ON)\n'
            'set(CMAKE_MSVC_RUNTIME_LIBRARY MultiThreadedDLL)\n'
            'add_library(rage_graphics SHARED\n' + '\n'.join(quote(x) for x in sources + [component / 'component.rc']) + ')\n'
            'target_compile_definitions(rage_graphics PRIVATE UNICODE _UNICODE GTA_FIVE HAS_LOCAL_H '
            'COMPILING_RAGE_GRAPHICS_FIVE _CFX_COMPONENT_NAME=rage-graphics-five '
            'BOOST_ALL_NO_LIB BOOST_NULLPTR=nullptr _HAS_AUTO_PTR_ETC _PPLTASK_ASYNC_LOGGING=0 '
            '_CRT_SECURE_NO_WARNINGS _WIN32_WINNT=0x0A00 WINVER=0x0A00 '
            '"GAME_BUILDS=(1)(1604)(2060)(2189)(2372)(2545)(2612)(2699)(2802)(2944)(3095)(3258)(3323)(3407)(3570)(3751)(3788)(3889)")\n'
            'target_compile_options(rage_graphics PRIVATE "$<$<COMPILE_LANGUAGE:CXX>:/EHsc>" '
            '"$<$<COMPILE_LANGUAGE:CXX>:/clang:-fno-operator-names>" '
            '"$<$<COMPILE_LANGUAGE:CXX>:/utf-8>" "$<$<COMPILE_LANGUAGE:CXX>:/bigobj>" '
            '"$<$<COMPILE_LANGUAGE:CXX>:/Zc:__cplusplus>")\n'
            'target_include_directories(rage_graphics PRIVATE\n' + '\n'.join(map(quote, include_roots)) + ')\n'
            'foreach(dir ${CFX_WIN_INCLUDE_DIRS})\n'
            ' target_include_directories(rage_graphics PRIVATE "$<$<COMPILE_LANGUAGE:RC>:${dir}>")\nendforeach()\n'
            'target_link_libraries(rage_graphics PRIVATE\n' + '\n'.join(quote(ROOT / CORE / x) for x in LIB_NAMES)
            + '\n' + quote(BUILD / 'rage-allocator-five.lib')
            + '\nuser32 gdi32 advapi32 shell32 ole32 oleaut32 shlwapi ws2_32 iphlpapi psapi dbghelp bcrypt '
            'ntdll comctl32 version d3d11 dxgi dxguid dcomp winmm concrt)\n'
            'set_target_properties(rage_graphics PROPERTIES PREFIX "" OUTPUT_NAME "rage-graphics-five")\n')
        commands += [['cmake', '-S', str(BUILD), '-B', str(BUILD), '-G', 'Ninja',
            '-DCMAKE_TOOLCHAIN_FILE=' + str(ROOT / 'native/windows-core/toolchain.cmake'),
            '-DCMAKE_BUILD_TYPE=RelWithDebInfo', '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON'],
            ['cmake', '--build', str(BUILD), '--target', 'rage_graphics', '--parallel', '2']]
        record.update(source_evidence=source_inputs, existing_code_build_inputs=pinned,
            recipe_source=identity(HERE / 'build.py'), allocator_export_metadata=exports,
            generated_allocator_definition=identity(definition), generated_build_configuration=identity(cmake),
            compiler_support_tools=tool_inputs, commands=commands,
            deliberate_build_configuration_deltas=['Separate CMake target; no upstream Premake writes',
                'Existing Core10 libraries imported; no dependent component rebuilt',
                'No PCH; same complete public translation units and component resource',
                'ENBSERIES_CACHE_ATTEMPT remains undefined; unused optional msgpack target omitted'])
        environment = dict(os.environ)
        for key in ('CL', '_CL_', 'CFLAGS', 'CXXFLAGS', 'CPPFLAGS', 'LDFLAGS', 'INCLUDE', 'LIB', 'LIBPATH'):
            environment.pop(key, None)
        with (BUILD / 'build.log').open('x') as log:
            for phase, command in zip(('import-library', 'configure', 'compile-link'), commands):
                result = subprocess.run(command, cwd=ROOT, env=environment, stdout=log, stderr=subprocess.STDOUT)
                if result.returncode: raise RuntimeError(f'{phase} failed with exit {result.returncode}')
        phase = 'inspection'
        binary = BUILD / 'rage-graphics-five.dll'
        inspection_commands = [[str(tools['llvm-readobj']), '--file-headers', '--coff-imports', '--coff-exports', '--coff-resources', str(binary)]]
        text = subprocess.check_output(inspection_commands[0], text=True)
        (BUILD / 'pe-inspection.txt').write_text(text)
        own_exports = export_index(binary.read_bytes())
        original_exports = export_index(payloads[ORIGINAL_GRAPHICS])
        dlls = re.findall(r'^\s+Name: (.+\.dll)$', text, re.M | re.I)
        if ('IMAGE_FILE_MACHINE_AMD64' not in text or 'd3d11.dll' not in [x.casefold() for x in dlls]
                or 'dxgi.dll' not in [x.casefold() for x in dlls]
                or 'FXCOMPONENT' not in text.upper() or re.search(r'\b115\b', text) is None
                or not any(x['name'] == 'CreateComponent' and x['kind'] == 'function' for x in own_exports['exports'])):
            raise RuntimeError('Unexpected component PE imports, exports, architecture or resource')
        old_names = {(x['name'], x['kind']) for x in original_exports['exports']}
        new_names = {(x['name'], x['kind']) for x in own_exports['exports']}
        if (source_inputs != [identity(ROOT / x['path']) for x in source_inputs]
                or pinned != [identity(ROOT / x['path']) for x in pinned]
                or record['recipe_source'] != identity(HERE / 'build.py')):
            raise RuntimeError('Existing baseline source or dependency changed during compilation')
        objects = sorted((BUILD / 'CMakeFiles/rage_graphics.dir').rglob('*.obj'))
        resources = sorted((BUILD / 'CMakeFiles/rage_graphics.dir').rglob('*.res'))
        component_resource, manifest_resource = object_inventory(BUILD, sources, objects, resources)
        with (BUILD / 'object-directives.txt').open('x') as output:
            for obj in objects:
                command = [str(tools['llvm-readobj']), '--coff-directives', str(obj)]
                directives = subprocess.check_output(command, text=True)
                inspection_commands.append(command); output.write(directives)
                if (not ('RuntimeLibrary=MD_DynamicRelease' in directives
                         or re.search(r'/DEFAULTLIB:msvcrt(?:\.lib)?\b', directives, re.I))
                        or re.search(r'/DEFAULTLIB:(?:libcmt|libcmtd|msvcrtd)(?:\.lib)?\b', directives, re.I)):
                    raise RuntimeError('Unexpected component object CRT linkage')
        record.update(compiled=True, baseline_public_source_unchanged=True,
            artifact=identity(binary), generated_allocator_import_library=identity(BUILD / 'rage-allocator-five.lib'),
            objects=[identity(x) for x in objects], resource_object=identity(component_resource),
            cmake_manifest_resource=identity(manifest_resource) if manifest_resource is not None else None,
            object_directives=identity(BUILD / 'object-directives.txt'), md_verified_object_count=len(objects),
            imports=dlls, export_metadata=own_exports,
            original_component_export_metadata=original_exports,
            missing_original_named_exports=[list(x) for x in sorted(old_names - new_names)],
            additional_named_exports=[list(x) for x in sorted(new_names - old_names)],
            abi_export_coverage_complete=old_names <= new_names,
            pe_inspection=identity(BUILD / 'pe-inspection.txt'), inspection_commands=inspection_commands,
            build_log=identity(BUILD / 'build.log'), compile_commands=identity(BUILD / 'compile_commands.json'),
            deployment_or_runtime_compatibility_claimed=False)
    except Exception as error:
        record.update(failure_phase=phase, failure_type=type(error).__name__, failure_message=str(error))
        if (BUILD / 'build.log').exists(): record['build_log'] = identity(BUILD / 'build.log')
    record['at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    regular(REPORT, missing=True)
    with REPORT.open('x') as output: json.dump(record, output, indent=2);output.write('\n')
    print(json.dumps({'compiled': record['compiled'], 'report': identity(REPORT), 'runtime_started': False}))
    return 0 if record['compiled'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
