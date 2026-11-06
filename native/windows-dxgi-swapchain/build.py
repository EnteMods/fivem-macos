#!/usr/bin/env python3
"""Compile one own HWND/DXGI experiment; never start Wine or the resulting PE."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import types

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
BUILD = ROOT / 'build/windows-dxgi-swapchain'
REPORT = ROOT / 'research/windows-dxgi-swapchain-build.json'
HELPER = ROOT / 'native/windows-winhttp-probe/build.py'
HELPER_SHA = '4fe3acd14fe3a5ffdaf35ddcfd34ea80b1819640c4c31fbdc9a9a3a305bd4652'
RENDERER = ROOT / 'research/dxmt-a444716-code-inputs.json'
RENDERER_SHA = '0703fd74b63eb144378dc7f298dcccb8ed423701507654785b1267e8a64f4eba'
MARKER = b'Own fixed same-process HWND DXGI compile-only experiment\n'


def main():
    if sys.argv[1:]:
        raise RuntimeError('No arbitrary build paths or targets are accepted')
    if HELPER.resolve(strict=True) != HELPER or HELPER.stat().st_nlink != 1:
        raise RuntimeError('Unexpected original compile helper')
    raw = HELPER.read_bytes()
    if hashlib.sha256(raw).hexdigest() != HELPER_SHA:
        raise RuntimeError('Original compile helper changed')
    helper = types.ModuleType('_own_dxgi_compile_helper')
    helper.__file__ = str(HELPER)
    exec(compile(raw, str(HELPER), 'exec'), helper.__dict__)
    regular, identity = helper.regular, helper.identity
    sources = [identity(HERE / name) for name in ('probe.cpp', 'build.py')]
    renderer = identity(RENDERER)
    if renderer['sha256'] != RENDERER_SHA:
        raise RuntimeError('Fixed DXMT code-input review changed')
    toolchain = identity(ROOT / 'native/windows-core/toolchain.cmake')
    regular(REPORT, missing=True)
    if REPORT.exists():
        raise RuntimeError('Do not overwrite an issued experiment build report')
    helper._plain_path(BUILD, ROOT)
    if BUILD.exists():
        regular(BUILD / '.own-dxgi-swapchain')
        if not BUILD.is_dir() or (BUILD / '.own-dxgi-swapchain').read_bytes() != MARKER:
            raise RuntimeError('Require the exact own build marker')
        for base, folders, files in os.walk(BUILD, followlinks=False):
            for name in folders: helper._plain_path(Path(base) / name, ROOT)
            for name in files: regular(Path(base) / name)
    else:
        BUILD.mkdir(parents=True)
        (BUILD / '.own-dxgi-swapchain').write_bytes(MARKER)
    generated = BUILD / 'CMakeLists.txt'
    regular(generated, missing=True)
    generated.write_text('cmake_minimum_required(VERSION 3.25)\n'
        'project(OwnDxgiSwapchain LANGUAGES CXX)\n'
        'set(CMAKE_MSVC_RUNTIME_LIBRARY MultiThreaded)\n'
        'add_executable(dxgi_swapchain_probe "' + str(HERE / 'probe.cpp') + '")\n'
        'target_compile_features(dxgi_swapchain_probe PRIVATE cxx_std_17)\n'
        'target_compile_definitions(dxgi_swapchain_probe PRIVATE UNICODE _UNICODE)\n'
        'target_link_libraries(dxgi_swapchain_probe PRIVATE d3d11 dxgi user32)\n')
    commands = [
        ['cmake', '-S', str(BUILD), '-B', str(BUILD), '-G', 'Ninja',
         '-DCMAKE_TOOLCHAIN_FILE=' + str(ROOT / toolchain['path']), '-DCMAKE_BUILD_TYPE=RelWithDebInfo',
         '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON'],
        ['cmake', '--build', str(BUILD), '--target', 'dxgi_swapchain_probe', '--parallel', '2']]
    log = BUILD / 'build.log'
    regular(log, missing=True)
    with log.open('w') as output:
        for command in commands:
            if subprocess.run(command, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT).returncode:
                raise RuntimeError('Own DXGI compilation failed; see its separate build.log')
    binary = BUILD / 'dxgi_swapchain_probe.exe'
    objects = list((BUILD / 'CMakeFiles/dxgi_swapchain_probe.dir').rglob('*.obj'))
    if len(objects) != 1:
        raise RuntimeError('Expect exactly one own source object')
    regular(objects[0])
    llvm = '/opt/homebrew/opt/llvm/bin/llvm-readobj'
    imports = subprocess.check_output([llvm, '--file-headers', '--coff-imports', str(binary)], text=True)
    directives = subprocess.check_output([llvm, '--coff-directives', str(objects[0])], text=True)
    dlls = re.findall(r'^\s+Name: (.+)$', imports, re.M)
    symbols = re.findall(r'^\s+Symbol: ([^ ]+) \(', imports, re.M)
    required = ['CreateDXGIFactory1', 'D3D11CreateDevice', 'CreateWindowExW', 'DestroyWindow',
                'RegisterClassW', 'UnregisterClassW']
    if ('IMAGE_FILE_MACHINE_AMD64' not in imports
            or set(dlls) != {'KERNEL32.dll', 'USER32.dll', 'dxgi.dll', 'd3d11.dll'}
            or not set(required) <= set(symbols)
            or not ('RuntimeLibrary=MT_StaticRelease' in directives
                    or re.search(r'/DEFAULTLIB:libcmt(?:\.lib)?\b', directives, re.I))
            or re.search(r'/DEFAULTLIB:(?:msvcrt|msvcprtd|libcmtd)(?:\.lib)?\b', directives, re.I)):
        raise RuntimeError('Unexpected architecture, imports, or CRT linkage')
    inspection = BUILD / 'pe-inspection.txt'
    regular(inspection, missing=True)
    inspection.write_text(imports + directives)
    if (sources != [identity(ROOT / item['path']) for item in sources]
            or toolchain != identity(ROOT / toolchain['path']) or renderer != identity(RENDERER)
            or identity(HELPER)['sha256'] != HELPER_SHA):
        raise RuntimeError('Compile inputs changed')
    artifact = identity(binary)
    record = {'schema_version': 1, 'compiled': True,
        'at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'artifact': artifact, 'runtime_inputs': [artifact], 'source_evidence': sources,
        'toolchain': toolchain, 'reused_build_helper': identity(HELPER),
        'generated_build_input': identity(generated), 'object': identity(objects[0]),
        'pe_inspection': identity(inspection), 'imports': dlls,
        'required_real_api_imports': required, 'architecture': 'AMD64', 'runtime': '/MT',
        'renderer_input_review': renderer,
        'renderer_input_review_is_not_proof_of_runtime_provider': True,
        'build': {'commands': commands, 'exit': 0, 'log': identity(log),
                  'compile_commands': identity(BUILD / 'compile_commands.json')},
        'experiment': {'modes': 1, 'same_process_owned_hwnd': True, 'width': 1280, 'height': 720,
            'format': 28, 'buffer_count': 2, 'sample_count': 1, 'swap_effect': 0,
            'swapchain_flags': 2, 'windowed': True, 'present_called': False,
            'qi_requires_success_and_nonnull_output': True,
            'api_hresult_reported_as_unsigned_u32': True,
            'exit_zero_means_capture_and_cleanup_not_functional_success': True,
            'matches_actual_game_descriptor_claimed': False},
        'runtime_tested': False, 'wine_or_prefix_started': False,
        'client_game_or_account_code_used': False, 'existing_inputs_changed': False}
    with REPORT.open('x') as output:
        json.dump(record, output, indent=2); output.write('\n')
    print(json.dumps({'artifact': artifact, 'report': identity(REPORT), 'runtime_started': False}))


if __name__ == '__main__':
    main()
