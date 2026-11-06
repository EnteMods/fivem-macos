#!/usr/bin/env python3
"""Offline patch guards and SDK compile-time checks; no executable is produced."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import overlay

ROOT = overlay.ROOT
HERE = Path(__file__).resolve().parent

def identity(path):
    data = path.read_bytes()
    return {'path': str(path.relative_to(ROOT)), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}

def main():
    work = Path(tempfile.mkdtemp(prefix='dxmt-resource-usage-check-', dir=ROOT / 'build'))
    print(work, flush=True)
    source = work / 'pinned-file-only'
    target = source / 'src/d3d11/d3d11_resource.hpp'
    target.parent.mkdir(parents=True)
    original = ROOT / 'research/cef144-d3d-angle-api-20261105/src/d3d11/d3d11_resource.hpp'
    shutil.copyfile(original, target)
    report = {'scope': 'One source file only, not a full DXMT checkout or renderer build',
              'runtime_started': False, 'provider_installed': False, 'original': identity(original)}
    try:
        overlay.apply(source, work / 'dry-run.json', True)
        overlay.apply(source, work / 'overlay.json')
        try:
            overlay.apply(source, work / 'must-not-exist.json')
        except ValueError:
            report['second_application_rejected'] = True
        else:
            raise RuntimeError('Modified source must be rejected')
        text = target.read_text()
        begin = '  virtual HRESULT GetDXGIUsage(DXGI_USAGE *pUsage) {\n'
        end = '\n  }\n\n  /* IDXGISurface::GetDesc'
        assert text.count(begin) == 1
        body = text.split(begin, 1)[1].split(end, 1)[0]
        frozen = work / 'semantics-source'
        frozen.mkdir()
        (frozen / 'method-body.inc').write_text(body + '\n')
        for name in ('semantics.cpp', 'CMakeLists.txt'):
            shutil.copyfile(HERE / name, frozen / name)
        report['test_inputs'] = [identity(p) for p in sorted(frozen.iterdir())]
        commands = [['cmake', '-S', str(frozen), '-B', str(work / 'objects'), '-G', 'Ninja',
                     '-DCMAKE_TOOLCHAIN_FILE=' + str(ROOT / 'native/windows-core/toolchain.cmake'),
                     '-DCMAKE_BUILD_TYPE=Release'], ['cmake', '--build', str(work / 'objects')]]
        for number, command in enumerate(commands):
            with (work / ('step-' + str(number) + '.log')).open('x') as log:
                subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, check=True)
        report['sdk_compile_time_checks_passed'] = True
        report['descriptor_types'] = ['D3D11_BUFFER_DESC', 'D3D11_TEXTURE1D_DESC', 'D3D11_TEXTURE2D_DESC1', 'D3D11_TEXTURE3D_DESC1']
        report['case_categories'] = ['null', 'zero', 'shader_and_render_target', 'constant_buffer', 'unordered_access',
                                     'depth_stencil_not_render_target', 'three_shared_variants', 'immutable_cpu',
                                     'dynamic_cpu', 'staging_cpu', 'combined_without_swapchain_flags']
        report['patched_source'] = identity(target)
        report['module_inputs'] = [identity(p) for p in sorted(HERE.iterdir()) if p.is_file()]
        report['patch'] = identity(ROOT / 'patches/dxmt/0001-resource-usage-from-description.patch')
        report['passed'] = True
    finally:
        (work / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(identity(work / 'result.json')))

if __name__ == '__main__':
    main()
