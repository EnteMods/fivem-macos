#!/usr/bin/env python3
"""Hash and statically inspect the new complete engine without executing Wine."""
import json
from pathlib import Path
import stat
import struct
import subprocess

import build
from prepare import ROOT, WORK, FRAMEWORKS, GST_LIB, identity, own, sha


def inspect():
    build.verify_dependencies()
    source = build.verify_source()
    before = json.loads((build.BUILD / 'source-inputs.json').read_text())
    if source != before:
        raise RuntimeError('Original reviewed source tree changed during the build')
    phases = []
    for name in ('all', 'install'):
        path = build.BUILD / (name + '-results.json')
        result = json.loads(path.read_text())
        if result.get('passed') is not True or result.get('exit') != 0:
            raise RuntimeError('A successful complete build and install are mandatory')
        for key in ('log', 'build_provenance'):
            if result[key] != identity(Path(result[key]['path'])):
                raise RuntimeError('Build evidence changed')
        phases.append(identity(path))
    build.verify_configuration()
    if json.loads((build.INSTALL.parent / '.parity-runtime-owner.json').read_text()) != build.OWNER:
        raise RuntimeError('Separate installed engine ownership marker changed')
    entries = []
    formats = {'mach_o_x86_64': 0, 'pe_amd64': 0, 'pe_i386': 0, 'data': 0, 'symlinks': 0}
    for path in sorted(build.INSTALL.rglob('*')):
        mode = path.lstat().st_mode
        relative = str(path.relative_to(build.INSTALL))
        if stat.S_ISDIR(mode):
            continue
        if stat.S_ISLNK(mode):
            resolved = path.resolve(strict=True)
            resolved.relative_to(build.INSTALL)
            entries.append({'path': relative, 'kind': 'symlink', 'target': str(path.readlink())})
            formats['symlinks'] += 1
            continue
        if not stat.S_ISREG(mode) or path.stat().st_nlink != 1:
            raise RuntimeError('Unexpected installed runtime entry type')
        with path.open('rb') as source_file:
            header = source_file.read(4096)
        kind = 'data'
        if header[:4] in (b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca'):
            description = subprocess.check_output(['/usr/bin/file', '-b', str(path)], text=True).strip()
            if 'x86_64' not in description or 'arm64' in description:
                raise RuntimeError('Installed Unix code does not have the required x86_64 architecture')
            kind = 'mach_o_x86_64'
        elif header.startswith(b'MZ') and len(header) >= 64:
            offset = struct.unpack_from('<I', header, 60)[0]
            with path.open('rb') as source_file:
                source_file.seek(offset)
                pe = source_file.read(6)
            if pe[:4] == b'PE\0\0':
                machine = struct.unpack_from('<H', pe, 4)[0]
                if machine not in (0x8664, 0x14c):
                    raise RuntimeError('Unexpected installed PE architecture')
                kind = 'pe_amd64' if machine == 0x8664 else 'pe_i386'
        formats[kind] += 1
        item = identity(path)
        item.update(path=relative, kind=kind, executable=bool(mode & 0o111))
        entries.append(item)
    required = ['bin/wine', 'bin/wineserver', 'lib/wine/x86_64-unix/ntdll.so',
                'lib/wine/x86_64-unix/winemac.so', 'lib/wine/x86_64-unix/win32u.so',
                'lib/wine/x86_64-unix/secur32.so', 'lib/wine/x86_64-unix/bcrypt.so',
                'lib/wine/x86_64-unix/winebus.so', 'lib/wine/x86_64-unix/winecoreaudio.so',
                'lib/wine/x86_64-unix/winegstreamer.so', 'lib/wine/x86_64-unix/winedmo.so']
    for architecture in ('i386', 'x86_64'):
        required += [f'lib/wine/{architecture}-windows/{name}.dll' for name in ('ntdll', 'kernel32', 'kernelbase', 'winegstreamer')]
    if any(not (build.INSTALL / relative).is_file() for relative in required):
        raise RuntimeError('A required complete-engine component is absent')
    macdrv = build.INSTALL / 'lib/wine/x86_64-unix/winemac.so'
    exported = subprocess.check_output(['/usr/bin/nm', '-gU', str(macdrv)], text=True)
    if '_macdrv_functions' not in exported:
        raise RuntimeError('The original Mac driver graphics bridge export is absent')
    dependency = json.loads((WORK / 'dependency-preparation.json').read_text())
    linked = {}
    for relative in required:
        if relative.endswith('.so') or relative.startswith('bin/'):
            linked[relative] = subprocess.check_output(['/usr/bin/otool', '-L', str(build.INSTALL / relative)], text=True)
    record = {'schema_version': 1, 'engine_root': str(build.INSTALL), 'build_root': str(build.BUILD),
              'own_recipe_sources': [identity(path) for path in sorted((ROOT / 'native/wine-job-query-parity').iterdir())
                                     if path.is_file() and path.suffix in ('.py', '.c', '.md')],
              'sources_unchanged': True, 'source_inventory': identity(build.BUILD / 'source-inputs.json'),
              'reviewed_dependency_manifest': identity(WORK / 'parity-dependencies.json'),
              'configure_parser_adjustment': identity(build.BUILD / 'configure-parser-adjustment.json'),
              'native_font_build_helper_records': [identity(path) for path in sorted(build.BUILD.glob('font-helper-*-results.json'))],
              'archived_builder_recipes': [identity(path) for path in sorted((build.BUILD / 'logs').glob('recipe-*.py'))],
              'real_configure_outputs': [identity(build.BUILD / relative) for relative in ('config.status', 'include/config.h', 'Makefile')],
              'successful_phases': phases, 'entries': entries, 'format_counts': formats,
              'required_components': required, 'critical_mach_o_load_commands': linked,
              'macdrv_functions_export_present': True,
              'external_library_closure': dependency['libraries'],
              'pinned_moltenvk': identity(build.BUILD / 'dependencies/moltenvk/libMoltenVK.dylib'),
              'external_library_search_order_for_root_review': [str(build.BUILD / 'dependencies/moltenvk'), str(FRAMEWORKS), str(GST_LIB)],
              'framework_search_root_for_root_review': str(FRAMEWORKS),
              'external_libraries_copied_into_engine': False, 'dxmt_overlay_applied': False,
              'mono_or_gecko_addons_copied': False, 'installed_engine_self_contained': False,
              'job_protocol_version': 1810, 'unix_architecture': 'x86_64', 'pe_architectures': ['i386', 'AMD64'],
              'wine_or_prefix_started': False, 'graphics_job_or_client_runtime_tests_performed': False,
              'active_runtime_or_old_candidate_changed': False, 'passed_static_artifact_review': True}
    destination = own(build.BUILD / 'engine-manifest.json')
    destination.write_text(json.dumps(record, indent=2) + '\n')
    print('Complete engine static review PASS;', len(entries), 'entries;', formats)
    print('Manifest:', str(destination), 'SHA256', sha(destination))


if __name__ == '__main__':
    inspect()
