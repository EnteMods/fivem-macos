#!/usr/bin/env python3
"""Build an isolated, current CEF144 Wine CPU OSR candidate; never stage or launch it."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile

import overlay

ROOT = Path(__file__).resolve().parents[2]
REVISION = '88a413835e9d7f56633f249880a13f42297153a2'
SOURCE = ROOT / 'build/windows-main-candidate-27nal69i/source'
COMPONENT = Path('code/components/nui-core')
sys.path.insert(0, str(ROOT / 'native/windows-nui'))
from prepare_cef import extract_build_inputs


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sha(path):
    return digest(path.read_bytes())


def ident(path):
    return {'path': path.relative_to(ROOT).as_posix(), 'bytes': path.stat().st_size, 'sha256': sha(path)}


def run(command, log, **kwargs):
    with log.open('w') as stream:
        result = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, **kwargs)
    if result.returncode:
        raise RuntimeError(f'Command exit {result.returncode}; see {log.relative_to(ROOT)}')


def original_component():
    repo = ROOT / 'upstream/fivem'
    tree = subprocess.check_output(['git', '-C', str(repo), 'ls-tree', '-r', '-z', REVISION, '--', str(COMPONENT)])
    files = {}
    for row in tree.split(b'\0'):
        if not row:
            continue
        meta, name = row.split(b'\t')
        mode, kind, oid = meta.split()
        if (mode, kind) != (b'100644', b'blob'):
            raise RuntimeError('Unexpected component git entry')
        relative = Path(name.decode()).relative_to(COMPONENT)
        data = subprocess.check_output(['git', '-C', str(repo), 'cat-file', 'blob', oid.decode()])
        files[relative.as_posix()] = data
    # Original language-lifetime correction already used by the existing full build.
    name = 'src/NUIClient.cpp'
    before = b'auto& frameUrl = (frame) ? frame->GetURL().ToString() : std::string{};'
    if files[name].count(before) != 1:
        raise RuntimeError('Unexpected compiler-lifetime source')
    files[name] = files[name].replace(before, b'const ' + before)
    return files


def cef_abi_probe(work, cef):
    fixture = '''#include "include/base/cef_compiler_specific.h"
#include "include/base/cef_scoped_refptr.h"
struct Factory { void AddRef() const; void Release() const; };
extern "C" __declspec(dllexport) Factory* Receive(void*, void*, scoped_refptr<Factory> value) { return value.get(); }
'''
    source = work / 'parameter.cpp'
    source.write_text(fixture)
    sdk = ROOT / 'toolchains/msvc-2022'
    headers = [cef, sdk / 'VC/Tools/MSVC/14.44.35207/include',
               *(sdk / 'Windows Kits/10/Include/10.0.26100.0' / name for name in ('ucrt', 'shared', 'um', 'winrt'))]
    clang = '/opt/homebrew/opt/llvm/bin/clang-cl'
    dump = '/opt/homebrew/opt/llvm/bin/llvm-objdump'

    def compile(name):
        obj = work / f'parameter-{name}.obj'
        run([clang, '--target=x86_64-pc-windows-msvc', '/nologo', '/c', '/O2', '/std:c++17',
             '/EHsc', '/Zc:__cplusplus', *(f'/I{p}' for p in headers), f'/Fo{obj}', 'parameter.cpp'],
            work / f'parameter-{name}.log', cwd=work)
        text = subprocess.check_output([dump, '-d', '--x86-asm-syntax=intel',
            '--disassemble-symbols=Receive', str(obj)], text=True)
        (work / f'parameter-{name}.asm').write_text(text)
        return text

    before = compile('original')
    header = cef / 'include/base/cef_compiler_specific.h'
    data = header.read_bytes()
    anchor = b'#if defined(__clang__) && __has_attribute(trivial_abi)'
    if data.count(anchor) != 1:
        raise RuntimeError('CEF compiler header changed')
    adapted = data.replace(anchor, anchor + b' && !defined(_MSC_VER)')
    header.write_bytes(adapted)
    after = compile('msvc-abi')
    direct = r'(?m)\bmov\s+r\w+,\s*r8\s*$'
    indirect = r'\bmov\s+r\w+,\s*qword ptr \[r8\]'
    if not re.search(direct, before) or re.search(indirect, before) or not re.search(indirect, after):
        raise RuntimeError('Expected stock-MSVC reference parameter ABI not demonstrated')
    return {'header_original_sha256': digest(data), 'header_adapted_sha256': digest(adapted),
            'original_direct_register': True, 'adapted_indirect_reference': True,
            'runtime_tested': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepare-only', action='store_true')
    parser.add_argument('--resume', type=Path, help='Rebuild only this recipe\'s existing isolated output')
    args = parser.parse_args()
    result = json.loads((SOURCE.parent / 'result.json').read_text())
    if result['revision'] != REVISION or result['build_exit'] != 0:
        raise RuntimeError('Current source candidate identity mismatch')
    lock = json.loads((ROOT / 'config/cef-package.json').read_text())
    archive = ROOT / 'downloads/cef' / (lock['build_name'] + '.zip')
    if archive.stat().st_size != lock['archive_bytes'] or sha(archive) != lock['archive_sha256']:
        raise RuntimeError('Original CEF archive differs from reviewed lock')
    marker = (SOURCE / 'vendor/cef/cef_build_name.txt').read_text().strip()
    if marker != lock['build_name']:
        raise RuntimeError('Current source and reviewed CEF package differ')
    if args.resume:
        work = args.resume.absolute()
        if work.parent != ROOT / 'build' or not work.name.startswith('windows-nui-software144-'):
            raise RuntimeError('Unexpected isolated NUI output role')
        for path in (work, *work.parents):
            if path.is_symlink():
                raise RuntimeError('Redirected NUI output')
            if path == ROOT:
                break
        prior = json.loads((work / 'inputs.json').read_text())
        if prior['revision'] != REVISION or prior['source'] != str(SOURCE.relative_to(ROOT)):
            raise RuntimeError('Existing output belongs to another recipe')
        for path in work.rglob('*'):
            info = path.lstat()
            if not stat.S_ISDIR(info.st_mode) and not (stat.S_ISREG(info.st_mode) and info.st_nlink == 1):
                raise RuntimeError('Non-plain generated build input')
    else:
        work = Path(tempfile.mkdtemp(prefix='windows-nui-software144-', dir=ROOT / 'build'))
    print(work, flush=True)
    component = work / 'component'
    original = original_component()
    for name, data in original.items():
        target = component / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    _, adapted = overlay.stage(component, component)
    diffs = []
    for name, data in adapted.items():
        diffs.extend(difflib.unified_diff(original[name].decode().replace('\r\n', '\n').splitlines(True),
            data.decode().splitlines(True), fromfile='a/' + str(COMPONENT / name), tofile='b/' + str(COMPONENT / name)))
    helper = (Path(__file__).with_name('SoftwareNuiFrame.h')).read_text()
    diffs.extend(difflib.unified_diff([], helper.splitlines(True), fromfile='/dev/null',
        tofile='b/' + str(COMPONENT / 'include/SoftwareNuiFrame.h')))
    (work / 'software-nui144.patch').write_text(''.join(diffs))
    cef = work / 'cef'
    _, cef_files = extract_build_inputs(archive, cef, marker, {})
    cef_abi = cef_abi_probe(work, cef)
    run(['/usr/bin/clang++', '-std=c++17', '-fsanitize=address,undefined', '-g',
         str(Path(__file__).with_name('frame_test.cpp')), '-o', str(work / 'frame_test')], work / 'frame-test-build.log')
    run([str(work / 'frame_test')], work / 'frame-test-results.log')
    metadata = {'revision': REVISION, 'source': str(SOURCE.relative_to(ROOT)),
        'original_component': {name: digest(data) for name, data in original.items()},
        'adapted_component': {name: sha(path) for name in sorted(original) for path in [component / name]},
        'helper': ident(component / 'include/SoftwareNuiFrame.h'), 'cef_lock': ident(ROOT / 'config/cef-package.json'),
        'cef_files_original': cef_files, 'cef_parameter_abi': cef_abi,
        'frame_sanitizer_test_passed': True, 'active_stage_modified': False, 'runtime_tested': False,
        'recipe': {p.name: ident(p) for p in Path(__file__).parent.iterdir() if p.suffix in ('.py', '.h', '.cpp')}}
    (work / 'inputs.json').write_text(json.dumps(metadata, indent=2) + '\n')
    if args.prepare_only:
        return
    output = work / 'objects'
    configure = ['cmake', '-S', str(ROOT / 'native/windows-nui'), '-B', str(output), '-G', 'Ninja',
        '-DCMAKE_TOOLCHAIN_FILE=' + str(ROOT / 'native/windows-core/toolchain.cmake'),
        '-DCMAKE_POLICY_VERSION_MINIMUM=3.5', '-DCMAKE_BUILD_TYPE=RelWithDebInfo',
        '-DCFX_SOURCE_DIR=' + str(SOURCE), '-DCFX_NUI_COMPONENT_DIR=' + str(component),
        '-DCFX_CEF_ROOT=' + str(cef), '-DCFX_CORE_ACCOUNT_FREE_TESTS=OFF', '-DCFX_CORE_MAPPING_DIAGNOSTICS=OFF']
    metadata['configure_command'] = configure
    run(configure, work / 'configure.log')
    run(['cmake', '--build', str(output), '--target', 'NuiCore', '--parallel', '6'], work / 'build.log')
    metadata['artifact'] = ident(output / 'nui-core.dll')
    metadata['build_passed'] = True
    (work / 'result.json').write_text(json.dumps(metadata, indent=2) + '\n')
    print(json.dumps(metadata['artifact']), flush=True)


if __name__ == '__main__':
    main()
