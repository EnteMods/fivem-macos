#!/usr/bin/env python3
"""Prepare local development headers and inspect the unchanged x86_64 runtime."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT / 'build/wine-job-query-parity'
FRAMEWORKS = ROOT.parent / 'GTA-V-macOS/runtime/template-1.0.11-source/Template-1.0.11.app/Contents/Frameworks'
GST_LIB = FRAMEWORKS / 'GStreamer.framework/Versions/1.0/lib'
ARCHIVE = ROOT / 'downloads/crossover-sources-26.3.0.tar.gz'
ARCHIVE_SHA = 'ac99c8ca4b3848f3e81784135f023df266b61c2345726ea55a50b3e030dd6872'
SDL = {'url': 'https://github.com/libsdl-org/SDL/releases/download/release-2.32.10/SDL2-2.32.10.tar.gz',
       'sha256': '5f5993c530f084535c65a6879e9b26ad441169b3e25d789d83287040a9ca5165', 'bytes': 7630262,
       'identity_source': 'https://api.github.com/repos/libsdl-org/SDL/releases/tags/release-2.32.10'}


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for part in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(part)
    return digest.hexdigest()


def own(path):
    relative = path.relative_to(WORK)
    if '..' in relative.parts:
        raise RuntimeError('Invalid own output path')
    project_relative = path.relative_to(ROOT)
    for component in (ROOT, *(ROOT / Path(*project_relative.parts[:i]) for i in range(1, len(project_relative.parts) + 1))):
        try:
            info = component.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise RuntimeError('Refuse redirected own output')
        if not stat.S_ISDIR(info.st_mode) and not stat.S_ISREG(info.st_mode):
            raise RuntimeError('Refuse special own output')
        if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
            raise RuntimeError('Refuse linked own output')
    return path


def put(path, payload):
    own(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_bytes() != payload:
        raise RuntimeError('Refuse to replace different existing dependency: ' + str(path))
    if not path.exists():
        with path.open('xb') as output:
            output.write(payload)


def identity(path):
    return {'path': str(path), 'bytes': path.stat().st_size, 'sha256': sha(path)}


def download(item, path):
    own(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        partial = own(path.with_suffix(path.suffix + '.part'))
        request = urllib.request.Request(item['url'], headers={'User-Agent': 'Local-original-dependency-ABI-probe'})
        with urllib.request.urlopen(request, timeout=45) as source, partial.open('xb') as output:
            count = 0
            for part in iter(lambda: source.read(1024 * 1024), b''):
                count += len(part)
                if count > item['bytes']:
                    raise RuntimeError('Source exceeded pinned size')
                output.write(part)
        if count != item['bytes'] or sha(partial) != item['sha256']:
            raise RuntimeError('Downloaded original dependency identity mismatch')
        os.replace(partial, path)
    if path.stat().st_size != item['bytes'] or sha(path) != item['sha256']:
        raise RuntimeError('Original dependency identity mismatch')


def extract_headers():
    if sha(ARCHIVE) != ARCHIVE_SHA:
        raise RuntimeError('Require exact original CrossOver source archive')
    records = []
    with tarfile.open(ARCHIVE) as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            if path.is_absolute() or '..' in path.parts:
                raise RuntimeError('Unsafe source archive member')
            destination = None
            if member.name.startswith('sources/freetype/include/') and member.isfile():
                destination = WORK / 'dev/include/freetype2' / Path(*path.parts[3:])
            elif member.name.startswith('sources/gnutls/gnutls/lib/includes/gnutls/') and member.isfile():
                if path.suffix == '.h':
                    destination = WORK / 'dev/include/gnutls' / path.name
            elif member.name in ('sources/freetype/docs/FTL.TXT', 'sources/freetype/docs/GPLv2.TXT',
                                  'sources/gnutls/gnutls/doc/COPYING.LESSER', 'sources/gnutls/gnutls/doc/COPYING',
                                  'sources/gnutls/gnutls/LICENSE'):
                destination = WORK / 'licenses' / member.name.replace('/', '__')
            elif member.name == 'sources/gnutls/gnutls/configure.ac':
                destination = WORK / 'source-evidence/gnutls-configure.ac'
            if destination is not None:
                put(destination, archive.extractfile(member).read())
        template = archive.extractfile('sources/gnutls/gnutls/lib/includes/gnutls/gnutls.h.in').read().decode()
        # These are exactly the version substitutions and sys/uio.h branch in the original configure.ac.
        substitutions = {'VERSION': '3.8.3', 'MAJOR_VERSION': '3', 'MINOR_VERSION': '8',
                         'PATCH_VERSION': '3', 'NUMBER_VERSION': '0x030803',
                         'DEFINE_IOVEC_T': '#include <sys/uio.h>\ntypedef struct iovec giovec_t;'}
        if set(re.findall(r'@([A-Za-z0-9_]+)@', template)) != set(substitutions):
            raise RuntimeError('Unreviewed GnuTLS header template substitutions')
        rendered = re.sub(r'@([A-Za-z0-9_]+)@', lambda match: substitutions[match[1]], template)
        put(WORK / 'dev/include/gnutls/gnutls.h', rendered.encode())
        records.append({'component': 'gnutls', 'header_version': '3.8.3', 'runtime_version': 'not yet probed',
                        'header_generation': 'Original configure.ac version expressions and struct iovec branch',
                        'substitutions': substitutions, 'version_equality_claimed': False})
    sdl = WORK / 'downloads/SDL2-2.32.10.tar.gz'
    download(SDL, sdl)
    with tarfile.open(sdl) as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            if path.is_absolute() or '..' in path.parts:
                raise RuntimeError('Unsafe SDL source archive member')
            if member.isfile() and member.name.startswith('SDL2-2.32.10/include/'):
                put(WORK / 'dev/include/SDL2' / Path(*path.parts[2:]), archive.extractfile(member).read())
            elif member.isfile() and member.name == 'SDL2-2.32.10/LICENSE.txt':
                put(WORK / 'licenses/SDL2-LICENSE.txt', archive.extractfile(member).read())
    return records


def libraries():
    selected = {'gnutls': FRAMEWORKS / 'libgnutls.30.dylib',
                'freetype': FRAMEWORKS / 'libfreetype.6.dylib',
                'sdl2': FRAMEWORKS / 'libSDL2-2.0.0.dylib'}
    for name in ('gstreamer-1.0', 'gstvideo-1.0', 'gstaudio-1.0', 'gsttag-1.0', 'gstbase-1.0',
                 'glib-2.0', 'gobject-2.0', 'gmodule-2.0', 'avformat', 'avcodec', 'avutil'):
        selected[name] = GST_LIB / ('lib' + name + '.dylib')
    closure = {}
    queue = list(selected.values())
    while queue:
        original = queue.pop(0)
        path = original.resolve(strict=True)
        path.relative_to(FRAMEWORKS)
        if str(path) in closure:
            continue
        description = subprocess.check_output(['/usr/bin/file', '-b', str(path)], text=True).strip()
        if 'x86_64' not in description or 'Mach-O' not in description:
            raise RuntimeError('A selected dependency lacks x86_64: ' + str(path))
        report = subprocess.check_output(['/usr/bin/otool', '-L', str(path)], text=True)
        install_id = subprocess.check_output(['/usr/bin/otool', '-D', str(path)], text=True).splitlines()[-1]
        dependencies = []
        for line in report.splitlines()[1:]:
            match = re.match(r'\s+(.+?) \(compatibility version ([^,]+), current version ([^)]+)\)', line)
            if not match or match[1] == install_id:
                continue
            name = match[1]
            entry = {'load_command': name, 'compatibility_version': match[2], 'current_version': match[3]}
            if name.startswith(('/usr/lib/', '/System/Library/')):
                entry['resolution'] = 'macOS system library'
            else:
                candidates = [path.parent / name[len('@loader_path/'):] ] if name.startswith('@loader_path/') else []
                candidates += [FRAMEWORKS / Path(name).name, GST_LIB / Path(name).name]
                found = next((candidate for candidate in candidates if candidate.is_file()), None)
                if found is None:
                    raise RuntimeError('Unresolved own dependency closure: ' + name)
                entry['resolved_path'] = str(found.resolve())
                queue.append(found)
            dependencies.append(entry)
        closure[str(path)] = {**identity(path), 'file_description': description,
                              'install_id': install_id, 'dependencies': dependencies}
    return {'selected': {key: str(path.resolve()) for key, path in selected.items()}, 'closure': list(closure.values())}


def main():
    own(WORK)
    WORK.mkdir(exist_ok=True)
    generated = extract_headers()
    result = {'source_archive': identity(ARCHIVE), 'sdl_original_release': SDL,
              'headers': [identity(path) for path in sorted((WORK / 'dev/include').rglob('*')) if path.is_file()],
              'licenses': [identity(WORK / 'licenses' / name) for name in (
                  'SDL2-LICENSE.txt', 'sources__freetype__docs__FTL.TXT', 'sources__freetype__docs__GPLv2.TXT',
                  'sources__gnutls__gnutls__doc__COPYING.LESSER', 'sources__gnutls__gnutls__doc__COPYING',
                  'sources__gnutls__gnutls__LICENSE')],
              'source_generation_evidence': [identity(WORK / 'source-evidence/gnutls-configure.ac')],
              'header_generation': generated, 'libraries': libraries(),
              'runtime_files_modified': False, 'wine_or_prefix_started': False,
              'full_wine_build_started': False, 'x86_64_abi_verified': False}
    destination = own(WORK / 'dependency-preparation.json')
    destination.write_text(json.dumps(result, indent=2) + '\n')
    print('Prepared original headers and inspected', len(result['libraries']['closure']), 'x86_64 library nodes')


if __name__ == '__main__':
    main()
