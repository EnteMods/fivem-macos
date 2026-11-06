#!/usr/bin/env python3
"""Check a clean public source or installer staging tree against its reviewed file list."""
import argparse
import codecs
import hashlib
from itertools import chain
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat


LOCAL_PARTS = {'.git', 'build', 'prefixes', 'downloads', 'logs', 'upstream', 'port', 'research',
               'toolchains', 'game-library', 'game-storage', 'gta-v-legacy', 'rockstar games',
               'social club', 'profiles', 'userdata', '__pycache__'}
LOCAL_NAMES = {'gta5.exe', 'gta5_enhanced.exe', 'playgtav.exe', 'gtavlauncher.exe', 'rockstarservice.exe',
               'launcher.exe', 'rockstargameslauncher.exe', 'socialclubhelper.exe', 'socialclub.dll',
               'fivem.exe', 'adhesive.dll', 'user.reg', 'system.reg',
               'userdef.reg', 'cookies', 'login data', 'local state', 'cfxticket', 'ros_login.dat'}
GAME_SUFFIXES = {'.rpf', '.awc', '.ydd', '.ydr', '.yft', '.ytd', '.ymap', '.ytyp', '.ybn', '.ynv',
                 '.ycd', '.yld', '.ysc', '.gxt2', '.asi', '.dmp', '.reg'}
CONTAINERS = {'.zip', '.tar', '.tgz', '.gz', '.bz2', '.xz', '.7z', '.rar', '.dmg', '.pkg', '.msi', '.cab'}
SOURCE_SUFFIXES = {'.c', '.cpp', '.h', '.hpp', '.s', '.swift', '.py', '.sh', '.ps1', '.lua', '.in',
                   '.cmake', '.patch', '.md', '.txt', '.json', '.toml', '.yaml', '.yml'}
SOURCE_NAMES = {'.gitignore', 'license', 'notice', 'readme', 'makefile'}
# Executable identities from the reviewed local Legacy inventory, including the launcher alias.
KNOWN_GAME_HASHES = {'677e4e355cfbdb13273b1d992407e3c261b3a108dc4dd5c8a0c4c1da651802e5',
                     'c52e89a224cf2258b3ccbb4f5b211cf4c4c6793baf19a3e2a44b7fced0d8552d'}
FORBIDDEN_MAGIC = (b'RPF7', b'7FPR', b'RPF8', b'8FPR', b'RSC7', b'7CSR', b'RSC8', b'8CSR',
                   b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08', b'\x1f\x8b', b'BZh',
                   b'\xfd7zXZ\x00', b'7z\xbc\xaf\x27\x1c', b'Rar!\x1a\x07', b'MSCF', b'MDMP',
                   b'xar!', b'\x28\xb5\x2f\xfd', b'\x04\x22\x4d\x18')


def check_path(value, source=False):
    path = PurePosixPath(value)
    if (not path.parts or path.as_posix() != value or path.is_absolute() or '..' in path.parts
            or any(ord(char) < 32 or char in '\\:' for char in value)):
        raise ValueError(f'Invalid staging path {value!r}')
    name, suffix = path.name.casefold(), path.suffix.casefold()
    if ({part.casefold() for part in path.parts} & LOCAL_PARTS or name in LOCAL_NAMES
            or suffix in GAME_SUFFIXES | CONTAINERS):
        raise ValueError(f'Local, game or container path excluded: {value}')
    if source and suffix not in SOURCE_SUFFIXES and name not in SOURCE_NAMES:
        raise ValueError(f'Public source staging accepts reviewed text source only: {value}')
    return path


def read_manifest(path, mode):
    def no_duplicates(pairs):
        result = dict(pairs)
        if len(result) != len(pairs):
            raise ValueError('Duplicate field in distribution manifest')
        return result

    record = json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=no_duplicates)
    if (type(record) is not dict or set(record) != {'mode', 'files'} or record['mode'] != mode
            or not isinstance(record['files'], list) or not record['files']):
        raise ValueError('Expected a nonempty file manifest for the selected staging mode')
    rows, folded = {}, set()
    for item in record['files']:
        if (type(item) is not dict or set(item) != {'path', 'sha256', 'origin', 'license'}
                or not all(type(value) is str and value.strip() for value in item.values())
                or re.fullmatch('[0-9a-f]{64}', item['sha256']) is None):
            raise ValueError('Every file requires a path, SHA-256, origin and license')
        name = item['path']
        check_path(name, source=mode == 'source')
        if name.casefold() in folded:
            raise ValueError(f'Duplicate case-folded staging path: {name}')
        folded.add(name.casefold())
        rows[name] = item['sha256']
    return rows


def file_digest(path, source):
    digest = hashlib.sha256()
    decoder = codecs.getincrementaldecoder('utf-8')() if source else None
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as file:
        before = os.fstat(file.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError(f'Require an independent regular file: {path.name}')
        first = file.read(512)
        dmg_footer = before.st_size >= 512 and os.pread(file.fileno(), 4, before.st_size - 512) == b'koly'
        if first.startswith(FORBIDDEN_MAGIC) or first[257:262] == b'ustar' or dmg_footer:
            raise ValueError(f'Game, dump or container signature excluded: {path.name}')
        for block in chain((first,), iter(lambda: file.read(1024 * 1024), b'')):
            digest.update(block)
            if decoder is not None:
                if b'\0' in block:
                    raise ValueError(f'Binary data excluded from source: {path.name}')
                decoder.decode(block)
        if decoder is not None:
            decoder.decode(b'', final=True)
        after = path.lstat()
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError(f'Staging file changed during verification: {path.name}')
    return digest.hexdigest()


def verify(staging, manifest, mode):
    if mode not in ('source', 'installer'):
        raise ValueError('Unexpected staging mode')
    staging, manifest = Path(staging).absolute(), Path(manifest).absolute()
    if (not staging.is_dir() or not manifest.is_file() or staging.resolve() != staging
            or manifest.resolve() != manifest or staging in manifest.parents):
        raise ValueError('Require a real staging directory and an external reviewed manifest')
    rows = read_manifest(manifest, mode)
    seen = set()

    def fail(error):
        raise error

    for directory, dirs, files in os.walk(staging, followlinks=False, onerror=fail):
        if Path(directory).resolve() != Path(directory):
            raise ValueError('Redirected staging directory')
        for name in dirs + files:
            path = Path(directory) / name
            relative = path.relative_to(staging).as_posix()
            check_path(relative, source=mode == 'source' and name in files)
            if path.is_symlink():
                raise ValueError(f'Staging link excluded: {relative}')
            if name in dirs:
                continue
            if relative not in rows:
                raise ValueError(f'Undeclared staging file: {relative}')
            digest = file_digest(path, source=mode == 'source')
            if digest in KNOWN_GAME_HASHES or digest != rows[relative]:
                raise ValueError(f'Game executable or changed staging bytes: {relative}')
            seen.add(relative)
    if seen != rows.keys():
        raise ValueError('Missing staging file: ' + sorted(rows.keys() - seen)[0])
    return len(seen)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('source', 'installer'))
    parser.add_argument('staging', type=Path)
    parser.add_argument('manifest', type=Path)
    args = parser.parse_args()
    try:
        count = verify(args.staging, args.manifest, args.mode)
    except (OSError, ValueError) as error:
        parser.exit(1, f'Distribution check failed: {error}\n')
    print(f'Distribution staging PASS ({args.mode}, {count} reviewed files)')
