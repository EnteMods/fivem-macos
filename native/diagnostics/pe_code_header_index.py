#!/usr/bin/env python3
"""Header-only candidate index for two fixed declared code scopes; never start code."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys

ROOT = Path(__file__).absolute().parents[2]
MANIFEST = ROOT / 'research/client-source-code-inputs-v8.json'
MANIFEST_SHA = '64425886cd19ba73246cf6da849711c590d5cb6c7caaaf6aad40d891769c161a'
STAGE = ROOT / 'build/windows-source-integration'
ENGINE = ROOT / 'runtime/wine-job-query-parity/engine/lib/wine/x86_64-windows'
DOS_POINTER_LIMIT = 1048576


def signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def no_alias(path):
    if not path.is_absolute() or '..' in path.parts: raise RuntimeError('Noncanonical scope path')
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode): raise RuntimeError('Symlink scope refused')
        if current != path and not stat.S_ISDIR(info.st_mode): raise RuntimeError('Nondirectory ancestor refused')
    return path.lstat()


def regular(path):
    info = no_alias(path)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1: raise RuntimeError('Regular single-link code required')
    return info


def open_fixed(path, before):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    if signature(os.fstat(fd)) != signature(before):
        os.close(fd); raise RuntimeError('Code identity changed before read')
    return fd


def checked_read(fd, offset, width, size):
    if offset < 0 or width < 0 or offset > size or width > size - offset: raise ValueError('Truncated code header')
    raw = os.pread(fd, width, offset)
    if len(raw) != width: raise ValueError('Short code header read')
    return raw


def declared_code(name):
    path = Path(name)
    if path.suffix.lower() in ('.dll', '.exe', '.com'): return True
    if len(path.parts) == 1 and re.fullmatch(r'CitizenFX_SubProcess_[A-Za-z0-9_]+[.]bin', name): return True
    return re.fullmatch(r'data/game-storage/GTA5[.]exe_[0-9a-f]{40}', name) is not None


def manifest():
    before = regular(MANIFEST); fd = open_fixed(MANIFEST, before)
    try:
        raw = checked_read(fd, 0, before.st_size, before.st_size)
        if signature(os.fstat(fd)) != signature(before) or signature(regular(MANIFEST)) != signature(before): raise RuntimeError('Manifest changed')
    finally: os.close(fd)
    if hashlib.sha256(raw).hexdigest() != MANIFEST_SHA: raise RuntimeError('Fixed Source8 manifest changed')
    value = json.loads(raw)
    if value.get('stage') != 'build/windows-source-integration' or type(value.get('files')) is not list: raise RuntimeError('Unexpected code manifest scope')
    names = set(); selected = []
    for item in value['files']:
        name = item.get('name')
        if type(name) is not str or name.startswith('/') or '..' in Path(name).parts or Path(name).as_posix() != name or name in names:
            raise RuntimeError('Ambiguous declared code role')
        names.add(name)
        if declared_code(name): selected.append((STAGE / name, item))
    return raw, selected, len(value['files']) - len(selected)


def inspect(path, before):
    fd = open_fixed(path, before); count = 0
    try:
        def read(offset, width):
            nonlocal count
            raw = checked_read(fd, offset, width, before.st_size); count += width; return raw
        if read(0, 2) != b'MZ': return {'status': 'not_mz', 'header_bytes_read': count}
        pe = struct.unpack('<i', read(0x3c, 4))[0]
        if pe < 64 or pe > DOS_POINTER_LIMIT: raise ValueError('PE pointer outside bounded DOS-header scope')
        header = read(pe, 24)
        if header[:4] != b'PE\0\0': return {'status': 'not_pe_signature', 'header_bytes_read': count}
        machine = struct.unpack_from('<H', header, 4)[0]
        timestamp = struct.unpack_from('<I', header, 8)[0]
        optional_size = struct.unpack_from('<H', header, 20)[0]
        optional = pe + 24
        if optional_size < 68 or optional > before.st_size or optional_size > before.st_size - optional: raise ValueError('Truncated optional header')
        fields = read(optional, 68)
        magic = struct.unpack_from('<H', fields)[0]
        if magic == 0x20b: image_base = struct.unpack_from('<Q', fields, 24)[0]
        elif magic == 0x10b: image_base = struct.unpack_from('<I', fields, 28)[0]
        else: return {'status': 'unsupported_optional_magic', 'header_bytes_read': count, 'optional_magic': magic}
        size = struct.unpack_from('<I', fields, 56)[0]
        checksum = struct.unpack_from('<I', fields, 64)[0]
        if signature(os.fstat(fd)) != signature(before) or signature(regular(path)) != signature(before): raise RuntimeError('Code identity changed while reading')
        return {'status': 'pe', 'machine': machine, 'coff_timestamp': timestamp, 'size_of_image': size,
                'checksum': checksum, 'preferred_image_base': image_base, 'optional_magic': magic,
                'optional_header_size': optional_size, 'header_bytes_read': count}
    finally: os.close(fd)


def main():
    if len(sys.argv) != 1: raise RuntimeError('Only the two fixed code scopes are admitted')
    for directory in (STAGE, ENGINE, ROOT / 'research'):
        if not stat.S_ISDIR(no_alias(directory).st_mode): raise RuntimeError('Fixed code/report directory missing')
    raw, stage, excluded = manifest()
    engine = sorted(ENGINE.iterdir())
    # Admit every candidate by metadata before the first code-file read.
    admitted, rejected = [], []
    for scope, entries in (('declared_stage_code', stage), ('fixed_parity_engine_pe_directory', [(path, None) for path in engine])):
        for path, declaration in entries:
            relative = str(path.relative_to(ROOT)); row = {'scope': scope, 'path': relative}
            try:
                before = regular(path)
                if declaration is not None and (type(declaration.get('bytes')) is not int or before.st_size != declaration['bytes']):
                    raise RuntimeError('Manifest declared code size mismatch')
                admitted.append((path, before, row, declaration))
            except (OSError, RuntimeError) as error:
                rejected.append({**row, 'status': 'scope_or_identity_rejected', 'failure_type': type(error).__name__})
    result = []
    for path, before, row, declaration in admitted:
        try:
            fields = inspect(path, before)
            item = {**row, 'file_bytes': before.st_size, **fields}
            if declaration is not None:
                item['manifest_declared_sha256'] = declaration.get('sha256')
                item['manifest_full_file_hash_verified'] = False
            result.append(item)
        except (OSError, RuntimeError, ValueError, struct.error) as error:
            result.append({**row, 'status': 'header_or_identity_rejected', 'failure_type': type(error).__name__})
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    report = ROOT / 'research' / ('pe-code-header-index-' + stamp + '.json')
    payload = {'schema_version': 1, 'at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'manifest': {'path': str(MANIFEST.relative_to(ROOT)), 'bytes': len(raw), 'sha256': MANIFEST_SHA},
        'scope_preflight_before_code_reads': True, 'stage_declared_candidates': len(stage), 'stage_noncode_declarations_not_opened': excluded,
        'engine_direct_entries': len(engine), 'dos_pe_pointer_limit': DOS_POINTER_LIMIT,
        'pe_headers': [row for row in result if row['status'] == 'pe'],
        'non_pe_or_rejected': [*rejected, *(row for row in result if row['status'] != 'pe')],
        'preferred_base_is_live_load_base': False, 'full_code_bytes_hashed_or_copied': False,
        'dump_profile_or_cache_data_opened': False, 'generated_subprocess_aliases_opened': False,
        'runtime_started': False, 'existing_files_modified': False,
        'code_identity_or_pdb_attribution_proven': False, 'tuple_matches_are_candidates_only': True}
    with os.fdopen(os.open(report, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'w') as output:
        json.dump(payload, output, indent=2); output.write('\n')
    print(json.dumps({'report': str(report.relative_to(ROOT)), 'pe_count': len(payload['pe_headers']),
                      'non_pe_or_rejected': len(payload['non_pe_or_rejected']),
                      'code_identity_or_pdb_attribution_proven': False}))


if __name__ == '__main__': main()
