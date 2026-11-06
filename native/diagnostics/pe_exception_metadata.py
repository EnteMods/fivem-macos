#!/usr/bin/env python3
"""Read only fixed legitimacy.dll PE headers and bounded exception metadata."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys

ROOT = Path(__file__).absolute().parents[2]
CODE = ROOT / 'build/windows-source-integration/legitimacy.dll'
EXPECTED_BYTES = 12443232
EXPECTED_SHA = '95f5788ff0fec0c0808e357cd312c95344c618c3054dc12782ea8f1b66bcea97'
TARGET = 0x7a9105
MAX_PDATA = 1024 * 1024


def identity(info):
    return tuple(getattr(info, name) for name in
                 ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size',
                  'st_mtime_ns', 'st_ctime_ns'))


def no_alias(path, directory=False):
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ValueError('Symlink refused')
        if current != path and not stat.S_ISDIR(info.st_mode):
            raise ValueError('Nondirectory ancestor')
    if directory:
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError('Report directory required')
    elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError('Regular single-link code required')
    return info


def scan():
    before = no_alias(CODE)
    if before.st_size != EXPECTED_BYTES:
        raise ValueError('Known code size changed')
    fd = os.open(CODE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    reads = []
    try:
        if identity(os.fstat(fd)) != identity(before):
            raise ValueError('Code changed before read')

        def read(offset, size, role):
            if offset < 0 or size < 0 or offset > before.st_size or size > before.st_size - offset:
                raise ValueError('Metadata outside file')
            data = os.pread(fd, size, offset)
            if len(data) != size:
                raise ValueError('Short metadata read')
            reads.append({'role': role, 'file_offset': offset, 'bytes': size})
            return data

        dos = read(0, 64, 'dos_header')
        if dos[:2] != b'MZ':
            raise ValueError('Missing MZ')
        pe = struct.unpack_from('<i', dos, 60)[0]
        if not 64 <= pe <= 1024 * 1024:
            raise ValueError('Unbounded PE pointer')
        coff = read(pe, 24, 'pe_signature_and_coff')
        if coff[:4] != b'PE\0\0' or struct.unpack_from('<H', coff, 4)[0] != 0x8664:
            raise ValueError('Expected AMD64 PE')
        sections = struct.unpack_from('<H', coff, 6)[0]
        optsize = struct.unpack_from('<H', coff, 20)[0]
        if not 1 <= sections <= 96 or not 144 <= optsize <= 4096:
            raise ValueError('Unbounded header table')
        optional = read(pe + 24, optsize, 'optional_header')
        if struct.unpack_from('<H', optional)[0] != 0x20b or struct.unpack_from('<I', optional, 108)[0] < 4:
            raise ValueError('Missing AMD64 exception directory')
        image_size = struct.unpack_from('<I', optional, 56)[0]
        timestamp = struct.unpack_from('<I', coff, 8)[0]
        checksum = struct.unpack_from('<I', optional, 64)[0]
        if (image_size, checksum, timestamp) != (12976128, 12473764, 1792674854):
            raise ValueError('Known code header tuple changed')
        drva, dsize = struct.unpack_from('<II', optional, 112 + 3 * 8)
        if not 0 < dsize <= MAX_PDATA or dsize % 12 or not 0 < drva < image_size or dsize > image_size - drva:
            raise ValueError('Invalid or unbounded exception directory')
        sh = read(pe + 24 + optsize, sections * 40, 'section_table')
        providers = []
        for i in range(sections):
            row = sh[i * 40:(i + 1) * 40]
            vsize, va, rsize, raw = struct.unpack_from('<IIII', row, 8)
            if va <= drva and drva - va <= rsize and dsize <= rsize - (drva - va):
                providers.append({'name': row[:8].rstrip(b'\0').decode('ascii'),
                                  'virtual_address': va, 'virtual_size': vsize,
                                  'raw_pointer': raw, 'raw_size': rsize})
        if len(providers) != 1 or providers[0]['name'] != '.pdata':
            raise ValueError('Exception directory does not have unique .pdata provider')
        provider = providers[0]
        pdata_offset = provider['raw_pointer'] + drva - provider['virtual_address']
        pdata = read(pdata_offset, dsize, 'exception_directory_pdata')
        rows = list(struct.iter_unpack('<III', pdata))
        invalid = sum(not (0 < a < b <= image_size and 0 < u < image_size) for a, b, u in rows)
        decreases = sum(rows[i - 1][0] > rows[i][0] for i in range(1, len(rows)))
        equal_begins = sum(rows[i - 1][0] == rows[i][0] for i in range(1, len(rows)))
        duplicate_entries = len(rows) - len(set(rows))
        overlaps = sum(rows[i - 1][1] > rows[i][0] for i in range(1, len(rows)))
        hits = [i for i, (a, b, _) in enumerate(rows) if a <= TARGET < b]
        if invalid or decreases:
            raise ValueError('Invalid RVA or unsorted exception directory')
        if hits:
            selected = sorted({j for i in hits for j in range(max(0, i - 1), min(len(rows), i + 2))})
        else:
            left = [i for i, (_, b, _) in enumerate(rows) if b <= TARGET]
            right = [i for i, (a, _, _) in enumerate(rows) if a > TARGET]
            selected = sorted(set((left[-1:] if left else []) + (right[:1] if right else [])))
        shown = [{'index': i, 'begin_rva': rows[i][0], 'end_rva_exclusive': rows[i][1],
                  'unwind_info_rva': rows[i][2], 'contains_target': i in hits} for i in selected]
        after = no_alias(CODE)
        if identity(os.fstat(fd)) != identity(before) or identity(after) != identity(before):
            raise ValueError('Code changed during metadata scan')
        return {'code': {'path': str(CODE.relative_to(ROOT)), 'bytes': before.st_size,
                         'expected_sha256_from_root_rea_open': EXPECTED_SHA,
                         'full_file_hash_recomputed': False,
                         'fd_and_path_identity_unchanged': True},
                'target_rva': TARGET, 'machine': 0x8664,
                'coff_timestamp': timestamp, 'size_of_image': image_size, 'checksum': checksum,
                'exception_directory': {'rva': drva, 'bytes': dsize, 'file_offset': pdata_offset,
                                        'sha256': hashlib.sha256(pdata).hexdigest(),
                                        'entry_bytes': 12, 'entry_count': len(rows), 'section': provider},
                'validation': {'invalid_rva_entries': invalid, 'decreasing_begin_entries': decreases,
                               'equal_adjacent_begin_entries': equal_begins, 'duplicate_full_entries': duplicate_entries,
                               'adjacent_overlapping_ranges': overlaps,
                               'globally_strictly_unique_ranges': equal_begins == 0 and overlaps == 0,
                               'matching_entry_count': len(hits)},
                'matching_and_immediate_neighbor_entries': shown,
                'read_slices': reads, 'metadata_bytes_read': sum(x['bytes'] for x in reads),
                'interpretation': {'static_runtime_function_covers_target': bool(hits),
                                   'live_leaf_function_proven': False, 'live_unwind_registration_proven': False,
                                   'true_caller_or_crash_cause_proven': False}}
    finally:
        os.close(fd)


def main():
    if len(sys.argv) != 1:
        raise ValueError('Fixed candidate and target only')
    report = scan()
    source = Path(__file__).absolute()
    script = source.read_bytes()
    report.update({'schema_version': 1, 'kind': 'static_pe_exception_metadata',
                   'method': {'script': str(source.relative_to(ROOT)), 'bytes': len(script),
                              'sha256': hashlib.sha256(script).hexdigest(),
                              'command': ['python3', '-B', str(source.relative_to(ROOT))],
                              'maximum_pdata_bytes': MAX_PDATA,
                              'sdk_layout_source': 'toolchains/msvc-2022/Windows Kits/10/Include/10.0.26100.0/um/winnt.h:21781'},
                   'rea_evidence_claimed': False, 'dump_or_private_data_opened': False,
                   'runtime_started': False, 'existing_files_changed': False})
    destination = ROOT / 'research'
    no_alias(destination, directory=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    path = destination / ('legitimacy-exception-metadata-' + stamp + '.json')
    data = (json.dumps(report, indent=2) + '\n').encode()
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as out:
        out.write(data)
    print(json.dumps({'path': str(path.relative_to(ROOT)), 'bytes': len(data),
                      'sha256': hashlib.sha256(data).hexdigest(),
                      'matching_entry_count': report['validation']['matching_entry_count']}))


if __name__ == '__main__':
    main()
