#!/usr/bin/env python3
"""Numeric MDMP location metadata only; never names, parameters, context or memory.

Reuses the frozen v1 no-follow/anchored FD binding. Original SDK 10.0.26100.0
um/minidumpapiset.h: pack4; MiscInfo15 header8 + conditional PID4 (base size24);
ModuleList4 count4, entries108, numeric prefix20. Header/Exception slices match
v1. All stream ranges/overlaps are admitted before selected stream fields.
At most 11844 bytes / 520 pread calls, including at most512 module prefixes.

A declared PID is not independently verified. An anonymous unique module range
and RVA do not identify a file/PDB or establish the exception's cause. Timestamp,
ThreadID and filename do not establish a run or process identity. No dump hashes,
copies, ZIPs, names, CV records, VersionInfo, stacks, contexts or payload reads.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys
import types

BASE_SHA256 = '69707aa434593359dc32ec0a21a5c850c131742882657789e8c479cdbaa0b364'
BASE_BYTES = 9491


def _load_base():
    # Hashing is restricted to this fixed own Python source, never to a dump.
    path = Path(__file__).absolute().with_name('minidump_metadata.py')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size != BASE_BYTES:
            raise ValueError('frozen_reader_binding')
        data = os.read(fd, BASE_BYTES + 1)
        after = os.fstat(fd)
        if (len(data) != BASE_BYTES or hashlib.sha256(data).hexdigest() != BASE_SHA256
                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise ValueError('frozen_reader_binding')
    finally:
        os.close(fd)
    module = types.ModuleType('_frozen_minidump_metadata')
    module.__file__ = str(path)
    exec(compile(data, str(path), 'exec'), module.__dict__)
    return module


_BASE = _load_base()
MetadataError = _BASE.MetadataError
MAX_MODULES = 512
MODULE_STRIDE = 108
MAX_READ_BYTES = 32 + 128 * 12 + 20 + 12 + 4 + MAX_MODULES * 20
MAX_READ_CALLS = 1 + 1 + 3 + 2 + 1 + MAX_MODULES
ERRORS = {'duplicate_selected': 20, 'selected_overlap': 21, 'misc_size': 22,
          'module_size': 23, 'module_count': 24, 'module_address_range': 25}


class LocationError(MetadataError):
    def __init__(self, reason):
        self.reason, self.code = reason, ERRORS[reason]
        ValueError.__init__(self, reason)


class _Reader:
    def __init__(self, fd, size):
        self.fd, self.size = fd, size
        self.allowed = {(0, 32): 'header'}
        self.used = set()
        self.counts = dict.fromkeys(('header_bytes', 'directory_bytes', 'exception_field_bytes',
                                    'misc_field_bytes', 'module_count_bytes', 'module_prefix_bytes'), 0)

    def allow(self, offset, size, kind):
        if size <= 0 or not _BASE._within(offset, size, self.size) or (offset, size) in self.allowed:
            raise MetadataError('read_scope')
        self.allowed[offset, size] = kind

    def read(self, offset, size):
        key = offset, size
        if (key not in self.allowed or key in self.used or len(self.used) >= MAX_READ_CALLS
                or sum(self.counts.values()) + size > MAX_READ_BYTES):
            raise MetadataError('read_scope')
        self.used.add(key)
        self.counts[self.allowed[key] + '_bytes'] += size
        data = os.pread(self.fd, size, offset)
        if len(data) != size:
            raise MetadataError('short_read')
        return data

    def budget(self):
        return {**self.counts, 'total_bytes': sum(self.counts.values()), 'read_calls': len(self.used),
                'maximum_bytes': MAX_READ_BYTES, 'maximum_read_calls': MAX_READ_CALLS}


def _directory(reader, size):
    signature, version, count, directory, _, timestamp, _ = struct.unpack('<IIIIIIQ', reader.read(0, 32))
    if signature != _BASE.SIGNATURE:
        raise MetadataError('signature')
    if version & 0xffff != _BASE.VERSION_LOW:
        raise MetadataError('version')
    if count > _BASE.MAX_STREAMS:
        raise MetadataError('stream_count')
    length = count * 12
    if count == 0:
        if directory:
            raise MetadataError('directory_range')
        return timestamp, {}
    if directory < 32 or not _BASE._within(directory, length, size):
        raise MetadataError('directory_range')
    reader.allow(directory, length, 'directory')
    entries = list(struct.iter_unpack('<III', reader.read(directory, length)))
    reserved = ((0, 32), (directory, directory + length))
    selected = {}
    for kind, length, rva in entries:
        if (not _BASE._within(rva, length, size) or (length and
                (rva < 32 or any(_BASE._overlaps((rva, rva + length), area) for area in reserved)))):
            raise MetadataError('stream_range')
        if kind in (4, 6, 15):
            if kind in selected:
                raise LocationError('duplicate_selected')
            selected[kind] = length, rva
    # Even an unselected stream must not alias any selected field's full stream.
    for selected_kind, (length, rva) in selected.items():
        if any(kind != selected_kind and other_size and _BASE._overlaps(
                (rva, rva + length), (other_rva, other_rva + other_size))
               for kind, other_size, other_rva in entries):
            raise LocationError('selected_overlap')
    if 6 in selected and selected[6][0] != 168:
        raise MetadataError('exception_size')
    if 15 in selected and selected[15][0] < 24:
        raise LocationError('misc_size')
    if 4 in selected and selected[4][0] < 4:
        raise LocationError('module_size')
    return timestamp, selected


def parse_dump(basename):
    with _BASE._bound_dump(basename) as (fd, size):
        reader = _Reader(fd, size)
        timestamp, selected = _directory(reader, size)
        misc = None
        if 15 in selected:
            length, rva = selected[15]
            reader.allow(rva, 8, 'misc_field')
            info_size, flags = struct.unpack('<II', reader.read(rva, 8))
            if not 24 <= info_size <= length:
                raise LocationError('misc_size')
            pid = None
            if flags & 1:
                reader.allow(rva + 8, 4, 'misc_field')
                pid = struct.unpack('<I', reader.read(rva + 8, 4))[0]
            misc = {'size_of_info': info_size, 'flags1': flags, 'process_id': pid}
        modules = []
        if 4 in selected:
            length, rva = selected[4]
            reader.allow(rva, 4, 'module_count')
            count = struct.unpack('<I', reader.read(rva, 4))[0]
            if count > MAX_MODULES:
                raise LocationError('module_count')
            if 4 + count * MODULE_STRIDE > length:
                raise LocationError('module_size')
            for index in range(count):
                reader.allow(rva + 4 + index * MODULE_STRIDE, 20, 'module_prefix')
            for index in range(count):
                base, image_size, checksum, pe_time = struct.unpack('<QIII', reader.read(rva + 4 + index * MODULE_STRIDE, 20))
                if base + image_size > 1 << 64:
                    raise LocationError('module_address_range')
                modules.append({'index': index, 'base': base, 'size': image_size,
                                'checksum': checksum, 'pe_timestamp': pe_time})
        exception = None
        if 6 in selected:
            _, rva = selected[6]
            for relative, length in ((0, 4), (8, 8), (24, 8)):
                reader.allow(rva + relative, length, 'exception_field')
            thread = struct.unpack('<I', reader.read(rva, 4))[0]
            code, flags = struct.unpack('<II', reader.read(rva + 8, 8))
            address = struct.unpack('<Q', reader.read(rva + 24, 8))[0]
            exception = {'code': code, 'flags': flags, 'address': address, 'thread_id': thread}
        candidates = [] if exception is None else [item for item in modules
            if item['size'] and item['base'] <= exception['address'] < item['base'] + item['size']]
        unique = candidates[0] if len(candidates) == 1 else None
        result = {'header_time_unix': timestamp, 'exception': exception, 'misc_info': misc,
                  'module_list_present': 4 in selected, 'modules': modules,
                  'exception_module': {'candidate_count': len(candidates), 'unique': unique is not None,
                      'module_index': None if unique is None else unique['index'],
                      'rva': None if unique is None else exception['address'] - unique['base']},
                  'read_budget': reader.budget(), 'declared_process_id_verified_against_runtime': False,
                  'module_file_or_pdb_identity_established': False, 'timestamp_is_run_identifier_claim': False,
                  'thread_id_is_process_id_claim': False, 'exception_cause_established': False}
    return result


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print(json.dumps({'ok': False, 'error_code': _BASE.ERRORS['filename']}))
        return 2
    try:
        result = parse_dump(args[0])
    except MetadataError as error:
        print(json.dumps({'ok': False, 'error_code': error.code}))
        return 1
    print(json.dumps({'ok': True, **result}, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
