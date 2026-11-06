#!/usr/bin/env python3
"""Only documented ACCESS_VIOLATION kind/fault-address metadata from fixed MDMP role.

Original SDK 10.0.26100.0 um/minidumpapiset.h, pack4: ExceptionStream.Code@8,
NumberParameters@32, ExceptionInformation[0]@40/[1]@48 (each ULONG64).
Code==0xC0000005, count2..15, kind0/1/8 are separate gates before fault-address
read. No other parameters, context, stacks, memory, names or strings are read.
Uses frozen v2 directory validation and v1 FD binding without mutating either.
Maximum32+128*12+4+4+8+8=1592 bytes /6pread calls. Hashes below bind own code
only, never dumps. No runtime/PID/file/module/cause attribution is established.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys
import types


def _load_location():
    path = Path(__file__).absolute().with_name('minidump_numeric_location.py')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size != 9616:
            raise ValueError('frozen_location_reader_binding')
        data = os.read(fd, 9617)
        after = os.fstat(fd)
        if (len(data) != 9616 or hashlib.sha256(data).hexdigest()
                != '19b656fa95b56ba4126645b9fb9b80abfde4bf560746046d2ae228f4a5d20b19'
                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise ValueError('frozen_location_reader_binding')
    finally:
        os.close(fd)
    module = types.ModuleType('_frozen_minidump_numeric_location')
    module.__file__ = str(path)
    exec(compile(data, str(path), 'exec'), module.__dict__)
    return module


_LOCATION = _load_location()
MetadataError = _LOCATION.MetadataError
MAX_READ_BYTES = 1592
MAX_READ_CALLS = 6
ACCESS_VIOLATION = 0xc0000005


class _Reader(_LOCATION._Reader):
    def __init__(self, fd, size):
        super().__init__(fd, size)
        self.counts['av_field_bytes'] = 0

    def read(self, offset, size):
        if len(self.used) >= MAX_READ_CALLS or sum(self.counts.values()) + size > MAX_READ_BYTES:
            raise MetadataError('read_scope')
        return super().read(offset, size)

    def budget(self):
        return {'header_bytes': self.counts['header_bytes'], 'directory_bytes': self.counts['directory_bytes'],
                'av_field_bytes': self.counts['av_field_bytes'], 'total_bytes': sum(self.counts.values()),
                'read_calls': len(self.used), 'maximum_bytes': MAX_READ_BYTES, 'maximum_read_calls': MAX_READ_CALLS}


def parse_dump(basename):
    with _LOCATION._BASE._bound_dump(basename) as (fd, size):
        reader = _Reader(fd, size)
        timestamp, selected = _LOCATION._directory(reader, size)
        result = {'header_time_unix': timestamp, 'exception_code': None, 'number_parameters': None,
                  'access_kind': None, 'fault_address': None, 'av_fields_admitted': False,
                  'gate': 0, 'process_or_module_attribution_established': False,
                  'exception_cause_established': False}
        if 6 in selected:
            _, rva = selected[6]
            reader.allow(rva + 8, 4, 'av_field')
            result['exception_code'] = struct.unpack('<I', reader.read(rva + 8, 4))[0]
            result['gate'] = 1
            if result['exception_code'] == ACCESS_VIOLATION:
                reader.allow(rva + 32, 4, 'av_field')
                count = struct.unpack('<I', reader.read(rva + 32, 4))[0]
                result.update(number_parameters=count, gate=2)
                if 2 <= count <= 15:
                    reader.allow(rva + 40, 8, 'av_field')
                    kind = struct.unpack('<Q', reader.read(rva + 40, 8))[0]
                    result['gate'] = 3
                    if kind in (0, 1, 8):
                        reader.allow(rva + 48, 8, 'av_field')
                        fault = struct.unpack('<Q', reader.read(rva + 48, 8))[0]
                        result.update(access_kind=kind, fault_address=fault, av_fields_admitted=True, gate=4)
        result['read_budget'] = reader.budget()
    return result


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print(json.dumps({'ok': False, 'error_code': _LOCATION._BASE.ERRORS['filename']}))
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
