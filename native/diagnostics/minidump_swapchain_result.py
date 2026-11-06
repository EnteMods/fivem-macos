#!/usr/bin/env python3
"""Fixed-role swapchain return-register metadata, not a general register reader.

Only AV READ0 at the exact anonymous image tuple/RVA is admitted. AMD64
CONTROL|INTEGER context and matching RIP precede RAX-low32. Context slices:
flags48:4, RIP248:8, RAX120:4. No other registers, stack, memory, names or IDs.
The verified instruction model is call HRESULT; mov RCX,[slot]; faulting
mov RAX,[RCX]. Thus the value is a candidate HRESULT conditional on an
unmodified precise exception context. Header tuples do not prove file identity.
Frozen AV/v2/v1 code supplies the fixed-role FD and directory validators.
Max11862 bytes /524 pread calls, including512 anonymous20B module prefixes.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys
import types


def _load_av():
    path = Path(__file__).absolute().with_name('minidump_av_metadata.py')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size != 4780:
            raise ValueError('frozen_av_reader_binding')
        data = os.read(fd, 4781)
        after = os.fstat(fd)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if (len(data) != 4780 or identity(before) != identity(after)
                or hashlib.sha256(data).hexdigest() != '6e4b9e6a2e16c822a3a306b9ace9427f59f48bb297e3a6d8a590fe48dd754e41'):
            raise ValueError('frozen_av_reader_binding')
    finally:
        os.close(fd)
    module = types.ModuleType('_frozen_swapchain_av_metadata')
    module.__file__ = str(path)
    exec(compile(data, str(path), 'exec'), module.__dict__)
    return module


_AV = _load_av()
_LOCATION = _AV._LOCATION
_BASE = _LOCATION._BASE
MetadataError = _LOCATION.MetadataError
EXPECTED_MODULE = (770048, 798369, 1792674694)
EXPECTED_RVA = 0x3e056
MAX_READ_BYTES = 11862
MAX_READ_CALLS = 524


class _NotAdmitted(Exception):
    def __init__(self, gate):
        self.gate = gate


class _Reader(_LOCATION._Reader):
    def __init__(self, fd, size):
        super().__init__(fd, size)
        self.entries = []
        self.counts.update(system_field_bytes=0, context_field_bytes=0)

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
        if self.allowed[key] == 'directory':
            self.entries = list(struct.iter_unpack('<III', data))
        return data

    def field(self, offset, size, kind, form):
        self.allow(offset, size, kind)
        return struct.unpack(form, self.read(offset, size))

    def clean_context(self, offset, size):
        reserved = [(start, start + count) for (start, count), kind in self.allowed.items()
                    if kind in ('header', 'directory')]
        reserved += [(rva, rva + count) for _, count, rva in self.entries if count]
        return (offset >= 32 and _BASE._within(offset, size, self.size)
                and not any(_BASE._overlaps((offset, offset + size), area) for area in reserved))

    def budget(self):
        return {**self.counts, 'total_bytes': sum(self.counts.values()), 'read_calls': len(self.used),
                'maximum_bytes': MAX_READ_BYTES, 'maximum_read_calls': MAX_READ_CALLS}


def _inspect(reader, selected, result):
    for kind, size, rva in reader.entries:
        if kind == 7:
            if kind in selected:
                raise _LOCATION.LocationError('duplicate_selected')
            selected[kind] = size, rva
    for kind, (size, rva) in selected.items():
        if any(other != kind and length and _BASE._overlaps((rva, rva + size), (offset, offset + length))
               for other, length, offset in reader.entries):
            raise _LOCATION.LocationError('selected_overlap')
    if not all(kind in selected for kind in (4, 6, 7)):
        raise _NotAdmitted(0)
    _, ex = selected[6]
    code, = reader.field(ex + 8, 4, 'exception_field', '<I')
    if code != 0xc0000005:
        raise _NotAdmitted(1)
    count, = reader.field(ex + 32, 4, 'exception_field', '<I')
    if not 2 <= count <= 15:
        raise _NotAdmitted(2)
    access, = reader.field(ex + 40, 8, 'exception_field', '<Q')
    if access != 0:
        raise _NotAdmitted(3)
    length, module_rva = selected[4]
    count, = reader.field(module_rva, 4, 'module_count', '<I')
    if count > 512:
        raise _LOCATION.LocationError('module_count')
    if 4 + count * 108 > length:
        raise _LOCATION.LocationError('module_size')
    modules = []
    for index in range(count):
        base, size, checksum, stamp = reader.field(module_rva + 4 + index * 108, 20, 'module_prefix', '<QIII')
        if base + size > 1 << 64:
            raise _LOCATION.LocationError('module_address_range')
        modules.append((base, size, checksum, stamp))
    address, = reader.field(ex + 24, 8, 'exception_field', '<Q')
    matches = [item for item in modules if item[1] and item[0] <= address < item[0] + item[1]]
    if len(matches) != 1 or matches[0][1:] != EXPECTED_MODULE or address - matches[0][0] != EXPECTED_RVA:
        raise _NotAdmitted(4)
    length, system_rva = selected[7]
    if length < 56 or reader.field(system_rva, 2, 'system_field', '<H')[0] != 9:
        raise _NotAdmitted(5)
    context_size, context = reader.field(ex + 160, 8, 'exception_field', '<II')
    if context_size < 1232 or not reader.clean_context(context, context_size):
        raise _NotAdmitted(6)
    flags, = reader.field(context + 48, 4, 'context_field', '<I')
    if flags & 0x00ff0000 != 0x00100000 or flags & 3 != 3:
        raise _NotAdmitted(7)
    rip, = reader.field(context + 248, 8, 'context_field', '<Q')
    if rip != address:
        raise _NotAdmitted(8)
    value, = reader.field(context + 120, 4, 'context_field', '<I')
    result.update(gate=9, register_value_admitted=True, captured_rax_low32=value,
                  candidate_hresult_hex=f'0x{value:08x}', candidate_hresult_failed=bool(value & 0x80000000))


def parse_dump(basename):
    with _BASE._bound_dump(basename) as (fd, size):
        reader = _Reader(fd, size)
        timestamp, selected = _LOCATION._directory(reader, size)
        result = {'header_time_unix': timestamp, 'gate': 0, 'register_value_admitted': False,
            'captured_rax_low32': None, 'candidate_hresult_hex': None, 'candidate_hresult_failed': None,
            'interpretation_requires_unmodified_precise_exception_context': True,
            'module_file_identity_established': False, 'process_identity_established': False,
            'exception_cause_established': False}
        try:
            _inspect(reader, selected, result)
        except _NotAdmitted as error:
            result['gate'] = error.gate
        result['read_budget'] = reader.budget()
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
