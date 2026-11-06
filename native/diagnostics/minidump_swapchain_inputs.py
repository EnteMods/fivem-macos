#!/usr/bin/env python3
"""After the frozen swapchain gates, classify RDI and two exact API scalars.

Only RDI/R12/R14 (24 context bytes), bounded capture-descriptor metadata, and
8 bytes each at R14+0x30 / R12 may be added. Never scan memory, follow COM
objects, unwind, or emit raw registers/pointers. Redundant descriptors for the
same file slice are one source; different translations are ambiguous. A real
self-process test does not prove a provider identity in this captured process.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys
import types


def _load_result():
    path = Path(__file__).absolute().with_name('minidump_swapchain_result.py')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size != 7770:
            raise ValueError('frozen_swapchain_reader_binding')
        data = os.read(fd, 7771)
        after = os.fstat(fd)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if (len(data) != 7770 or identity(before) != identity(after)
                or hashlib.sha256(data).hexdigest() != '6ea6c07058a732930bc8a9d75ca02c916d70df29396ec4c2f496896a5d1d4214'):
            raise ValueError('frozen_swapchain_reader_binding')
    finally:
        os.close(fd)
    module = types.ModuleType('_frozen_swapchain_result')
    module.__file__ = str(path)
    exec(compile(data, str(path), 'exec'), module.__dict__)
    return module


_RESULT = _load_result()
_BASE = _RESULT._BASE
MetadataError = _RESULT.MetadataError
MAX_THREADS, MAX_MEMORY_RANGES = 512, 1024
MAX_READ_BYTES, MAX_READ_CALLS = 36502, 2068
PROVIDER_TUPLES = {'dxmt_dxgi': (1421312, 1977323, 1790784891),
                   'wine_dxgi': (1478656, 1886848, 1793607447)}


class _Unavailable(Exception):
    def __init__(self, reason):
        self.reason = reason


class _Reader(_RESULT._Reader):
    def __init__(self, fd, size):
        super().__init__(fd, size)
        self.modules, self.context, self.scalar_cache = [], None, {}
        self.counts.update(input_context_bytes=0, memory_header_bytes=0,
                           memory_descriptor_bytes=0, input_scalar_bytes=0)

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
        values = super().field(offset, size, kind, form)
        if kind == 'module_prefix':
            self.modules.append(values)
        elif kind == 'exception_field' and form == '<II':
            self.context = values
        return values

    def clean_capture(self, offset, size):
        context_size, context = self.context
        return (size > 0 and self.clean_context(offset, size)
                and not _BASE._overlaps((offset, offset + size), (context, context + context_size)))

    def scalar(self, address, ranges):
        if not 0 < address <= (1 << 64) - 8:
            return {'available': False, 'is_null': None, 'reason': 'invalid_pointer'}
        offsets = {rva + address - base for base, size, rva in ranges
                   if base <= address and address - base <= size - 8}
        if len(offsets) != 1:
            return {'available': False, 'is_null': None,
                    'reason': 'not_captured' if not offsets else 'ambiguous_capture'}
        offset = offsets.pop()
        if offset not in self.scalar_cache:
            self.scalar_cache[offset] = self.field(offset, 8, 'input_scalar', '<Q')[0]
        return {'available': True, 'is_null': self.scalar_cache[offset] == 0, 'reason': None}

    def budget(self):
        return {**self.counts, 'total_bytes': sum(self.counts.values()), 'read_calls': len(self.used),
                'maximum_bytes': MAX_READ_BYTES, 'maximum_read_calls': MAX_READ_CALLS}


def _memory_ranges(reader, selected):
    selected = dict(selected)
    for kind, size, rva in reader.entries:
        if kind in (3, 5, 9):
            if kind in selected:
                raise _RESULT._LOCATION.LocationError('duplicate_selected')
            selected[kind] = size, rva
    for kind, (size, rva) in selected.items():
        if any(other != kind and length and _BASE._overlaps((rva, rva + size), (offset, offset + length))
               for other, length, offset in reader.entries):
            raise _RESULT._LOCATION.LocationError('selected_overlap')
    ranges, memory_count = [], 0
    for kind in (3, 5, 9):
        if kind not in selected:
            continue
        length, at = selected[kind]
        header = 16 if kind == 9 else 4
        if length < header:
            raise _Unavailable('invalid_memory_metadata')
        if kind == 9:
            count, payload = reader.field(at, 16, 'memory_header', '<QQ')
        else:
            count, = reader.field(at, 4, 'memory_header', '<I')
        stride = 48 if kind == 3 else 16
        if ((kind == 3 and count > MAX_THREADS) or (kind != 3 and memory_count + count > MAX_MEMORY_RANGES)):
            raise _Unavailable('memory_metadata_limit')
        if header + count * stride > length:
            raise _Unavailable('invalid_memory_metadata')
        if kind != 3:
            memory_count += count
        for index in range(count):
            location = at + header + index * stride + (24 if kind == 3 else 0)
            if kind == 9:
                base, size = reader.field(location, 16, 'memory_descriptor', '<QQ')
                rva = payload
                payload += size
            else:
                base, size, rva = reader.field(location, 16, 'memory_descriptor', '<QII')
            if base + size > 1 << 64:
                raise _Unavailable('invalid_memory_metadata')
            if size and not reader.clean_capture(rva, size):
                raise _Unavailable('invalid_memory_capture')
            if size:
                ranges.append((base, size, rva))
    return ranges


def _inspect_inputs(reader, selected, result):
    _, context = reader.context
    rdi, = reader.field(context + 176, 8, 'input_context', '<Q')
    r12, = reader.field(context + 216, 8, 'input_context', '<Q')
    r14, = reader.field(context + 232, 8, 'input_context', '<Q')
    matches = [(index, item) for index, item in enumerate(reader.modules)
               if item[1] and item[0] <= rdi < item[0] + item[1]]
    if len(matches) == 1:
        index, module = matches[0]
        result['callee'] = {'candidate_count': 1, 'module_index': index, 'rva': rdi - module[0],
            'image_size': module[1], 'checksum': module[2], 'pe_timestamp': module[3],
            'provider_tuple_hint': next((name for name, fields in PROVIDER_TUPLES.items() if module[1:] == fields), 'unrecognized')}
    else:
        result['callee'] = {'candidate_count': len(matches), 'module_index': None, 'rva': None,
            'image_size': None, 'checksum': None, 'pe_timestamp': None, 'provider_tuple_hint': None}
    try:
        ranges = _memory_ranges(reader, selected)
    except _Unavailable as error:
        for name in ('hwnd_argument', 'device_argument'):
            result[name] = {'available': False, 'is_null': None, 'reason': error.reason}
        return
    hwnd_address = r14 + 0x30 if 0 < r14 <= (1 << 64) - 0x38 else 0
    result['hwnd_argument'] = reader.scalar(hwnd_address, ranges)
    result['device_argument'] = reader.scalar(r12, ranges)


def parse_dump(basename):
    with _BASE._bound_dump(basename) as (fd, size):
        reader = _Reader(fd, size)
        timestamp, selected = _RESULT._LOCATION._directory(reader, size)
        result = {'header_time_unix': timestamp, 'gate': 0, 'register_value_admitted': False,
            'captured_rax_low32': None, 'candidate_hresult_hex': None, 'candidate_hresult_failed': None,
            'interpretation_requires_unmodified_precise_exception_context': True,
            'input_provenance_requires_preserved_callee_abi': True, 'module_file_identity_established': False,
            'process_identity_established': False, 'exception_cause_established': False,
            'callee': None, 'hwnd_argument': None, 'device_argument': None}
        try:
            _RESULT._inspect(reader, selected, result)
        except _RESULT._NotAdmitted as error:
            result['gate'] = error.gate
        if result['gate'] == 9:
            _inspect_inputs(reader, selected, result)
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
