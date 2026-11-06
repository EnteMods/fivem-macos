#!/usr/bin/env python3
"""One possible leaf-return word, never a stack scan or proven caller.

Fixed crash-role FD binding and directory checks come from frozen v1/v2 code.
Required anonymous exception tuple(size/checksum/stamp) and RVA are literal.
AMD64 SystemInfo, CONTROL flags, exception RIP and aligned RSP must match.
Only20 bytes of the exception context (flags/RIP/RSP), selected TIDs, one
matched stack descriptor and, after every gate, one captured stack QWORD are
read. No fallback to ThreadList.ThreadContext; no other registers or stack words.
The QWORD/RSP/stack addresses are never emitted. Only a unique anonymous
module index/RVA can be returned, explicitly without caller/file/PDB certainty.

SDK10.0.26100.0: minidumpapiset.h pack4, Thread48/Stack24, SystemInfo56;
winnt.h AMD64 CONTEXT1232 (flags48/RSP152/RIP248). Max128 streams/512 modules/
512 threads:13930 read bytes,1037 pread calls. Short context is non-admitted,
not evidence of a client defect. Own-code hashes never apply to dump contents.
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
    module = types.ModuleType('_frozen_leaf_numeric_location')
    module.__file__ = str(path)
    exec(compile(data, str(path), 'exec'), module.__dict__)
    return module


_LOCATION = _load_location()
_BASE = _LOCATION._BASE
MetadataError = _LOCATION.MetadataError
EXPECTED_MODULE = (12976128, 12473764, 1792674854)
EXPECTED_RVA = 0x7a9105
MAX_THREADS = 512
MAX_READ_BYTES = 13930
MAX_READ_CALLS = 1037
# 0 missing streams;1 no unique exception module;2 tuple/RVA mismatch;3 arch;
# 4 context descriptor;5 CONTROL flags;6 RIP/RSP;7 thread selection/extent;
# 8 captured stack extent;9 no unique return-word module;10 possible leaf word.


class _NotAdmitted(Exception):
    def __init__(self, gate):
        self.gate = gate


class _Reader(_LOCATION._Reader):
    def __init__(self, fd, size):
        super().__init__(fd, size)
        self.entries = []
        self.counts.update(dict.fromkeys(('system_field_bytes', 'context_field_bytes',
            'thread_count_bytes', 'thread_id_bytes', 'stack_descriptor_bytes', 'return_word_bytes'), 0))

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

    def fields(self, offset, size, kind, form):
        self.allow(offset, size, kind)
        return struct.unpack(form, self.read(offset, size))

    def clean_payload(self, offset, size, other=()):
        areas = [(start, start + count) for (start, count), kind in self.allowed.items() if kind in ('header', 'directory')]
        areas += [(rva, rva + count) for _, count, rva in self.entries if count]
        return (size > 0 and offset >= 32 and _BASE._within(offset, size, self.size)
                and not any(_BASE._overlaps((offset, offset + size), area) for area in (*areas, *other)))

    def budget(self):
        return {**self.counts, 'total_bytes': sum(self.counts.values()), 'read_calls': len(self.used),
                'maximum_bytes': MAX_READ_BYTES, 'maximum_read_calls': MAX_READ_CALLS}


def _ranges(reader, selected):
    for kind, size, rva in reader.entries:
        if kind in (3, 7):
            if kind in selected:
                raise _LOCATION.LocationError('duplicate_selected')
            selected[kind] = size, rva
    for kind, (size, rva) in selected.items():
        if any(other_kind != kind and other_size and _BASE._overlaps((rva, rva + size),
                (other_rva, other_rva + other_size)) for other_kind, other_size, other_rva in reader.entries):
            raise _LOCATION.LocationError('selected_overlap')
    if not all(kind in selected for kind in (3, 4, 6, 7)):
        raise _NotAdmitted(0)


def _inspect(reader, selected, result):
    _ranges(reader, selected)
    module_size, module_rva = selected[4]
    count, = reader.fields(module_rva, 4, 'module_count', '<I')
    if count > _LOCATION.MAX_MODULES:
        raise _LOCATION.LocationError('module_count')
    if 4 + count * 108 > module_size:
        raise _LOCATION.LocationError('module_size')
    modules = []
    for index in range(count):
        base, size, checksum, stamp = reader.fields(module_rva + 4 + index * 108, 20, 'module_prefix', '<QIII')
        if base + size > 1 << 64:
            raise _LOCATION.LocationError('module_address_range')
        modules.append((base, size, checksum, stamp))
    _, ex = selected[6]
    tid, = reader.fields(ex, 4, 'exception_field', '<I')
    address, = reader.fields(ex + 24, 8, 'exception_field', '<Q')
    matches = [item for item in modules if item[1] and item[0] <= address < item[0] + item[1]]
    if len(matches) != 1:
        raise _NotAdmitted(1)
    target = matches[0]
    if target[1:] != EXPECTED_MODULE or address - target[0] != EXPECTED_RVA:
        raise _NotAdmitted(2)
    sys_size, sys_rva = selected[7]
    if sys_size < 56 or reader.fields(sys_rva, 2, 'system_field', '<H')[0] != 9:
        raise _NotAdmitted(3)
    context_size, context = reader.fields(ex + 160, 8, 'exception_field', '<II')
    if context_size < 1232 or not reader.clean_payload(context, context_size):
        raise _NotAdmitted(4)
    flags, = reader.fields(context + 48, 4, 'context_field', '<I')
    if flags & 0x100001 != 0x100001:
        raise _NotAdmitted(5)
    rip, = reader.fields(context + 248, 8, 'context_field', '<Q')
    if rip != address:
        raise _NotAdmitted(6)
    rsp, = reader.fields(context + 152, 8, 'context_field', '<Q')
    if rsp % 8 or rsp > (1 << 64) - 8:
        raise _NotAdmitted(6)
    thread_size, thread_rva = selected[3]
    if thread_size < 4 or not tid:
        raise _NotAdmitted(7)
    threads, = reader.fields(thread_rva, 4, 'thread_count', '<I')
    if threads > MAX_THREADS or 4 + threads * 48 > thread_size:
        raise _NotAdmitted(7)
    matched = []
    for index in range(threads):
        observed_tid, = reader.fields(thread_rva + 4 + index * 48, 4, 'thread_id', '<I')
        if observed_tid == tid:
            matched.append(index)
    if len(matched) != 1:
        raise _NotAdmitted(7)
    stack_start, stack_size, stack = reader.fields(thread_rva + 4 + matched[0] * 48 + 24, 16, 'stack_descriptor', '<QII')
    if (stack_size < 8 or stack_start + stack_size > 1 << 64 or rsp < stack_start
            or rsp - stack_start > stack_size - 8 or not reader.clean_payload(
                stack, stack_size, ((context, context + context_size),))):
        raise _NotAdmitted(8)
    word, = reader.fields(stack + rsp - stack_start, 8, 'return_word', '<Q')
    result['captured_stack_word_read'] = True
    possible = [(index, word - base) for index, (base, size, _, _) in enumerate(modules)
                if size and base <= word < base + size]
    if len(possible) != 1:
        raise _NotAdmitted(9)
    result.update(admission_gate=10, possible_leaf_return_word={'module_index': possible[0][0], 'rva': possible[0][1]})


def parse_dump(basename):
    with _BASE._bound_dump(basename) as (fd, size):
        reader = _Reader(fd, size)
        timestamp, selected = _LOCATION._directory(reader, size)
        result = {'header_time_unix': timestamp, 'admission_gate': 0, 'possible_leaf_return_word': None,
                  'classification': 'possible_leaf_return_word_only', 'captured_stack_word_read': False,
                  'whole_context_or_stack_read': False, 'raw_unknown_stack_words_persisted': False,
                  'live_leaf_code_verified': False, 'callstack_established': False,
                  'caller_or_file_or_pdb_identity_established': False, 'exception_cause_established': False}
        try:
            _inspect(reader, selected, result)
        except _NotAdmitted as denied:
            result['admission_gate'] = denied.gate
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
