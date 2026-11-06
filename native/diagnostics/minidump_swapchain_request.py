#!/usr/bin/env python3
"""One nullable request pointer after the frozen old-graphics swapchain gates.

The unchanged edb22 graphics DLL loads MS-x64 argument9 (ppSwapChain) into
nonvolatile R13, retains it through RVA3e056, and uses it as the later QI
output argument. That interpretation remains conditional on exact code and a
precise, preserved exception context; the anonymous image tuple is no file hash.
Add only CONTEXT.R13 at224:8 after frozen gate9, emitting its nullness only.
No pointed-to memory, stack, other registers, names, account or process data.
Maximum11870 bytes/525pread calls: the frozen reader plus exactly8bytes/1call.
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
        raw = os.read(fd, 7771)
        after = os.fstat(fd)
        identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if (len(raw) != 7770 or identity(before) != identity(after)
                or hashlib.sha256(raw).hexdigest() != '6ea6c07058a732930bc8a9d75ca02c916d70df29396ec4c2f496896a5d1d4214'):
            raise ValueError('frozen_swapchain_reader_binding')
    finally:
        os.close(fd)
    module = types.ModuleType('_frozen_swapchain_request_result')
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


_RESULT = _load_result()
_BASE = _RESULT._BASE
MetadataError = _RESULT.MetadataError
MAX_READ_BYTES = _RESULT.MAX_READ_BYTES + 8
MAX_READ_CALLS = _RESULT.MAX_READ_CALLS + 1


class _Reader(_RESULT._Reader):
    def __init__(self, fd, size):
        super().__init__(fd, size)
        self.context = None
        self.counts['request_context_bytes'] = 0

    def read(self, offset, size):
        key = offset, size
        if (key not in self.allowed or key in self.used or len(self.used) >= MAX_READ_CALLS
                or sum(self.counts.values()) + size > MAX_READ_BYTES):
            raise MetadataError('read_scope')
        self.used.add(key)
        self.counts[self.allowed[key] + '_bytes'] += size
        raw = os.pread(self.fd, size, offset)
        if len(raw) != size:
            raise MetadataError('short_read')
        if self.allowed[key] == 'directory':
            self.entries = list(struct.iter_unpack('<III', raw))
        return raw

    def field(self, offset, size, kind, form):
        values = super().field(offset, size, kind, form)
        if kind == 'exception_field' and form == '<II':
            self.context = values
        return values

    def budget(self):
        return {**self.counts, 'total_bytes': sum(self.counts.values()), 'read_calls': len(self.used),
                'maximum_bytes': MAX_READ_BYTES, 'maximum_read_calls': MAX_READ_CALLS}


def parse_dump(basename):
    with _BASE._bound_dump(basename) as (fd, size):
        reader = _Reader(fd, size)
        timestamp, selected = _RESULT._LOCATION._directory(reader, size)
        original = {'gate': 0}
        try:
            _RESULT._inspect(reader, selected, original)
        except _RESULT._NotAdmitted as error:
            original['gate'] = error.gate
        result = {'header_time_unix': timestamp, 'gate': original['gate'],
            'original_pp_swapchain': {'available': False, 'is_null': None},
            'interpretation_requires_exact_original_code_and_preserved_r13': True,
            'module_file_identity_established': False, 'process_identity_established': False,
            'exception_cause_established': False}
        if original['gate'] == 9:
            _, context = reader.context
            value, = reader.field(context + 224, 8, 'request_context', '<Q')
            result['original_pp_swapchain'] = {'available': True, 'is_null': value == 0}
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
