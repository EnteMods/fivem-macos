#!/usr/bin/env python3
"""Read only fixed numeric MDMP metadata from one direct Source crashes/*.dmp.

Layout source: original Windows SDK 10.0.26100.0 um/minidumpapiset.h,
pshpack4, MINIDUMP_HEADER/DIRECTORY/EXCEPTION_STREAM. The independent tests
assert sizeof/offsetof against that original SDK, without importing the older
full-dump analyzer. No memory, stack, parameter, context, module or string stream
is read. ThreadId is not a process ID; neither filename nor header time proves
the dumped process, a run identifier, a module or the cause of failure.

At most 32 + 128*12 + 20 = 1588 bytes and five bounded pread calls are used.
No dump hashes/copies, ZIP extraction, enumeration, runtime or prefix access.
"""
from contextlib import ExitStack, contextmanager
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys

ROOT = Path(__file__).resolve().parents[2]
ROLE_PARTS = ('build', 'windows-source-integration', 'crashes')
SDK_LAYOUT_SOURCE = 'toolchains/msvc-2022/Windows Kits/10/Include/10.0.26100.0/um/minidumpapiset.h'
HEADER_BYTES = 32
DIRECTORY_ENTRY_BYTES = 12
EXCEPTION_STREAM_BYTES = 168
MAX_STREAMS = 128
MAX_FILE_BYTES = 16 * 1024**3
MAX_READ_BYTES = HEADER_BYTES + MAX_STREAMS * DIRECTORY_ENTRY_BYTES + 20
SIGNATURE = 0x504d444d
VERSION_LOW = 0xa793
EXCEPTION_STREAM = 6
ERRORS = {'filename': 1, 'path_binding': 2, 'file_type': 3, 'file_size': 4,
          'signature': 5, 'version': 6, 'stream_count': 7, 'directory_range': 8,
          'stream_range': 9, 'exception_size': 10, 'duplicate_exception': 11,
          'exception_overlap': 12, 'read_scope': 13, 'short_read': 14, 'input_changed': 15}


class MetadataError(ValueError):
    def __init__(self, reason):
        self.reason = reason
        self.code = ERRORS[reason]
        super().__init__(reason)


def _fingerprint(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)


def _within(offset, size, total):
    return offset >= 0 and size >= 0 and offset <= total and size <= total - offset


def _overlaps(a, b):
    return a[0] < b[1] and b[0] < a[1]


@contextmanager
def _bound_dump(basename):
    if (type(basename) is not str or len(basename) > 200
            or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*[.]dmp', basename) is None):
        raise MetadataError('filename')
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    with ExitStack() as stack:
        bindings = []
        try:
            parent = os.open(ROOT.anchor, directory_flags)
            stack.callback(os.close, parent)
            for name in (*ROOT.parts[1:], *ROLE_PARTS):
                child = os.open(name, directory_flags, dir_fd=parent)
                stack.callback(os.close, child)
                info = os.fstat(child)
                entry = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(entry.st_mode) or (info.st_dev, info.st_ino) != (entry.st_dev, entry.st_ino):
                    raise MetadataError('path_binding')
                bindings.append((parent, name, child, (info.st_dev, info.st_ino)))
                parent = child
            fd = os.open(basename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            stack.callback(os.close, fd)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise MetadataError('file_type')
            if not HEADER_BYTES <= info.st_size <= MAX_FILE_BYTES:
                raise MetadataError('file_size')
            entry = os.stat(basename, dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISREG(entry.st_mode) or _fingerprint(entry) != _fingerprint(info):
                raise MetadataError('path_binding')
            yield fd, info.st_size
            if _fingerprint(os.fstat(fd)) != _fingerprint(info):
                raise MetadataError('input_changed')
            current = os.stat(basename, dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISREG(current.st_mode) or _fingerprint(current) != _fingerprint(info):
                raise MetadataError('input_changed')
            for old_parent, name, child, identity in bindings:
                current = os.stat(name, dir_fd=old_parent, follow_symlinks=False)
                held = os.fstat(child)
                if (not stat.S_ISDIR(current.st_mode) or (current.st_dev, current.st_ino) != identity
                        or (held.st_dev, held.st_ino) != identity):
                    raise MetadataError('input_changed')
        except OSError:
            raise MetadataError('path_binding') from None


class _Reader:
    def __init__(self, fd, size):
        self.fd, self.size = fd, size
        self.allowed = {(0, HEADER_BYTES): 'header'}
        self.used = set()
        self.counts = {'header_bytes': 0, 'directory_bytes': 0, 'exception_field_bytes': 0}
        self.calls = 0

    def allow(self, offset, size, kind):
        if size <= 0 or not _within(offset, size, self.size) or (offset, size) in self.allowed:
            raise MetadataError('read_scope')
        self.allowed[(offset, size)] = kind

    def read(self, offset, size):
        key = (offset, size)
        if (key not in self.allowed or key in self.used or self.calls >= 5
                or sum(self.counts.values()) + size > MAX_READ_BYTES):
            raise MetadataError('read_scope')
        self.used.add(key)
        self.calls += 1
        self.counts[self.allowed[key] + '_bytes'] += size
        data = os.pread(self.fd, size, offset)
        if len(data) != size:
            raise MetadataError('short_read')
        return data

    def budget(self):
        return {**self.counts, 'total_bytes': sum(self.counts.values()), 'read_calls': self.calls,
                'maximum_bytes': MAX_READ_BYTES, 'maximum_read_calls': 5}


def parse_dump(basename):
    """No arbitrary path/root argument: only a direct filename in the fixed Source role."""
    with _bound_dump(basename) as (fd, size):
        reader = _Reader(fd, size)
        signature, version, count, directory, checksum, timestamp, flags = struct.unpack('<IIIIIIQ', reader.read(0, HEADER_BYTES))
        if signature != SIGNATURE:
            raise MetadataError('signature')
        if version & 0xffff != VERSION_LOW:
            raise MetadataError('version')
        if count > MAX_STREAMS:
            raise MetadataError('stream_count')
        directory_bytes = count * DIRECTORY_ENTRY_BYTES
        if count == 0:
            if directory != 0:
                raise MetadataError('directory_range')
            entries = []
        else:
            if directory < HEADER_BYTES or not _within(directory, directory_bytes, size):
                raise MetadataError('directory_range')
            reader.allow(directory, directory_bytes, 'directory')
            data = reader.read(directory, directory_bytes)
            entries = list(struct.iter_unpack('<III', data))
        reserved = [(0, HEADER_BYTES), (directory, directory + directory_bytes)]
        exception = None
        for stream_type, length, rva in entries:
            if not _within(rva, length, size):
                raise MetadataError('stream_range')
            if length and (rva < HEADER_BYTES or any(_overlaps((rva, rva + length), region) for region in reserved)):
                raise MetadataError('stream_range')
            if stream_type == EXCEPTION_STREAM:
                if exception is not None:
                    raise MetadataError('duplicate_exception')
                if length != EXCEPTION_STREAM_BYTES:
                    raise MetadataError('exception_size')
                exception = rva
        numeric = None
        if exception is not None:
            area = exception, exception + EXCEPTION_STREAM_BYTES
            if any(kind != EXCEPTION_STREAM and length and _overlaps(area, (rva, rva + length)) for kind, length, rva in entries):
                raise MetadataError('exception_overlap')
            # These three slices deliberately skip nested-record, parameter and context-descriptor bytes.
            for relative, length in ((0, 4), (8, 8), (24, 8)):
                reader.allow(exception + relative, length, 'exception_field')
            thread_id = struct.unpack('<I', reader.read(exception, 4))[0]
            code, exception_flags = struct.unpack('<II', reader.read(exception + 8, 8))
            address = struct.unpack('<Q', reader.read(exception + 24, 8))[0]
            numeric = {'code': code, 'flags': exception_flags, 'address': address, 'thread_id': thread_id}
        result = {'header_time_unix': timestamp, 'exception': numeric, 'read_budget': reader.budget(),
                  'process_or_module_attribution_established': False,
                  'thread_id_is_process_id_claim': False, 'timestamp_is_run_identifier_claim': False,
                  'exception_cause_established': False}
    return result


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print(json.dumps({'ok': False, 'error_code': ERRORS['filename']}))
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
