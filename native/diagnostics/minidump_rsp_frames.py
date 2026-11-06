#!/usr/bin/env python3
"""At most eight conditional RSP-only return candidates, never a stack scan.

The unchanged frozen leaf reader supplies its checked exception context and
captured-thread stack. A pinned standard-LLVM metadata index may justify only
ALLOC_SMALL/LARGE and PUSH_NONVOL stack effects in the fixed anonymous image.
Every lookup includes all overlapping entries, with ControlPC=returnRVA-1.
Version1/bodyOffset>Prolog is an explicit static_rsp_effect_assumption, not
proof of live body state or absence of an epilog. No registers are restored.
At most64 stack bytes (eight QWORDs),20 selected context bytes,13986 total
dump bytes and1044 pread calls. Only unique anonymous module indices/RVAs are
emitted; other images terminate the continuation after one candidate. Unknown
words remain private. No caller, file/PDB, callstack or root-cause claim.
"""
import json
import os
from pathlib import Path
import struct
import sys
import types

ROOT = Path(__file__).resolve().parents[2]
INDEX_PATH = 'build/llvm-unwind-metadata/legitimacy-rsp-frame-index-v1.json'
INPUT_REPORT = 'research/legitimacy-rsp-frame-index-inputs-v1.json'
INPUT_REPORT_BYTES = 2167
INPUT_REPORT_SHA256 = '2b3c223c1ba65066c8a673b09087c5e543604958a6514dd3bce77d4142283cfb'
INDEX_BYTES = 24273045
INDEX_SHA256 = 'd1525c6cd2892bd37dee6dba39009be0ac4b3301afbaf981efe971405c961bbe'
MAX_WORDS = 8
MAX_READ_BYTES = 13986
MAX_READ_CALLS = 1044
MAX_FRAME_BYTES = 1048576
CODE_SHA256 = '95f5788ff0fec0c0808e357cd312c95344c618c3054dc12782ea8f1b66bcea97'


def _load_second():
    # Reuse the frozen private-state reader; its fixed LLVM single-frame
    # verification function and parser are not invoked by this adapter.
    import hashlib
    import stat
    path = Path(__file__).absolute().with_name('minidump_second_frame.py')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        data = os.read(fd, 10829)
        after = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size != 10828
                or len(data) != 10828 or hashlib.sha256(data).hexdigest()
                != '54d51490786d5c77d7a4e6e8cd2e6e75a370ae267265eabe3f18233a78d18df9'
                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise ValueError('frozen_private_reader_binding')
    finally:
        os.close(fd)
    module = types.ModuleType('_frozen_rsp_second_reader')
    module.__file__ = str(path)
    exec(compile(data, str(path), 'exec'), module.__dict__)
    return module


_SECOND = _load_second()
_LEAF = _SECOND._LEAF
MetadataError = _LEAF.MetadataError


def verify_inputs():
    record = json.loads(_SECOND._bound_bytes(ROOT / INPUT_REPORT, INPUT_REPORT_BYTES, INPUT_REPORT_SHA256))
    identity = record.get('index', {})
    if (record.get('schema_version') != 1 or record.get('kind') != 'llvm_rsp_frame_index_inputs'
            or identity != {'path': INDEX_PATH, 'bytes': INDEX_BYTES, 'sha256': INDEX_SHA256}
            or record.get('full_code_sha256_verified') is not True):
        raise ValueError('fixed_rsp_index_scope')
    # Exactly one literal index path is admitted before its first content read.
    index = json.loads(_SECOND._bound_bytes(ROOT / INDEX_PATH, identity['bytes'], identity['sha256']))
    expected_code = {'path': 'build/windows-source-integration/legitimacy.dll', 'bytes': 12443232,
                     'sha256': CODE_SHA256}
    for document in (record, index):
        if any(document.get('code', {}).get(key) != value for key, value in expected_code.items()):
            raise ValueError('fixed_rsp_code_identity')
    expected_tuple = dict(zip(('size_of_image', 'checksum', 'time_date_stamp'), _LEAF.EXPECTED_MODULE))
    if (index.get('schema_version') != 1 or index.get('kind') != 'llvm_rsp_frame_metadata_index'
            or index.get('image_base') != 0x180000000 or index.get('max_stack_frame_bytes') != MAX_FRAME_BYTES
            or index.get('code', {}).get('header_tuple') != expected_tuple
            or index.get('all_ranges_preserved') is not True or index.get('lookup_requires_all_matches') is not True
            or type(index.get('entries')) is not list or len(index['entries']) != 37619):
        raise ValueError('fixed_rsp_index_contract')
    for entry in index['entries']:
        if (type(entry) is not dict or type(entry.get('begin_rva')) is not int
                or type(entry.get('end_rva_exclusive')) is not int
                or not 0 <= entry['begin_rva'] < entry['end_rva_exclusive'] <= _LEAF.EXPECTED_MODULE[0]):
            raise ValueError('rsp_index_range')
    return index, {'path': INPUT_REPORT, 'bytes': INPUT_REPORT_BYTES, 'sha256': INPUT_REPORT_SHA256,
                   'index': identity}


def _lookup(index, rva):
    if rva <= 0:
        return None, 'no_unwind_range'
    pc = rva - 1
    matches = [entry for entry in index['entries'] if entry['begin_rva'] <= pc < entry['end_rva_exclusive']]
    if not matches:
        return None, 'no_unwind_range'
    if len(matches) != 1:
        return None, 'ambiguous_unwind_range'
    entry = matches[0]
    if (entry.get('supported_rsp_body') is not True or entry.get('version') != 1
            or entry.get('flags') != 0 or entry.get('frame_register') != 0 or entry.get('frame_offset') != 0
            or any(entry.get(key) is not False for key in ('chaininfo', 'exception_handler', 'unwind_handler', 'explicit_epilog_codes'))
            or entry.get('unsupported_reasons') != []):
        return None, 'unsupported_rsp_metadata'
    prolog, frame, operations = entry.get('prolog_size'), entry.get('stack_frame_bytes'), entry.get('operations')
    if (type(prolog) is not int or not 0 <= prolog <= 255 or type(frame) is not int
            or not 0 <= frame <= MAX_FRAME_BYTES or frame % 8 or type(operations) is not list
            or len(operations) > 255):
        return None, 'unsupported_rsp_metadata'
    if pc - entry['begin_rva'] <= prolog:
        return None, 'prolog_pc'
    total = 0
    for operation in operations:
        if type(operation) is not dict:
            return None, 'unsupported_rsp_metadata'
        code, size = operation.get('operation'), operation.get('size')
        offset = operation.get('code_offset')
        if type(offset) is not int or not 0 <= offset <= prolog or type(size) is not int:
            return None, 'unsupported_rsp_metadata'
        if code == 'PUSH_NONVOL':
            if size != 8 or operation.get('register') not in ('RBX', 'RBP', 'RSI', 'RDI', 'R12', 'R13', 'R14', 'R15'):
                return None, 'unsupported_rsp_metadata'
        elif code in ('ALLOC_SMALL', 'ALLOC_LARGE'):
            if size < 8 or size > MAX_FRAME_BYTES or size % 8 or (code == 'ALLOC_SMALL' and size > 128):
                return None, 'unsupported_rsp_metadata'
        else:
            return None, 'unsupported_rsp_metadata'
        total += size
    if total != frame:
        return None, 'unsupported_rsp_metadata'
    return frame + 8, None


class _Reader(_SECOND._Reader):
    def __init__(self, fd, size):
        super().__init__(fd, size)
        self.counts['rsp_continuation_word_bytes'] = 0

    def next_word(self, slot, delta):
        start, count, file_rva = self._stack
        context_size, context_rva = self._context
        if (type(delta) is not int or delta <= 0 or delta % 8 or slot > (1 << 64) - delta - 8
                or count < 8 or start + count > 1 << 64):
            return None
        target = slot + delta
        if (target < start or target - start > count - 8
                or not self.clean_payload(file_rva, count, ((context_rva, context_rva + context_size),))):
            return None
        offset = file_rva + target - start
        if not _LEAF._BASE._within(offset, 8, self.size):
            return None
        self.allow(offset, 8, 'rsp_continuation_word')
        key = offset, 8
        if (key in self.used or len(self.used) >= MAX_READ_CALLS or self.counts['rsp_continuation_word_bytes'] >= 56
                or sum(self.counts.values()) + 8 > MAX_READ_BYTES):
            raise MetadataError('read_scope')
        self.used.add(key)
        self.counts['rsp_continuation_word_bytes'] += 8
        data = os.pread(self.fd, 8, offset)
        if len(data) != 8:
            raise MetadataError('short_read')
        return struct.unpack('<Q', data)[0], target

    def budget(self):
        return {**super().budget(), 'maximum_bytes': MAX_READ_BYTES, 'maximum_read_calls': MAX_READ_CALLS}


def parse_dump(basename):
    index, reference = verify_inputs()
    with _LEAF._BASE._bound_dump(basename) as (fd, size):
        reader = _Reader(fd, size)
        timestamp, selected = _LEAF._LOCATION._directory(reader, size)
        reader._exception = selected.get(6, (None, None))[1]
        first = {'admission_gate': 0, 'possible_leaf_return_word': None, 'captured_stack_word_read': False}
        try:
            _LEAF._inspect(reader, selected, first)
        except _LEAF._NotAdmitted as denied:
            first['admission_gate'] = denied.gate
        frames, stop = [], 'leaf_not_admitted'
        if first['admission_gate'] == 10:
            candidate = first['possible_leaf_return_word']
            frames.append({'frame': 1, **candidate})
            slot = reader._rsp
            while True:
                module = reader._modules[candidate['module_index']]
                if module[1:] != _LEAF.EXPECTED_MODULE:
                    stop = 'other_module'
                    break
                if len(frames) == MAX_WORDS:
                    stop = 'maximum_words'
                    break
                delta, reason = _lookup(index, candidate['rva'])
                if reason:
                    stop = reason
                    break
                next_value = reader.next_word(slot, delta)
                if next_value is None:
                    stop = 'captured_stack_bounds'
                    break
                word, slot = next_value
                matches = [(number, word - base) for number, (base, count, _, _) in enumerate(reader._modules)
                           if count and base <= word < base + count]
                if len(matches) != 1:
                    stop = 'unmapped_or_ambiguous_word'
                    break
                candidate = {'module_index': matches[0][0], 'rva': matches[0][1]}
                frames.append({'frame': len(frames) + 1, **candidate})
        words = int(first['captured_stack_word_read']) + reader.counts['rsp_continuation_word_bytes'] // 8
        result = {'header_time_unix': timestamp, 'leaf_admission_gate': first['admission_gate'], 'frames': frames,
                  'stop_reason': stop, 'classification': 'conditional_rsp_only_return_candidates', 'index_evidence': reference,
                  'static_rsp_effect_assumption': True, 'metadata_control_pc': 'return_rva_minus_one',
                  'live_body_or_epilog_freedom_verified': False, 'captured_stack_words_read': words,
                  'captured_stack_bytes_read': words * 8, 'maximum_stack_words': MAX_WORDS,
                  'whole_context_or_stack_read': False, 'raw_unknown_stack_words_persisted': False,
                  'registers_restored': False, 'stack_scanned': False, 'callstack_established': False,
                  'caller_or_file_or_pdb_identity_established': False, 'exception_cause_established': False,
                  'read_budget': reader.budget()}
    return result


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print(json.dumps({'ok': False, 'error_code': _LEAF._BASE.ERRORS['filename']}))
        return 2
    try:
        result = parse_dump(args[0])
    except MetadataError as error:
        print(json.dumps({'ok': False, 'error_code': error.code}))
        return 1
    except (OSError, ValueError, KeyError, TypeError):
        print(json.dumps({'ok': False, 'error_code': 41}))
        return 1
    print(json.dumps({'ok': True, **result}, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
