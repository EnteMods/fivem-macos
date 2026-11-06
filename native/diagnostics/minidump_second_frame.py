#!/usr/bin/env python3
"""Two version-bound possible return words; no general unwind or stack scan.

Frozen leaf checks must admit the first word at the exact anonymous module
tuple/RVA7d10ee. A separately pinned LLVM v1/flags0/frame0 record must describe
32 allocated bytes and three pushes. Only then may one extra QWORD at original
RSP+0x40 be read, after repeating u64/file/full captured-stack checks. There are
at most16 captured-stack bytes,20 selected context bytes,13938 total read bytes
and1038 pread calls. Registers are not restored and no later frame is visited.
RSP and raw words stay private; only unique anonymous module index/RVA results
are emitted. Static unwind data does not verify live code, epilog state, caller
identity or crash cause. Own-code/evidence hashes never hash dump contents.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys
import types

ROOT = Path(__file__).resolve().parents[2]
FRAME_REPORT = 'research/legitimacy-caller-llvm-unwind-20261102T231153214140Z.json'
FRAME_REPORT_BYTES = 4123
FRAME_REPORT_SHA256 = 'df0c176d64cd83c93f239afc5d51595be8ead4c4e4f54b80b958185130120dc2'
CODE_SHA256 = '95f5788ff0fec0c0808e357cd312c95344c618c3054dc12782ea8f1b66bcea97'
FIRST_RETURN_RVA = 0x7d10ee
SECOND_SLOT_OFFSET = 0x40
MAX_READ_BYTES = 13938
MAX_READ_CALLS = 1038


def _bound_bytes(path, count, digest):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size != count:
            raise ValueError('fixed_diagnostic_input_binding')
        data = os.read(fd, count + 1)
        after = os.fstat(fd)
        if (len(data) != count or hashlib.sha256(data).hexdigest() != digest
                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise ValueError('fixed_diagnostic_input_binding')
    finally:
        os.close(fd)
    return data


def _load_leaf():
    path = Path(__file__).absolute().with_name('minidump_leaf_caller.py')
    data = _bound_bytes(path, 9726, '460e1f07d98fc9a7d55321fecf5a6f793c3d2cc3e176f4858d96ed3c4b104cf3')
    module = types.ModuleType('_frozen_second_frame_leaf')
    module.__file__ = str(path)
    exec(compile(data, str(path), 'exec'), module.__dict__)
    return module


_LEAF = _load_leaf()
MetadataError = _LEAF.MetadataError


def verify_frame_evidence():
    proof = json.loads(_bound_bytes(ROOT / FRAME_REPORT, FRAME_REPORT_BYTES, FRAME_REPORT_SHA256))
    frame = {'begin_rva': 0x7d1090, 'end_rva_exclusive': 0x7d118e, 'unwind_info_rva': 0xa9981c,
             'version': 1, 'flags': 0, 'frame_register': 0, 'frame_offset': 0, 'prolog_size': 7,
             'control_pc_offset': 0x5d, 'unwind_code_count': 4,
             'codes': [{'code_offset': 7, 'operation': 'ALLOC_SMALL', 'size': 32},
                       {'code_offset': 3, 'operation': 'PUSH_NONVOL', 'register': 'RBX', 'size': 8},
                       {'code_offset': 2, 'operation': 'PUSH_NONVOL', 'register': 'RDI', 'size': 8},
                       {'code_offset': 1, 'operation': 'PUSH_NONVOL', 'register': 'RSI', 'size': 8}],
             'chaininfo': False, 'exception_handler': False, 'unwind_handler': False, 'explicit_epilog_codes': False}
    expected_code = {'path': 'build/windows-source-integration/legitimacy.dll', 'bytes': 12443232,
                     'sha256': CODE_SHA256, 'full_hash_verified': True, 'fd_and_path_identity_unchanged': True}
    expected_selection = {'image_base': 0x180000000, 'control_pc_rva': FIRST_RETURN_RVA - 1,
                          'observed_leaf_return_rva_from_root': FIRST_RETURN_RVA, 'covering_block_count': 1}
    expected_effect = {'pushed_nonvolatile_bytes': 24, 'explicit_allocation_bytes': 32,
                      'body_stack_frame_bytes_excluding_return_address': 56, 'first_leaf_return_pop_bytes': 8,
                      'second_return_slot_from_captured_leaf_rsp_bytes': SECOND_SLOT_OFFSET,
                      'rsp_after_second_return_from_captured_leaf_rsp_bytes': 72,
                      'static_metadata_confirms_plus_0x40_hypothesis': True,
                      'live_stack_or_return_word_read': False, 'live_call_chain_identity_proven': False}
    # The raw report SHA is authoritative; exact numeric checks document the offset admission.
    same = lambda left, right: json.dumps(left, sort_keys=True) == json.dumps(right, sort_keys=True)
    if (proof.get('schema_version') != 1 or proof.get('kind') != 'llvm_static_caller_unwind'
            or not same(proof.get('code'), expected_code) or not same(proof.get('runtime_function'), frame)
            or any(not same(proof.get('selection', {}).get(key), value) for key, value in expected_selection.items())
            or any(not same(proof.get('stack_effect', {}).get(key), value) for key, value in expected_effect.items())
            or proof.get('llvm', {}).get('exit') != 0 or proof.get('llvm', {}).get('version_exit') != 0
            or proof.get('llvm', {}).get('stderr_bytes') != 0):
        raise ValueError('fixed_static_frame_not_admitted')
    return {'path': FRAME_REPORT, 'bytes': FRAME_REPORT_BYTES, 'sha256': FRAME_REPORT_SHA256}


class _Reader(_LEAF._Reader):
    def __init__(self, fd, size):
        super().__init__(fd, size)
        self._modules = []
        self._exception = None
        self._context = None
        self._rsp = None
        self._stack = None
        self.counts['second_return_word_bytes'] = 0

    def read(self, offset, size):
        data = super().read(offset, size)
        kind = self.allowed[offset, size]
        if kind == 'module_prefix':
            self._modules.append(struct.unpack('<QIII', data))
        elif kind == 'exception_field' and self._exception is not None and offset == self._exception + 160:
            self._context = struct.unpack('<II', data)
        elif kind == 'context_field' and self._context is not None and offset == self._context[1] + 152:
            self._rsp, = struct.unpack('<Q', data)
        elif kind == 'stack_descriptor':
            self._stack = struct.unpack('<QII', data)
        return data

    def second_word(self):
        if self._rsp is None or self._stack is None or self._context is None:
            return None
        start, count, file_rva = self._stack
        context_size, context_rva = self._context
        if (self._rsp > (1 << 64) - SECOND_SLOT_OFFSET - 8 or count < 8
                or start + count > 1 << 64):
            return None
        target = self._rsp + SECOND_SLOT_OFFSET
        if (target < start or target - start > count - 8
                or not self.clean_payload(file_rva, count, ((context_rva, context_rva + context_size),))):
            return None
        offset = file_rva + target - start
        if not _LEAF._BASE._within(offset, 8, self.size):
            return None
        key = offset, 8
        self.allow(offset, 8, 'second_return_word')
        if (key in self.used or len(self.used) >= MAX_READ_CALLS
                or sum(self.counts.values()) + 8 > MAX_READ_BYTES):
            raise MetadataError('read_scope')
        self.used.add(key)
        self.counts['second_return_word_bytes'] += 8
        data = os.pread(self.fd, 8, offset)
        if len(data) != 8:
            raise MetadataError('short_read')
        return struct.unpack('<Q', data)[0]

    def budget(self):
        return {**super().budget(), 'maximum_bytes': MAX_READ_BYTES, 'maximum_read_calls': MAX_READ_CALLS}


def parse_dump(basename):
    reference = verify_frame_evidence()  # No dump is opened if the static frame evidence is absent or changed.
    with _LEAF._BASE._bound_dump(basename) as (fd, size):
        reader = _Reader(fd, size)
        timestamp, selected = _LEAF._LOCATION._directory(reader, size)
        reader._exception = selected.get(6, (None, None))[1]
        first = {'admission_gate': 0, 'possible_leaf_return_word': None, 'captured_stack_word_read': False}
        try:
            _LEAF._inspect(reader, selected, first)
        except _LEAF._NotAdmitted as denied:
            first['admission_gate'] = denied.gate
        result = {'header_time_unix': timestamp, 'leaf_admission_gate': first['admission_gate'],
                  'first_possible_leaf_return_word': first['possible_leaf_return_word'], 'admission_gate': 1,
                  'second_possible_return_word': None, 'classification': 'two_version_bound_possible_return_words_only',
                  'frame_evidence': reference, 'captured_stack_words_read': int(first['captured_stack_word_read']),
                  'captured_stack_bytes_read': 8 * int(first['captured_stack_word_read']),
                  'maximum_stack_words': 2, 'additional_slot_offset': SECOND_SLOT_OFFSET,
                  'whole_context_or_stack_read': False, 'raw_unknown_stack_words_persisted': False,
                  'live_code_or_epilog_state_verified': False, 'callstack_established': False,
                  'caller_or_file_or_pdb_identity_established': False, 'exception_cause_established': False}
        if first['admission_gate'] == 10:
            candidate = first['possible_leaf_return_word']
            module = reader._modules[candidate['module_index']]
            result['admission_gate'] = 2
            if module[1:] == _LEAF.EXPECTED_MODULE and candidate['rva'] == FIRST_RETURN_RVA:
                result['admission_gate'] = 3
                word = reader.second_word()
                if word is not None:
                    result.update(captured_stack_words_read=2, captured_stack_bytes_read=16, admission_gate=4)
                    matches = [(index, word - base) for index, (base, count, _, _) in enumerate(reader._modules)
                               if count and base <= word < base + count]
                    if len(matches) == 1:
                        result.update(admission_gate=5, second_possible_return_word={'module_index': matches[0][0], 'rva': matches[0][1]})
        result['read_budget'] = reader.budget()
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
        print(json.dumps({'ok': False, 'error_code': 40}))
        return 1
    print(json.dumps({'ok': True, **result}, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
