"""Synthetic bounded RSP effects; actual reads only own code/LLVM index metadata."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import struct
import tempfile
import types
import unittest
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('minidump_rsp_frames', PROJECT / 'native/diagnostics/minidump_rsp_frames.py')
rsp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rsp)
helper_path = PROJECT / 'tests/test_minidump_leaf_caller.py'
helper_data = rsp._SECOND._bound_bytes(helper_path, 11851, '500f90b5f44645bddd0fe3ab75b9f31987fa29de22dbb64281fd633695140c3d')
helper = types.ModuleType('_frozen_rsp_synthetic_fixture')
helper.__file__ = str(helper_path)
exec(compile(helper_data, str(helper_path), 'exec'), helper.__dict__)


def entry(**changes):
    row = {'begin_rva': 0, 'end_rva_exclusive': rsp._LEAF.EXPECTED_MODULE[0], 'version': 1,
           'flags': 0, 'frame_register': 0, 'frame_offset': 0, 'prolog_size': 0,
           'chaininfo': False, 'exception_handler': False, 'unwind_handler': False,
           'explicit_epilog_codes': False, 'supported_rsp_body': True, 'stack_frame_bytes': 0,
           'unsupported_reasons': [], 'operations': []}
    row.update(changes)
    return row


def synthetic(values=None, *, maximum=False, modules=None, stride=64):
    data, positions = helper.synthetic(maximum=maximum, modules=modules)
    data.extend(b'\xa5' * (positions['stack'] + 512 - len(data)))
    struct.pack_into('<I', data, positions['thread'] + 4 + 32, 512)
    values = [0x1807d10ee, 0x1807d104a, 0x200001234] if values is None else values
    for index, word in enumerate(values):
        struct.pack_into('<Q', data, positions['stack'] + 16 + index * stride, word)
    return data, positions


class RspFrameTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.actual_index, cls.reference = rsp.verify_inputs()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.crashes = self.root.joinpath(*rsp._LEAF._BASE.ROLE_PARTS)
        self.crashes.mkdir(parents=True)
        patch = mock.patch.object(rsp._LEAF._BASE, 'ROOT', self.root)
        patch.start()
        self.addCleanup(patch.stop)

    def parse(self, data, entries=None):
        (self.crashes / 'synthetic.dmp').write_bytes(data)
        index = self.actual_index if entries is None else {'entries': entries}
        original = os.pread
        with mock.patch.object(rsp, 'verify_inputs', return_value=(index, self.reference)), \
                mock.patch.object(rsp.os, 'pread', wraps=original) as reads:
            result = rsp.parse_dump('synthetic.dmp')
        return result, [(call.args[2], call.args[1]) for call in reads.call_args_list]

    def test_actual_index_known_first_two_frames_and_rsp_exclusion(self):
        self.assertEqual(len(self.actual_index['entries']), 37619)
        self.assertEqual(rsp._lookup(self.actual_index, 0x7d10ee), (64, None))
        self.assertEqual(rsp._lookup(self.actual_index, 0x7d104a), (64, None))
        self.assertEqual(rsp._lookup(self.actual_index, 0x7a9106)[1], 'no_unwind_range')
        self.assertFalse(any(row['supported_rsp_body'] and any(operation.get('register') == 'RSP'
                             for operation in row['operations']) for row in self.actual_index['entries']))

    def test_two_known_steps_then_other_module_candidate_stops(self):
        data, p = synthetic()
        result, calls = self.parse(data)
        self.assertEqual(result['frames'], [{'frame': 1, 'module_index': 0, 'rva': 0x7d10ee},
            {'frame': 2, 'module_index': 0, 'rva': 0x7d104a}, {'frame': 3, 'module_index': 1, 'rva': 0x1234}])
        self.assertEqual(result['stop_reason'], 'other_module')
        self.assertEqual(calls[-3:], [(p['stack'] + 16, 8), (p['stack'] + 80, 8), (p['stack'] + 144, 8)])
        self.assertEqual(result['captured_stack_bytes_read'], 24)
        self.assertEqual(result['read_budget']['context_field_bytes'], 20)
        self.assertEqual(result['read_budget']['total_bytes'], 218)
        self.assertIs(result['static_rsp_effect_assumption'], True)
        for key in ('live_body_or_epilog_freedom_verified', 'whole_context_or_stack_read',
                    'raw_unknown_stack_words_persisted', 'registers_restored', 'stack_scanned',
                    'callstack_established', 'caller_or_file_or_pdb_identity_established', 'exception_cause_established'):
            self.assertIs(result[key], False)
        for value in (0x70000010, 0x1807d10ee, 0x1807d104a, 0x200001234):
            self.assertNotIn(str(value), json.dumps(result))

    def test_lookup_ambiguity_unknown_and_prolog_stop_before_extra_read(self):
        pc = 0x7d10ee - 1
        cases = [([], 'no_unwind_range'),
                 ([entry(), entry(supported_rsp_body=False)], 'ambiguous_unwind_range'),
                 ([entry(begin_rva=pc - 7, prolog_size=7)], 'prolog_pc'),
                 ([entry(end_rva_exclusive=pc)], 'no_unwind_range')]
        for rows, reason in cases:
            with self.subTest(reason=reason):
                data, p = synthetic()
                result, calls = self.parse(data, rows)
                self.assertEqual(result['stop_reason'], reason)
                self.assertEqual(result['captured_stack_words_read'], 1)
                self.assertNotIn((p['stack'] + 80, 8), calls)

    def test_unsupported_frame_ops_and_rsp_push_stop_before_extra_read(self):
        cases = [entry(version=2), entry(flags=4), entry(frame_register=5), entry(frame_offset=1),
                 entry(chaininfo=True), entry(explicit_epilog_codes=True),
                 entry(operations=[{'code_offset': 0, 'operation': 'SAVE_NONVOL', 'size': 8}], stack_frame_bytes=8),
                 entry(operations=[{'code_offset': 0, 'operation': 'PUSH_NONVOL', 'size': 8, 'register': 'RSP'}], stack_frame_bytes=8),
                 entry(operations=[{'code_offset': 0, 'operation': 'PUSH_NONVOL', 'size': 8, 'register': 'RAX'}], stack_frame_bytes=8),
                 entry(operations=[{'code_offset': 0, 'operation': 'ALLOC_SMALL', 'size': 256}], stack_frame_bytes=256),
                 entry(stack_frame_bytes=8), entry(stack_frame_bytes=rsp.MAX_FRAME_BYTES + 8)]
        for row in cases:
            with self.subTest(row=row):
                data, p = synthetic()
                result, calls = self.parse(data, [row])
                self.assertEqual(result['stop_reason'], 'unsupported_rsp_metadata')
                self.assertEqual(result['captured_stack_words_read'], 1)
                self.assertNotIn((p['stack'] + 80, 8), calls)

    def test_leaf_gate_and_first_other_module_never_continue(self):
        data, p = synthetic()
        struct.pack_into('<I', data, p['module'] + 4 + 12, 0)
        result, calls = self.parse(data)
        self.assertEqual(result['stop_reason'], 'leaf_not_admitted')
        self.assertEqual(result['frames'], [])
        self.assertEqual(result['captured_stack_words_read'], 0)
        data, p = synthetic([0x200001234])
        result, calls = self.parse(data)
        self.assertEqual(result['stop_reason'], 'other_module')
        self.assertEqual(len(result['frames']), 1)
        self.assertEqual(result['captured_stack_words_read'], 1)

    def test_captured_and_u64_bounds_precede_each_extra_read(self):
        for overflow in (False, True):
            with self.subTest(overflow=overflow):
                data, p = synthetic()
                if overflow:
                    struct.pack_into('<Q', data, p['context'] + 152, (1 << 64) - 16)
                    struct.pack_into('<QI', data, p['thread'] + 4 + 24, (1 << 64) - 32, 32)
                else:
                    struct.pack_into('<I', data, p['thread'] + 4 + 32, 64)
                result, calls = self.parse(data)
                self.assertEqual(result['leaf_admission_gate'], 10)
                self.assertEqual(result['stop_reason'], 'captured_stack_bounds')
                self.assertEqual(result['captured_stack_words_read'], 1)
                self.assertNotIn((p['stack'] + 80, 8), calls)
        for file_rva in (4200, 512, 2048):
            reader = rsp._Reader(-1, 4224)
            reader.entries = [(6, 168, 512)]
            reader._context = 1232, 2048
            reader._stack = 0x70000000, 128, file_rva
            with mock.patch.object(rsp.os, 'pread') as reads:
                self.assertIsNone(reader.next_word(0x70000010, 64))
                reads.assert_not_called()

    def test_unknown_or_ambiguous_word_is_redacted_and_stops(self):
        overlapping = [(0x180000000, *rsp._LEAF.EXPECTED_MODULE),
                       (0x200000000, 0x400000, 7, 8), (0x200001000, 0x1000, 9, 10)]
        cases = [([0x1807d10ee, 0xffffffffffffffff], None),
                 ([0x1807d10ee, 0x200001234], overlapping)]
        for values, modules in cases:
            with self.subTest(values=values):
                data, p = synthetic(values, modules=modules)
                result, calls = self.parse(data)
                self.assertEqual(result['stop_reason'], 'unmapped_or_ambiguous_word')
                self.assertEqual(len(result['frames']), 1)
                self.assertEqual(result['captured_stack_words_read'], 2)
                self.assertEqual(calls.count((p['stack'] + 80, 8)), 1)
                self.assertNotIn(str(values[1]), json.dumps(result))

    def test_eight_words_and_maximum_budget_with_zero_stack_frames(self):
        data, p = synthetic([0x1807d10ee] * 8, maximum=True, stride=8)
        result, calls = self.parse(data, [entry()])
        self.assertEqual(result['stop_reason'], 'maximum_words')
        self.assertEqual(len(result['frames']), 8)
        self.assertEqual(result['captured_stack_bytes_read'], 64)
        self.assertEqual(result['read_budget']['total_bytes'], 13986)
        self.assertEqual(len(calls), 1044)
        self.assertEqual(calls[-8:], [(p['stack'] + 16 + 8 * number, 8) for number in range(8)])
        self.assertNotIn((p['stack'] + 80, 8), calls)
        self.assertEqual(rsp._LEAF.MAX_READ_BYTES, 13930)
        self.assertEqual(rsp._LEAF.MAX_READ_CALLS, 1037)

    def test_alloc_large_reads_only_its_metadata_selected_slot(self):
        data, p = synthetic([0x1807d10ee, 0x200001234], stride=264)
        row = entry(prolog_size=1, stack_frame_bytes=256,
                    operations=[{'code_offset': 1, 'operation': 'ALLOC_LARGE', 'size': 256}])
        result, calls = self.parse(data, [row])
        self.assertEqual(result['stop_reason'], 'other_module')
        self.assertEqual(calls[-2:], [(p['stack'] + 16, 8), (p['stack'] + 280, 8)])
        self.assertEqual(result['captured_stack_words_read'], 2)

    def test_index_role_and_identity_are_checked_before_reads_or_dump_open(self):
        record = json.loads(rsp._SECOND._bound_bytes(rsp.ROOT / rsp.INPUT_REPORT, rsp.INPUT_REPORT_BYTES, rsp.INPUT_REPORT_SHA256))
        for field, value in (('path', '../private-file'), ('sha256', '0' * 64), ('bytes', 1)):
            with self.subTest(field=field):
                altered = copy.deepcopy(record)
                altered['index'][field] = value
                with mock.patch.object(rsp._SECOND, '_bound_bytes', return_value=json.dumps(altered).encode()) as bound, \
                        mock.patch.object(rsp._LEAF._BASE, '_bound_dump') as opened:
                    with self.assertRaises(ValueError):
                        rsp.parse_dump('synthetic.dmp')
                    self.assertEqual(bound.call_count, 1)
                    opened.assert_not_called()


if __name__ == '__main__':
    unittest.main()
