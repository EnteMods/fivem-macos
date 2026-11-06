"""Synthetic version-bound two-word checks; no actual dump or runtime access."""
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
spec = importlib.util.spec_from_file_location('minidump_second_frame', PROJECT / 'native/diagnostics/minidump_second_frame.py')
second = importlib.util.module_from_spec(spec)
spec.loader.exec_module(second)

# Reuse only the unchanged own synthetic fixture constructor, never its tests.
helper_path = PROJECT / 'tests/test_minidump_leaf_caller.py'
helper_bytes = second._bound_bytes(helper_path, 11851, '500f90b5f44645bddd0fe3ab75b9f31987fa29de22dbb64281fd633695140c3d')
helper = types.ModuleType('_frozen_leaf_synthetic_fixture')
helper.__file__ = str(helper_path)
exec(compile(helper_bytes, str(helper_path), 'exec'), helper.__dict__)


def synthetic(*, maximum=False, first=None, other_word=None, modules=None):
    data, positions = helper.synthetic(maximum=maximum, modules=modules)
    first = 0x180000000 + second.FIRST_RETURN_RVA if first is None else first
    other_word = (0x200001044 if maximum else 0x200001234) if other_word is None else other_word
    struct.pack_into('<I', data, positions['thread'] + 4 + 32, 128)
    struct.pack_into('<Q', data, positions['stack'] + 16, first)
    struct.pack_into('<Q', data, positions['stack'] + 80, other_word)
    return data, positions


class SecondFrameTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.crashes = self.root.joinpath(*second._LEAF._BASE.ROLE_PARTS)
        self.crashes.mkdir(parents=True)
        patch = mock.patch.object(second._LEAF._BASE, 'ROOT', self.root)
        patch.start()
        self.addCleanup(patch.stop)

    def parse(self, data):
        (self.crashes / 'synthetic.dmp').write_bytes(data)
        original = os.pread
        with mock.patch.object(second.os, 'pread', wraps=original) as reads:
            result = second.parse_dump('synthetic.dmp')
        return result, [(call.args[2], call.args[1]) for call in reads.call_args_list]

    def test_exact_extra_word_scope_and_redacted_result(self):
        data, p = synthetic()
        result, calls = self.parse(data)
        self.assertEqual(result['leaf_admission_gate'], 10)
        self.assertEqual(result['admission_gate'], 5)
        self.assertEqual(result['first_possible_leaf_return_word'], {'module_index': 0, 'rva': second.FIRST_RETURN_RVA})
        self.assertEqual(result['second_possible_return_word'], {'module_index': 1, 'rva': 0x1234})
        self.assertEqual(calls[-2:], [(p['stack'] + 16, 8), (p['stack'] + 80, 8)])
        self.assertEqual(len(calls), 18)
        self.assertEqual(result['read_budget']['total_bytes'], 210)
        self.assertEqual(result['read_budget']['context_field_bytes'], 20)
        self.assertEqual(result['captured_stack_words_read'], 2)
        self.assertEqual(result['captured_stack_bytes_read'], 16)
        self.assertIs(result['whole_context_or_stack_read'], False)
        self.assertIs(result['raw_unknown_stack_words_persisted'], False)
        self.assertIs(result['callstack_established'], False)
        self.assertIs(result['live_code_or_epilog_state_verified'], False)
        for raw_value in (0x70000010, 0x180000000 + second.FIRST_RETURN_RVA, 0x200001234):
            self.assertNotIn(str(raw_value), json.dumps(result))

    def test_static_frame_evidence_gate_precedes_dump_open(self):
        self.assertEqual(second.verify_frame_evidence()['sha256'], second.FRAME_REPORT_SHA256)
        proof = json.loads(second._bound_bytes(second.ROOT / second.FRAME_REPORT, second.FRAME_REPORT_BYTES, second.FRAME_REPORT_SHA256))
        mutations = [(['runtime_function', 'version'], 2), (['runtime_function', 'flags'], 4),
                     (['runtime_function', 'frame_register'], 5), (['runtime_function', 'chaininfo'], True),
                     (['stack_effect', 'second_return_slot_from_captured_leaf_rsp_bytes'], 72),
                     (['selection', 'observed_leaf_return_rva_from_root'], second.FIRST_RETURN_RVA + 1)]
        for keys, value in mutations:
            with self.subTest(keys=keys):
                altered = copy.deepcopy(proof)
                altered[keys[0]][keys[1]] = value
                with mock.patch.object(second, '_bound_bytes', return_value=json.dumps(altered).encode()), \
                        mock.patch.object(second._LEAF._BASE, '_bound_dump') as opened:
                    with self.assertRaises(ValueError):
                        second.parse_dump('synthetic.dmp')
                    opened.assert_not_called()
        with mock.patch.object(second, '_bound_bytes', side_effect=FileNotFoundError), \
                mock.patch.object(second._LEAF._BASE, '_bound_dump') as opened:
            with self.assertRaises(FileNotFoundError):
                second.parse_dump('synthetic.dmp')
            opened.assert_not_called()

    def test_leaf_admission_is_required(self):
        data, p = synthetic()
        struct.pack_into('<I', data, p['module'] + 4 + 12, 0)
        result, calls = self.parse(data)
        self.assertEqual(result['leaf_admission_gate'], 2)
        self.assertEqual(result['admission_gate'], 1)
        self.assertEqual(result['captured_stack_words_read'], 0)
        self.assertNotIn((p['stack'] + 80, 8), calls)

    def test_first_word_requires_exact_tuple_and_rva(self):
        for first in (0x200001234, 0x180000000 + second.FIRST_RETURN_RVA + 1):
            with self.subTest(first=first):
                data, p = synthetic(first=first)
                result, calls = self.parse(data)
                self.assertEqual(result['leaf_admission_gate'], 10)
                self.assertEqual(result['admission_gate'], 2)
                self.assertEqual(result['captured_stack_words_read'], 1)
                self.assertNotIn((p['stack'] + 80, 8), calls)

    def test_additional_slot_requires_captured_extent_and_nonwrapping_rsp(self):
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
                self.assertEqual(result['admission_gate'], 3)
                self.assertEqual(result['captured_stack_words_read'], 1)
                self.assertNotIn((p['stack'] + 80, 8), calls)

    def test_extra_reader_rechecks_full_file_and_alias_bounds(self):
        for file_rva in (4200, 512, 2048):
            with self.subTest(file_rva=file_rva):
                reader = second._Reader(-1, 4224)
                reader.entries = [(6, 168, 512)]
                reader._context = 1232, 2048
                reader._rsp = 0x70000010
                reader._stack = 0x70000000, 128, file_rva
                with mock.patch.object(second.os, 'pread') as reads:
                    self.assertIsNone(reader.second_word())
                    reads.assert_not_called()

    def test_unknown_or_ambiguous_second_word_is_not_persisted(self):
        modules = [(0x180000000, *second._LEAF.EXPECTED_MODULE),
                   (0x200000000, 0x400000, 7, 8), (0x200001000, 0x1000, 9, 10)]
        for options in ({'other_word': (1 << 64) - 1}, {'modules': modules}):
            with self.subTest(options=options):
                data, p = synthetic(**options)
                result, calls = self.parse(data)
                self.assertEqual(result['admission_gate'], 4)
                self.assertEqual(result['captured_stack_words_read'], 2)
                self.assertIsNone(result['second_possible_return_word'])
                self.assertEqual(calls.count((p['stack'] + 80, 8)), 1)
                self.assertNotIn(str(options.get('other_word', 0x200001234)), json.dumps(result))

    def test_maximum_budget_adds_exactly_eight_bytes_and_one_call(self):
        data, _ = synthetic(maximum=True)
        result, calls = self.parse(data)
        self.assertEqual(result['admission_gate'], 5)
        self.assertEqual(result['captured_stack_bytes_read'], 16)
        self.assertEqual(result['read_budget']['total_bytes'], 13938)
        self.assertEqual(len(calls), 1038)
        self.assertEqual(second._LEAF.MAX_READ_BYTES, 13930)
        self.assertEqual(second._LEAF.MAX_READ_CALLS, 1037)


if __name__ == '__main__':
    unittest.main()
