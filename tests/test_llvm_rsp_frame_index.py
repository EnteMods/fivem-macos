import importlib.util
from pathlib import Path
import unittest

SOURCE = Path(__file__).absolute().parents[1] / 'native/diagnostics/llvm_rsp_frame_index.py'
SPEC = importlib.util.spec_from_file_location('llvm_rsp_frame_index_tested', SOURCE)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def block(ops=None, count=None, version=1, flags=0, register='-', offset='-', extra=''):
    if ops is None:
        ops = ['0x07: ALLOC_SMALL size=32', '0x03: PUSH_NONVOL reg=RBX',
               '0x02: PUSH_NONVOL reg=RDI', '0x01: PUSH_NONVOL reg=RSI']
    if count is None:
        count = len(ops)
    lines = ['  RuntimeFunction {', '    StartAddress: (0x1807D1090)',
             '    EndAddress: (0x1807D118E)', '    UnwindInfoAddress: (0x180A9981C)',
             '    UnwindInfo {', f'      Version: {version}', f'      Flags [ (0x{flags:X})',
             '      ]', '      PrologSize: 7', f'      FrameRegister: {register}',
             f'      FrameOffset: {offset}', f'      UnwindCodeCount: {count}',
             '      UnwindCodes [', *['        ' + line for line in ops],
             '      ]', '    }', '  }']
    if extra:
        lines.insert(-2, extra)
    return '\n'.join(lines) + '\n'


class LLVMRspIndexTests(unittest.TestCase):
    def test_original_caller_body_effect(self):
        entry = MODULE.parse_block(block())
        self.assertTrue(entry['supported_rsp_body'])
        self.assertEqual(entry['stack_frame_bytes'], 56)
        self.assertEqual(entry['prolog_size'], 7)
        self.assertEqual(entry['unwind_code_count'], 4)
        self.assertEqual([x.get('register') for x in entry['operations'][1:]], ['RBX', 'RDI', 'RSI'])

    def test_alloc_large_explicit_size_and_variable_slots(self):
        for count in (2, 3):
            entry = MODULE.parse_block(block(['0x07: ALLOC_LARGE size=520'], count=count))
            self.assertTrue(entry['supported_rsp_body'])
            self.assertEqual(entry['stack_frame_bytes'], 520)

    def test_alloc_large_without_size_is_unsupported(self):
        entry = MODULE.parse_block(block(['0x07: ALLOC_LARGE'], count=2))
        self.assertFalse(entry['supported_rsp_body'])
        self.assertIsNone(entry['stack_frame_bytes'])

    def test_non_rsp_operation_is_unsupported_and_kept(self):
        entry = MODULE.parse_block(block(['0x07: SAVE_NONVOL reg=RBX, offset=0x10'], count=2))
        self.assertFalse(entry['supported_rsp_body'])
        self.assertEqual(entry['operations'][0]['operation'], 'SAVE_NONVOL')
        self.assertEqual(len(MODULE.matching_entries([entry], 0x7d10ed)), 1)

    def test_chain_fp_version_and_handler_are_not_supported(self):
        for kwargs in ({'flags': 4}, {'flags': 1}, {'flags': 2}, {'version': 2},
                       {'register': 'RBP (0x5)', 'offset': '0x3'}, {'offset': '0x1'}):
            entry = MODULE.parse_block(block(**kwargs))
            self.assertFalse(entry['supported_rsp_body'])
            self.assertIsNone(entry['stack_frame_bytes'])

    def test_empty_operations_has_zero_body_frame(self):
        entry = MODULE.parse_block(block([], count=0))
        self.assertTrue(entry['supported_rsp_body'])
        self.assertEqual(entry['stack_frame_bytes'], 0)

    def test_unknown_extra_structure_rejects_support(self):
        entry = MODULE.parse_block(block(extra='      UnexpectedRegisterRestore: 1'))
        self.assertFalse(entry['supported_rsp_body'])
        self.assertIn('unrecognized_llvm_structure', entry['unsupported_reasons'])

    def test_bad_allocation_and_register(self):
        for operation in ('ALLOC_SMALL size=7', 'ALLOC_SMALL size=136',
                          'ALLOC_LARGE size=1048584', 'PUSH_NONVOL reg=RSP'):
            entry = MODULE.parse_block(block(['0x07: ' + operation], count=2 if 'LARGE' in operation else 1))
            self.assertFalse(entry['supported_rsp_body'])

    def test_bad_slot_count_and_prolog_offset(self):
        for text in (block(count=3), block().replace('0x07: ALLOC', '0x08: ALLOC')):
            self.assertFalse(MODULE.parse_block(text)['supported_rsp_body'])

    def test_duplicate_and_overlap_lookup_preserves_all(self):
        one = MODULE.parse_block(block())
        duplicate = dict(one)
        overlap = {**one, 'begin_rva': one['begin_rva'] + 1, 'supported_rsp_body': False}
        entries = MODULE.parse_output(block() + block())
        self.assertEqual(len(entries), 2)
        self.assertEqual(len(MODULE.matching_entries([one, duplicate, overlap], 0x7d10ed)), 3)
        self.assertEqual(MODULE.matching_entries([one], one['end_rva_exclusive']), [])

    def test_missing_and_duplicate_fields_fail(self):
        for text in (block().replace('      Version: 1\n', ''),
                     block().replace('      Version: 1\n', '      Version: 1\n      Version: 1\n')):
            with self.assertRaises(ValueError):
                MODULE.parse_block(text)

    def test_truncated_output_rejected(self):
        with self.assertRaises(ValueError):
            MODULE.parse_output(block()[:-4])


if __name__ == '__main__':
    unittest.main()
