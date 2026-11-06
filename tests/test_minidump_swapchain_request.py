"""Synthetic old-graphics contexts only; never open an actual dump."""
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest import mock

import test_minidump_swapchain_result as fixtures

PROJECT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('minidump_swapchain_request',
    PROJECT / 'native/diagnostics/minidump_swapchain_request.py')
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)


class SwapchainRequestTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.crashes = self.root.joinpath(*reader._BASE.ROLE_PARTS)
        self.crashes.mkdir(parents=True)
        patch = mock.patch.object(reader._BASE, 'ROOT', self.root)
        patch.start()
        self.addCleanup(patch.stop)

    def tracked(self, value=0, **kwargs):
        raw, positions = fixtures.synthetic(**kwargs)
        struct.pack_into('<Q', raw, positions['context'] + 224, value)
        (self.crashes / 'synthetic.dmp').write_bytes(raw)
        with mock.patch.object(reader.os, 'pread', wraps=os.pread) as reads:
            result = reader.parse_dump('synthetic.dmp')
        calls = [(call.args[2], call.args[1]) for call in reads.call_args_list]
        return result, calls, positions

    def test_zero_nonzero_and_maximum_emit_only_nullness(self):
        for value in (0, 1, 0xffffffffffffffff, 0xdeadbeef12345678):
            with self.subTest(value=value):
                result, calls, positions = self.tracked(value)
                self.assertEqual(result['gate'], 9)
                self.assertEqual(result['original_pp_swapchain'], {'available': True, 'is_null': value == 0})
                self.assertEqual(calls[-1], (positions['context'] + 224, 8))
                self.assertEqual(result['read_budget']['request_context_bytes'], 8)
                self.assertEqual(result['read_budget']['context_field_bytes'], 16)
                self.assertEqual(result['read_budget']['total_bytes'], 150)
                self.assertEqual(len(calls), 14)
                output = json.dumps(result)
                self.assertNotIn('captured_rax', output)
                self.assertNotIn('candidate_hresult', output)
                self.assertNotIn('deadbeef', output)
                self.assertNotIn(str(0xffffffffffffffff), output)
                self.assertFalse(result['exception_cause_established'])

    def test_all_existing_gates_precede_the_one_added_register_read(self):
        cases = [({'code': 0x80000003}, 1), ({'count': 1}, 2), ({'access': 1}, 3),
            ({'module_tuple': (770048, 798369, 1)}, 4), ({'rva': 0x3e057}, 4),
            ({'arch': 0}, 5), ({'context_size': 1231}, 6), ({'context_alias': True}, 6),
            ({'flags': 0x100001}, 7), ({'rip_delta': 1}, 8)]
        for kwargs, gate in cases:
            with self.subTest(kwargs=kwargs):
                result, calls, positions = self.tracked(**kwargs)
                self.assertEqual(result['gate'], gate)
                self.assertNotIn((positions['context'] + 224, 8), calls)
                self.assertEqual(result['read_budget']['request_context_bytes'], 0)
                self.assertEqual(result['original_pp_swapchain'], {'available': False, 'is_null': None})

    def test_full_context_bounds_precede_added_read_and_short_read_is_an_error(self):
        raw, positions = fixtures.synthetic()
        struct.pack_into('<II', raw, positions['ex'] + 160, 1232, len(raw) - 100)
        path = self.crashes / 'synthetic.dmp'
        path.write_bytes(raw)
        with mock.patch.object(reader.os, 'pread', wraps=os.pread) as reads:
            result = reader.parse_dump('synthetic.dmp')
        self.assertEqual(result['gate'], 6)
        self.assertEqual(result['read_budget']['request_context_bytes'], 0)
        self.assertFalse(any(call.args[2] == len(raw) - 100 + 224 for call in reads.call_args_list))
        raw, positions = fixtures.synthetic()
        path.write_bytes(raw)
        original = os.pread
        def short(fd, size, offset):
            return original(fd, size - 1 if (offset, size) == (positions['context'] + 224, 8) else size, offset)
        with mock.patch.object(reader.os, 'pread', side_effect=short), self.assertRaises(reader.MetadataError) as caught:
            reader.parse_dump('synthetic.dmp')
        self.assertEqual(caught.exception.reason, 'short_read')

    def test_maximum_budget_is_frozen_reader_plus_one_eight_byte_read(self):
        result, calls, positions = self.tracked(modules=512, streams=128)
        self.assertEqual(result['gate'], 9)
        self.assertEqual(result['read_budget']['total_bytes'], 11870)
        self.assertEqual(result['read_budget']['maximum_bytes'], 11870)
        self.assertEqual(len(calls), 525)
        self.assertEqual(result['read_budget']['maximum_read_calls'], 525)
        self.assertEqual(calls[-1], (positions['context'] + 224, 8))
        self.assertEqual(result['read_budget']['request_context_bytes'], 8)

    def test_fixed_dump_role_and_alias_rejected_before_any_pread(self):
        self.tracked()
        (self.crashes / 'alias.dmp').symlink_to(self.crashes / 'synthetic.dmp')
        with mock.patch.object(reader.os, 'pread') as reads:
            for name in ('../synthetic.dmp', 'alias.dmp'):
                with self.subTest(name=name), self.assertRaises(reader.MetadataError):
                    reader.parse_dump(name)
            reads.assert_not_called()

    def test_original_sdk_r13_layout_syntax_only(self):
        source = r'''
#include <windows.h>
#include <cstddef>
static_assert(sizeof(CONTEXT)==1232);
static_assert(offsetof(CONTEXT,R13)==224);
static_assert(sizeof(((CONTEXT*)0)->R13)==8);
static_assert(CONTEXT_INTEGER==0x100002);
'''
        cpp = self.root / 'request_context_layout.cpp'
        cpp.write_text(source)
        sdk = PROJECT / 'toolchains/msvc-2022/Windows Kits/10/Include/10.0.26100.0'
        includes = [PROJECT / 'toolchains/msvc-2022/VC/Tools/MSVC/14.44.35207/include',
                    sdk / 'ucrt', sdk / 'shared', sdk / 'um']
        command = ['/opt/homebrew/opt/llvm/bin/clang-cl', '--target=x86_64-pc-windows-msvc', '/Zs', '/std:c++17',
                   *('/I' + str(path) for path in includes), '--', str(cpp)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=45)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(list(self.root.glob('*.obj')))


if __name__ == '__main__':
    unittest.main()
