"""Bounded AV metadata from temporary synthetic dumps only."""
import importlib.util
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('minidump_av_metadata', PROJECT / 'native/diagnostics/minidump_av_metadata.py')
av = importlib.util.module_from_spec(spec)
spec.loader.exec_module(av)


def synthetic(*, code=0xc0000005, count=2, kind=1, address=0xdeed, entries=None, size=512):
    entries = [(6, 168, 128)] if entries is None else entries
    data = bytearray(b'\xa5' * size)
    struct.pack_into('<IIIIIIQ', data, 0, 0x504d444d, 0xa793, len(entries), 32 if entries else 0, 0, 1793664000, 0)
    for index, entry in enumerate(entries):
        struct.pack_into('<III', data, 32 + index * 12, *entry)
    for stream, length, rva in entries:
        if stream == 6 and length == 168 and rva >= 32 + 12 * len(entries) and rva + 168 <= size:
            struct.pack_into('<I', data, rva + 8, code)
            struct.pack_into('<I', data, rva + 32, count)
            struct.pack_into('<QQ', data, rva + 40, kind, address)
    return data


class AvMetadataTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.crashes = self.root.joinpath(*av._LOCATION._BASE.ROLE_PARTS)
        self.crashes.mkdir(parents=True)
        patch = mock.patch.object(av._LOCATION._BASE, 'ROOT', self.root)
        patch.start()
        self.addCleanup(patch.stop)

    def write(self, data):
        path = self.crashes / 'synthetic.dmp'
        path.write_bytes(data)
        return path

    def parse_tracked(self, **arguments):
        self.write(synthetic(**arguments))
        original = os.pread
        with mock.patch.object(av.os, 'pread', wraps=original) as reads:
            result = av.parse_dump('synthetic.dmp')
        return result, [(call.args[2], call.args[1]) for call in reads.call_args_list]

    def test_exact_slices_only_first_two_av_parameters(self):
        result, calls = self.parse_tracked()
        self.assertEqual(calls, [(0, 32), (32, 12), (136, 4), (160, 4), (168, 8), (176, 8)])
        self.assertEqual(result['exception_code'], 0xc0000005)
        self.assertEqual(result['number_parameters'], 2)
        self.assertEqual(result['access_kind'], 1)
        self.assertEqual(result['fault_address'], 0xdeed)
        self.assertIs(result['av_fields_admitted'], True)
        self.assertEqual(result['gate'], 4)
        self.assertEqual(result['read_budget']['total_bytes'], 68)
        self.assertEqual(result['read_budget']['av_field_bytes'], 24)
        self.assertIs(result['exception_cause_established'], False)
        self.assertIs(result['process_or_module_attribution_established'], False)

    def test_other_exception_code_never_reads_count_or_parameters(self):
        result, calls = self.parse_tracked(code=0x80000003)
        self.assertEqual(calls, [(0, 32), (32, 12), (136, 4)])
        self.assertEqual(result['gate'], 1)
        self.assertIsNone(result['number_parameters'])
        self.assertIsNone(result['fault_address'])

    def test_count_gate_precedes_both_parameter_reads(self):
        for count in (0, 1, 16, 0xffffffff):
            with self.subTest(count=count):
                result, calls = self.parse_tracked(count=count)
                self.assertEqual(calls, [(0, 32), (32, 12), (136, 4), (160, 4)])
                self.assertEqual(result['gate'], 2)
                self.assertEqual(result['number_parameters'], count)
                self.assertIsNone(result['access_kind'])
                self.assertIsNone(result['fault_address'])

    def test_kind_gate_precedes_fault_address_read(self):
        for kind in (2, 7, 0xffffffffffffffff):
            with self.subTest(kind=kind):
                result, calls = self.parse_tracked(kind=kind)
                self.assertEqual(calls[-1], (168, 8))
                self.assertEqual(len(calls), 5)
                self.assertEqual(result['gate'], 3)
                self.assertIsNone(result['access_kind'])
                self.assertIsNone(result['fault_address'])
        for kind in (0, 1, 8):
            with self.subTest(valid_kind=kind):
                result, calls = self.parse_tracked(kind=kind, count=15)
                self.assertEqual(result['access_kind'], kind)
                self.assertEqual(calls[-1], (176, 8))
                self.assertEqual(len(calls), 6)

    def test_bounds_overlap_and_exception_size_precede_fields(self):
        cases = [([(6, 167, 128)], 'exception_size'), ([(6, 168, 400)], 'stream_range'),
                 ([(6, 168, 128), (7, 8, 176)], 'selected_overlap')]
        for entries, reason in cases:
            with self.subTest(reason=reason):
                self.write(synthetic(entries=entries))
                original = os.pread
                with mock.patch.object(av.os, 'pread', wraps=original) as reads:
                    with self.assertRaises(av.MetadataError) as caught:
                        av.parse_dump('synthetic.dmp')
                self.assertEqual(caught.exception.reason, reason)
                self.assertEqual(reads.call_count, 2)

    def test_absent_exception_and_maximum_explicit_budget(self):
        result, calls = self.parse_tracked(entries=[])
        self.assertEqual(calls, [(0, 32)])
        self.assertEqual(result['gate'], 0)
        self.assertIsNone(result['exception_code'])
        entries = [(100 + index, 0, 0) for index in range(127)] + [(6, 168, 1568)]
        result, calls = self.parse_tracked(entries=entries, size=1736)
        self.assertEqual(result['read_budget']['total_bytes'], 1592)
        self.assertEqual(len(calls), 6)
        self.assertEqual(calls[-4:], [(1576, 4), (1600, 4), (1608, 8), (1616, 8)])

    def test_bound_role_and_file_stability_are_reused(self):
        path = self.write(synthetic())
        (self.crashes / 'alias.dmp').symlink_to(path)
        with mock.patch.object(av.os, 'pread') as reads:
            for name in ('../synthetic.dmp', 'alias.dmp'):
                with self.assertRaises(av.MetadataError):
                    av.parse_dump(name)
            reads.assert_not_called()
        original = os.pread
        def changed(fd, size, offset):
            data = original(fd, size, offset)
            if offset == 0:
                with path.open('r+b') as target:
                    target.seek(400)
                    target.write(b'changed')
            return data
        with mock.patch.object(av.os, 'pread', side_effect=changed):
            with self.assertRaises(av.MetadataError) as caught:
                av.parse_dump('synthetic.dmp')
        self.assertEqual(caught.exception.reason, 'input_changed')

    def test_original_sdk_parameter_layout_syntax_only(self):
        source = r'''
#include <windows.h>
#include <dbghelp.h>
#include <cstddef>
static_assert(sizeof(MINIDUMP_EXCEPTION_STREAM)==168);
static_assert(offsetof(MINIDUMP_EXCEPTION_STREAM,ExceptionRecord)+offsetof(MINIDUMP_EXCEPTION,ExceptionCode)==8);
static_assert(offsetof(MINIDUMP_EXCEPTION_STREAM,ExceptionRecord)+offsetof(MINIDUMP_EXCEPTION,NumberParameters)==32);
static_assert(offsetof(MINIDUMP_EXCEPTION_STREAM,ExceptionRecord)+offsetof(MINIDUMP_EXCEPTION,ExceptionInformation)==40);
static_assert(sizeof(((MINIDUMP_EXCEPTION*)0)->ExceptionInformation[0])==8);
static_assert(sizeof(((MINIDUMP_EXCEPTION*)0)->ExceptionInformation)/8==15);
static_assert(EXCEPTION_ACCESS_VIOLATION==0xc0000005);
'''
        cpp = self.root / 'av_layout.cpp'
        cpp.write_text(source)
        sdk = PROJECT / 'toolchains/msvc-2022/Windows Kits/10/Include/10.0.26100.0'
        includes = [PROJECT / 'toolchains/msvc-2022/VC/Tools/MSVC/14.44.35207/include',
                    sdk / 'ucrt', sdk / 'shared', sdk / 'um']
        command = ['/opt/homebrew/opt/llvm/bin/clang-cl', '--target=x86_64-pc-windows-msvc', '/Zs', '/std:c++17',
                   *('/I' + str(path) for path in includes), '--', str(cpp)]
        checked = subprocess.run(command, capture_output=True, text=True, timeout=45)
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertEqual(list(self.root.glob('*.obj')), [])


if __name__ == '__main__':
    unittest.main()
