"""Only synthetic temporary MDMPs; never enumerate or open real crash files."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('minidump_metadata', PROJECT / 'native/diagnostics/minidump_metadata.py')
metadata = importlib.util.module_from_spec(spec)
spec.loader.exec_module(metadata)


def synthetic(entries=None, *, version=0xa793, size=512):
    entries = [(6, 168, 128)] if entries is None else entries
    data = bytearray(b'\xa5' * size)
    struct.pack_into('<IIIIIIQ', data, 0, 0x504d444d, version, len(entries), 32 if entries else 0, 0, 1793664000, 0)
    for index, item in enumerate(entries):
        struct.pack_into('<III', data, 32 + 12 * index, *item)
    for kind, length, rva in entries:
        if kind == 6 and length == 168 and rva >= 32 + 12 * len(entries) and rva + 168 <= size:
            struct.pack_into('<I', data, rva, 42)
            struct.pack_into('<II', data, rva + 8, 0xc0000005, 1)
            struct.pack_into('<Q', data, rva + 24, 0x1803203b0)
    return data


class MetadataTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.crashes = self.root.joinpath(*metadata.ROLE_PARTS)
        self.crashes.mkdir(parents=True)
        self.patch = mock.patch.object(metadata, 'ROOT', self.root)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def write(self, data, name='synthetic.dmp'):
        path = self.crashes / name
        path.write_bytes(data)
        return path

    def assert_rejected(self, data, reason):
        self.write(data)
        with self.assertRaises(metadata.MetadataError) as caught:
            metadata.parse_dump('synthetic.dmp')
        self.assertEqual(caught.exception.reason, reason)

    def test_exact_read_ranges_skip_all_parameters_context_and_memory(self):
        self.write(synthetic())
        original = os.pread
        calls = []
        def tracked(fd, size, offset):
            calls.append((offset, size))
            return original(fd, size, offset)
        with mock.patch.object(metadata.os, 'pread', side_effect=tracked):
            result = metadata.parse_dump('synthetic.dmp')
        self.assertEqual(calls, [(0, 32), (32, 12), (128, 4), (136, 8), (152, 8)])
        self.assertEqual(result['exception'], {'code': 0xc0000005, 'flags': 1, 'address': 0x1803203b0, 'thread_id': 42})
        self.assertEqual(result['read_budget']['total_bytes'], 64)
        self.assertEqual(result['read_budget']['exception_field_bytes'], 20)
        self.assertEqual(result['header_time_unix'], 1793664000)
        self.assertNotIn('synthetic', json.dumps(result))
        for key in ('process_or_module_attribution_established', 'thread_id_is_process_id_claim',
                    'timestamp_is_run_identifier_claim', 'exception_cause_established'):
            self.assertIs(result[key], False)

    def test_version_high_bits_are_implementation_specific(self):
        self.write(synthetic(version=0xbeefa793))
        self.assertEqual(metadata.parse_dump('synthetic.dmp')['exception']['thread_id'], 42)

    def test_missing_exception_never_reads_other_stream_payload(self):
        self.write(synthetic([(4, 128, 128)]))
        original = os.pread
        with mock.patch.object(metadata.os, 'pread', wraps=original) as reads:
            result = metadata.parse_dump('synthetic.dmp')
        self.assertIsNone(result['exception'])
        self.assertEqual([(c.args[2], c.args[1]) for c in reads.call_args_list], [(0, 32), (32, 12)])
        self.write(synthetic([]))
        self.assertEqual(metadata.parse_dump('synthetic.dmp')['read_budget']['total_bytes'], 32)

    def test_maximum_directory_stays_within_fixed_budget(self):
        entries = [(100 + index, 0, 0) for index in range(127)] + [(6, 168, 1568)]
        self.write(synthetic(entries, size=1736))
        result = metadata.parse_dump('synthetic.dmp')
        self.assertEqual(result['read_budget']['total_bytes'], 1588)
        self.assertEqual(result['read_budget']['read_calls'], 5)

    def test_invalid_header_and_directory_ranges(self):
        for offset, value, reason in ((0, 0, 'signature'), (4, 0, 'version'),
                                      (8, 129, 'stream_count'), (12, 8, 'directory_range'),
                                      (12, 508, 'directory_range')):
            with self.subTest(reason=reason, value=value):
                data = synthetic()
                struct.pack_into('<I', data, offset, value)
                self.assert_rejected(data, reason)

    def test_invalid_streams_rejected_before_any_exception_fields(self):
        cases = [([(6, 168, 400)], 'stream_range'), ([(6, 168, 32)], 'stream_range'),
                 ([(6, 167, 128)], 'exception_size'),
                 ([(6, 168, 128), (6, 168, 300)], 'duplicate_exception'),
                 ([(6, 168, 128), (4, 16, 200)], 'exception_overlap')]
        original = os.pread
        for entries, reason in cases:
            with self.subTest(reason=reason):
                with mock.patch.object(metadata.os, 'pread', wraps=original) as reads:
                    self.assert_rejected(synthetic(entries), reason)
                self.assertEqual(reads.call_count, 2)

    def test_filename_role_is_admitted_before_open(self):
        for name in ('../synthetic.dmp', '/tmp/synthetic.dmp', 'synthetic.zip', '.dmp', 'a.dmp/x', 7):
            with self.subTest(name=name), mock.patch.object(metadata.os, 'open') as opened:
                with self.assertRaises(metadata.MetadataError) as caught:
                    metadata.parse_dump(name)
                self.assertEqual(caught.exception.reason, 'filename')
                opened.assert_not_called()

    def test_symlink_hardlink_and_special_files_are_not_read(self):
        original = self.write(synthetic(), 'original.dmp')
        (self.crashes / 'alias.dmp').symlink_to(original)
        os.link(original, self.crashes / 'hard.dmp')
        os.mkfifo(self.crashes / 'fifo.dmp')
        for name in ('alias.dmp', 'hard.dmp', 'fifo.dmp'):
            with self.subTest(name=name), mock.patch.object(metadata.os, 'pread') as reads:
                with self.assertRaises(metadata.MetadataError):
                    metadata.parse_dump(name)
                reads.assert_not_called()

    def test_directory_symlink_is_not_followed(self):
        self.write(synthetic())
        renamed = self.crashes.with_name('real-crashes')
        self.crashes.rename(renamed)
        self.crashes.symlink_to(renamed, target_is_directory=True)
        with mock.patch.object(metadata.os, 'pread') as reads:
            with self.assertRaises(metadata.MetadataError):
                metadata.parse_dump('synthetic.dmp')
            reads.assert_not_called()

    def test_input_change_or_replacement_prevents_output(self):
        original = os.pread
        for replace in (False, True):
            with self.subTest(replace=replace):
                path = self.write(synthetic())
                triggered = False
                def changed(fd, size, offset):
                    nonlocal triggered
                    data = original(fd, size, offset)
                    if not triggered:
                        triggered = True
                        if replace:
                            path.rename(self.crashes / 'previous.dmp')
                            self.write(synthetic())
                        else:
                            with path.open('r+b') as target:
                                target.seek(400)
                                target.write(b'changed')
                    return data
                with mock.patch.object(metadata.os, 'pread', side_effect=changed):
                    with self.assertRaises(metadata.MetadataError) as caught:
                        metadata.parse_dump('synthetic.dmp')
                self.assertEqual(caught.exception.reason, 'input_changed')

    def test_short_read_and_cli_error_have_no_raw_fields(self):
        self.write(synthetic())
        with mock.patch.object(metadata.os, 'pread', return_value=b''):
            with self.assertRaises(metadata.MetadataError) as caught:
                metadata.parse_dump('synthetic.dmp')
        self.assertEqual(caught.exception.reason, 'short_read')
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = metadata.main(['../private.dmp'])
        self.assertEqual(status, 1)
        self.assertEqual(json.loads(output.getvalue()), {'ok': False, 'error_code': 1})

    def test_original_sdk_layout_syntax_only(self):
        source = r'''
#include <windows.h>
#include <dbghelp.h>
#include <cstddef>
static_assert(sizeof(MINIDUMP_HEADER)==32);
static_assert(offsetof(MINIDUMP_HEADER,TimeDateStamp)==20);
static_assert(sizeof(MINIDUMP_DIRECTORY)==12);
static_assert(offsetof(MINIDUMP_DIRECTORY,Location)==4);
static_assert(sizeof(MINIDUMP_EXCEPTION)==152);
static_assert(sizeof(MINIDUMP_EXCEPTION_STREAM)==168);
static_assert(offsetof(MINIDUMP_EXCEPTION_STREAM,ThreadId)==0);
static_assert(offsetof(MINIDUMP_EXCEPTION_STREAM,ExceptionRecord)+offsetof(MINIDUMP_EXCEPTION,ExceptionCode)==8);
static_assert(offsetof(MINIDUMP_EXCEPTION_STREAM,ExceptionRecord)+offsetof(MINIDUMP_EXCEPTION,ExceptionFlags)==12);
static_assert(offsetof(MINIDUMP_EXCEPTION_STREAM,ExceptionRecord)+offsetof(MINIDUMP_EXCEPTION,ExceptionAddress)==24);
static_assert(offsetof(MINIDUMP_EXCEPTION_STREAM,ThreadContext)==160);
static_assert(MINIDUMP_SIGNATURE==0x504d444d);
static_assert((MINIDUMP_VERSION&0xffff)==0xa793);
static_assert(ExceptionStream==6);
'''
        cpp = self.root / 'sdk_layout.cpp'
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
