"""Synthetic numeric MDMPs only; no real crash enumeration/reads or dump hashes."""
import importlib.util
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('minidump_numeric_location', PROJECT / 'native/diagnostics/minidump_numeric_location.py')
location = importlib.util.module_from_spec(spec)
spec.loader.exec_module(location)


def synthetic(modules=None, *, flags=1, info_size=24, misc_size=24, misc=True, exception=True,
              address=0x1803203b0, extra_entries=()):
    modules = [(0x1000, 0x100, 9, 1), (0x180000000, 0x400000, 13, 2)] if modules is None else modules
    module_rva, module_size = 256, 4 + 108 * len(modules)
    exception_rva = max(1024, module_rva + module_size + 64)
    entries = ([(15, misc_size, 128)] if misc else []) + [(4, module_size, module_rva)]
    entries += [(6, 168, exception_rva)] if exception else []
    entries += list(extra_entries)
    data = bytearray(b'\xa5' * (exception_rva + 200))
    struct.pack_into('<IIIIIIQ', data, 0, 0x504d444d, 0xbeefa793, len(entries), 32, 0, 1793664000, 0)
    for index, entry in enumerate(entries):
        struct.pack_into('<III', data, 32 + index * 12, *entry)
    if misc:
        struct.pack_into('<III', data, 128, info_size, flags, 1776)
    struct.pack_into('<I', data, module_rva, len(modules))
    for index, module in enumerate(modules):
        struct.pack_into('<QIII', data, module_rva + 4 + index * 108, *module)
    if exception:
        struct.pack_into('<I', data, exception_rva, 42)
        struct.pack_into('<II', data, exception_rva + 8, 0xc0000005, 0)
        struct.pack_into('<Q', data, exception_rva + 24, address)
    return data, entries


class NumericLocationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.crashes = self.root.joinpath(*location._BASE.ROLE_PARTS)
        self.crashes.mkdir(parents=True)
        patch = mock.patch.object(location._BASE, 'ROOT', self.root)
        patch.start()
        self.addCleanup(patch.stop)

    def write(self, data):
        path = self.crashes / 'synthetic.dmp'
        path.write_bytes(data)
        return path

    def parse(self, **kwargs):
        data, entries = synthetic(**kwargs)
        self.write(data)
        return location.parse_dump('synthetic.dmp'), entries

    def assert_bad(self, data, reason):
        self.write(data)
        with self.assertRaises(location.MetadataError) as caught:
            location.parse_dump('synthetic.dmp')
        self.assertEqual(caught.exception.reason, reason)

    def test_exact_disjoint_slices_and_anonymous_unique_rva(self):
        data, entries = synthetic()
        self.write(data)
        original, calls = os.pread, []
        def tracked(fd, size, offset):
            calls.append((offset, size))
            return original(fd, size, offset)
        with mock.patch.object(location.os, 'pread', side_effect=tracked):
            result = location.parse_dump('synthetic.dmp')
        ex = entries[2][2]
        self.assertEqual(calls, [(0, 32), (32, 36), (128, 8), (136, 4), (256, 4),
                                 (260, 20), (368, 20), (ex, 4), (ex + 8, 8), (ex + 24, 8)])
        self.assertEqual(result['misc_info'], {'size_of_info': 24, 'flags1': 1, 'process_id': 1776})
        self.assertEqual(result['exception_module'], {'candidate_count': 1, 'unique': True, 'module_index': 1, 'rva': 0x3203b0})
        self.assertEqual(result['modules'][1], {'index': 1, 'base': 0x180000000, 'size': 0x400000, 'checksum': 13, 'pe_timestamp': 2})
        self.assertEqual(result['read_budget']['total_bytes'], 144)
        for key in ('declared_process_id_verified_against_runtime', 'module_file_or_pdb_identity_established',
                    'timestamp_is_run_identifier_claim', 'thread_id_is_process_id_claim', 'exception_cause_established'):
            self.assertIs(result[key], False)

    def test_pid_read_requires_flag_and_valid_full_base_layout(self):
        original = os.pread
        data, _ = synthetic(flags=2, info_size=44, misc_size=44)
        self.write(data)
        with mock.patch.object(location.os, 'pread', wraps=original) as reads:
            result = location.parse_dump('synthetic.dmp')
        self.assertIsNone(result['misc_info']['process_id'])
        self.assertNotIn((136, 4), [(c.args[2], c.args[1]) for c in reads.call_args_list])
        for arguments in ({'misc_size': 23}, {'info_size': 23}, {'info_size': 25}):
            with self.subTest(arguments=arguments):
                data, _ = synthetic(**arguments)
                with mock.patch.object(location.os, 'pread', wraps=original) as reads:
                    self.assert_bad(data, 'misc_size')
                self.assertNotIn((136, 4), [(c.args[2], c.args[1]) for c in reads.call_args_list])

    def test_missing_optional_streams_zero_modules_and_no_exception(self):
        result, _ = self.parse(modules=[], misc=False, exception=False)
        self.assertIsNone(result['misc_info'])
        self.assertIsNone(result['exception'])
        self.assertEqual(result['modules'], [])
        self.assertEqual(result['exception_module']['candidate_count'], 0)
        self.assertEqual(result['read_budget']['total_bytes'], 48)
        data = bytearray(32)
        struct.pack_into('<IIIIIIQ', data, 0, 0x504d444d, 0xa793, 0, 0, 0, 0, 0)
        self.write(data)
        self.assertIs(location.parse_dump('synthetic.dmp')['module_list_present'], False)

    def test_ambiguous_ranges_and_endpoint_exclusion_never_select_module(self):
        for modules, address, expected in (([(0x1000, 0x100, 0, 0), (0x1080, 0x100, 0, 0)], 0x1090, 2),
                                            ([(0x1000, 0x100, 0, 0)], 0x1100, 0),
                                            ([(0x1000, 0, 0, 0)], 0x1000, 0)):
            with self.subTest(modules=modules):
                result, _ = self.parse(modules=modules, address=address)
                self.assertEqual(result['exception_module'], {'candidate_count': expected, 'unique': False, 'module_index': None, 'rva': None})

    def test_address_range_never_wraps_u64(self):
        data, _ = synthetic(modules=[((1 << 64) - 8, 16, 0, 0)])
        self.assert_bad(data, 'module_address_range')
        result, _ = self.parse(modules=[((1 << 64) - 16, 16, 0, 0)], address=(1 << 64) - 1)
        self.assertEqual(result['exception_module']['rva'], 15)

    def test_all_declared_ranges_and_selected_overlaps_precede_payload(self):
        original = os.pread
        for extra, reason in (([(7, 4, 129)], 'selected_overlap'), ([(7, 999999, 500)], 'stream_range'),
                              ([(15, 24, 600)], 'duplicate_selected')):
            with self.subTest(reason=reason):
                data, _ = synthetic(extra_entries=extra)
                with mock.patch.object(location.os, 'pread', wraps=original) as reads:
                    self.assert_bad(data, reason)
                self.assertEqual(reads.call_count, 2)

    def test_count_cap_and_stride_extent_before_any_module_prefix(self):
        original = os.pread
        for count, reason in ((513, 'module_count'), (3, 'module_size')):
            with self.subTest(count=count):
                data, _ = synthetic()
                struct.pack_into('<I', data, 256, count)
                with mock.patch.object(location.os, 'pread', wraps=original) as reads:
                    self.assert_bad(data, reason)
                self.assertFalse(any(c.args[1] == 20 for c in reads.call_args_list))

    def test_maximum_stream_and_module_counts_have_fixed_budget(self):
        module_count = 512
        misc_rva, module_rva = 1568, 1592
        module_size = 4 + module_count * 108
        ex_rva = module_rva + module_size
        data = bytearray(b'\xa5' * (ex_rva + 168))
        entries = [(15, 24, misc_rva), (4, module_size, module_rva), (6, 168, ex_rva)] + [(100 + index, 0, 0) for index in range(125)]
        struct.pack_into('<IIIIIIQ', data, 0, 0x504d444d, 0xa793, 128, 32, 0, 0, 0)
        for index, entry in enumerate(entries):
            struct.pack_into('<III', data, 32 + 12 * index, *entry)
        struct.pack_into('<III', data, misc_rva, 24, 1, 77)
        struct.pack_into('<I', data, module_rva, module_count)
        for index in range(module_count):
            struct.pack_into('<QIII', data, module_rva + 4 + index * 108, index * 0x1000, 0x100, 0, 0)
        self.write(data)
        result = location.parse_dump('synthetic.dmp')
        self.assertEqual(result['read_budget']['total_bytes'], 11844)
        self.assertEqual(result['read_budget']['read_calls'], 520)

    def test_frozen_binding_rejects_links_and_changed_dump(self):
        data, _ = synthetic()
        path = self.write(data)
        alias = self.crashes / 'alias.dmp'
        alias.symlink_to(path)
        with mock.patch.object(location.os, 'pread') as reads:
            with self.assertRaises(location.MetadataError):
                location.parse_dump('alias.dmp')
            reads.assert_not_called()
        original = os.pread
        def changed(fd, size, offset):
            result = original(fd, size, offset)
            if offset == 0:
                with path.open('r+b') as target:
                    target.seek(100)
                    target.write(b'changed')
            return result
        with mock.patch.object(location.os, 'pread', side_effect=changed):
            with self.assertRaises(location.MetadataError) as caught:
                location.parse_dump('synthetic.dmp')
        self.assertEqual(caught.exception.reason, 'input_changed')

    def test_original_sdk_misc_and_module_layout_syntax_only(self):
        source = r'''
#include <windows.h>
#include <dbghelp.h>
#include <cstddef>
static_assert(alignof(MINIDUMP_MODULE)==4);
static_assert(sizeof(MINIDUMP_MODULE)==108);
static_assert(offsetof(MINIDUMP_MODULE_LIST,Modules)==4);
static_assert(offsetof(MINIDUMP_MODULE,BaseOfImage)==0);
static_assert(offsetof(MINIDUMP_MODULE,SizeOfImage)==8);
static_assert(offsetof(MINIDUMP_MODULE,CheckSum)==12);
static_assert(offsetof(MINIDUMP_MODULE,TimeDateStamp)==16);
static_assert(offsetof(MINIDUMP_MODULE,ModuleNameRva)==20);
static_assert(sizeof(MINIDUMP_MISC_INFO)==24);
static_assert(sizeof(MINIDUMP_MISC_INFO_2)==44);
static_assert(offsetof(MINIDUMP_MISC_INFO,SizeOfInfo)==0);
static_assert(offsetof(MINIDUMP_MISC_INFO,Flags1)==4);
static_assert(offsetof(MINIDUMP_MISC_INFO,ProcessId)==8);
static_assert(MINIDUMP_MISC1_PROCESS_ID==1);
static_assert(ModuleListStream==4 && MiscInfoStream==15);
'''
        cpp = self.root / 'numeric_layout.cpp'
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
