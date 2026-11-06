"""Synthetic one-word leaf hypothesis only, never actual dump execution."""
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('minidump_leaf_caller', PROJECT / 'native/diagnostics/minidump_leaf_caller.py')
leaf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(leaf)


def synthetic(*, maximum=False, modules=None, tids=None, word=0x200001234):
    if maximum:
        module_rva, ex, system, thread_rva, context, stack = 1600, 57024, 57216, 57344, 82000, 84000
        modules = [(0x180000000, *leaf.EXPECTED_MODULE)] + [(0x200000000 + index * 0x1000, 0x100, 0, 0) for index in range(1, 512)]
        tids = [42] + list(range(100, 611))
        word = modules[1][0] + 0x44
    else:
        module_rva, ex, system, thread_rva, context, stack = 128, 512, 720, 832, 2048, 4096
        modules = [(0x180000000, *leaf.EXPECTED_MODULE), (0x200000000, 0x400000, 7, 8)] if modules is None else modules
        tids = [42, 43] if tids is None else tids
    entries = [(4, 4 + 108 * len(modules), module_rva), (6, 168, ex),
               (7, 56, system), (3, 4 + 48 * len(tids), thread_rva)]
    if maximum:
        entries += [(100 + index, 0, 0) for index in range(124)]
    data = bytearray(b'\xa5' * (stack + 128))
    struct.pack_into('<IIIIIIQ', data, 0, 0x504d444d, 0xa793, len(entries), 32, 0, 1793664000, 0)
    for index, entry in enumerate(entries):
        struct.pack_into('<III', data, 32 + index * 12, *entry)
    struct.pack_into('<I', data, module_rva, len(modules))
    for index, module in enumerate(modules):
        struct.pack_into('<QIII', data, module_rva + 4 + index * 108, *module)
    address = modules[0][0] + leaf.EXPECTED_RVA
    struct.pack_into('<I', data, ex, 42)
    struct.pack_into('<Q', data, ex + 24, address)
    struct.pack_into('<II', data, ex + 160, 1232, context)
    struct.pack_into('<H', data, system, 9)
    struct.pack_into('<I', data, context + 48, 0x100001)
    struct.pack_into('<Q', data, context + 152, 0x70000010)
    struct.pack_into('<Q', data, context + 248, address)
    struct.pack_into('<I', data, thread_rva, len(tids))
    for index, tid in enumerate(tids):
        struct.pack_into('<I', data, thread_rva + 4 + index * 48, tid)
    struct.pack_into('<QII', data, thread_rva + 4 + 24, 0x70000000, 64, stack)
    struct.pack_into('<Q', data, stack + 16, word)
    return data, {'module': module_rva, 'exception': ex, 'system': system,
                  'thread': thread_rva, 'context': context, 'stack': stack}


class LeafCallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.crashes = self.root.joinpath(*leaf._BASE.ROLE_PARTS)
        self.crashes.mkdir(parents=True)
        patch = mock.patch.object(leaf._BASE, 'ROOT', self.root)
        patch.start()
        self.addCleanup(patch.stop)

    def parse(self, data):
        (self.crashes / 'synthetic.dmp').write_bytes(data)
        original = os.pread
        with mock.patch.object(leaf.os, 'pread', wraps=original) as reads:
            result = leaf.parse_dump('synthetic.dmp')
        return result, [(call.args[2], call.args[1]) for call in reads.call_args_list]

    def assert_no_word(self, data, gate, paths):
        result, calls = self.parse(data)
        self.assertEqual(result['admission_gate'], gate)
        self.assertIsNone(result['possible_leaf_return_word'])
        self.assertIs(result['captured_stack_word_read'], False)
        self.assertNotIn((paths['stack'] + 16, 8), calls)
        return calls

    def test_exact_scoped_reads_one_word_and_no_raw_addresses_emitted(self):
        data, p = synthetic()
        result, calls = self.parse(data)
        self.assertEqual(calls, [(0, 32), (32, 48), (128, 4), (132, 20), (240, 20),
            (512, 4), (536, 8), (720, 2), (672, 8), (2096, 4), (2296, 8), (2200, 8),
            (832, 4), (836, 4), (884, 4), (860, 16), (4112, 8)])
        self.assertEqual(result['possible_leaf_return_word'], {'module_index': 1, 'rva': 0x1234})
        self.assertEqual(result['read_budget']['total_bytes'], 202)
        self.assertEqual(result['read_budget']['context_field_bytes'], 20)
        self.assertEqual(result['read_budget']['return_word_bytes'], 8)
        self.assertIs(result['captured_stack_word_read'], True)
        for key in ('whole_context_or_stack_read', 'raw_unknown_stack_words_persisted',
                    'live_leaf_code_verified', 'callstack_established',
                    'caller_or_file_or_pdb_identity_established', 'exception_cause_established'):
            self.assertIs(result[key], False)
        encoded = json.dumps(result)
        self.assertNotIn(str(0x70000010), encoded)
        self.assertNotIn(str(0x200001234), encoded)

    def test_exception_unique_tuple_and_rva_gate_precedes_context(self):
        data, p = synthetic()
        struct.pack_into('<I', data, p['module'] + 4 + 12, 7)
        calls = self.assert_no_word(data, 2, p)
        self.assertFalse(any(offset >= p['context'] for offset, _ in calls))
        data, p = synthetic()
        struct.pack_into('<Q', data, p['exception'] + 24, 0x180000000 + leaf.EXPECTED_RVA + 1)
        self.assert_no_word(data, 2, p)
        data, p = synthetic(modules=[(0x180000000, *leaf.EXPECTED_MODULE), (0x180000000, *leaf.EXPECTED_MODULE)])
        self.assert_no_word(data, 1, p)

    def test_arch_context_extent_and_control_flags_gates(self):
        for category in ('architecture', 'short_context', 'context_file_bound', 'context_alias', 'control_flags'):
            with self.subTest(category=category):
                data, p = synthetic()
                if category == 'architecture':
                    struct.pack_into('<H', data, p['system'], 0)
                    gate = 3
                elif category == 'short_context':
                    struct.pack_into('<I', data, p['exception'] + 160, 256)
                    gate = 4
                elif category == 'context_file_bound':
                    struct.pack_into('<I', data, p['exception'] + 164, len(data) - 8)
                    gate = 4
                elif category == 'context_alias':
                    struct.pack_into('<I', data, p['exception'] + 164, p['exception'])
                    gate = 4
                else:
                    struct.pack_into('<I', data, p['context'] + 48, 0x100000)
                    gate = 5
                calls = self.assert_no_word(data, gate, p)
                if gate in (3, 4):
                    self.assertFalse(any(offset >= p['context'] for offset, _ in calls))
        data, p = synthetic()
        struct.pack_into('<I', data, p['context'] + 48, 0x10101f)
        self.assertEqual(self.parse(data)[0]['admission_gate'], 10)

    def test_rip_and_aligned_rsp_before_thread_selection(self):
        for offset, value in ((248, 0), (152, 0x70000011), (152, 0xffffffffffffffff)):
            with self.subTest(offset=offset, value=value):
                data, p = synthetic()
                struct.pack_into('<Q', data, p['context'] + offset, value)
                calls = self.assert_no_word(data, 6, p)
                self.assertNotIn((p['thread'], 4), calls)

    def test_all_tids_before_single_selected_stack_descriptor(self):
        for tids in ([42, 42], [43, 44]):
            with self.subTest(tids=tids):
                data, p = synthetic(tids=tids)
                calls = self.assert_no_word(data, 7, p)
                self.assertIn((p['thread'] + 4 + 48, 4), calls)
                self.assertNotIn((p['thread'] + 4 + 24, 16), calls)
        for count in (513, 3):
            with self.subTest(count=count):
                data, p = synthetic()
                struct.pack_into('<I', data, p['thread'], count)
                calls = self.assert_no_word(data, 7, p)
                self.assertNotIn((p['thread'] + 4, 4), calls)

    def test_stack_full_file_extent_alias_and_virtual_bounds(self):
        for start, size, rva_kind in ((0x70000000, 16, 'normal'),
                                      (0x70000000, 64, 'outside'),
                                      (0x70000000, 64, 'stream'),
                                      (0x70000000, 64, 'context'),
                                      (0xfffffffffffffff8, 64, 'normal')):
            with self.subTest(size=size, rva_kind=rva_kind, start=start):
                data, p = synthetic()
                rva = {'normal': p['stack'], 'outside': len(data) - 4,
                       'stream': p['exception'], 'context': p['context']}[rva_kind]
                struct.pack_into('<QII', data, p['thread'] + 4 + 24, start, size, rva)
                self.assert_no_word(data, 8, p)

    def test_unmatched_or_ambiguous_word_is_read_once_but_not_persisted(self):
        for modules, word in ((None, 0xffffffffffffffff),
                ([(0x180000000, *leaf.EXPECTED_MODULE), (0x200000000, 0x400000, 7, 8),
                  (0x200001000, 0x1000, 9, 10)], 0x200001234)):
            with self.subTest(word=word):
                data, p = synthetic(modules=modules, word=word)
                result, calls = self.parse(data)
                self.assertEqual(result['admission_gate'], 9)
                self.assertIs(result['captured_stack_word_read'], True)
                self.assertIsNone(result['possible_leaf_return_word'])
                self.assertEqual(calls.count((p['stack'] + 16, 8)), 1)
                self.assertNotIn(str(word), json.dumps(result))

    def test_maximum_explicit_budget_and_old_reader_limits_not_mutated(self):
        data, _ = synthetic(maximum=True)
        result, calls = self.parse(data)
        self.assertEqual(result['admission_gate'], 10)
        self.assertEqual(result['read_budget']['total_bytes'], 13930)
        self.assertEqual(len(calls), 1037)
        self.assertEqual(leaf._LOCATION.MAX_READ_BYTES, 11844)
        self.assertEqual(leaf._LOCATION.MAX_READ_CALLS, 520)

    def test_original_sdk_layout_syntax_only(self):
        source = r'''
#include <windows.h>
#include <dbghelp.h>
#include <cstddef>
static_assert(sizeof(MINIDUMP_THREAD)==48);
static_assert(offsetof(MINIDUMP_THREAD_LIST,Threads)==4);
static_assert(offsetof(MINIDUMP_THREAD,ThreadId)==0);
static_assert(offsetof(MINIDUMP_THREAD,Stack)==24);
static_assert(sizeof(MINIDUMP_MEMORY_DESCRIPTOR)==16);
static_assert(offsetof(MINIDUMP_MEMORY_DESCRIPTOR,Memory)==8);
static_assert(offsetof(MINIDUMP_EXCEPTION_STREAM,ThreadContext)==160);
static_assert(sizeof(MINIDUMP_SYSTEM_INFO)==56);
static_assert(offsetof(MINIDUMP_SYSTEM_INFO,ProcessorArchitecture)==0);
static_assert(PROCESSOR_ARCHITECTURE_AMD64==9);
static_assert(sizeof(CONTEXT)==1232);
static_assert(offsetof(CONTEXT,ContextFlags)==48);
static_assert(offsetof(CONTEXT,Rsp)==152);
static_assert(offsetof(CONTEXT,Rip)==248);
static_assert(CONTEXT_CONTROL==0x100001);
'''
        cpp = self.root / 'leaf_layout.cpp'
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
