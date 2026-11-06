"""Temporary synthetic capture descriptors; no real dumps or memory scans."""
import importlib.util
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest import mock

import test_minidump_swapchain_result as fixtures

PROJECT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('minidump_swapchain_inputs', PROJECT / 'native/diagnostics/minidump_swapchain_inputs.py')
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)


def synthetic(*, kind=5, hwnd=0, device=0xabc, ambiguous=False, alias=False, missing=False,
              modules=2, streams=6, maximum=False, **kwargs):
    raw, p = fixtures.synthetic(modules=modules, streams=streams, **kwargs)
    if modules > 1:
        struct.pack_into('<QIII', raw, p['mod'] + 4, 0x100000000, *reader.PROVIDER_TUPLES['dxmt_dxgi'])
    rdi, r12, r14 = 0x100001234, 0x333330000, 0x222220000
    for offset, value in ((176, rdi), (216, r12), (232, r14)):
        struct.pack_into('<Q', raw, p['context'] + offset, value)
    if missing:
        return raw, p, []
    table = len(raw)
    thread_count, mem_count, mem64_count = (512, 512, 512) if maximum else (0, 0, 0)
    if maximum:
        table_sizes = [4 + 48 * thread_count, 4 + 16 * mem_count, 16 + 16 * mem64_count]
    else:
        count = 3 if ambiguous else 2
        table_sizes = [16 + 16 * count if kind == 9 else 4 + (48 if kind == 3 else 16) * count]
    data_at = table + sum(table_sizes) + 64
    raw.extend(b'\xa5' * (data_at + 32 - len(raw)))
    struct.pack_into('<QQQ', raw, data_at, hwnd, device, 0x7777)
    captures = [(r14 + 0x30, 8, p['context'] if alias else data_at), (r12, 8, data_at + 8)]
    if ambiguous: captures.append((r12, 8, data_at + 16))
    if maximum:
        for index, (stream_kind, count, size) in enumerate(zip((3, 5, 9), (thread_count, mem_count, mem64_count), table_sizes)):
            struct.pack_into('<III', raw, 32 + (3 + index) * 12, stream_kind, size, table)
            if stream_kind == 9: struct.pack_into('<QQ', raw, table, count, data_at + 24)
            else: struct.pack_into('<I', raw, table, count)
            for i in range(count):
                if stream_kind == 3: struct.pack_into('<QII', raw, table + 4 + i * 48 + 24, *captures[0])
                elif stream_kind == 5: struct.pack_into('<QII', raw, table + 4 + i * 16, *captures[1])
                else: struct.pack_into('<QQ', raw, table + 16 + i * 16, 0, 0)
            table += size
    else:
        struct.pack_into('<III', raw, 32 + 3 * 12, kind, table_sizes[0], table)
        if kind == 9: struct.pack_into('<QQ', raw, table, len(captures), data_at)
        else: struct.pack_into('<I', raw, table, len(captures))
        for i, (base, size, offset) in enumerate(captures):
            if kind == 9: struct.pack_into('<QQ', raw, table + 16 + i * 16, base, size)
            else: struct.pack_into('<QII', raw, table + 4 + i * (48 if kind == 3 else 16) + (24 if kind == 3 else 0), base, size, offset)
    p.update(data=data_at, table=len(raw) if missing else len(fixtures.synthetic(modules=modules, streams=streams, **kwargs)[0]))
    return raw, p, captures


class SwapchainInputsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.crashes = self.root.joinpath(*reader._BASE.ROLE_PARTS);self.crashes.mkdir(parents=True)
        patch = mock.patch.object(reader._BASE, 'ROOT', self.root);patch.start();self.addCleanup(patch.stop)

    def tracked(self, **kwargs):
        raw, positions, captures = synthetic(**kwargs)
        (self.crashes / 'synthetic.dmp').write_bytes(raw)
        with mock.patch.object(reader.os, 'pread', wraps=os.pread) as reads:
            result = reader.parse_dump('synthetic.dmp')
        return result, [(call.args[2], call.args[1]) for call in reads.call_args_list], positions, captures

    def test_exact_register_and_two_scalar_slices_with_redacted_output(self):
        result, calls, p, _ = self.tracked()
        self.assertEqual(result['gate'], 9)
        self.assertEqual(result['callee']['provider_tuple_hint'], 'dxmt_dxgi')
        self.assertEqual(result['callee']['module_index'], 0)
        self.assertEqual(result['callee']['rva'], 0x1234)
        self.assertEqual(result['hwnd_argument'], {'available': True, 'is_null': True, 'reason': None})
        self.assertEqual(result['device_argument'], {'available': True, 'is_null': False, 'reason': None})
        self.assertEqual(calls[-2:], [(p['data'], 8), (p['data'] + 8, 8)])
        self.assertEqual(result['read_budget']['input_context_bytes'], 24)
        self.assertEqual(result['read_budget']['context_field_bytes'], 16)
        self.assertEqual(result['read_budget']['input_scalar_bytes'], 16)
        self.assertTrue(all((p['context'] + at, 8) in calls for at in (176, 216, 232)))
        self.assertNotIn('8589939252', repr(result))
        self.assertNotIn('333330000', repr(result))

    def test_each_supported_capture_table_reads_only_two_words(self):
        for kind in (3, 5, 9):
            with self.subTest(kind=kind):
                result, _, _, _ = self.tracked(kind=kind, hwnd=0x11, device=0)
                self.assertFalse(result['hwnd_argument']['is_null'])
                self.assertTrue(result['device_argument']['is_null'])
                self.assertEqual(result['read_budget']['input_scalar_bytes'], 16)

    def test_missing_ambiguous_and_context_alias_are_explicitly_unavailable(self):
        for kwargs, reason in (({'missing': True}, 'not_captured'),
                               ({'ambiguous': True}, 'ambiguous_capture'),
                               ({'alias': True}, 'invalid_memory_capture')):
            with self.subTest(kwargs=kwargs):
                result, calls, p, _ = self.tracked(**kwargs)
                target = result['device_argument'] if 'ambiguous' in kwargs else result['hwnd_argument']
                self.assertFalse(target['available']);self.assertIsNone(target['is_null'])
                self.assertEqual(target['reason'], reason)
                if 'alias' in kwargs:
                    self.assertEqual(result['read_budget']['input_scalar_bytes'], 0)

    def test_wrong_base_gates_never_read_added_registers_or_capture_tables(self):
        for kwargs in ({'rva': 0x3e057}, {'access': 1}, {'flags': 0x100001}, {'rip_delta': 1}, {'context_size': 1231}):
            with self.subTest(kwargs=kwargs):
                result, calls, p, _ = self.tracked(**kwargs)
                self.assertLess(result['gate'], 9)
                self.assertEqual(result['read_budget']['input_context_bytes'], 0)
                self.assertEqual(result['read_budget']['memory_descriptor_bytes'], 0)
                self.assertEqual(result['read_budget']['input_scalar_bytes'], 0)
                self.assertFalse(any((p['context'] + at, 8) in calls for at in (176, 216, 232)))

    def test_callee_unknown_or_multiple_ranges_does_not_emit_raw_register(self):
        raw, p, _ = synthetic()
        struct.pack_into('<Q', raw, p['context'] + 176, 0xdead123456789abc)
        (self.crashes / 'synthetic.dmp').write_bytes(raw)
        result = reader.parse_dump('synthetic.dmp')
        self.assertEqual(result['callee']['candidate_count'], 0)
        self.assertIsNone(result['callee']['rva'])
        self.assertNotIn('dead1234', repr(result))
        raw, p, _ = synthetic(modules=3)
        struct.pack_into('<QIII', raw, p['mod'] + 4 + 108, 0x100000000, *reader.PROVIDER_TUPLES['dxmt_dxgi'])
        (self.crashes / 'synthetic.dmp').write_bytes(raw)
        result = reader.parse_dump('synthetic.dmp')
        self.assertEqual(result['gate'], 9)
        self.assertEqual(result['callee']['candidate_count'], 2)
        self.assertIsNone(result['callee']['module_index'])
        self.assertIsNone(result['callee']['provider_tuple_hint'])

    def test_argument_pointer_overflow_never_reads_a_scalar(self):
        raw, p, _ = synthetic()
        for offset in (216, 232):
            struct.pack_into('<Q', raw, p['context'] + offset, 0xffffffffffffffff)
        (self.crashes / 'synthetic.dmp').write_bytes(raw)
        result = reader.parse_dump('synthetic.dmp')
        self.assertEqual(result['hwnd_argument']['reason'], 'invalid_pointer')
        self.assertEqual(result['device_argument']['reason'], 'invalid_pointer')
        self.assertEqual(result['read_budget']['input_scalar_bytes'], 0)

    def test_metadata_limits_and_maximum_budget(self):
        result, calls, _, _ = self.tracked(maximum=True, modules=512, streams=128)
        self.assertEqual(result['read_budget']['total_bytes'], 36502)
        self.assertEqual(len(calls), 2068)
        self.assertTrue(result['hwnd_argument']['available'])
        self.assertTrue(result['device_argument']['available'])
        raw, p, _ = synthetic()
        struct.pack_into('<I', raw, p['table'], 1025)
        (self.crashes / 'synthetic.dmp').write_bytes(raw)
        result = reader.parse_dump('synthetic.dmp')
        self.assertEqual(result['device_argument']['reason'], 'memory_metadata_limit')
        self.assertEqual(result['read_budget']['input_scalar_bytes'], 0)

    def test_original_sdk_offsets_syntax_only(self):
        cpp = self.root / 'input_layout.cpp'
        cpp.write_text('#include <windows.h>\n#include <cstddef>\n'
            'static_assert(offsetof(CONTEXT,Rdi)==176);\nstatic_assert(offsetof(CONTEXT,R12)==216);\n'
            'static_assert(offsetof(CONTEXT,R14)==232);\nstatic_assert(sizeof(((CONTEXT*)0)->Rdi)==8);\n')
        sdk = PROJECT / 'toolchains/msvc-2022/Windows Kits/10/Include/10.0.26100.0'
        includes = [PROJECT / 'toolchains/msvc-2022/VC/Tools/MSVC/14.44.35207/include', sdk / 'ucrt', sdk / 'shared', sdk / 'um']
        command = ['/opt/homebrew/opt/llvm/bin/clang-cl', '--target=x86_64-pc-windows-msvc', '/Zs', '/std:c++17',
            *('/I' + str(path) for path in includes), '--', str(cpp)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=45)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(list(self.root.glob('*.obj')), [])


if __name__ == '__main__':
    unittest.main()
