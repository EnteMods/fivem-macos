"""Synthetic fixed-role exception contexts only; no actual crash dumps."""
import importlib.util
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('minidump_swapchain_result', PROJECT / 'native/diagnostics/minidump_swapchain_result.py')
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)


def synthetic(*, code=0xc0000005, count=2, access=0, module_tuple=None, rva=0x3e056,
              arch=9, context_size=1232, flags=0x100003, rip_delta=0, rax=0xdeadbeef887a0001,
              modules=1, streams=3, overlap=False, context_alias=False):
    align = lambda value, step: (value + step - 1) // step * step
    ex = max(128, align(32 + streams * 12, 32))
    mod = ex + 192
    system = align(mod + 4 + modules * 108, 64)
    context = system + 64
    size = context + 1232 + 64
    data = bytearray(b'\xa5' * size)
    entries = [(6, 168, ex), (4, 4 + modules * 108, mod), (7, 56, system)]
    entries += [(1000 + index, 0, 0) for index in range(streams - 3)]
    struct.pack_into('<IIIIIIQ', data, 0, 0x504d444d, 0xa793, len(entries), 32, 0, 1793664000, 0)
    for index, entry in enumerate(entries): struct.pack_into('<III', data, 32 + index * 12, *entry)
    struct.pack_into('<I', data, mod, modules)
    module_tuple = reader.EXPECTED_MODULE if module_tuple is None else module_tuple
    base = 0x100000000 + (modules - 1) * 0x200000
    for index in range(modules):
        current = base if overlap else 0x100000000 + index * 0x200000
        struct.pack_into('<QIII', data, mod + 4 + index * 108, current, *module_tuple)
    struct.pack_into('<I', data, ex + 8, code)
    struct.pack_into('<I', data, ex + 32, count)
    struct.pack_into('<Q', data, ex + 40, access)
    struct.pack_into('<Q', data, ex + 24, base + rva)
    struct.pack_into('<II', data, ex + 160, context_size, ex if context_alias else context)
    struct.pack_into('<H', data, system, arch)
    struct.pack_into('<I', data, context + 48, flags)
    struct.pack_into('<Q', data, context + 248, base + rva + rip_delta)
    struct.pack_into('<Q', data, context + 120, rax)
    return data, {'ex': ex, 'mod': mod, 'system': system, 'context': context}


class SwapchainResultTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.crashes = self.root.joinpath(*reader._BASE.ROLE_PARTS)
        self.crashes.mkdir(parents=True)
        patch = mock.patch.object(reader._BASE, 'ROOT', self.root)
        patch.start();self.addCleanup(patch.stop)

    def write(self, raw):
        path = self.crashes / 'synthetic.dmp'
        path.write_bytes(raw)
        return path

    def tracked(self, **kwargs):
        raw, locations = synthetic(**kwargs)
        self.write(raw)
        with mock.patch.object(reader.os, 'pread', wraps=os.pread) as reads:
            result = reader.parse_dump('synthetic.dmp')
        return result, [(call.args[2], call.args[1]) for call in reads.call_args_list], locations

    def test_exact_slices_include_only_low_four_rax_bytes_after_all_gates(self):
        result, calls, _ = self.tracked()
        self.assertEqual(calls, [(0, 32), (32, 36), (136, 4), (160, 4), (168, 8),
            (320, 4), (324, 20), (152, 8), (448, 2), (288, 8), (560, 4), (760, 8), (632, 4)])
        self.assertEqual(result['gate'], 9)
        self.assertTrue(result['register_value_admitted'])
        self.assertEqual(result['captured_rax_low32'], 0x887a0001)
        self.assertEqual(result['candidate_hresult_hex'], '0x887a0001')
        self.assertTrue(result['candidate_hresult_failed'])
        self.assertEqual(result['read_budget']['context_field_bytes'], 16)
        self.assertEqual(result['read_budget']['total_bytes'], 142)
        self.assertFalse(result['exception_cause_established'])
        self.assertNotIn('deadbeef', repr(result))

    def test_success_and_failure_bit_preserve_unsigned_result(self):
        for value in (0, 1, 0x7fffffff, 0x80000000, 0xffffffff):
            with self.subTest(value=value):
                result, _, _ = self.tracked(rax=0xfacefeed00000000 | value)
                self.assertEqual(result['captured_rax_low32'], value)
                self.assertEqual(result['candidate_hresult_failed'], bool(value & 0x80000000))

    def test_role_and_av_gates_never_read_any_context(self):
        cases = [({'code': 0x80000003}, 1), ({'count': 1}, 2), ({'count': 16}, 2),
            ({'access': 1}, 3), ({'access': 8}, 3), ({'module_tuple': (770048, 1, 1792674694)}, 4),
            ({'rva': 0x3e057}, 4), ({'modules': 2, 'overlap': True}, 4), ({'arch': 0}, 5)]
        for kwargs, gate in cases:
            with self.subTest(kwargs=kwargs):
                result, calls, locations = self.tracked(**kwargs)
                self.assertEqual(result['gate'], gate)
                self.assertIsNone(result['captured_rax_low32'])
                self.assertFalse(any(locations['context'] <= offset < locations['context'] + 1232 for offset, _ in calls))

    def test_context_flags_rip_and_bounds_gate_precedes_rax(self):
        for kwargs, gate in [({'context_size': 1231}, 6), ({'context_alias': True}, 6),
            ({'flags': 0x100001}, 7), ({'flags': 0x100002}, 7), ({'flags': 0x300003}, 7), ({'rip_delta': 1}, 8)]:
            with self.subTest(kwargs=kwargs):
                result, calls, positions = self.tracked(**kwargs)
                self.assertEqual(result['gate'], gate)
                self.assertNotIn((positions['context'] + 120, 4), calls)
                self.assertIsNone(result['candidate_hresult_hex'])
        raw, positions = synthetic()
        struct.pack_into('<II', raw, positions['ex'] + 160, 1232, len(raw) - 10)
        self.write(raw)
        result = reader.parse_dump('synthetic.dmp')
        self.assertEqual(result['gate'], 6)

    def test_stream_overlap_or_duplicate_system_rejected_before_context(self):
        for duplicate in (False, True):
            raw, positions = synthetic(streams=4)
            struct.pack_into('<III', raw, 32 + 3 * 12, 7 if duplicate else 999, 2, positions['system'])
            self.write(raw)
            with mock.patch.object(reader.os, 'pread', wraps=os.pread) as reads, self.assertRaises(reader.MetadataError):
                reader.parse_dump('synthetic.dmp')
            self.assertEqual(reads.call_count, 2)

    def test_short_rax_read_rejected_instead_of_emitting_partial_value(self):
        raw, positions = synthetic();self.write(raw)
        original = os.pread
        def short(fd, size, offset):
            return original(fd, size - 1 if (offset, size) == (positions['context'] + 120, 4) else size, offset)
        with mock.patch.object(reader.os, 'pread', side_effect=short), self.assertRaises(reader.MetadataError) as caught:
            reader.parse_dump('synthetic.dmp')
        self.assertEqual(caught.exception.reason, 'short_read')

    def test_fixed_role_and_maximum_budget(self):
        result, calls, _ = self.tracked(modules=512, streams=128)
        self.assertEqual(result['gate'], 9)
        self.assertEqual(result['read_budget']['total_bytes'], 11862)
        self.assertEqual(len(calls), 524)
        path = self.crashes / 'synthetic.dmp'
        (self.crashes / 'alias.dmp').symlink_to(path)
        with mock.patch.object(reader.os, 'pread') as reads:
            for name in ('../synthetic.dmp', 'alias.dmp'):
                with self.assertRaises(reader.MetadataError): reader.parse_dump(name)
            reads.assert_not_called()

    def test_original_sdk_context_layout_syntax_only(self):
        source = r'''
#include <windows.h>
#include <dbghelp.h>
#include <cstddef>
static_assert(sizeof(CONTEXT)==1232);
static_assert(offsetof(CONTEXT,ContextFlags)==48);
static_assert(offsetof(CONTEXT,Rax)==120);
static_assert(sizeof(((CONTEXT*)0)->Rax)==8);
static_assert(offsetof(CONTEXT,Rip)==248);
static_assert(CONTEXT_AMD64==0x100000);
static_assert(CONTEXT_CONTROL==0x100001);
static_assert(CONTEXT_INTEGER==0x100002);
static_assert(PROCESSOR_ARCHITECTURE_AMD64==9);
static_assert(sizeof(MINIDUMP_EXCEPTION_STREAM)==168);
static_assert(offsetof(MINIDUMP_EXCEPTION_STREAM,ThreadContext)==160);
static_assert(sizeof(MINIDUMP_LOCATION_DESCRIPTOR)==8);
static_assert(sizeof(MINIDUMP_MODULE)==108);
static_assert(sizeof(MINIDUMP_SYSTEM_INFO)==56);
'''
        cpp = self.root / 'swapchain_layout.cpp';cpp.write_text(source)
        sdk = PROJECT / 'toolchains/msvc-2022/Windows Kits/10/Include/10.0.26100.0'
        includes = [PROJECT / 'toolchains/msvc-2022/VC/Tools/MSVC/14.44.35207/include', sdk / 'ucrt', sdk / 'shared', sdk / 'um']
        command = ['/opt/homebrew/opt/llvm/bin/clang-cl', '--target=x86_64-pc-windows-msvc', '/Zs', '/std:c++17',
            *('/I' + str(path) for path in includes), '--', str(cpp)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=45)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(list(self.root.glob('*.obj')), [])


if __name__ == '__main__':
    unittest.main()
