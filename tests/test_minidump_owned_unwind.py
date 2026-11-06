"""Own synthetic AMD64 unwind structures; no real dump/runtime/ZIP access."""
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import types
import unittest
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('minidump_owned_unwind', PROJECT / 'native/diagnostics/minidump_owned_unwind.py')
owned = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owned)
helper_path = PROJECT / 'tests/test_minidump_leaf_caller.py'
helper_data = owned._SECOND._bound_bytes(helper_path, 11851, '500f90b5f44645bddd0fe3ab75b9f31987fa29de22dbb64281fd633695140c3d')
helper = types.ModuleType('_frozen_owned_unwind_synthetic')
helper.__file__ = str(helper_path)
exec(compile(helper_data, str(helper_path), 'exec'), helper.__dict__)


def synthetic_dump(*, maximum=False, integer=True):
    data, p = helper.synthetic(maximum=maximum)
    data.extend(b'\xa5' * (p['stack'] + 4096 - len(data)))
    struct.pack_into('<I', data, p['thread'] + 4 + 32, 4096)
    struct.pack_into('<I', data, p['context'] + 48, 0x100003 if integer else 0x100001)
    struct.pack_into('<Q', data, p['stack'] + 16, 0x1807d10ee)
    values = {name: 0x112233440000 + index for index, name in enumerate(owned.NV_OFFSETS)}
    for name, relative in owned.NV_OFFSETS.items():
        struct.pack_into('<Q', data, p['context'] + relative, values[name])
    return data, p, values


def synthetic_pe(pe_class, codes=b'', *, count=0, frame=0, flags=0, prolog=0, epilog=False, duplicate=False):
    data = bytearray(b'\0' * 0x2a00)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 60, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', data, 0x84, 0x8664, 3, owned._LEAF.EXPECTED_MODULE[2], 0, 0, 0xf0, 0)
    optional = 0x98
    struct.pack_into('<H', data, optional, 0x20b)
    struct.pack_into('<I', data, optional + 16, 0x7d0000)
    struct.pack_into('<Q', data, optional + 24, 0x180000000)
    struct.pack_into('<I', data, optional + 32, 0x1000)
    struct.pack_into('<I', data, optional + 56, owned._LEAF.EXPECTED_MODULE[0])
    struct.pack_into('<I', data, optional + 64, owned._LEAF.EXPECTED_MODULE[1])
    struct.pack_into('<Q', data, optional + 72, 0x180000)
    struct.pack_into('<II', data, optional + 112 + 3 * 8, 0xc00000, 24 if duplicate else 12)
    sections = [(b'.text', 0x2000, 0x7d0000, 0x2000, 0x400, 0x60000020),
                (b'.pdata', 0x200, 0xc00000, 0x200, 0x2400, 0x40000040),
                (b'.xdata', 0x400, 0xc01000, 0x400, 0x2600, 0x40000040)]
    for index, (name, size, rva, raw_size, raw, characteristics) in enumerate(sections):
        at = optional + 0xf0 + index * 40
        struct.pack_into('<8sIIII', data, at, name, size, rva, raw_size, raw)
        struct.pack_into('<I', data, at + 36, characteristics)
    data[0x400:0x2400] = b'\x90' * 0x2000
    if epilog:
        data[0x400 + 0x10ee] = 0xc3
    struct.pack_into('<III', data, 0x2400, 0x7d0000, 0x7d2000, 0xc01000)
    if duplicate:
        struct.pack_into('<III', data, 0x240c, 0x7d0000, 0x7d2000, 0xc01000)
    struct.pack_into('<BBBB', data, 0x2600, 1 | (flags << 3), prolog, count, frame)
    data[0x2604:0x2604 + len(codes)] = codes
    return pe_class(owned._CodeSnapshot(bytes(data)))


class OwnedUnwindTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.algorithms = owned.load_algorithms()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.crashes = self.root.joinpath(*owned._LEAF._BASE.ROLE_PARTS)
        self.crashes.mkdir(parents=True)
        patch = mock.patch.object(owned._LEAF._BASE, 'ROOT', self.root)
        patch.start()
        self.addCleanup(patch.stop)

    def parse(self, data, pe):
        (self.crashes / 'synthetic.dmp').write_bytes(data)
        entry, unwind, _, proof = self.algorithms
        original = os.pread
        with mock.patch.object(owned, 'load_inputs', return_value=(entry, unwind, pe, {**proof, 'synthetic_code': True})), \
                mock.patch.object(owned.os, 'pread', wraps=original) as reads:
            result = owned.parse_dump('synthetic.dmp')
        return result, [(call.args[2], call.args[1]) for call in reads.call_args_list]

    def test_actual_source_ast_scope_and_fixed_code_snapshot(self):
        original = owned._SECOND._bound_bytes
        with mock.patch.object(owned._SECOND, '_bound_bytes', wraps=original) as reads:
            entry, unwind, pe, proof = owned.load_inputs()
        self.assertEqual([str(call.args[0].relative_to(owned.ROOT)) for call in reads.call_args_list],
                         [owned.ALGORITHM_SOURCE[0], owned.PE_SOURCE[0], owned.CODE_INPUT[0]])
        self.assertEqual(proof['executed_original_top_level_nodes'], ['REGS', 'function_entry', 'unwind_one', 'PE'])
        self.assertIs(proof['algorithm_ast_rewritten'], False)
        self.assertIs(proof['other_legacy_top_level_or_imports_executed'], False)
        self.assertEqual(unwind.__globals__['function_entry'], entry)
        self.assertEqual(pe.image_size, owned._LEAF.EXPECTED_MODULE[0])

    def test_known_old_64_byte_frame_and_exact_nv_slices_redaction(self):
        pe = synthetic_pe(self.algorithms[2], bytes([7, 0x32, 3, 0x30, 2, 0x70, 1, 0x60]), count=4, prolog=7)
        data, p, values = synthetic_dump()
        for index in range(3):
            struct.pack_into('<Q', data, p['stack'] + 16 + 40 + index * 8, 0x998877660000 + index)
        struct.pack_into('<Q', data, p['stack'] + 16 + 64, 0x200001234)
        result, calls = self.parse(data, pe)
        self.assertEqual(result['stop_reason'], 'other_module')
        self.assertEqual([row['rva'] for row in result['frames']], [0x7d10ee, 0x1234])
        self.assertEqual(calls[-12:-4], [(p['context'] + relative, 8) for relative in owned.NV_OFFSETS.values()])
        self.assertEqual(calls[-4:], [(p['stack'] + 56, 8), (p['stack'] + 64, 8), (p['stack'] + 72, 8), (p['stack'] + 80, 8)])
        self.assertEqual(result['context_bytes_read'], 84)
        self.assertEqual(result['captured_stack_bytes_read'], 40)
        self.assertEqual(result['distinct_stack_words_read'], 5)
        for raw in [0x70000010, 0x1807d10ee, 0x200001234, *values.values(), 0x998877660000]:
            self.assertNotIn(str(raw), json.dumps(result))
        self.assertNotIn('return_slot_address', json.dumps(result))
        self.assertNotIn('return_address', json.dumps(result))

    def test_frame_pointer_and_all_nv_restores_using_unchanged_algorithm(self):
        registers = [15, 14, 13, 12, 7, 6, 5, 3]
        codes = bytes([20, 3, 17, 1]) + struct.pack('<H', 65)
        codes += b''.join(bytes([16 - index, register << 4]) for index, register in enumerate(registers))
        pe = synthetic_pe(self.algorithms[2], codes, count=11, frame=0x85, flags=3, prolog=20)
        data, p, _ = synthetic_dump()
        struct.pack_into('<Q', data, p['context'] + 160, 0x70000010 + 8 + 128)
        restored = [0x887766550000 + index for index in range(8)]
        for index, value in enumerate(restored):
            struct.pack_into('<Q', data, p['stack'] + 16 + 528 + index * 8, value)
        struct.pack_into('<Q', data, p['stack'] + 16 + 592, 0x200001234)
        result, calls = self.parse(data, pe)
        self.assertEqual(result['stop_reason'], 'other_module')
        self.assertEqual(result['frames'][0]['unwind']['unwind_flags'], 3)
        self.assertEqual(result['captured_stack_bytes_read'], 80)
        self.assertEqual(len(result['frames'][0]['unwind']['operations']), 10)
        self.assertIs(result['handlers_executed'], False)
        for value in restored:
            self.assertNotIn(str(value), json.dumps(result))
        # Independently observe the unchanged function's integer restore result.
        class Memory:
            def memory(self, address, count):
                self.last = address
                offset = p['stack'] + address - 0x70000000
                return bytes(data[offset:offset + count])
            def label(self, address):
                return {'module_index': 1, 'rva': 0x1234}
        context = {key: 0 for key in owned.NV_OFFSETS}
        context.update(rip=0x1807d10ee, rsp=0x70000018, rbp=0x70000018 + 128)
        following, metadata = self.algorithms[1](Memory(), pe, {'base': 0x180000000}, context, 1)
        for register, value in zip(registers, restored):
            self.assertEqual(following[self.algorithms[1].__globals__['REGS'][register]], value)
        self.assertEqual(following['rip'], 0x200001234)

    def test_integer_mask_precedes_all_added_nv_context_reads(self):
        data, p, _ = synthetic_dump(integer=False)
        result, calls = self.parse(data, synthetic_pe(self.algorithms[2]))
        self.assertEqual(result['stop_reason'], 'context_integer_not_admitted')
        self.assertEqual(result['context_bytes_read'], 20)
        self.assertEqual(result['read_budget']['nonvolatile_context_bytes'], 0)
        for relative in owned.NV_OFFSETS.values():
            self.assertNotIn((p['context'] + relative, 8), calls)

    def test_cache_reuses_exact_slices_and_distinct_budget_includes_leaf(self):
        pe = synthetic_pe(self.algorithms[2], bytes([5, 0x34, 0, 0, 4, 0x34, 0, 0]), count=4, prolog=5)
        data, p, _ = synthetic_dump()
        struct.pack_into('<Q', data, p['stack'] + 24, 0x200001234)
        result, calls = self.parse(data, pe)
        self.assertEqual(result['stop_reason'], 'other_module')
        self.assertEqual(result['stack_memory_requests'], 3)
        self.assertEqual(result['stack_cache_hits'], 2)
        self.assertEqual(result['distinct_stack_words_read'], 2)
        self.assertEqual(result['captured_stack_bytes_read'], 16)
        self.assertEqual(calls.count((p['stack'] + 24, 8)), 1)

    def test_maximum_128_words_and_metadata_budget_stops_inside_rejected_step(self):
        codes = b''.join(bytes([255 - index, 0x30]) for index in range(255))
        pe = synthetic_pe(self.algorithms[2], codes, count=255, prolog=255)
        data, p, _ = synthetic_dump(maximum=True)
        result, calls = self.parse(data, pe)
        self.assertEqual(result['stop_reason'], 'distinct_stack_word_budget')
        self.assertEqual(len(result['frames']), 1)
        self.assertEqual(result['distinct_stack_words_read'], 128)
        self.assertEqual(result['captured_stack_bytes_read'], 1024)
        self.assertEqual(result['context_bytes_read'], 84)
        self.assertEqual(result['read_budget']['total_bytes'], 15010)
        self.assertEqual(len(calls), 1172)
        self.assertIs(result['rejected_step_reads_included_in_budget'], True)

    def test_twelve_frame_limit_without_scan_or_extra_context(self):
        data, p, _ = synthetic_dump()
        for index in range(12):
            struct.pack_into('<Q', data, p['stack'] + 16 + index * 8, 0x1807d10ee)
        result, calls = self.parse(data, synthetic_pe(self.algorithms[2]))
        self.assertEqual(result['stop_reason'], 'maximum_frames')
        self.assertEqual(len(result['frames']), 12)
        self.assertEqual(result['captured_stack_bytes_read'], 96)
        self.assertNotIn((p['stack'] + 16 + 12 * 8, 8), calls)
        self.assertIs(result['stack_scanned'], False)
        self.assertIs(result['callstack_established'], False)
        self.assertIs(result['raw_registers_or_stack_words_persisted'], False)

    def test_volatile_operation_rejects_step_after_bounded_reads(self):
        pe = synthetic_pe(self.algorithms[2], bytes([1, 0]), count=1, prolog=1)
        data, p, _ = synthetic_dump()
        for offset in (24, 32):
            struct.pack_into('<Q', data, p['stack'] + offset, 0x200001234)
        result, calls = self.parse(data, pe)
        self.assertEqual(result['stop_reason'], 'unsupported_operation_register')
        self.assertEqual(len(result['frames']), 1)
        self.assertNotIn('unwind', result['frames'][0])
        self.assertEqual(result['distinct_stack_words_read'], 3)
        self.assertEqual(result['captured_stack_bytes_read'], 24)
        self.assertNotIn('rax', json.dumps(result['frames']))

    def test_epilog_chain_overlap_and_volatile_frame_register_stop(self):
        cases = [(synthetic_pe(self.algorithms[2], epilog=True), 'possible_epilog'),
                 (synthetic_pe(self.algorithms[2], flags=4), 'unsupported_version_or_chain'),
                 (synthetic_pe(self.algorithms[2], duplicate=True), 'no_unique_runtime_function'),
                 (synthetic_pe(self.algorithms[2], frame=1), 'unavailable_nonvolatile_register')]
        for pe, reason in cases:
            with self.subTest(reason=reason):
                data, p, _ = synthetic_dump()
                result, calls = self.parse(data, pe)
                self.assertEqual(result['stop_reason'], reason)
                self.assertEqual(result['distinct_stack_words_read'], 1)
        # Strict >prolog is imposed by the adapter before the unchanged '<' gate.
        pe = synthetic_pe(self.algorithms[2], prolog=1)
        pe.data = bytearray(pe.data)
        struct.pack_into('<III', pe.data, 0x2400, 0x7d10ec, 0x7d2000, 0xc01000)
        data, _, _ = synthetic_dump()
        result, _ = self.parse(data, pe)
        self.assertEqual(result['stop_reason'], 'prolog_pc')
        self.assertEqual(result['distinct_stack_words_read'], 1)

    def test_callback_shape_full_bounds_and_unknown_word_redaction(self):
        for address, count in ((0x70000010, 16), (-1, 8), ((1 << 64) - 4, 8), (0x6fffffff, 8)):
            reader = owned._Reader(-1, 8192)
            reader.entries = [(6, 168, 512)]
            reader._stack = 0x70000000, 4096, 4096
            reader._context = 1232, 2048
            with mock.patch.object(owned.os, 'pread') as reads:
                with self.assertRaises(owned._Stop):
                    reader.memory(address, count)
                reads.assert_not_called()
        for file_rva in (4200, 512, 2048):
            reader = owned._Reader(-1, 8192)
            reader.entries = [(6, 168, 512)]
            reader._stack = 0x70000000, 4096, file_rva
            reader._context = 1232, 2048
            with mock.patch.object(owned.os, 'pread') as reads:
                with self.assertRaises(owned._Stop):
                    reader.memory(0x70000010, 8)
                reads.assert_not_called()
        data, p, _ = synthetic_dump()
        struct.pack_into('<Q', data, p['stack'] + 24, 0xffffffffffffffff)
        result, calls = self.parse(data, synthetic_pe(self.algorithms[2]))
        self.assertEqual(result['stop_reason'], 'unknown_or_ambiguous_return_word')
        self.assertEqual(len(result['frames']), 1)
        self.assertNotIn(str(0xffffffffffffffff), json.dumps(result))

    def test_original_sdk_added_nonvolatile_context_layout_syntax_only(self):
        source = '#include <windows.h>\n#include <cstddef>\n'
        for register, offset in owned.NV_OFFSETS.items():
            source += f'static_assert(offsetof(CONTEXT,{register.title()})=={offset});\n'
        source += 'static_assert((CONTEXT_CONTROL|CONTEXT_INTEGER)==0x100003);\n'
        source += 'static_assert(sizeof(CONTEXT)==1232);\n'
        cpp = self.root / 'nonvolatile_layout.cpp'
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
