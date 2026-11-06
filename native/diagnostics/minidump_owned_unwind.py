#!/usr/bin/env python3
"""Bounded use of the unchanged owned function_entry/unwind_one algorithms.

Only those two functions and REGS, plus the existing PE class, are compiled
from pinned own source AST nodes. Other legacy top-level code, imports, Dump,
safe_extract, analyze and main never execute. PE reads only the captured bytes
of the literal SHA-bound legitimacy.dll. Dump access uses the frozen leaf FD,
directory, module, context and unique-thread-stack gates.

After leaf admission and INTEGER validity, only eight nonvolatile context
QWORDs are added (84 context bytes total). memory() permits only 8 bytes inside
that one captured stack: max128 distinct words/1024 bytes, cached repeats.
Max12 candidates; max15010 dump bytes/1172 pread calls. Legacy operations on
unsupported registers are rejected AFTER the unchanged call; rejected-step
reads still count. No raw registers/RSP/return slots/unknown words are emitted.
The old single-byte epilog check is incomplete: all continuation remains a
conditional metadata assumption, with no proven live callstack or crash cause.
"""
import ast
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import types

ROOT = Path(__file__).resolve().parents[2]
ALGORITHM_SOURCE = ('scripts/analyze_crashdump.py', 26294, '8449266235a92c750f3875b044a72d444d72b6cc4f8fb7c2ec562758c1650e8f')
PE_SOURCE = ('native/windows-client/inspect_game.py', 7095, 'bf2b7463ea9f6c8f83be54a423eb1f09d32ac1ca0a423efa75d815d60751d552')
CODE_INPUT = ('build/windows-source-integration/legitimacy.dll', 12443232, '95f5788ff0fec0c0808e357cd312c95344c618c3054dc12782ea8f1b66bcea97')
NV_OFFSETS = {'rbx': 144, 'rbp': 160, 'rsi': 168, 'rdi': 176, 'r12': 216, 'r13': 224, 'r14': 232, 'r15': 240}
MAX_FRAMES = 12
MAX_STACK_WORDS = 128
MAX_READ_BYTES = 15010
MAX_READ_CALLS = 1172


def _load_second():
    # Only the frozen reader and bound-own-code utility are reused.
    import stat
    path = Path(__file__).absolute().with_name('minidump_second_frame.py')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        data = os.read(fd, 10829)
        after = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size != 10828
                or len(data) != 10828 or hashlib.sha256(data).hexdigest()
                != '54d51490786d5c77d7a4e6e8cd2e6e75a370ae267265eabe3f18233a78d18df9'
                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise ValueError('frozen_slice_reader_binding')
    finally:
        os.close(fd)
    module = types.ModuleType('_frozen_owned_unwind_reader')
    module.__file__ = str(path)
    exec(compile(data, str(path), 'exec'), module.__dict__)
    return module


_SECOND = _load_second()
_LEAF = _SECOND._LEAF
MetadataError = _LEAF.MetadataError


def _identity(spec):
    return dict(zip(('path', 'bytes', 'sha256'), spec))


def load_algorithms():
    source = _SECOND._bound_bytes(ROOT / ALGORITHM_SOURCE[0], *ALGORITHM_SOURCE[1:]).decode('utf-8')
    tree = ast.parse(source, ALGORITHM_SOURCE[0])
    names = ('function_entry', 'unwind_one')
    selected = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    regs = [node for node in tree.body if isinstance(node, ast.Assign)
            and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == 'REGS']
    if len(regs) != 1 or [node.name for node in selected] != list(names):
        raise ValueError('fixed_algorithm_ast_scope')
    if ast.literal_eval(regs[0].value) != ('rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'):
        raise ValueError('fixed_algorithm_register_names')
    forbidden = {'open', 'eval', 'exec', 'compile', '__import__', 'globals', 'locals', 'Path', 'subprocess', 'zipfile'}
    if any(isinstance(node, (ast.Import, ast.ImportFrom)) or isinstance(node, ast.Name) and node.id in forbidden
           for root in selected for node in ast.walk(root)):
        raise ValueError('algorithm_import_or_io_scope')
    namespace = {'struct': struct, '__name__': '_owned_unchanged_unwind'}
    exec(compile(ast.Module(body=[regs[0], *selected], type_ignores=[]), ALGORITHM_SOURCE[0], 'exec'), namespace)
    pe_text = _SECOND._bound_bytes(ROOT / PE_SOURCE[0], *PE_SOURCE[1:]).decode('utf-8')
    pe_nodes = [node for node in ast.parse(pe_text, PE_SOURCE[0]).body if isinstance(node, ast.ClassDef) and node.name == 'PE']
    if len(pe_nodes) != 1:
        raise ValueError('fixed_pe_class_scope')
    pe_namespace = {'struct': struct, '__name__': '_owned_unchanged_pe'}
    exec(compile(ast.Module(body=pe_nodes, type_ignores=[]), PE_SOURCE[0], 'exec'), pe_namespace)
    proof = {'algorithm_source': _identity(ALGORITHM_SOURCE), 'pe_source': _identity(PE_SOURCE),
             'executed_original_top_level_nodes': ['REGS', 'function_entry', 'unwind_one', 'PE'],
             'other_legacy_top_level_or_imports_executed': False, 'algorithm_ast_rewritten': False,
             'function_segments_sha256': {node.name: hashlib.sha256(ast.get_source_segment(source, node).encode()).hexdigest() for node in selected}}
    return namespace['function_entry'], namespace['unwind_one'], pe_namespace['PE'], proof


class _CodeSnapshot:
    def __init__(self, data):
        self._data, self.reads = data, 0

    def read_bytes(self):
        self.reads += 1
        if self.reads != 1:
            raise ValueError('single_captured_code_snapshot')
        return self._data


def load_inputs():
    entry, unwind, pe_class, proof = load_algorithms()
    code = _SECOND._bound_bytes(ROOT / CODE_INPUT[0], *CODE_INPUT[1:])
    snapshot = _CodeSnapshot(code)
    pe = pe_class(snapshot)
    nt = pe.u32(60)
    if (pe.image_size, pe.u32(pe.optional + 64), pe.u32(nt + 8)) != _LEAF.EXPECTED_MODULE or snapshot.reads != 1:
        raise ValueError('fixed_code_header_tuple')
    return entry, unwind, pe, {**proof, 'code_snapshot': _identity(CODE_INPUT), 'pe_constructor_reads_captured_code_only': True}


class _Stop(ValueError):
    pass


class _Reader(_SECOND._Reader):
    def __init__(self, fd, size):
        super().__init__(fd, size)
        self._flags = None
        self._cache = {}
        self.cache_hits = self.memory_requests = 0
        self.counts.update(nonvolatile_context_bytes=0, unwind_stack_bytes=0)

    def read(self, offset, size):
        data = super().read(offset, size)
        kind = self.allowed[offset, size]
        if kind == 'context_field' and self._context and offset == self._context[1] + 48:
            self._flags, = struct.unpack('<I', data)
        elif kind == 'return_word' and self._rsp is not None:
            self._cache[self._rsp] = data
        return data

    def _slice8(self, offset, kind):
        self.allow(offset, 8, kind)
        key = offset, 8
        if key in self.used or len(self.used) >= MAX_READ_CALLS or sum(self.counts.values()) + 8 > MAX_READ_BYTES:
            raise _Stop('dump_read_budget')
        self.used.add(key)
        self.counts[kind + '_bytes'] += 8
        data = os.pread(self.fd, 8, offset)
        if len(data) != 8:
            raise MetadataError('short_read')
        return data

    def nonvolatile_context(self):
        if self._flags is None or self._flags & 0x100003 != 0x100003:
            raise _Stop('context_integer_not_admitted')
        size, rva = self._context
        if size < 1232 or not self.clean_payload(rva, size):
            raise _Stop('context_bounds')
        return {register: struct.unpack('<Q', self._slice8(rva + relative, 'nonvolatile_context'))[0]
                for register, relative in NV_OFFSETS.items()}

    def memory(self, address, count):
        self.memory_requests += 1
        if type(address) is not int or type(count) is not int or count != 8 or not 0 <= address <= (1 << 64) - 8:
            raise _Stop('stack_slice_shape_or_u64')
        start, size, rva = self._stack
        context_size, context_rva = self._context
        if (size < 8 or start + size > 1 << 64 or address < start or address - start > size - 8
                or not self.clean_payload(rva, size, ((context_rva, context_rva + context_size),))):
            raise _Stop('captured_stack_bounds')
        offset = rva + address - start
        if not _LEAF._BASE._within(offset, 8, self.size):
            raise _Stop('captured_stack_bounds')
        if address in self._cache:
            self.cache_hits += 1
            return self._cache[address]
        if len(self._cache) >= MAX_STACK_WORDS:
            raise _Stop('distinct_stack_word_budget')
        data = self._slice8(offset, 'unwind_stack')
        self._cache[address] = data
        return data

    def locate(self, address):
        matches = [{'index': index, 'base': base, 'image_bytes': size, 'checksum': checksum, 'timestamp': stamp}
                   for index, (base, size, checksum, stamp) in enumerate(self._modules)
                   if size and base <= address < base + size]
        return matches[0] if len(matches) == 1 else None

    def label(self, address):
        module = self.locate(address)
        return {'module_index': None if module is None else module['index'],
                'rva': None if module is None else address - module['base']}

    def budget(self):
        return {**super().budget(), 'maximum_bytes': MAX_READ_BYTES, 'maximum_read_calls': MAX_READ_CALLS}


def _metadata(record):
    operations = []
    for operation in record['operations']:
        code = operation['op']
        if code in ('PUSH_NONVOL', 'SET_FPREG', 'SAVE_NONVOL'):
            if operation.get('register') not in NV_OFFSETS:
                raise _Stop('unsupported_operation_register')
        if code not in ('PUSH_NONVOL', 'SET_FPREG', 'SAVE_NONVOL', 'ALLOC_SMALL', 'ALLOC_LARGE', 'SAVE_XMM'):
            raise _Stop('unsupported_unwind_operation')
        operations.append({key: operation[key] for key in ('op', 'register', 'bytes', 'offset', 'scope') if key in operation})
    return {'runtime_function_begin_rva': int(record['runtime_function_begin_rva'], 16),
            'runtime_function_end_rva': int(record['runtime_function_end_rva'], 16),
            'unwind_info_rva': int(record['unwind_info_rva'], 16), 'unwind_flags': record['unwind_flags'],
            'operations': operations}


def _legacy_stop(error):
    if isinstance(error, _Stop):
        return str(error)
    if isinstance(error, KeyError):
        return 'unavailable_nonvolatile_register'
    text = str(error)
    for prefix, reason in (('No unique static RUNTIME_FUNCTION', 'no_unique_runtime_function'),
                           ('Unsupported unwind version/chaining', 'unsupported_version_or_chain'),
                           ('Prolog continuation', 'prolog_pc'), ('Possible epilog/tail', 'possible_epilog'),
                           ('Unsupported unwind opcode', 'unsupported_unwind_opcode'),
                           ('Non-progressing stack unwind', 'nonprogressing_unwind')):
        if text.startswith(prefix):
            return reason
    return 'invalid_unwind_metadata'


def parse_dump(basename):
    function_entry, unwind_one, pe, proof = load_inputs()
    with _LEAF._BASE._bound_dump(basename) as (fd, size):
        reader = _Reader(fd, size)
        timestamp, selected = _LEAF._LOCATION._directory(reader, size)
        reader._exception = selected.get(6, (None, None))[1]
        first = {'admission_gate': 0, 'possible_leaf_return_word': None, 'captured_stack_word_read': False}
        try:
            _LEAF._inspect(reader, selected, first)
        except _LEAF._NotAdmitted as denied:
            first['admission_gate'] = denied.gate
        frames, stop = [], 'leaf_not_admitted'
        if first['admission_gate'] == 10:
            candidate = first['possible_leaf_return_word']
            module = reader._modules[candidate['module_index']]
            frames.append({'frame': 1, **candidate})
            stop = 'leaf_return_not_version_bound'
            if module[1:] == _LEAF.EXPECTED_MODULE and candidate['rva'] == 0x7d10ee:
                try:
                    if reader._rsp > (1 << 64) - 9:
                        raise _Stop('initial_rsp_u64')
                    current = reader.nonvolatile_context()
                    current.update(rsp=reader._rsp + 8, rip=module[0] + candidate['rva'])
                    for index in range(1, MAX_FRAMES):
                        known = reader.locate(current['rip'])
                        if known is None:
                            raise _Stop('unknown_or_ambiguous_return_word')
                        if (known['image_bytes'], known['checksum'], known['timestamp']) != _LEAF.EXPECTED_MODULE:
                            raise _Stop('other_module')
                        rva = current['rip'] - known['base'] - 1
                        begin, _, info = function_entry(pe, rva)
                        _, prolog, _, _ = struct.unpack_from('<BBBB', pe.data, pe.file_offset(info, 4))
                        if rva - begin <= prolog:
                            raise _Stop('prolog_pc')
                        following, raw_metadata = unwind_one(reader, pe, known, current, index)
                        metadata = _metadata(raw_metadata)  # Rejected-step reads remain counted, result is discarded.
                        located = reader.locate(following['rip'])
                        if located is None:
                            raise _Stop('unknown_or_ambiguous_return_word')
                        frames[-1]['unwind'] = metadata
                        frames.append({'frame': len(frames) + 1, **reader.label(following['rip'])})
                        current = following
                        if (located['image_bytes'], located['checksum'], located['timestamp']) != _LEAF.EXPECTED_MODULE:
                            raise _Stop('other_module')
                    stop = 'maximum_frames'
                except (ValueError, KeyError, struct.error) as error:
                    stop = _legacy_stop(error)
        stack_bytes = reader.counts['return_word_bytes'] + reader.counts['unwind_stack_bytes']
        result = {'header_time_unix': timestamp, 'leaf_admission_gate': first['admission_gate'], 'frames': frames,
                  'stop_reason': stop, 'classification': 'bounded_owned_metadata_unwind_candidates', 'input_proof': proof,
                  'conditional_metadata_assumption': True, 'live_epilog_freedom_verified': False,
                  'maximum_frames': MAX_FRAMES, 'distinct_stack_words_read': len(reader._cache),
                  'captured_stack_bytes_read': stack_bytes, 'maximum_distinct_stack_words': MAX_STACK_WORDS,
                  'stack_memory_requests': reader.memory_requests, 'stack_cache_hits': reader.cache_hits,
                  'context_bytes_read': reader.counts['context_field_bytes'] + reader.counts['nonvolatile_context_bytes'],
                  'whole_context_or_stack_read': False, 'raw_registers_or_stack_words_persisted': False,
                  'legacy_register_scope_validation': 'post_call_before_following_frame_persistence',
                  'rejected_step_reads_included_in_budget': True, 'handlers_executed': False, 'stack_scanned': False,
                  'callstack_established': False, 'caller_or_file_or_pdb_identity_established': False,
                  'exception_cause_established': False, 'read_budget': reader.budget()}
    return result


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print(json.dumps({'ok': False, 'error_code': _LEAF._BASE.ERRORS['filename']}))
        return 2
    try:
        result = parse_dump(args[0])
    except MetadataError as error:
        print(json.dumps({'ok': False, 'error_code': error.code}))
        return 1
    except (OSError, ValueError, KeyError, TypeError, struct.error):
        print(json.dumps({'ok': False, 'error_code': 42}))
        return 1
    print(json.dumps({'ok': True, **result}, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
