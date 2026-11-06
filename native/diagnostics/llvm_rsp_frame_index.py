#!/usr/bin/env python3
"""Index restricted RSP effects from one already generated LLVM text artifact."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path(__file__).absolute().parents[2]
HERE = Path(__file__).absolute()
TEST = ROOT / 'tests/test_llvm_rsp_frame_index.py'
CODE = ROOT / 'build/windows-source-integration/legitimacy.dll'
LLVM = Path('/opt/homebrew/Cellar/llvm/23.1.4/bin/llvm-readobj')
LOG = ROOT / 'build/llvm-unwind-metadata/legitimacy-caller-tc23fkgn.txt'
EVIDENCE = ROOT / 'research/legitimacy-caller-llvm-unwind-20261102T231153214140Z.json'
HEADER_EVIDENCE = ROOT / 'research/legitimacy-exception-metadata-20261102T225538622860Z.json'
INDEX = ROOT / 'build/llvm-unwind-metadata/legitimacy-rsp-frame-index-v1.json'
REPORT = ROOT / 'research/legitimacy-rsp-frame-index-inputs-v1.json'
CODE_SHA = '95f5788ff0fec0c0808e357cd312c95344c618c3054dc12782ea8f1b66bcea97'
LLVM_SHA = '0018f06c497f0992e16dc6a3cbb8f3f287439df171af6157d32aa83521bf0c2e'
LOG_SHA = 'a5f4818e216f932ffbf30f7d24203c1ed267c89892afb90f581e71ba8bfe78da'
EVIDENCE_SHA = 'df0c176d64cd83c93f239afc5d51595be8ead4c4e4f54b80b958185130120dc2'
HEADER_SHA = 'b4edd7cf7f2c0d8aac86c6fd691f6c38d46a863ebcc1c40159e573994bb0c042'
IMAGE_BASE = 0x180000000
IMAGE_SIZE = 0xc60000
MAX_FRAME_BYTES = 1024 * 1024
NONVOLATILE = frozenset(('RBX', 'RBP', 'RSI', 'RDI', 'R12', 'R13', 'R14', 'R15'))


def one(block, pattern):
    values = re.findall(pattern, block, re.MULTILINE)
    if len(values) != 1:
        raise ValueError('Missing or duplicate LLVM field')
    return values[0]


def number(value):
    return int(value, 16 if value.startswith('0x') else 10)


def parse_block(block):
    start = int(one(block, r'^    StartAddress:.*\(0x([0-9A-Fa-f]+)\)$'), 16) - IMAGE_BASE
    end = int(one(block, r'^    EndAddress:.*\(0x([0-9A-Fa-f]+)\)$'), 16) - IMAGE_BASE
    unwind = int(one(block, r'^    UnwindInfoAddress:.*\(0x([0-9A-Fa-f]+)\)$'), 16) - IMAGE_BASE
    if not 0 < start < end <= IMAGE_SIZE or not 0 < unwind < IMAGE_SIZE:
        raise ValueError('LLVM range outside exact candidate image')
    version = int(one(block, r'^      Version: ([0-9]+)$'))
    flags = int(one(block, r'^      Flags \[ \(0x([0-9A-Fa-f]+)\)$'), 16)
    prolog = int(one(block, r'^      PrologSize: ([0-9]+)$'))
    register = one(block, r'^      FrameRegister: (.+)$')
    if register == '-':
        frame_register = 0
    else:
        match = re.fullmatch(r'[A-Z0-9]+ \(0x([0-9A-Fa-f]+)\)', register)
        if not match:
            raise ValueError('Unknown LLVM frame register format')
        frame_register = int(match.group(1), 16)
    offset = one(block, r'^      FrameOffset: (.+)$')
    frame_offset = 0 if offset == '-' else number(offset)
    count = int(one(block, r'^      UnwindCodeCount: ([0-9]+)$'))
    if not 0 <= prolog <= 255 or not 0 <= count <= 255 or not 0 <= frame_register <= 15 or not 0 <= frame_offset <= 15:
        raise ValueError('LLVM field outside AMD64 bounds')
    operations, reasons, stack_bytes = [], set(), 0
    if version != 1:
        reasons.add('version_not_one')
    if flags:
        reasons.add('flags_nonzero')
    if frame_register or frame_offset:
        reasons.add('frame_register_or_offset_nonzero')
    rows = re.findall(r'^        0x([0-9A-Fa-f]+): ([A-Z0-9_]+)(.*)$', block, re.MULTILINE)
    min_slots = max_slots = 0
    for code_offset, operation, args in rows:
        code_offset = int(code_offset, 16)
        item = {'code_offset': code_offset, 'operation': operation}
        if code_offset > prolog or code_offset > 255:
            reasons.add('code_offset_outside_prolog')
        if operation in ('ALLOC_SMALL', 'ALLOC_LARGE'):
            match = re.fullmatch(r' size=([0-9]+)', args)
            if match:
                size = int(match.group(1))
                item['size'] = size
                if size <= 0 or size % 8 or size > MAX_FRAME_BYTES:
                    reasons.add('invalid_allocation_size')
                if operation == 'ALLOC_SMALL' and size > 128:
                    reasons.add('invalid_small_allocation_size')
                stack_bytes += size
            else:
                reasons.add('allocation_without_exact_llvm_size')
            min_slots += 1 if operation == 'ALLOC_SMALL' else 2
            max_slots += 1 if operation == 'ALLOC_SMALL' else 3
        elif operation == 'PUSH_NONVOL':
            match = re.fullmatch(r' reg=([A-Z0-9]+)', args)
            if match and match.group(1) in NONVOLATILE:
                item.update(register=match.group(1), size=8)
                stack_bytes += 8
            else:
                reasons.add('invalid_push_register')
            min_slots += 1
            max_slots += 1
        else:
            reasons.add('unsupported_operation')
        operations.append(item)
    if not min_slots <= count <= max_slots:
        reasons.add('llvm_slot_count_inconsistent')
    if stack_bytes > MAX_FRAME_BYTES:
        reasons.add('frame_exceeds_fixed_cap')
    if any(operations[i - 1]['code_offset'] < operations[i]['code_offset'] for i in range(1, len(operations))):
        reasons.add('operation_offsets_not_descending')
    if not flags:
        allowed = (
            r'^  RuntimeFunction \{$', r'^  \}$', r'^    (StartAddress|EndAddress|UnwindInfoAddress):.*$',
            r'^    UnwindInfo \{$', r'^    \}$', r'^      (Version|PrologSize|FrameRegister|FrameOffset|UnwindCodeCount):.*$',
            r'^      Flags \[ \(0x0\)$', r'^      \]$', r'^      UnwindCodes \[$',
            r'^        0x[0-9A-Fa-f]+: [A-Z0-9_]+.*$')
        if any(not any(re.fullmatch(pattern, line) for pattern in allowed) for line in block.splitlines()):
            reasons.add('unrecognized_llvm_structure')
    if block.count('    UnwindInfo {\n') != 1 or block.count('      UnwindCodes [\n') != 1:
        reasons.add('unrecognized_nested_unwind_structure')
    if 'Chained {' in block:
        reasons.add('chained_structure')
    supported = not reasons
    return {'begin_rva': start, 'end_rva_exclusive': end, 'unwind_info_rva': unwind,
            'version': version, 'flags': flags, 'frame_register': frame_register,
            'frame_offset': frame_offset, 'prolog_size': prolog, 'unwind_code_count': count,
            'chaininfo': bool(flags & 4), 'exception_handler': bool(flags & 1),
            'unwind_handler': bool(flags & 2),
            'explicit_epilog_codes': any(x['operation'].startswith('EPILOG') for x in operations),
            'supported_rsp_body': supported, 'stack_frame_bytes': stack_bytes if supported else None,
            'unsupported_reasons': sorted(reasons), 'operations': operations}


def parse_output(text):
    entries, block = [], []
    for line in text.splitlines(keepends=True):
        if line == '  RuntimeFunction {\n':
            if block:
                raise ValueError('Nested top-level LLVM function')
            block = [line]
        elif block:
            block.append(line)
            if line == '  }\n':
                entries.append(parse_block(''.join(block)))
                block = []
    if block or not entries or len(entries) > 100000:
        raise ValueError('Incomplete or unbounded LLVM output')
    return entries


def matching_entries(entries, rva):
    """Return every containing range, including unsupported/overlapping entries."""
    return [entry for entry in entries if entry['begin_rva'] <= rva < entry['end_rva_exclusive']]


def signature(info):
    return tuple(getattr(info, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def admit(path, directory=False):
    cursor = Path(path.anchor)
    for part in path.parts[1:]:
        cursor /= part
        info = cursor.lstat()
        if stat.S_ISLNK(info.st_mode) or (cursor != path and not stat.S_ISDIR(info.st_mode)):
            raise ValueError('Alias or non-directory ancestor')
    if directory:
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError('Expected fixed output directory')
    elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError('Expected regular single-link input')
    return info


def read_input(path, before, expected_sha=None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        if signature(os.fstat(fd)) != signature(before):
            raise ValueError('Input changed before read')
        chunks, offset, digest = [], 0, hashlib.sha256()
        while offset < before.st_size:
            chunk = os.pread(fd, min(1048576, before.st_size - offset), offset)
            if not chunk:
                raise ValueError('Short immutable input')
            digest.update(chunk)
            if path not in (CODE, LLVM):
                chunks.append(chunk)
            offset += len(chunk)
        sha = digest.hexdigest()
        if expected_sha is not None and sha != expected_sha:
            raise ValueError('Input SHA mismatch')
        if signature(os.fstat(fd)) != signature(before) or signature(admit(path)) != signature(before):
            raise ValueError('Input changed during read')
        return b''.join(chunks), {'path': str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path),
                                'bytes': before.st_size, 'sha256': sha}
    finally:
        os.close(fd)


def write_new(path, payload):
    data = (json.dumps(payload, separators=(',', ':'), ensure_ascii=True) + '\n').encode()
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as output:
        output.write(data)
    return {'path': str(path.relative_to(ROOT)), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def main():
    if len(sys.argv) != 1:
        raise ValueError('Only the fixed verified LLVM output is admitted')
    inputs = ((CODE, 12443232, CODE_SHA), (LLVM, 1805104, LLVM_SHA), (LOG, 17268414, LOG_SHA),
              (EVIDENCE, 4123, EVIDENCE_SHA), (HEADER_EVIDENCE, 2847, HEADER_SHA), (HERE, None, None), (TEST, None, None))
    before = {path: admit(path) for path, _, _ in inputs}
    for path, size, _ in inputs:
        if size is not None and before[path].st_size != size:
            raise ValueError('Fixed input size mismatch')
    for path in (INDEX.parent, REPORT.parent):
        admit(path, directory=True)
    if INDEX.exists() or INDEX.is_symlink() or REPORT.exists() or REPORT.is_symlink():
        raise ValueError('Index/output role already exists; never overwrite')
    records, payloads = {}, {}
    for path, _, sha in inputs:
        payloads[path], records[path] = read_input(path, before[path], sha)
    evidence = json.loads(payloads[EVIDENCE])
    headers = json.loads(payloads[HEADER_EVIDENCE])
    if evidence['code']['sha256'] != CODE_SHA or evidence['llvm']['stdout'] != records[LOG] or evidence['llvm']['exit'] != 0:
        raise ValueError('Original LLVM evidence binding mismatch')
    if (headers['size_of_image'], headers['checksum'], headers['coff_timestamp']) != (IMAGE_SIZE, 12473764, 1792674854):
        raise ValueError('Original header tuple mismatch')
    text = payloads[LOG].decode('utf-8')
    if not text.startswith('\nFile: ' + str(CODE) + '\nFormat: COFF-x86-64\nArch: x86_64\nAddressSize: 64bit\nUnwindInformation [\n'):
        raise ValueError('LLVM output belongs to another code scope')
    entries = parse_output(text)
    if len(entries) != 37619 or any(entries[i - 1]['begin_rva'] > entries[i]['begin_rva'] for i in range(1, len(entries))):
        raise ValueError('Original function count or sort changed')
    code = {**records[CODE], 'header_tuple': {'size_of_image': IMAGE_SIZE, 'checksum': 12473764, 'time_date_stamp': 1792674854}}
    counts = {'entries': len(entries), 'supported_rsp_body': sum(x['supported_rsp_body'] for x in entries),
              'unsupported_rsp_body': sum(not x['supported_rsp_body'] for x in entries),
              'adjacent_equal_begins': sum(entries[i - 1]['begin_rva'] == entries[i]['begin_rva'] for i in range(1, len(entries))),
              'adjacent_overlapping_ranges': sum(entries[i - 1]['end_rva_exclusive'] > entries[i]['begin_rva'] for i in range(1, len(entries)))}
    index = {'schema_version': 1, 'kind': 'llvm_rsp_frame_metadata_index', 'image_base': IMAGE_BASE,
             'code': code, 'max_stack_frame_bytes': MAX_FRAME_BYTES, 'entries': entries,
             'all_ranges_preserved': True, 'lookup_requires_all_matches': True,
             'use_condition': 'Exactly one containing range; supported_rsp_body; return_rva-1 minus begin_rva strictly greater than prolog_size; explicit conditional static_rsp_effect_assumption only.',
             'limitations': ['No live body/epilog freedom or unchanged stack/code is proved.',
                             'No arbitrary stack scanning or saved-register restoration.',
                             'Unsupported/chained/frame-pointer ranges remain present and must stop a unique lookup.']}
    index_record = write_new(INDEX, index)
    report = {'schema_version': 1, 'kind': 'llvm_rsp_frame_index_inputs', 'index': index_record,
              'code': code, 'llvm_stdout': records[LOG], 'llvm_tool': {**records[LLVM], 'version': evidence['llvm']['version']},
              'producer': records[HERE], 'synthetic_tests': records[TEST],
              'original_cli_evidence': records[EVIDENCE], 'original_header_evidence': records[HEADER_EVIDENCE],
              'max_stack_frame_bytes': MAX_FRAME_BYTES, 'counts': counts,
              'method': 'Parse existing pinned standard LLVM RuntimeFunction text blocks; sum only explicit ALLOC_SMALL/ALLOC_LARGE size and 8-byte PUSH_NONVOL. Never decode PE/.xdata here.',
              'full_code_sha256_verified': True, 'all_input_paths_admitted_before_reads': True,
              'fd_and_path_identities_unchanged': True, 'new_llvm_process_started': False,
              'dump_or_private_data_opened': False, 'runtime_started': False, 'existing_files_changed': False}
    for path, info in before.items():
        if signature(admit(path)) != signature(info):
            raise ValueError('Input changed before report issuance')
    result = write_new(REPORT, report)
    print(json.dumps({'report': result, 'index': index_record, 'counts': counts}))


if __name__ == '__main__':
    main()
