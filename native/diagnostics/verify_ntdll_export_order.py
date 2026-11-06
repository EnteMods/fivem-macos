"""Check public PE export-name order in pinned Wine files and Windows metadata."""
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = ROOT / 'research/windows-wine-ntdll-actual-names-comparison-20261106.json'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read_pinned(path, expected):
    raw = path.read_bytes()
    if digest(raw) != expected:
        raise ValueError('Pinned input hash changed: ' + str(path))
    return raw


def export_names(raw):
    def u16(offset):
        return struct.unpack_from('<H', raw, offset)[0]

    def u32(offset):
        return struct.unpack_from('<I', raw, offset)[0]

    if raw[:2] != b'MZ':
        raise ValueError('Not an MZ image')
    pe = u32(60)
    if raw[pe:pe + 4] != b'PE\0\0' or u16(pe + 4) != 0x8664:
        raise ValueError('Not AMD64 PE')
    section_count, optional_size = u16(pe + 6), u16(pe + 20)
    optional = pe + 24
    if not 1 <= section_count <= 96 or optional_size < 120 or u16(optional) != 0x20B:
        raise ValueError('Unsupported PE headers')
    sections = [struct.unpack_from('<IIII', raw, optional + optional_size + 40 * i + 8)
                for i in range(section_count)]

    def offset(rva, length):
        if length < 0:
            raise ValueError('Negative read')
        found = []
        for virtual_size, virtual_base, raw_size, raw_base in sections:
            delta = rva - virtual_base
            if 0 <= delta and delta + length <= raw_size and raw_base + delta + length <= len(raw):
                found.append(raw_base + delta)
        if len(found) != 1:
            raise ValueError('Missing or ambiguous file-backed RVA')
        return found[0]

    export_rva, export_size = struct.unpack_from('<II', raw, optional + 112)
    directory = offset(export_rva, 40)
    function_count, count, name_rva, ordinal_rva = (u32(directory + x) for x in (20, 24, 32, 36))
    if not 0 < count <= 8192 or not count <= function_count <= 65536 or export_size < 40:
        raise ValueError('Export counts outside bounds')
    names, ordinals = offset(name_rva, count * 4), offset(ordinal_rva, count * 2)
    result = []
    for index in range(count):
        if u16(ordinals + index * 2) >= function_count:
            raise ValueError('Invalid EAT index')
        name_address = u32(names + index * 4)
        chars = bytearray()
        for char_index in range(256):
            value = raw[offset(name_address + char_index, 1)]
            if value == 0:
                break
            if not 33 <= value <= 126:
                raise ValueError('Unexpected export-name encoding')
            chars.append(value)
        else:
            raise ValueError('Unbounded export name')
        if not chars:
            raise ValueError('Empty export name')
        result.append(bytes(chars))
    return result


def ordered_summary(names):
    violations = [i for i in range(1, len(names)) if names[i - 1] >= names[i]]
    return {'name_count': len(names), 'unique_count': len(set(names)),
            'strict_ascii_ascending': not violations,
            'nonascending_pair_count': len(violations),
            'first_violation_indices': violations[:3]}


def main():
    comparison_raw = REFERENCE.read_bytes()
    comparison = json.loads(comparison_raw)
    windows = comparison['windows_reference']
    windows_raw = read_pinned(ROOT / windows['path'], windows['json_sha256'])
    metadata = json.loads(windows_raw)
    names = [row['name'].encode('ascii') for row in metadata['exports']]
    if len(names) != metadata['nameCount']:
        raise ValueError('Windows metadata count changed')
    results = [{'input_kind': 'user_collected_windows_metadata', 'path': windows['path'],
                'sha256': digest(windows_raw), **ordered_summary(names)}]
    for label, row in comparison['comparisons'].items():
        raw = read_pinned(Path(row['wine_path']), row['wine_sha256'])
        results.append({'input_kind': 'wine_pe_file', 'label': label,
                        'path': row['wine_path'], 'sha256': digest(raw),
                        **ordered_summary(export_names(raw))})
    report = {'schema': 'public-ntdll-export-name-order-v1',
              'script_sha256': digest(Path(__file__).read_bytes()),
              'comparison_sha256': digest(comparison_raw),
              'source': 'https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#export-name-pointer-table',
              'results': results,
              'limits': ['Static file and previously collected metadata only; no target executed or changed.',
                         'Windows metadata preserves collector table order; no Windows DLL bytes were received.',
                         'This check cannot identify the private resolver target, issuer or reason for its failure.']}
    destination = ROOT / 'research/public-ntdll-export-name-order-20261106.json'
    with destination.open('x') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'report': str(destination), 'results': results}))


if __name__ == '__main__':
    main()
