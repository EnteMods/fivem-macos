#!/usr/bin/env python3
"""Compare an offline M103 NUI DLL with the canonical V12 PE contracts."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
STAGE = ROOT / 'build/windows-source-integration'
MANIFEST = ROOT / 'research/client-source-code-inputs-v12.json'
MANIFEST_PIN = (174675, '410d70694279d659ab84b90841eea547bdfa3c333b17e5f6bd9d0125c8a3d9b2')
LLVM = Path('/opt/homebrew/opt/llvm/bin/llvm-readobj')
CONSUMERS = {
    'citizen-game-main.dll': 29, 'conhost-v2.dll': 6, 'extra-natives-five.dll': 4,
    'glue.dll': 20, 'loading-screens-five.dll': 7, 'nui-gsclient.dll': 4, 'nui-resources.dll': 20,
}
CEF = 'libcef.dll'
CEF_HASHES = ('0c8498b736ae104e62ab02d934ce5b123763f92f', '57e063df2e22f33cc8cf73989e095b697cdde298')
SYSTEM = frozenset('advapi32 bcrypt comctl32 combase concrt140 crypt32 d3d11 dxgi gdi32 imm32 kernel32 '
                   'kernelbase msvcp140 msvcp140_1 msvcp140_2 ntdll ole32 oleaut32 psapi rpcrt4 runtimeobject '
                   'secur32 setupapi shell32 shcore shlwapi ucrtbase user32 userenv '
                   'vcruntime140 vcruntime140_1 version windowscodecs winhttp wininet winmm ws2_32'.split())
IMPORTS = re.compile(r'^(Import|DelayImport) \{\n  Name: ([A-Za-z0-9_.-]+)\n(.*?)^\}', re.M | re.S)
SYMBOLS = re.compile(r'^ +Symbol: ([^ \n]*) \(([0-9]+)\)$', re.M)
EXPORTS = re.compile(r'^Export \{\n  Ordinal: ([0-9]+)\n  Name: ([^\n]*)\n  RVA: (0x[0-9A-Fa-f]+)\n\}', re.M)
COMPONENT = re.compile(r'^    Name: FXCOMPONENT \[\n(.*?)(?=^    \])', re.M | re.S)
COMPONENT_TYPE = re.compile(r'^  Type: ID 115 \[\n(.*?)(?=^  \])', re.M | re.S)
PACKAGED_CRT = frozenset(f'{name}.dll' for name in ('concrt140', 'msvcp140', 'msvcp140_1', 'msvcp140_2',
    'msvcp140_atomic_wait', 'msvcp140_codecvt_ids', 'vccorlib140', 'vcruntime140', 'vcruntime140_1', 'ucrtbase'))
ACCESSORS = {
    '?GetWidth@NUIWindow@@QEAAHXZ': bytes.fromhex('8b416cc3'),
    '?GetHeight@NUIWindow@@QEAAHXZ': bytes.fromhex('8b4170c3'),
    '?GetRoundedWidth@NUIWindow@@QEAAHXZ': bytes.fromhex('8b4174c3'),
    '?GetRenderBuffer@NUIWindow@@QEAAPEAXXZ': bytes.fromhex('488b81a0000000c3'),
}

sys.path.insert(0, str(ROOT / 'native/windows-client'))
from inspect_game import PE


def stable_file(path):
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or path.resolve(strict=True) != path:
        raise ValueError(f'Expected a plain file: {path}')
    return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns


def identity(path, before):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    if stable_file(path) != before:
        raise ValueError(f'File changed while verifying: {path}')
    return before[2], digest.hexdigest()


def inventory(path, pins=None, *, nui=False):
    before = stable_file(path)
    size, digest = identity(path, before)
    if pins is not None and (size, digest) != pins:
        raise ValueError(f'V12 identity mismatch: {path}')
    options = ['--file-headers', '--coff-imports', '--coff-exports']
    if nui:
        options.append('--coff-resources')
    output = subprocess.run([str(LLVM), *options, str(path)], check=True, capture_output=True,
                            text=True, timeout=30).stdout
    if 'Machine: IMAGE_FILE_MACHINE_AMD64' not in output or 'Magic: 0x20B' not in output:
        raise ValueError(f'Expected AMD64 PE32+: {path}')

    imports = {}
    for mode, dll, body in IMPORTS.findall(output):
        rows = SYMBOLS.findall(body)
        key = mode, dll.lower()
        if not rows or key in imports:
            raise ValueError(f'Unexpected PE import table: {path}')
        imports[key] = {name if name else int(ordinal) for name, ordinal in rows}
    export_rows = EXPORTS.findall(output)
    exports = {name: (int(ordinal), int(rva, 16)) for ordinal, name, rva in export_rows if name and int(rva, 16)}
    ordinals = {int(ordinal) for ordinal, _, rva in export_rows if int(rva, 16)}
    result = {'identity': {'path': str(path), 'bytes': size, 'sha256': digest}, 'imports': imports,
              'exports': exports, 'ordinals': ordinals}

    if nui:
        if len(exports) != len(ordinals) or len(export_rows) != output.count('\nExport {'):
            raise ValueError('NUI has unnamed, null, or forwarded export entries')
        pe = PE(path)
        kinds = {}
        for name, (_, rva) in exports.items():
            sections = [s for s in pe.sections if s['rva'] <= rva < s['rva'] + s['virtual_bytes']]
            if len(sections) != 1:
                raise ValueError(f'Unclassified NUI export: {name}')
            flags = sections[0]['characteristics']
            kinds[name] = 'function' if flags & 0x20000000 else 'data'
        resource_types = COMPONENT_TYPE.findall(output)
        resources = COMPONENT.findall(resource_types[0]) if len(resource_types) == 1 else []
        if len(resources) != 1 or 'Language: (ID 1033)' not in resources[0]:
            raise ValueError('Expected one FXCOMPONENT resource')
        locations = re.findall(r'DataRVA: (0x[0-9A-Fa-f]+)\n\s+DataSize: ([0-9]+)', resources[0])
        if len(locations) != 1 or not 1 <= int(locations[0][1]) <= 4096:
            raise ValueError('Unexpected FXCOMPONENT payload')
        rva, count = int(locations[0][0], 16), int(locations[0][1])
        offset = pe.file_offset(rva, count)
        result['component'] = json.loads(pe.data[offset:offset + count])
        result['kinds'] = kinds
        result['cef_header_hash_literals'] = {value: value.encode() + b'\0' in pe.data for value in CEF_HASHES}
        result['jitless_literal'] = b'--jitless\0' in pe.data
        result['accessors'] = {}
        for name, code in ACCESSORS.items():
            if name in exports:
                offset = pe.file_offset(exports[name][1], len(code))
                result['accessors'][name] = pe.data[offset:offset + len(code)] == code
            else:
                result['accessors'][name] = False
    if stable_file(path) != before:
        raise ValueError(f'File changed during PE inspection: {path}')
    return result


def read_pe(path):
    """Return direct loader dependency names and the offline file identity."""
    info = inventory(Path(path).absolute())
    return {'identity': info['identity'],
            'normal_imports': sorted(dll for mode, dll in info['imports'] if mode == 'Import'),
            'delay_imports': sorted(dll for mode, dll in info['imports'] if mode == 'DelayImport')}


def manifest_roles():
    before = stable_file(MANIFEST)
    raw = MANIFEST.read_bytes()
    if (len(raw), hashlib.sha256(raw).hexdigest()) != MANIFEST_PIN or stable_file(MANIFEST) != before:
        raise ValueError('Canonical V12 manifest identity mismatch')
    manifest = json.loads(raw)
    if manifest['stage'] != STAGE.relative_to(ROOT).as_posix() or manifest['developer_code_version'] != 12:
        raise ValueError('Unexpected V12 manifest role')
    rows = {row['name'].lower(): row for row in manifest['files']}
    if len(rows) != len(manifest['files']):
        raise ValueError('Ambiguous V12 code role')
    return rows


def provider_name(dll, roles):
    if dll == CEF:
        return 'bin/libcef.dll'
    if dll in roles:
        return dll
    if (dll in PACKAGED_CRT or dll in ('libegl.dll', 'libglesv2.dll', 'chrome_elf.dll')) and f'bin/{dll}' in roles:
        return f'bin/{dll}'
    return None


def missing(symbols, provider):
    return sorted((symbol if isinstance(symbol, str) else f'#{symbol}') for symbol in symbols
                  if (isinstance(symbol, str) and symbol not in provider['exports'])
                  or (isinstance(symbol, int) and symbol not in provider['ordinals']))


def verify(candidate_path):
    roles = manifest_roles()
    cache = {}

    def stock(role, *, nui=False):
        if role not in cache:
            row = roles[role]
            path = STAGE / row['name']
            if role == 'nui-core.dll':
                backup = STAGE / '.nui-core.dll.resize-v12.previous/nui-core.dll'
                if backup.is_file():
                    path = backup
            cache[role] = inventory(path, (row['bytes'], row['sha256']), nui=nui)
        return cache[role]

    baseline = stock('nui-core.dll', nui=True)
    candidate = inventory(candidate_path, nui=True)
    cef = stock('bin/libcef.dll')
    consumed, consumers = set(), {}
    for dll, count in CONSUMERS.items():
        provider = stock(dll)
        symbols = provider['imports'].get(('Import', 'nui-core.dll'), set())
        if len(symbols) != count or missing(symbols, baseline):
            raise ValueError(f'Unexpected stock NUI consumer contract: {dll}')
        consumed.update(symbols)
        consumers[dll] = {'identity': provider['identity'], 'imports': count, 'missing': missing(symbols, candidate)}
    if len(consumed) != 58 or len(baseline['exports']) != 113:
        raise ValueError('Unexpected aggregate V12 NUI surface')

    project, outside = [], []
    for (mode, dll), symbols in sorted(candidate['imports'].items()):
        role = provider_name(dll, roles)
        row = {'dll': dll, 'mode': mode, 'imports': len(symbols), 'ordinal_imports': sum(type(x) is int for x in symbols)}
        if role is not None:
            exact = stock(role)
            project.append(dict(row, provider=exact['identity'], missing=missing(symbols, exact)))
        else:
            windows = dll.removesuffix('.dll') in SYSTEM or dll.startswith(('api-ms-win-', 'ext-ms-win-'))
            outside.append(dict(row, status='windows_or_crt_not_checked' if windows else 'provider_not_bound'))

    old_cef = baseline['imports'].get(('DelayImport', CEF), set())
    new_cef = candidate['imports'].get(('DelayImport', CEF), set())
    if len(old_cef) != 53 or missing(old_cef, cef):
        raise ValueError('Unexpected V12 CEF103 delay-import contract')
    cef_report = {'stock_delayed_imports': len(old_cef), 'candidate_delayed_imports': len(new_cef),
                  'added': sorted(map(str, new_cef - old_cef)), 'omitted': sorted(map(str, old_cef - new_cef)),
                  'api_hash_import_delayed': 'cef_api_hash' in new_cef,
                  'regular_import_present': ('Import', CEF) in candidate['imports'],
                  'matching_header_hash_literals': candidate['cef_header_hash_literals']}
    base_names, new_names = set(baseline['exports']), set(candidate['exports'])
    shared = base_names & new_names
    exports = {'stock_count': len(base_names), 'candidate_count': len(new_names),
               'missing': sorted(base_names - new_names), 'added': sorted(new_names - base_names),
               'kind_changes': sorted(name for name in shared if baseline['kinds'][name] != candidate['kinds'][name]),
               'ordinal_changes': sorted(name for name in shared if baseline['exports'][name][0] != candidate['exports'][name][0])}
    component_matches = candidate['component'] == baseline['component']
    passed = (not any(consumers[dll]['missing'] for dll in consumers)
              and not any(row['missing'] for row in project)
              and not any(row['status'] == 'provider_not_bound' for row in outside)
              and not any(exports[key] for key in ('missing', 'added', 'kind_changes', 'ordinal_changes'))
              and component_matches and cef_report['api_hash_import_delayed'] and not cef_report['regular_import_present']
              and all(candidate['cef_header_hash_literals'].values())
              and candidate['jitless_literal'] == baseline['jitless_literal'])
    return {'passed_static_provider_contract': passed, 'candidate': candidate['identity'], 'stock': baseline['identity'],
            'manifest_sha256': MANIFEST_PIN[1], 'consumers': consumers, 'exports': exports,
            'candidate_project_imports': project, 'outside_project_imports': outside, 'cef103': cef_report,
            'component_manifest_matches': component_matches, 'jitless_literal_matches': candidate['jitless_literal'] == baseline['jitless_literal'],
            'stock_accessor_encodings_match': baseline['accessors'], 'candidate_accessor_encodings_match': candidate['accessors'],
            'accessor_mismatches_require_manual_layout_review': not all(candidate['accessors'].values()),
            'limits': ['Named PE imports and ordinal slots establish symbol availability only.',
                       'Accessor encodings cover selected fields, not vtables, class layout, or callbacks.',
                       'Dynamic imports, system and CRT providers, startup, and rendering were not exercised.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('candidate', type=Path)
    options = parser.parse_args()
    try:
        result = verify(options.candidate.absolute())
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print(json.dumps({'passed_static_provider_contract': False, 'error': str(exc)}, indent=2))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result['passed_static_provider_contract'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
