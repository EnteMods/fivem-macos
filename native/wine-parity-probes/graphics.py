#!/usr/bin/env python3
"""Prepare and run only the pinned own D3D11 readback through the reviewed DXMT overlay."""
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import struct
import tarfile
import tempfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('own_graphics_health_adapter', HERE/'health.py')
health = importlib.util.module_from_spec(spec)
spec.loader.exec_module(health)
runner = health.runner
runtime = runner.runtime
ROOT = runner.ROOT
REVIEW_PATH = 'research/dxmt-a444716-code-inputs.json'
REVIEW_SHA = '0703fd74b63eb144378dc7f298dcccb8ed423701507654785b1267e8a64f4eba'
ARCHIVE_SHA = '96feaf5d98d3c6cdc3edea9503e2891d435df8d5bfdf7d3f6998a56ec62bbd58'
ARCHIVE_BYTES = 18923969
ROLE = 'gta_v_macos_matched_dxmt_a444716'
PROVIDER_RELATIVE = 'runtime/matched-dxmt-a444716/highball'
FILES = frozenset(
    [arch+'-windows/'+name+'.dll' for arch in ('i386', 'x86_64')
     for name in ('d3d10core', 'd3d11', 'dxgi', 'winemetal')]
    + ['x86_64-windows/nvapi64.dll', 'x86_64-windows/nvngx.dll', 'x86_64-unix/winemetal.so'])
BRIDGES = {'windows/system32/winemetal.dll': 'x86_64-windows/winemetal.dll',
           'windows/syswow64/winemetal.dll': 'i386-windows/winemetal.dll'}
OVERRIDES = 'dxgi,d3d11,d3d10core,winemetal=b'
FEATURE_LEVELS = frozenset((0xb000, 0xb100, 0xc000, 0xc100, 0xc200))


def provider():
    return ROOT.parent/'GTA-V-macOS'/PROVIDER_RELATIVE


def _regular(path, boundary, *, missing=False):
    runtime.canonical(path, boundary)
    try:
        info = path.lstat()
    except FileNotFoundError:
        if missing:
            return None
        raise
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise RuntimeError('Require a regular single-link graphics artifact')
    return info


def verify_renderer():
    review = ROOT/REVIEW_PATH
    raw = runtime.read_regular(review, ROOT)
    if len(raw) != 7463 or hashlib.sha256(raw).hexdigest() != REVIEW_SHA:
        raise RuntimeError('Fixed DXMT review report changed')
    value = json.loads(raw)
    rows = value.get('files', [])
    archive = value.get('source_archive', {})
    if (value.get('schema_version') != 1 or value.get('provider_role') != ROLE
            or value.get('pin_id') != 'dxmt-highball-20260930T161516Z-a444716'
            or value.get('fixed_project_sibling') != 'GTA-V-macOS'
            or value.get('provider_relative_root') != PROVIDER_RELATIVE
            or not isinstance(rows, list) or len(rows) != 11
            or any(not isinstance(row, dict) for row in rows)
            or {row.get('relative_path') for row in rows} != FILES
            or archive.get('fixed_project_sibling') != 'GTA-V-macOS'
            or archive.get('relative_path') != 'downloads/matched-dxmt-a444716.tar.gz'
            or archive.get('bytes') != ARCHIVE_BYTES or archive.get('sha256') != ARCHIVE_SHA):
        raise RuntimeError('Renderer scope must be the literal sibling, root and complete eleven-file set')
    for row in rows:
        name = row['relative_path']
        pe = name.endswith('.dll')
        machine = 0x14c if name.startswith('i386-') else 0x8664 if pe else 0x1000007
        if (type(row.get('bytes')) is not int or row['bytes'] <= 0
                or not isinstance(row.get('sha256'), str) or re.fullmatch('[0-9a-f]{64}', row['sha256']) is None
                or row.get('architecture') != ('i386' if machine == 0x14c else 'x86_64')
                or row.get('machine') != machine or row.get('matches_verified_original_archive') is not True
                or row.get('wine_builtin_marker') is not (True if pe else None)
                or row.get('wine_placeholder_marker') is not (False if pe else None)):
            raise RuntimeError('Unexpected fixed renderer architecture or builtin contract')
    directory = provider()
    archive_path = ROOT.parent/'GTA-V-macOS/downloads/matched-dxmt-a444716.tar.gz'
    # Admit every fixed role before reading any renderer/archive bytes.
    runtime.canonical(directory, ROOT.parent)
    for row in rows:
        _regular(directory/row['relative_path'], ROOT.parent)
    _regular(archive_path, ROOT.parent)
    actual = set()
    for path in directory.rglob('*'):
        runtime.canonical(path, ROOT.parent)
        if not path.is_dir():
            _regular(path, ROOT.parent)
            actual.add(path.relative_to(directory).as_posix())
    if actual != FILES:
        raise RuntimeError('Unbound renderer directory member')
    archive_data = runtime.read_regular(archive_path, ROOT.parent)
    if len(archive_data) != ARCHIVE_BYTES or hashlib.sha256(archive_data).hexdigest() != ARCHIVE_SHA:
        raise RuntimeError('Original renderer archive changed')
    checked = []
    with tarfile.open(fileobj=io.BytesIO(archive_data)) as container:
        for row in rows:
            data = runtime.read_regular(directory/row['relative_path'], ROOT.parent)
            if len(data) != row['bytes'] or hashlib.sha256(data).hexdigest() != row['sha256']:
                raise RuntimeError('Pinned renderer code changed')
            member = container.getmember('highball/'+row['relative_path'])
            if not member.isfile() or member.size != row['bytes'] or container.extractfile(member).read() != data:
                raise RuntimeError('Renderer code differs from the verified original archive')
            if row['relative_path'].endswith('.dll'):
                if len(data) < 64 or data[:2] != b'MZ':
                    raise RuntimeError('Renderer PE header is absent')
                offset = struct.unpack_from('<I', data, 60)[0]
                if (data[offset:offset+4] != b'PE\0\0' or struct.unpack_from('<H', data, offset+4)[0] != row['machine']
                        or b'Wine builtin DLL\0' not in data[:128] or b'Wine placeholder DLL' in data[:128]):
                    raise RuntimeError('Renderer PE architecture or builtin marker changed')
            elif (len(data) < 8 or struct.unpack_from('<II', data) != (0xfeedfacf, 0x1000007)):
                raise RuntimeError('Renderer sidecar is not the fixed x86_64 Mach-O')
            checked.append(dict(row))
    return {'provider_role': ROLE, 'fixed_project_sibling': 'GTA-V-macOS', 'provider_relative_root': PROVIDER_RELATIVE,
            'review': {'path': REVIEW_PATH, 'bytes': len(raw), 'sha256': REVIEW_SHA},
            'source_archive': {'path_from_project_parent': 'GTA-V-macOS/downloads/matched-dxmt-a444716.tar.gz',
                               'bytes': ARCHIVE_BYTES, 'sha256': ARCHIVE_SHA}, 'code_inputs': checked}


def verify_graphics_inputs():
    fixture = health.verify_health()
    fixture['graphics_renderer'] = verify_renderer()
    fixture['graphics_adapter_source'] = runner.identity(HERE/'graphics.py')
    return fixture


def graphics_environment(verified):
    verify_renderer()
    env = runtime.environment(verified)
    env.update(WINEDLLPATH_PREPEND=str(provider()),
               WINEDLLOVERRIDES=env['WINEDLLOVERRIDES']+';'+OVERRIDES,
               DXMT_ALLOW_CROSS_PROCESS_SWAPCHAIN='1',
               WINEDEBUG='-all,err+all,trace+loaddll,trace+module', DYLD_PRINT_LIBRARIES='1',
               DYLD_LIBRARY_PATH=os.pathsep.join(map(str, (runtime.MOLTENVK.parent,
                   runtime.ENGINE/'lib/wine/x86_64-unix', runtime.FRAMEWORKS, runtime.GST_LIB))))
    return env


def _binding():
    runner.assert_account_free_prefix(runner.PREFIX, root=ROOT)
    return runner.bind_prefix(True)


def _bridge_marker():
    return runner.PREFIX/'.wine-parity-graphics.json'


def _expected_bridge_metadata(binding, renderer):
    selected = {row['relative_path']: row for row in renderer['code_inputs']}
    return {'role': 'own-dxmt-runtime-health', 'prefix_binding': binding, 'renderer_report_sha256': REVIEW_SHA,
            'engine_manifest_sha256': runtime.MANIFEST_SHA,
            'files': [{'relative_prefix_path': 'drive_c/'+destination, 'source_relative_path': source,
                       'bytes': selected[source]['bytes'], 'sha256': selected[source]['sha256'],
                       'machine': selected[source]['machine']} for destination, source in BRIDGES.items()]}


def _publish_new(path, data):
    _regular(path, runner.PREFIX, missing=True)
    if path.exists():
        raise RuntimeError('Never overwrite an existing prefix graphics artifact')
    descriptor, name = tempfile.mkstemp(prefix='.graphics-code-', dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, 'wb') as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        # Atomic no-clobber publication, with no replacement of an intervening unknown file.
        os.link(temporary, path, follow_symlinks=False)
    finally:
        temporary.unlink(missing_ok=True)


def verify_bridge_binding(renderer=None):
    renderer = verify_renderer() if renderer is None else renderer
    binding = _binding()
    expected = _expected_bridge_metadata(binding, renderer)
    if json.loads(runtime.read_regular(_bridge_marker(), runner.PREFIX)) != expected:
        raise RuntimeError('Prefix graphics engine/provider/inode binding changed')
    for item in expected['files']:
        data = runtime.read_regular(runner.PREFIX/item['relative_prefix_path'], runner.PREFIX)
        if len(data) != item['bytes'] or hashlib.sha256(data).hexdigest() != item['sha256']:
            raise RuntimeError('Bound prefix bridge code changed')
    if _binding() != binding:
        raise RuntimeError('Prefix inode changed during graphics verification')
    return expected


def prepare_prefix(verified, env):
    if (verified.get('manifest_sha256') != runtime.MANIFEST_SHA
            or env.get('WINEPREFIX') != str(runner.PREFIX)
            or env.get('WINESERVER') != str(runtime.ENGINE/'bin/wineserver')):
        raise RuntimeError('Graphics preparation requires the bound independent prefix and server')
    renderer = verify_renderer()
    binding = _binding()
    expected = _expected_bridge_metadata(binding, renderer)
    marker = _bridge_marker()
    # Every destination is checked before even the first source read or publication.
    for item in expected['files']:
        destination = runner.PREFIX/item['relative_prefix_path']
        runtime.canonical(destination.parent, runner.PREFIX)
        if not destination.parent.is_dir():
            raise RuntimeError('Expected bootstrapped Windows system directory is missing')
        _regular(destination, runner.PREFIX, missing=True)
    _regular(marker, runner.PREFIX, missing=True)
    if marker.exists() and json.loads(runtime.read_regular(marker, runner.PREFIX)) != expected:
        raise RuntimeError('Refusing a different existing prefix graphics binding')
    payloads = []
    for item in expected['files']:
        destination = runner.PREFIX/item['relative_prefix_path']
        data = runtime.read_regular(provider()/item['source_relative_path'], ROOT.parent)
        if len(data) != item['bytes'] or hashlib.sha256(data).hexdigest() != item['sha256']:
            raise RuntimeError('Source bridge changed before staging')
        if destination.exists() and runtime.read_regular(destination, runner.PREFIX) != data:
            raise RuntimeError('Refusing to overwrite unknown existing prefix bridge code')
        payloads.append((destination, data))
    if _binding() != binding:
        raise RuntimeError('Prefix inode changed before graphics publication')
    created = []
    for destination, data in payloads:
        if _binding() != binding:
            raise RuntimeError('Prefix inode changed during graphics publication')
        if not destination.exists():
            _publish_new(destination, data)
            created.append(destination.relative_to(runner.PREFIX).as_posix())
    if not marker.exists():
        _publish_new(marker, (json.dumps(expected, indent=2)+'\n').encode())
    return {'binding': verify_bridge_binding(renderer), 'created_relative_paths': created,
            'base_engine_modified': False}


def parse_provider_diagnostics(lines, returncode):
    native_paths = {str(provider()/'x86_64-unix/winemetal.so'): 'dxmt_winemetal_unix',
                    **{str(runtime.ENGINE/'lib/wine/x86_64-unix'/name): 'engine_'+name.removesuffix('.so')
                       for name in ('ntdll.so', 'winemac.so', 'win32u.so')}}
    pe_paths = {('c:\\windows\\system32\\'+name+'.dll'): name
                for name in ('d3d11', 'dxgi', 'd3d10core', 'winemetal')}
    native, windows, rejected_native = {}, set(), set()
    for line in lines:
        match = re.fullmatch(r'dyld\[([0-9]+)\]:\s+(?:<([0-9A-Fa-f-]{36})>\s+)?(.+)', line)
        if match and match[3] in native_paths:
            native.setdefault(int(match[1]), set()).add(native_paths[match[3]])
        match = re.search(r'\bLoaded L"([^"]+)" at (?:0x)?[0-9a-fA-F]+: (builtin|native)$', line)
        if match:
            path = match[1].replace('\\\\', '\\').casefold()
            if path in pe_paths:
                (windows if match[2] == 'builtin' else rejected_native).add(pe_paths[path])
    required_native = {'dxmt_winemetal_unix', 'engine_ntdll', 'engine_winemac', 'engine_win32u'}
    complete = sorted(pid for pid, names in native.items() if required_native <= names)
    passed = returncode == 0 and bool(complete) and {'d3d11', 'dxgi', 'winemetal'} <= windows and not rejected_native
    return {'passed': passed, 'provider_chain': {
        'complete_native_process_ids': complete,
        'native_modules': [{'pid': pid, 'roles': sorted(roles)} for pid, roles in sorted(native.items())],
        'windows_builtin_modules': sorted(windows), 'unexpected_native_renderer_modules': sorted(rejected_native),
        'only_fixed_code_roles_retained': True, 'arbitrary_diagnostic_strings_retained': False}}


def parse_graphics_output(lines, returncode, contract=None):
    contract = health.load_health_contract() if contract is None else contract
    parsed = contract('\n'.join(lines), 'graphics', returncode)
    summary = parsed.get('summary')
    level = summary.get('feature_level') if isinstance(summary, dict) else None
    valid = type(level) is int and level in FEATURE_LEVELS
    return {**parsed, 'raw_contract_passed': parsed.get('passed') is True,
            'feature_level_is_known_sdk_value': valid, 'passed': parsed.get('passed') is True and valid}


def graphics_cases():
    contract = health.load_health_contract()
    binary = ROOT/'build/windows-runtime-health/runtime_health_probe.exe'

    def diagnostics(lines, code):
        result = parse_provider_diagnostics(lines, code)
        result['prefix_bridge_binding'] = verify_bridge_binding()
        return result

    return [{'name': 'runtime_health_graphics_dxmt', 'binary': binary, 'cwd': binary.parent,
             'arguments': ['--graphics'],
             'parse_output': lambda lines, code: parse_graphics_output(lines, code, contract),
             'parse_diagnostics': diagnostics}]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('inspect', 'run'))
    args = parser.parse_args(argv)
    if args.action == 'inspect':
        print(json.dumps({'runtime': runtime.verify_runtime(), 'fixture': verify_graphics_inputs(),
                          'runtime_or_prefix_started': False, 'end_to_end_or_cef_swapchain_tested': False}, indent=2))
        return 0
    return runner.run_cases(graphics_cases(), verify_inputs=verify_graphics_inputs, role='graphics-dxmt',
                            environment_factory=graphics_environment, prepare_prefix=prepare_prefix)


if __name__ == '__main__':
    raise SystemExit(main())
