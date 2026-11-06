"""Explicit one-DLL WinINet candidate for the existing authorized Source UI role."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from types import ModuleType, SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
SOURCE_PREFIX = ROOT / 'prefixes/fivem-source-main'
ENGINE = ROOT / 'runtime/wine-session-proxy/engine'
MANIFEST_SHA = '94d892713d27db706a719a700e95252e9a1fb43cd0de94aaba7f4d6c9e7f0475'
BUILD_SHA = '46bf63d662dfa0a5c05d2d807f5338b930c36375d6f22bd2da5aad68f229e8b0'
PARITY_PATH = ROOT / 'native/windows-client/parity_runtime_profile.py'
PARITY_SHA = 'b84ae9bfcd201ab53014a15e8e4cc6cb6a169d817908d0388dd3c23689b66119'
VERIFIER_PATH = ROOT / 'native/wine-session-proxy-runtime/environment.py'
VERIFIER_SHA = '10c12e571f2407fed9e9ccb207dee69d0da624e2d055986bfb3c2526913a44f7'
CONTROL_PATH = ROOT / 'research/wine-parity-session-proxy-candidate-20261103T094740766641Z-results.json'
CONTROL_SHA = '4bbaf17df92c173937f824f34a462f3265822ebef9731ebe256044472cf2cd7b'
CONTROL_SIZE = 73404
CONTROL_LABEL = 'wine-parity-session-proxy-candidate-20261103T094740766641Z'
CONTROL_RUNNERS = (
    ('native/windows-session-proxy-tests/run.py', 'c4e63ae1d081a054f9230d904ee35d343a91c53ebd7ae41ab24b190dbffea907'),
    ('native/windows-public-options-direct/run.py', 'feb9d3e4a4ee3bc17d30608c3a4d34c5e71ef5fc83b854b2bd056809de30cd1b'),
    ('native/windows-public-options-probe/run.py', 'b431e46860e0e5f69ea66df43a7e0b16f1247960ef447a4822b36ee332bd37ce'),
)
RUNNER_PINS = (
    ('native/wine-session-proxy-runtime/run.py', 2971, 'e3874611792e7d2fcb225573d6ae905710f65d124e13c87bfc369e8ff87a6d48'),
    ('native/wine-session-proxy-runtime/environment.py', 17461, VERIFIER_SHA),
    ('native/wine-parity-probes/run.py', 22555, '476315318538c8db93712ba74848d636a5af587492d590a2e33e4b4d3aae6fe7'),
)
CASES = (
    ('offline_session_proxy_state', 'build/windows-session-proxy-tests/session_proxy_tests.exe', 2451,
     'ef8c9c7b916089e08fdd537deaad5e929203444c233ed2e3024bd9b8082b7901'),
    ('public_options_direct_proxy_get', 'build/windows-public-options-direct/public_options_direct.exe', 1010,
     '89aa9c80e19bc7c669995f5f6d9d33079c15e25508d3b50967f2cee5ffdfeba1'),
    ('public_options_get', 'build/windows-public-options-probe/public_options_probe.exe', 913,
     'fc30a227512e7bced1aa849acdffdff96cbe5b719f621e471062c125ac03f233'),
)
CLEANUP = [{'flag': '-k', 'exit': 0}, {'flag': '-w', 'exit': 0}]


def _read_direct(path):
    if not path.is_absolute() or not path.is_relative_to(ROOT) or '..' in path.parts:
        raise RuntimeError('Source candidate code/evidence outside fixed project scope')
    current = ROOT
    for part in path.relative_to(ROOT).parts:
        current /= part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or (current != path and not stat.S_ISDIR(info.st_mode)):
            raise RuntimeError('Source candidate code/evidence has an alias')
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise RuntimeError('Source candidate code/evidence must be a direct single-link file')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as source:
        opened = os.fstat(source.fileno())
        data = source.read()
        after = os.fstat(source.fileno())
    fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    if any(getattr(before, key) != getattr(opened, key) or getattr(opened, key) != getattr(after, key) for key in fields):
        raise RuntimeError('Source candidate code/evidence changed while reading')
    return data


def _load_frozen(path, digest, name):
    data = _read_direct(path)
    if hashlib.sha256(data).hexdigest() != digest:
        raise RuntimeError('Frozen Source candidate reuse code changed before execution')
    module = ModuleType(name)
    module.__file__ = str(path)
    previous_path = sys.path[:]
    try:
        exec(compile(data, str(path), 'exec'), module.__dict__)
    finally:
        sys.path[:] = previous_path
    return module


parity = _load_frozen(PARITY_PATH, PARITY_SHA, '_session_proxy_source_parity')
candidate = _load_frozen(VERIFIER_PATH, VERIFIER_SHA, '_session_proxy_source_verifier')


def _same(left, right):
    return json.dumps(left, sort_keys=True, separators=(',', ':')) == json.dumps(right, sort_keys=True, separators=(',', ':'))


def _identity(path, data):
    return {'path': str(path.relative_to(ROOT)), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def _check_engine(engine):
    if (engine.get('profile') != 'wine-session-proxy-api-probes' or type(engine.get('protocol_version')) is not int
            or engine['protocol_version'] != 1810 or engine.get('manifest_sha256') != MANIFEST_SHA
            or engine.get('engine') != 'runtime/wine-session-proxy/engine'
            or engine.get('prefix') != 'prefixes/wine-session-proxy-regression'
            or engine.get('entries') != 1761 or engine.get('changed_files') != ['lib/wine/x86_64-windows/wininet.dll']
            or engine.get('selective_build_report') != {'path': 'research/wine-session-proxy-build.json', 'bytes': 3875, 'sha256': BUILD_SHA}):
        raise RuntimeError('Require the exact fully verified one-DLL candidate engine')


def _check_control_record(record, engine):
    if (record.get('profile') != 'wine-session-proxy-api-probes' or record.get('probe_role') != 'session-proxy-candidate'
            or type(record.get('protocol_version')) is not int or record['protocol_version'] != 1810
            or record.get('prefix') != 'prefixes/wine-session-proxy-regression'
            or record.get('passed') is not True or record.get('runtime_started') is not True
            or record.get('only_own_fixtures_and_builtin_initialization') is not True
            or record.get('client_cef_rockstar_game_or_account_code_started') is not False
            or not _same(record.get('cleanup'), CLEANUP)
            or record.get('quarantine_cleared_after_confirmed_cleanup') is not True
            or type(record.get('initialization_exit')) is not int or record['initialization_exit'] != 0
            or any(key in record for key in ('failure', 'post_run_guard_failure', 'prefix_terminal_state_uncertain'))
            or not _same(record.get('runtime_verification'), engine)):
        raise RuntimeError('Require the actual clean own control on the identical candidate engine')
    binding = record.get('prefix_binding', {})
    if (binding.get('prefix') != 'prefixes/wine-session-proxy-regression'
            or binding.get('role') != 'wine-session-proxy-api-probes'
            or type(binding.get('protocol_version')) is not int or binding['protocol_version'] != 1810
            or binding.get('manifest_sha256') != MANIFEST_SHA):
        raise RuntimeError('Own control has another prefix/engine binding')
    runs = record.get('runs')
    if not isinstance(runs, list) or len(runs) != 3:
        raise RuntimeError('Require all three original candidate controls')
    for row, (name, binary, _, _) in zip(runs, CASES):
        if (row.get('name') != name or row.get('binary') != binary
                or type(row.get('exit')) is not int or row['exit'] != 0 or row.get('passed') is not True
                or row.get('log') != 'logs/' + CONTROL_LABEL + '-' + name + '.ndjson'
                or row.get('wine_log') != 'logs/' + CONTROL_LABEL + '-' + name + '-wine.log'):
            raise RuntimeError('Own control case, exit or fixed log role differs')
    offline, direct, preconfig = runs
    if (offline.get('complete') is not True or offline.get('rejected') != 0
            or offline.get('summary') != {'event': 'completed', 'cases': 20, 'failed_cases': 0,
                'sessions_opened': 2, 'handles_closed': 2, 'network_requests': 0, 'exit': 0}
            or len(offline.get('cases', [])) != 20
            or any(row.get('contract') is not True for row in offline['cases'])
            or direct.get('direct_setup_passed') is not True
            or direct.get('direct_setup_events') != [{'stage': 'OPEN', 'succeeded': 1, 'error': 0},
                                                   {'stage': 'PROXY', 'succeeded': 1, 'error': 0}]):
        raise RuntimeError('The actual 20-case state control or DIRECT setup did not pass')
    for row in (direct, preconfig):
        summary = row.get('summary', {})
        if (row.get('api_contract_succeeded') is not True or row.get('bounded_body_eof_confirmed') is not True
                or row.get('complete_api_sequence') is not True or summary.get('http_status') != 200
                or summary.get('body_bytes') != 661 or summary.get('eof_count') != 1
                or summary.get('body_complete') != 1 or summary.get('successful_closes') != 3
                or summary.get('cleanup') != 1):
            raise RuntimeError('Require both actual public GET/EOF/close controls')


def verify_own_control(engine):
    raw = _read_direct(CONTROL_PATH)
    if len(raw) != CONTROL_SIZE or hashlib.sha256(raw).hexdigest() != CONTROL_SHA:
        raise RuntimeError('Actual candidate own-control report changed')
    record = json.loads(raw)
    _check_control_record(record, engine)
    fixture = record.get('fixture_inputs', {})
    expected_runners = [{'path': path, 'bytes': size, 'sha256': digest} for path, size, digest in RUNNER_PINS]
    if fixture.get('runner_sources') != expected_runners or len(fixture.get('control_inputs', [])) != 3:
        raise RuntimeError('Own control runner or fixture-input roles differ')
    # All selected report/log/module paths below are literals, never report-selected paths.
    for name, size, digest in RUNNER_PINS:
        data = _read_direct(ROOT / name)
        if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
            raise RuntimeError('Own control runner code changed after the actual run')
    controls = [_load_frozen(ROOT / name, digest, '_session_proxy_source_control_' + str(n))
                for n, (name, digest) in enumerate(CONTROL_RUNNERS)]
    current_inputs = [control.verify_inputs() for control in controls]
    if not _same(fixture['control_inputs'], current_inputs):
        raise RuntimeError('Actual candidate control fixture/build/parser inputs changed')
    binaries = {}
    for item in current_inputs:
        for identity in item['runtime_inputs']:
            if identity['path'] in binaries and binaries[identity['path']] != identity:
                raise RuntimeError('Own control binary identity conflict')
            binaries[identity['path']] = identity
    if not _same(fixture, {'probe_family': 'session-proxy-candidate-own-state-and-public-get',
                         'runtime_inputs': list(binaries.values()), 'control_inputs': current_inputs,
                         'runner_sources': expected_runners}):
        raise RuntimeError('Own control full fixture closure differs')
    logs = []
    for control, row, (name, binary, size, digest) in zip(controls, record['runs'], CASES):
        case = control.cases()
        if (len(case) != 1 or case[0]['name'] != name or case[0]['binary'] != ROOT / binary
                or case[0].get('arguments') != ()):
            raise RuntimeError('Own parser delegation has another case role')
        path = ROOT / ('logs/' + CONTROL_LABEL + '-' + name + '.ndjson')
        data = _read_direct(path)
        if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
            raise RuntimeError('Actual own control numeric stdout changed')
        parsed = case[0]['parse_output'](data.decode().splitlines(), row['exit'])
        if parsed.get('passed') is not True or any(not _same(value, row.get(key)) for key, value in parsed.items()):
            raise RuntimeError('Actual own stdout no longer meets its original strict parser')
        logs.append(_identity(path, data))
    return {'report': _identity(CONTROL_PATH, raw), 'numeric_stdout_inputs': logs,
            'fixture_inputs': fixture, 'all_three_controls_reparsed_passed': True,
            'own_api_prefix_accessed': False}


def verify_profile(parity_context):
    engine = candidate.verify_runtime()
    _check_engine(engine)
    return {'profile': 'session-proxy', 'engine': engine, 'own_control_proof': verify_own_control(engine),
            'matched_parity_reference': parity_context,
            'source_profile_code': _identity(Path(__file__).resolve(), _read_direct(Path(__file__).resolve())),
            'source_stage_update_performed': False, 'gta_installation_changed': False,
            'ui_authentication_anticheat_or_gameplay_success_claim': False}


def source_environment(matched, source_prefix):
    if source_prefix != SOURCE_PREFIX:
        raise RuntimeError('Session-proxy Source profile only accepts the existing authorized Source prefix')
    environment = parity.source_environment(matched, source_prefix)
    environment.update(WINESERVER=str(ENGINE / 'bin/wineserver'), WINELOADER=str(ENGINE / 'bin/wine'))
    return environment


def select_runtime(matched, source_prefix=SOURCE_PREFIX):
    if source_prefix != SOURCE_PREFIX:
        raise RuntimeError('Refusing another prefix before session-proxy Source verification')
    original = parity.select_runtime(matched, source_prefix)
    context = verify_profile(original.source_runtime_profile)

    def before_source_spawn():
        rechecked = parity.select_runtime(matched, source_prefix)
        if not _same(verify_profile(rechecked.source_runtime_profile), context):
            raise RuntimeError('Session-proxy Source runtime, original parity context or own control changed before spawn')

    return SimpleNamespace(ENGINE=ENGINE, WINE=ENGINE / 'bin/wine', PREFIX=original.PREFIX,
        environment=lambda: source_environment(matched, source_prefix), before_source_spawn=before_source_spawn,
        source_runtime_profile=context)
