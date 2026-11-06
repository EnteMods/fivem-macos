"""Explicit read-diagnostic engine for the existing source role; no implicit starts."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from types import SimpleNamespace, ModuleType

import parity_runtime_profile as baseline

ROOT = baseline.ROOT
SOURCE_PREFIX = baseline.SOURCE_PREFIX
ENGINE = ROOT / 'runtime/wine-read-diagnostics/engine'
ROOT_PIN = ROOT / 'research/wine-read-engine-code-inputs.json'
VERIFIER = ROOT / 'native/wine-read-diagnostics/environment.py'
READY = ROOT / 'research/wine-read-source-prerequisites.json'
DEBUG = '-all,+cfxnum'
MODES = frozenset(('kernel-off', 'kernel-on', 'kernel-unlisted', 'wininet-off', 'wininet-on',
                   'jobs', 'font', 'graphics', 'pipe-off', 'pipe-on'))
CLEANUP = [{'flag': '-k', 'exit': 0}, {'flag': '-w', 'exit': 0}]


def bootstrap_read(path):
    if path not in (ROOT_PIN, VERIFIER) or not path.is_relative_to(ROOT) or '..' in path.parts:
        raise RuntimeError('Unreviewed read-source verifier bootstrap path')
    current = ROOT
    for part in path.relative_to(ROOT).parts:
        current /= part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
            raise RuntimeError('Refusing a read-source verifier alias or special object')
        if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
            raise RuntimeError('Read-source verifier inputs must be single-link files')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise RuntimeError('Read-source verifier input changed before reading')
        return source.read()


def identity_shape(item, path):
    return (isinstance(item, dict) and set(item) == {'path', 'bytes', 'sha256'}
            and item.get('path') == path and type(item.get('bytes')) is int and item['bytes'] > 0
            and type(item.get('sha256')) is str and re.fullmatch('[0-9a-f]{64}', item['sha256']) is not None)


def candidate_module():
    pin_bytes = bootstrap_read(ROOT_PIN)
    pin = json.loads(pin_bytes)
    if (not isinstance(pin, dict) or type(pin.get('schema_version')) is not int or pin['schema_version'] != 1
            or pin.get('profile') != 'wine-read-api-probes' or type(pin.get('protocol_version')) is not int
            or pin['protocol_version'] != 1810
            or not identity_shape(pin.get('verifier'), str(VERIFIER.relative_to(ROOT)))):
        raise RuntimeError('Require Root admission of the fixed read-source verifier code identity')
    raw = bootstrap_read(VERIFIER)
    identity = pin['verifier']
    if len(raw) != identity['bytes'] or hashlib.sha256(raw).hexdigest() != identity['sha256']:
        raise RuntimeError('Root-bound read-source verifier code changed before loading')
    module = ModuleType('source_read_engine_verifier')
    module.__file__ = str(VERIFIER)
    exec(compile(raw, str(VERIFIER), 'exec'), module.__dict__)
    module.source_verifier_admission = {
        'code_pin': {'path': str(ROOT_PIN.relative_to(ROOT)), 'bytes': len(pin_bytes),
                     'sha256': hashlib.sha256(pin_bytes).hexdigest()},
        'verifier': dict(identity), 'verified_before_code_execution': True}
    return module


def verify_prerequisites(candidate, engine):
    raw = candidate.read_regular(READY)
    ready = json.loads(raw)
    if (not isinstance(ready, dict) or type(ready.get('schema_version')) is not int or ready['schema_version'] != 1
            or ready.get('profile') != 'wine-read-source-prerequisites'
            or ready.get('engine_manifest_sha256') != engine['manifest_sha256']
            or ready.get('source_stage_modified') is not False
            or any(ready.get(family + '_behavior_equal_on_off') is not True for family in ('kernel', 'wininet', 'pipe'))):
        raise RuntimeError('Require Root-recorded prerequisites for this exact read-diagnostic engine')
    checks = ready.get('checks')
    if (not isinstance(checks, list) or len(checks) != len(MODES)
            or any(not isinstance(item, dict) or type(item.get('mode')) is not str for item in checks)
            or {item['mode'] for item in checks} != MODES):
        raise RuntimeError('Every own read-diagnostic regression mode must be present exactly once')
    admitted = []
    for item in checks:
        mode = item['mode']
        name = item.get('path')
        if (set(item) != {'mode', 'path', 'bytes', 'sha256'} or type(name) is not str
                or re.fullmatch(r'research/wine-parity-numeric-' + re.escape(mode)
                                + r'-[0-9]{8}T[0-9]{12}Z-results[.]json', name) is None
                or not identity_shape({key: item[key] for key in ('path', 'bytes', 'sha256')}, name)):
            raise RuntimeError('Unreviewed read prerequisite result path or identity')
        admitted.append((item, mode, name))
    result = []
    for item, mode, name in admitted:
        data = candidate.read_regular(ROOT / name)
        if len(data) != item['bytes'] or hashlib.sha256(data).hexdigest() != item['sha256']:
            raise RuntimeError('Read-diagnostic prerequisite result changed')
        report = json.loads(data)
        if (not isinstance(report, dict) or report.get('passed') is not True or report.get('runtime_started') is not True
                or report.get('profile') != 'wine-read-api-probes'
                or type(report.get('protocol_version')) is not int or report['protocol_version'] != 1810
                or report.get('probe_role') != 'numeric-' + mode
                or report.get('prefix') != 'prefixes/wine-read-regression'
                or not isinstance(report.get('runtime_verification'), dict)
                or report['runtime_verification'].get('manifest_sha256') != engine['manifest_sha256']
                or report.get('cleanup') != CLEANUP
                or any(type(row.get('exit')) is not int for row in report['cleanup'])
                or report.get('quarantine_cleared_after_confirmed_cleanup') is not True
                or report.get('only_own_fixtures_and_builtin_initialization') is not True
                or report.get('client_cef_rockstar_game_or_account_code_started') is not False
                or any(key in report for key in ('failure', 'post_run_guard_failure', 'prefix_terminal_state_uncertain',
                                                 'numeric_adapter_guard_failure'))):
            raise RuntimeError('Require an actual clean account-free read regression run')
        runs = report.get('runs')
        if (not isinstance(runs, list) or not runs
                or any(not isinstance(row, dict) or row.get('passed') is not True
                       or type(row.get('exit')) is not int or row['exit'] != 0 for row in runs)):
            raise RuntimeError('A read prerequisite has missing or unsuccessful own cases')
        result.append(dict(item))
    return {'record': str(READY.relative_to(ROOT)), 'sha256': hashlib.sha256(raw).hexdigest(),
            'checked_result_identities': result, 'root_reviewed_runtime_reports': True,
            'api_prefix_or_account_storage_read': False}


def verify_profile():
    candidate = candidate_module()
    engine = candidate.verify_runtime()
    if engine.get('protocol_version') != 1810:
        raise RuntimeError('Read-diagnostic engine protocol changed')
    admission = candidate.source_verifier_admission
    if (engine.get('root_pin') != admission['code_pin']
            or engine.get('verifier_source') != dict(admission['verifier'], path=str(VERIFIER))):
        raise RuntimeError('Read verifier code or Root pin changed between admission and engine verification')
    return {'profile': 'read', 'engine': engine, 'verifier_admission': admission,
            'renderer': baseline.graphics.verify_renderer(), 'source_bridge_code': baseline.verify_source_bridge_code(),
            'own_runtime_prerequisites': verify_prerequisites(candidate, engine),
            'source_prefix_code_only_read': True, 'source_stage_update_performed': False,
            'source_debug_channels': DEBUG, 'authentication_security_or_integrity_decisions_modified': False,
            'launcher_authentication_gameplay_or_anticheat_success_claim': False}


def source_environment(matched, source_prefix, candidate):
    if source_prefix != SOURCE_PREFIX:
        raise RuntimeError('Read-diagnostic source runtime requires the existing authorized source prefix')
    env = baseline.source_environment(matched, source_prefix)
    search = os.pathsep.join(map(str, (ENGINE / 'lib/wine/x86_64-unix', candidate.MOLTENVK.parent,
                                      candidate.FRAMEWORKS, candidate.GST_LIB)))
    env.update(WINEPREFIX=str(SOURCE_PREFIX), WINESERVER=str(ENGINE / 'bin/wineserver'),
               PATH=str(ENGINE / 'bin') + ':/usr/bin:/bin:/usr/sbin:/sbin',
               DYLD_LIBRARY_PATH=search, DYLD_FALLBACK_LIBRARY_PATH=search, WINEDEBUG=DEBUG)
    return env


def select_runtime(matched, source_prefix=SOURCE_PREFIX):
    if source_prefix != SOURCE_PREFIX:
        raise RuntimeError('Refusing a different read-diagnostic source role')
    baseline._matched_base(matched)
    sibling = ROOT.parent / 'GTA-V-macOS'
    if (matched.ENGINE != sibling / 'runtime/matched-wine11-r29/engine'
            or matched.WINE != matched.ENGINE / 'bin/wine'
            or matched.PREFIX != sibling / 'prefixes/rockstar-legacy'):
        raise RuntimeError('Read-diagnostic source selection requires the retained matched baseline')
    context = verify_profile()
    candidate = candidate_module()

    def before_source_spawn():
        baseline._matched_base(matched)
        if verify_profile() != context:
            raise RuntimeError('Read-diagnostic source code or regression evidence changed before spawn')

    return SimpleNamespace(ENGINE=ENGINE, WINE=ENGINE / 'bin/wine', PREFIX=matched.PREFIX,
        environment=lambda: source_environment(matched, source_prefix, candidate), source_winedebug=DEBUG,
        before_source_spawn=before_source_spawn, source_runtime_profile=context)
