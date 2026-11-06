"""Explicit diagnostic engine for the unchanged source client; no implicit starts."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
from types import SimpleNamespace

import parity_runtime_profile as baseline

ROOT = baseline.ROOT
SOURCE_PREFIX = baseline.SOURCE_PREFIX
ENGINE = ROOT / 'runtime/wine-numeric-diagnostics/engine'
READY = ROOT / 'research/wine-numeric-source-prerequisites.json'
DEBUG = '-all,+cfxnum'
MODES = frozenset(('kernel-off', 'kernel-on', 'kernel-unlisted', 'wininet-off', 'wininet-on', 'jobs', 'font', 'graphics'))


def candidate_module():
    spec = importlib.util.spec_from_file_location('source_numeric_engine_verifier',
                                                 ROOT / 'native/wine-numeric-diagnostics/environment.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify_prerequisites(candidate, engine):
    raw = candidate.read_regular(READY)
    ready = json.loads(raw)
    if (ready.get('schema_version') != 1 or ready.get('profile') != 'wine-numeric-source-prerequisites'
            or ready.get('engine_manifest_sha256') != engine['manifest_sha256']
            or ready.get('source_stage_modified') is not False
            or ready.get('kernel_behavior_equal_on_off') is not True
            or ready.get('wininet_behavior_equal_on_off') is not True):
        raise RuntimeError('Require Root-recorded prerequisites for this exact diagnostic engine')
    checks = ready.get('checks')
    if (not isinstance(checks, list) or len(checks) != len(MODES)
            or {item.get('mode') for item in checks if isinstance(item, dict)} != MODES):
        raise RuntimeError('Every own diagnostic engine regression mode must be present once')
    admitted = []
    for item in checks:
        mode = item['mode']
        name = item.get('path')
        if (not isinstance(name, str) or re.fullmatch(
                r'research/wine-parity-numeric-' + re.escape(mode) + r'-[0-9]{8}T[0-9]{12}Z-results[.]json', name) is None
                or type(item.get('bytes')) is not int or item['bytes'] <= 0
                or type(item.get('sha256')) is not str or re.fullmatch('[0-9a-f]{64}', item['sha256']) is None):
            raise RuntimeError('Unreviewed prerequisite result path or identity')
        admitted.append((item, mode, name))
    result = []
    for item, mode, name in admitted:
        data = candidate.read_regular(ROOT / name)
        if len(data) != item['bytes'] or hashlib.sha256(data).hexdigest() != item['sha256']:
            raise RuntimeError('Diagnostic prerequisite result changed')
        report = json.loads(data)
        if (report.get('passed') is not True or report.get('runtime_started') is not True
                or report.get('profile') != 'wine-numeric-api-probes'
                or report.get('protocol_version') != 1810
                or report.get('probe_role') != 'numeric-' + mode
                or report.get('prefix') != 'prefixes/wine-numeric-regression'
                or report.get('runtime_verification', {}).get('manifest_sha256') != engine['manifest_sha256']
                or report.get('cleanup') != [{'flag': '-k', 'exit': 0}, {'flag': '-w', 'exit': 0}]
                or report.get('quarantine_cleared_after_confirmed_cleanup') is not True
                or report.get('only_own_fixtures_and_builtin_initialization') is not True
                or report.get('client_cef_rockstar_game_or_account_code_started') is not False
                or any(key in report for key in ('failure', 'post_run_guard_failure', 'prefix_terminal_state_uncertain'))):
            raise RuntimeError('Require an actual clean account-free regression run')
        if not report.get('runs') or any(row.get('passed') is not True or row.get('exit') != 0 for row in report['runs']):
            raise RuntimeError('A prerequisite has missing or unsuccessful own cases')
        result.append(dict(item))
    return {'record': str(READY.relative_to(ROOT)), 'sha256': hashlib.sha256(raw).hexdigest(),
            'checked_result_identities': result,
            'root_reviewed_runtime_reports': True,
            'api_prefix_or_account_storage_read': False}


def verify_profile():
    candidate = candidate_module()
    engine = candidate.verify_runtime()
    if engine.get('protocol_version') != 1810:
        raise RuntimeError('Diagnostic engine protocol changed')
    return {'profile': 'numeric', 'engine': engine, 'renderer': baseline.graphics.verify_renderer(),
            'source_bridge_code': baseline.verify_source_bridge_code(),
            'own_runtime_prerequisites': verify_prerequisites(candidate, engine),
            'source_prefix_code_only_read': True, 'source_stage_update_performed': False,
            'source_debug_channels': DEBUG,
            'authentication_security_or_integrity_decisions_modified': False,
            'launcher_authentication_gameplay_or_anticheat_success_claim': False}


def source_environment(matched, source_prefix, candidate):
    if source_prefix != SOURCE_PREFIX:
        raise RuntimeError('Numeric source runtime requires the existing authorized source prefix')
    # The source environment retains normal CLR/browser behavior; the API environment is not reused.
    env = baseline.source_environment(matched, source_prefix)
    search = os.pathsep.join(map(str, (ENGINE / 'lib/wine/x86_64-unix', candidate.MOLTENVK.parent,
                                      candidate.FRAMEWORKS, candidate.GST_LIB)))
    env.update(WINEPREFIX=str(SOURCE_PREFIX), WINESERVER=str(ENGINE / 'bin/wineserver'),
               PATH=str(ENGINE / 'bin') + ':/usr/bin:/bin:/usr/sbin:/sbin',
               DYLD_LIBRARY_PATH=search, DYLD_FALLBACK_LIBRARY_PATH=search, WINEDEBUG=DEBUG)
    return env


def select_runtime(matched, source_prefix=SOURCE_PREFIX):
    if source_prefix != SOURCE_PREFIX:
        raise RuntimeError('Refusing a different diagnostic source role')
    baseline._matched_base(matched)
    sibling = ROOT.parent / 'GTA-V-macOS'
    if (matched.ENGINE != sibling / 'runtime/matched-wine11-r29/engine'
            or matched.WINE != matched.ENGINE / 'bin/wine'
            or matched.PREFIX != sibling / 'prefixes/rockstar-legacy'):
        raise RuntimeError('Numeric source selection requires the retained matched baseline')
    context = verify_profile()
    candidate = candidate_module()

    def before_source_spawn():
        if verify_profile() != context:
            raise RuntimeError('Numeric source code or regression evidence changed before spawn')

    return SimpleNamespace(ENGINE=ENGINE, WINE=ENGINE / 'bin/wine', PREFIX=matched.PREFIX,
        environment=lambda: source_environment(matched, source_prefix, candidate), source_winedebug=DEBUG,
        before_source_spawn=before_source_spawn, source_runtime_profile=context)
