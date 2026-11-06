#!/usr/bin/env python3
"""Inspect the separate complete parity engine or run unchanged own Job probes."""
import argparse
import datetime
import getpass
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import time

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('own_parity_environment', HERE/'environment.py')
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)
ROOT = runtime.ROOT
PREFIX = runtime.PREFIX
BUILD = ROOT/'build/windows-job-tests'
helper_spec = importlib.util.spec_from_file_location('own_unchanged_job_seed', ROOT/'native/windows-job-tests/run_query.py')
job_helper = importlib.util.module_from_spec(helper_spec)
helper_spec.loader.exec_module(job_helper)
from probe_environment import assert_account_free_prefix, probe_prefix

BINARIES = {
    'job_parent': ('f7d08bc11bdade8f4e9b3421c5b5fe2c20a356f2a3bbd31c25f210d90d4b4cbe', 676864),
    'job_child': ('366e8ba7aff6765ac3b7b0565e70b0cd90d6f8eb3dbdf9e3a58f9b14886b01e7', 514560),
    'job_query_contract': ('1e116d2e7c7f44bf0c0efa21fbbd591e4c0027f28d788303cc87c2f1e31a4801', 510976),
}
SOURCES = {
    'events.h': 'bc6359b92cf389b28f44bc6b250c622ced07611ef0b2eec486d72aa030c031d3',
    'job_parent.cpp': '4b7cd142935fc4d15a65c5c7a276a644cec657b66e6a7b82d164b6dac4dcb0cf',
    'job_child.cpp': '6659f92ae517f9b59b5c56f4f17a1fd08668908660de8ee167d84387d5891a56',
    'job_query_contract.cpp': '8555dabd403cb1ab313d73c822f63c94fcecf8864245dfc2688a6abf24fea6a7',
    'CMakeLists.txt': '6103238d4f02bd76b9ca05e0cf1ed423de04395c25e7785fe78f61d6fa280925',
}


def identity(path):
    data = runtime.read_regular(path)
    return {'path': str(path.relative_to(ROOT)), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def verify_jobs():
    parent_path, query_path = (ROOT/'research'/name for name in ('windows-job-build.json', 'windows-job-query-build.json'))
    parent = json.loads(runtime.read_regular(parent_path))
    query = json.loads(runtime.read_regular(query_path))
    source_paths = {'native/windows-job-tests/'+name for name in ('events.h', 'job_parent.cpp', 'job_child.cpp')}
    if (parent.get('passed') is not True or parent.get('runtime_started') is not False
            or set(parent.get('binaries', {})) != {'job_parent', 'job_child'}
            or set(parent.get('sources', {})) != source_paths
            or parent.get('public_main_source') != 'port/fivem/code/client/launcher/Main.cpp'
            or parent.get('public_main_source_sha256') != '25b95c5bd2136b6207f6e93633bd1e6afe44799e753bdb92af9d1b6af265df3d'
            or query.get('passed') is not True or query.get('runtime_started') is not False
            or query.get('binary') != 'build/windows-job-tests/job_query_contract.exe'):
        raise RuntimeError('Unexpected own Job fixture build/source inventory')
    for name in ('job_parent', 'job_child'):
        item = parent['binaries'][name]
        if (item.get('path') != 'build/windows-job-tests/'+name+'.exe'
                or item.get('sha256') != BINARIES[name][0] or item.get('bytes') != BINARIES[name][1]
                or item.get('machine') != 'AMD64' or item.get('runtime') != '/MT'
                or item.get('import_dlls') != ['KERNEL32.dll']):
            raise RuntimeError('Unexpected unchanged parent/child PE identity')
    if (query.get('sha256') != BINARIES['job_query_contract'][0] or query.get('bytes') != BINARIES['job_query_contract'][1]
            or query.get('source_sha256') != SOURCES['job_query_contract.cpp']
            or query.get('events_header_sha256') != SOURCES['events.h'] or query.get('cmake_sha256') != SOURCES['CMakeLists.txt']
            or any(parent['sources']['native/windows-job-tests/'+name] != SOURCES[name]
                   for name in ('events.h', 'job_parent.cpp', 'job_child.cpp'))):
        raise RuntimeError('Own Job query/source evidence differs')
    # All report-selected paths have been admitted before any binary/source read.
    binaries, sources = [], []
    for name, (digest, size) in BINARIES.items():
        item = identity(BUILD/(name+'.exe'))
        if item['sha256'] != digest or item['bytes'] != size:
            raise RuntimeError('Own Job PE changed')
        binaries.append(item)
    for name, digest in SOURCES.items():
        item = identity(ROOT/'native/windows-job-tests'/name)
        if item['sha256'] != digest:
            raise RuntimeError('Own Job source changed')
        sources.append(item)
    main = identity(ROOT/'port/fivem/code/client/launcher/Main.cpp')
    if main['sha256'] != parent['public_main_source_sha256']:
        raise RuntimeError('Public Main reference changed; no fixture rebuild or client start is implicit')
    return {'runtime_inputs': binaries, 'source_inputs': sources, 'public_main_reference': main,
            'build_reports': [identity(parent_path), identity(query_path)],
            'runner_sources': [identity(path) for path in (HERE/'environment.py', HERE/'run.py', ROOT/'native/windows-job-tests/run_query.py')]}


def job_cases():
    return [{'name': 'job_parent', 'binary': BUILD/'job_parent.exe', 'cwd': BUILD, 'expected_events': 79,
             'final_event': 'all_cases_passed', 'final_kind': 'result'},
            {'name': 'job_query_contract', 'binary': BUILD/'job_query_contract.exe', 'cwd': BUILD, 'expected_events': 170,
             'final_event': 'all_query_cases_passed', 'final_kind': 'assertion'}]


def event_contract(lines, expected_count, final_event, exitcode, *, final_kind):
    expected = {'all_cases_passed': (79, 'result', 'parent'),
                'all_query_cases_passed': (170, 'assertion', 'query')}
    if final_event not in expected or (expected_count, final_kind) != expected[final_event][:2]:
        raise RuntimeError('Unexpected fixed Job terminal contract')
    events = [json.loads(line) for line in lines]
    required = {'actor', 'case', 'kind', 'name', 'pid', 'ok', 'value', 'last_error'}
    for event in events:
        if (not isinstance(event, dict) or set(event) != required
                or event['actor'] not in ('parent', 'child', 'query') or type(event['ok']) is not bool
                or type(event['pid']) is not int or event['pid'] <= 0
                or type(event['value']) is not int or not 0 <= event['value'] < 2**64
                or (event['last_error'] is not None and (type(event['last_error']) is not int or not 0 <= event['last_error'] < 2**32))
                or any(not isinstance(event[key], str) or re.fullmatch(r'[A-Za-z0-9_.-]+', event[key]) is None
                       for key in ('case', 'kind', 'name'))):
            raise RuntimeError('Unexpected own Job event fields')
    failures = [event for event in events if event['ok'] is not True]
    final = [event for event in events if event['name'] == final_event]
    passed = (exitcode == 0 and len(events) == expected_count and not failures and len(final) == 1
              and final[0]['kind'] == final_kind and final[0]['actor'] == expected[final_event][2]
              and final[0]['case'] == 'complete' and events[-1] == final[0])
    return {'events': events, 'event_count': len(events), 'failed_assertions': len(failures), 'passed': passed}


def binding_path():
    return PREFIX/'.wine-parity-api.json'


def bind_prefix(existed_before):
    info = PREFIX.stat()
    expected = {'prefix': str(PREFIX.relative_to(ROOT)), 'device': info.st_dev, 'inode': info.st_ino,
                'role': runtime.ROLE, 'protocol_version': runtime.PROTOCOL, 'manifest_sha256': runtime.MANIFEST_SHA}
    marker = binding_path()
    runtime.canonical(marker, ROOT)
    if marker.exists():
        if json.loads(runtime.read_regular(marker)) != expected:
            raise RuntimeError('Parity prefix role, protocol, engine or inode binding differs')
    elif existed_before:
        raise RuntimeError('Refusing adoption of an existing unbound parity prefix')
    else:
        fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as output:
            json.dump(expected, output)
    return expected


def quarantine_path():
    return PREFIX.parent/('.'+PREFIX.name+'.quarantined.json')


def refuse_quarantine():
    path = quarantine_path()
    runtime.canonical(path, ROOT)
    if path.exists():
        raise RuntimeError('Parity API prefix is quarantined; terminal state requires Root review')


def quarantine(result_path):
    path = quarantine_path()
    runtime.canonical(path, ROOT)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as output:
        json.dump({'role': runtime.ROLE, 'protocol_version': runtime.PROTOCOL,
                   'manifest_sha256': runtime.MANIFEST_SHA, 'result': str(result_path.relative_to(ROOT)),
                   'reason': 'Owned execution in progress or terminal cleanup unconfirmed'}, output)
        output.flush()
        os.fsync(output.fileno())


def save_result(path, result):
    runtime.canonical(path, ROOT)
    path.parent.mkdir(exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as output:
        json.dump(result, output, indent=2)
        output.write('\n')


def validate_environment(env):
    """Keep caller overlays bound to this runner's independent loader, server and prefix."""
    required = {'WINEPREFIX': str(PREFIX), 'WINESERVER': str(runtime.ENGINE/'bin/wineserver'),
                'WINELOADER': str(runtime.ENGINE/'bin/wine'), 'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'}
    wine_keys = {'WINEPREFIX', 'WINESERVER', 'WINELOADER', 'WINEDEBUG', 'WINEESYNC', 'WINEMSYNC',
                 'WINEDLLOVERRIDES', 'WINEDLLPATH_PREPEND'}
    dyld_keys = {'DYLD_LIBRARY_PATH', 'DYLD_FRAMEWORK_PATH', 'DYLD_PRINT_LIBRARIES'}
    if (not isinstance(env, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in env.items())
            or any(env.get(key) != value for key, value in required.items())):
        raise RuntimeError('Environment must bind the independent prefix, server, loader and system PATH')
    for key in env:
        upper = key.upper()
        if ((upper.startswith('WINE') and (key not in wine_keys))
                or (upper.startswith('DYLD_') and key not in dyld_keys)
                or upper.startswith(('CITIZENFX_', 'CX_', 'LD_'))):
            raise RuntimeError('Unreviewed loader, socket or client environment role')


def run_cases(cases, *, verify_inputs=verify_jobs, role='jobs', environment_factory=None, prepare_prefix=None):
    """Shared isolated lifecycle; callers supply reviewed own cases and an input verifier."""
    label = 'wine-parity-'+role+'-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    result_path = ROOT/'research'/(label+'-results.json')
    result = {'profile': runtime.ROLE, 'probe_role': role, 'protocol_version': runtime.PROTOCOL,
              'prefix': str(PREFIX.relative_to(ROOT)), 'only_own_fixtures_and_builtin_initialization': True,
              'client_cef_rockstar_game_or_account_code_started': False, 'runs': [], 'cleanup': [], 'passed': False}
    started = time.monotonic()
    runtime_started = False
    try:
        verified = runtime.verify_runtime()
        fixture = verify_inputs()
        admitted = {ROOT/item['path'] for item in fixture['runtime_inputs']}
        if not cases or any(case['binary'] not in admitted or case['cwd'] != case['binary'].parent for case in cases):
            raise RuntimeError('A case executable is outside its reviewed own fixture inventory')
        env = (runtime.environment if environment_factory is None else environment_factory)(verified)
        validate_environment(env)
        env = dict(env)
        bound_environment = dict(env)
        wine, server = runtime.ENGINE/'bin/wine', runtime.ENGINE/'bin/wineserver'
        result.update(runtime_verification=verified, fixture_inputs=fixture)
        refuse_quarantine()
        existed = PREFIX.exists()
        with probe_prefix(PREFIX, root=ROOT, create=True):
            owned_marker = False
            try:
                refuse_quarantine()
                result['prefix_binding'] = bind_prefix(existed)
                quarantine(result_path)
                owned_marker = True
                logs = ROOT/'logs'
                runtime.canonical(logs, ROOT)
                logs.mkdir(exist_ok=True)
                if not (PREFIX/'system.reg').exists():
                    job_helper.seed_personal_directories(PREFIX)
                    init_log = logs/(label+'-initialization.log')
                    runtime.canonical(init_log, ROOT)
                    with init_log.open('x') as output:
                        runtime_started = True
                        init = subprocess.run([str(wine), 'wineboot', '-i'], env=env, cwd=BUILD,
                            stdout=output, stderr=subprocess.STDOUT, timeout=60)
                    result['initialization_exit'] = init.returncode
                    if init.returncode:
                        raise RuntimeError('Parity prefix initialization failed')
                    assert_account_free_prefix(PREFIX, root=ROOT)
                if prepare_prefix is not None:
                    result['prefix_preparation'] = prepare_prefix(verified, env)
                    validate_environment(env)
                    if env != bound_environment:
                        raise RuntimeError('Prefix preparation changed the bound execution environment')
                for case in cases:
                    runtime.verify_runtime()
                    if verify_inputs() != fixture:
                        raise RuntimeError('Own fixture input binding changed before start')
                    validate_environment(env)
                    if env != bound_environment:
                        raise RuntimeError('Execution environment changed before start')
                    assert_account_free_prefix(PREFIX, root=ROOT)
                    log = logs/(label+'-'+case['name']+'.ndjson')
                    errors = logs/(label+'-'+case['name']+'-wine.log')
                    for path in (log, errors):
                        runtime.canonical(path, ROOT)
                    with log.open('x') as output, errors.open('x') as stderr:
                        runtime_started = True
                        completed = subprocess.run([str(wine), str(case['binary']), *case.get('arguments', ())], cwd=case['cwd'], env=env,
                            stdout=output, stderr=stderr, timeout=45)
                    lines = runtime.read_regular(log).decode().splitlines()
                    if 'parse_output' in case:
                        parsed = case['parse_output'](lines, completed.returncode)
                    else:
                        parsed = event_contract(lines, case['expected_events'], case['final_event'], completed.returncode,
                                                final_kind=case['final_kind'])
                    if 'parse_diagnostics' in case:
                        diagnostics = case['parse_diagnostics'](runtime.read_regular(errors).decode().splitlines(),
                                                                 completed.returncode)
                        parsed = {**parsed, 'diagnostics': diagnostics,
                                  'passed': parsed.get('passed') is True and diagnostics.get('passed') is True}
                    result['runs'].append({'name': case['name'], 'binary': str(case['binary'].relative_to(ROOT)),
                        'exit': completed.returncode, **parsed, 'log': str(log.relative_to(ROOT)),
                        'wine_log': str(errors.relative_to(ROOT))})
            finally:
                if runtime_started:
                    for flag in ('-k', '-w'):
                        try:
                            completed = subprocess.run([str(server), flag], env=bound_environment, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=15)
                            result['cleanup'].append({'flag': flag, 'exit': completed.returncode})
                        except BaseException as error:
                            result['cleanup'].append({'flag': flag, 'exit': None, 'failure_type': type(error).__name__})
                try:
                    assert_account_free_prefix(PREFIX, root=ROOT)
                    bind_prefix(True)
                    runtime.verify_runtime()
                except BaseException as error:
                    result['post_run_guard_failure'] = {'type': type(error).__name__, 'message': str(error)}
                clean = ((not runtime_started or result['cleanup'] == [{'flag': '-k', 'exit': 0}, {'flag': '-w', 'exit': 0}])
                         and 'post_run_guard_failure' not in result)
                if clean and owned_marker:
                    runtime.canonical(quarantine_path(), ROOT)
                    quarantine_path().unlink()
                    result['quarantine_cleared_after_confirmed_cleanup'] = True
                elif not clean:
                    result['prefix_terminal_state_uncertain'] = True
    except BaseException as error:
        result['failure'] = {'type': type(error).__name__, 'message': str(error)}
    finally:
        result['passed'] = (len(result['runs']) == len(cases) and all(run['passed'] for run in result['runs'])
            and result['cleanup'] == [{'flag': '-k', 'exit': 0}, {'flag': '-w', 'exit': 0}]
            and 'failure' not in result and 'post_run_guard_failure' not in result)
        result['runtime_started'] = runtime_started
        result['elapsed_seconds'] = round(time.monotonic()-started, 3)
        save_result(result_path, result)
    print(role, 'PASS' if result['passed'] else 'FAIL', str(result_path.relative_to(ROOT)), flush=True)
    return 0 if result['passed'] else 1


ORIGINAL_JOB_LABEL = 'wine-parity-jobs-20261102T084737610462Z'
REASSESS_INPUTS = {
    'research/'+ORIGINAL_JOB_LABEL+'-results.json':
        (70230, '5213648f43d98c7e8c09eebd6522f68520ade6cb13ee35fec6fe071c968e8bd9'),
    'logs/'+ORIGINAL_JOB_LABEL+'-job_parent.ndjson':
        (10672, 'cbf5f5a41a35c0094b8cc99584db654f7302194a0e9c1746232266946bce0170'),
    'logs/'+ORIGINAL_JOB_LABEL+'-job_query_contract.ndjson':
        (24517, 'dbea751dd3bcf2cc142a1a60c31b4a942fed36913b6996209313862965584d0a'),
}


def reassess_jobs():
    """Reparse three fixed historical files; never inspect or start a runtime/prefix."""
    inputs, data = [], {}
    for relative, (size, digest) in REASSESS_INPUTS.items():
        raw = runtime.read_regular(ROOT/relative)
        if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
            raise RuntimeError('Historical Job reassessment input changed')
        inputs.append({'path': relative, 'bytes': size, 'sha256': digest})
        data[relative] = raw
    original_path = 'research/'+ORIGINAL_JOB_LABEL+'-results.json'
    original = json.loads(data[original_path])
    cleanup = [{'flag': '-k', 'exit': 0}, {'flag': '-w', 'exit': 0}]
    if (original.get('profile') != runtime.ROLE or original.get('probe_role') != 'jobs'
            or original.get('protocol_version') != runtime.PROTOCOL or original.get('runtime_started') is not True
            or original.get('runtime_verification', {}).get('manifest_sha256') != runtime.MANIFEST_SHA
            or original.get('cleanup') != cleanup or original.get('quarantine_cleared_after_confirmed_cleanup') is not True
            or 'failure' in original or 'post_run_guard_failure' in original or len(original.get('runs', [])) != 2):
        raise RuntimeError('Historical execution does not have the required clean terminal evidence')
    reassessed = []
    for case, previous in zip(job_cases(), original['runs']):
        log = 'logs/'+ORIGINAL_JOB_LABEL+'-'+case['name']+'.ndjson'
        binary = 'build/windows-job-tests/'+case['name']+'.exe'
        if (previous.get('name') != case['name'] or previous.get('binary') != binary
                or previous.get('log') != log or previous.get('exit') != 0):
            raise RuntimeError('Historical Job case or fixed log binding differs')
        parsed = event_contract(data[log].decode().splitlines(), case['expected_events'], case['final_event'],
                                previous['exit'], final_kind=case['final_kind'])
        if parsed['events'] != previous.get('events'):
            raise RuntimeError('Original result events differ from its own NDJSON log')
        reassessed.append({'name': case['name'], 'binary': binary, 'log': log, 'exit': previous['exit'],
                           'original_reported_passed': previous.get('passed'), 'final_kind': case['final_kind'], **parsed})
    result = {'schema_version': 1, 'reassessment_only': True, 'no_new_wine_run': True,
              'runtime_started': False, 'prefix_or_engine_accessed': False,
              'original_result': next(item for item in inputs if item['path']==original_path),
              'original_logs': [item for item in inputs if item['path'] != original_path],
              'parser_source': identity(ROOT/'native/wine-parity-probes/run.py'),
              'original_reported_passed': original['passed'], 'original_prefix_binding': original['prefix_binding'],
              'original_cleanup': original['cleanup'],
              'original_quarantine_cleared_after_confirmed_cleanup': original['quarantine_cleared_after_confirmed_cleanup'],
              'original_postguards_clean': True, 'runs': reassessed,
              'passed': all(run['passed'] for run in reassessed)}
    label = 'wine-parity-jobs-reassessment-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    target = ROOT/'research'/(label+'-results.json')
    save_result(target, result)
    print('Job reassessment', 'PASS' if result['passed'] else 'FAIL', str(target.relative_to(ROOT)), flush=True)
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('inspect', 'jobs', 'reassess-jobs'))
    action = parser.parse_args().action
    if action == 'inspect':
        print(json.dumps({'runtime': runtime.verify_runtime(), 'fixtures': verify_jobs()}, indent=2))
    elif action == 'reassess-jobs':
        raise SystemExit(reassess_jobs())
    else:
        raise SystemExit(run_cases(job_cases()))
