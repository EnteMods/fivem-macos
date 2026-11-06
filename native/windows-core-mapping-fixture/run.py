#!/usr/bin/env python3
"""Three own Core9 comparisons; no client, tool mode, or private module loading."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
from types import ModuleType

ROOT = Path(__file__).resolve().parents[2]
HERE = 'native/windows-core-mapping-fixture/'
BUILD = 'build/windows-core-mapping-fixture/'
REPORT = 'research/windows-core-mapping-fixture-build.json'
REPORT_BYTES = 22064
REPORT_SHA = '410cfbff3dfeba92c11e4b886a026069984ad1489186378c10bb719f6c18e458'
PREVIOUS = 'native/windows-ntdll-hook-fixture/run.py'
PREVIOUS_SHA = '13be462ec03809537dc1b0ad83b4c98922ecd9f82fe8a53782e00d19847929fd'
CANONICAL = BUILD + 'Program Files/Rockstar Games/Social Club/'
MODES = ('baseline', 'core-load-only', 'core-mapping')
REFERENCES = {
    'research/core-lifecycle-diagnostic-build.json': 'bb309c253a6c1e77d1ed520ffe04a81668728801f722437ab9d42944299511ae',
    'research/windows-mapping-policy-build.json': '26dabe93f68c4eea9b018ea2c4e9c726e6bfa0318141f310032d6e55ea271346',
    'native/windows-mapping-nt-policy/probe.cpp': '33e44511a43d94c908c745b1dcc618b3cf0b1d0578778896a69c60f417749299',
    'build/windows-core-lifecycle-diagnostic/CoreRT.dll': '51b7d6432f8a32b404144d19a5abf0a16bcadc764971e99e6fcb12e708a16396',
    'build/windows-core-lifecycle-diagnostic/clang_23.1_cxx17_64_md_relwithdebinfo/tbb12.dll':
        'c3931068206dc672fc8a070285b8623804d45c051d1ac73f33a13c6497e33038',
    'build/windows-mapping-policy/socialclub.dll': '7ada69ccb50339f3f0cc5cb650fbe37f2a4fb2a5ab85afe2f7a5469394f04393',
    'build/windows-mapping-policy/mapping-target.dll': '4aba15a984cbbbd54e053541f445596e9e45bfcfac4ca041971ab33493eca00d'}
RUNTIME = {BUILD + 'core_mapping_fixture.exe', BUILD + 'CoreRT.dll', BUILD + 'tbb12.dll',
           CANONICAL + 'socialclub.dll', CANONICAL + 'mapping-target.dll'}
CONTRACT = {'modes': list(MODES), 'checkpoints': 8, 'apis': ['LdrLoadDll', 'NtCreateFile', 'NtOpenFile'],
    'rvas': [0x15b50, 0xf420, 0xefe0], 'ntdll_size': 4349952, 'read_width': 21,
    'real_self_rpm': True, 'local_before_after': True, 'core_freelibrary_or_private_stop': False,
    'toolmode_or_componentloader_called': False, 'own_source_marker': 0x46585231, 'own_target_marker': 0x46585232}


def load_previous():
    path = ROOT / PREVIOUS
    if path.resolve(strict=True) != path or path.stat().st_nlink != 1:
        raise RuntimeError('Require the original RPM fixture helper')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PREVIOUS_SHA:
        raise RuntimeError('RPM helper changed before execution')
    module = ModuleType('_core_mapping_frozen_rpm')
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def verify_inputs():
    previous = load_previous(); control = previous.load_control()
    if type(REPORT_BYTES) is not int or type(REPORT_SHA) is not str or re.fullmatch('[0-9a-f]{64}', REPORT_SHA) is None:
        raise RuntimeError('The actual own Core mapping build has not been pinned')
    raw = control.read(REPORT)
    if len(raw) != REPORT_BYTES or hashlib.sha256(raw).hexdigest() != REPORT_SHA:
        raise RuntimeError('The issued own build report changed')
    report = json.loads(raw)
    control.group(report.get('runtime_inputs'), RUNTIME)
    control.group(report.get('source_evidence'), {HERE + 'probe.cpp', HERE + 'build.py'})
    control.group(report.get('code_references'), set(REFERENCES))
    fixed = [('reused_rpm_helper', PREVIOUS), ('generated_header', BUILD + 'role_config.h'),
             ('object', BUILD + 'probe.obj'), ('inspection', BUILD + 'inspection.txt'),
             ('map', BUILD + 'core_mapping_fixture.map')]
    for key, path in fixed: control.shape(report.get(key), path)
    control.shape(report.get('build', {}).get('log'), BUILD + 'build.log')
    if (report.get('schema_version') != 1 or report.get('compiled') is not True
            or report.get('architecture') != 'AMD64' or report.get('runtime') != '/MT'
            or type(report.get('build', {}).get('exit')) is not int or report['build']['exit'] != 0
            or report.get('contract') != CONTRACT or report.get('wine_client_prefix_or_source_started') is not False
            or report.get('reused_rpm_inputs') != previous.verify_inputs()):
        raise RuntimeError('Unexpected Core9 experiment role or original RPM closure')
    selected = [*report['runtime_inputs'], *report['source_evidence'], *report['code_references'],
                *(report[key] for key, _ in fixed), report['build']['log']]
    for item in selected:
        if control.identity(item['path']) != item: raise RuntimeError('A fixed own build input changed')
    for item in report['code_references']:
        if item['sha256'] != REFERENCES[item['path']]: raise RuntimeError('Unexpected original provider')
    if report['reused_rpm_helper']['sha256'] != PREVIOUS_SHA: raise RuntimeError('Changed helper role')
    copied = {item['path']: item['sha256'] for item in report['runtime_inputs']}
    for destination, original in (
            (BUILD + 'CoreRT.dll', 'build/windows-core-lifecycle-diagnostic/CoreRT.dll'),
            (BUILD + 'tbb12.dll', 'build/windows-core-lifecycle-diagnostic/clang_23.1_cxx17_64_md_relwithdebinfo/tbb12.dll'),
            (CANONICAL + 'socialclub.dll', 'build/windows-mapping-policy/socialclub.dll'),
            (CANONICAL + 'mapping-target.dll', 'build/windows-mapping-policy/mapping-target.dll')):
        if copied[destination] != REFERENCES[original]: raise RuntimeError('A provider copy differs')
    return {'probe_family': 'own-core9-mapping-entry-lifetime', 'runtime_inputs': report['runtime_inputs'],
        'source_inputs': [item for item in selected if item not in report['runtime_inputs']],
        'build_reports': [control.identity(REPORT, raw)], 'reused_rpm_inputs': report['reused_rpm_inputs'],
        'adapter_sources': [control.identity(HERE + 'run.py'), *control.lifecycle_inputs()],
        'source_client_or_authenticated_prefix_used': False, 'source_failure_cause_claim': False}


def sequence():
    rows = [('ready',)]
    def sample(phase): rows.extend(('sample', phase, api) for api in (1, 2, 3))
    def call(phase): rows.extend(('call', phase, api) for api in (2, 3, 1))
    sample(0); rows.append(('core',)); sample(1); call(2); sample(2)
    rows.append(('library', 1)); sample(3); sample(4)
    rows.append(('library', 2)); sample(5); sample(6); call(7); sample(7)
    return rows + [('completed',)]


def parse_output(lines, exitcode, mode):
    events, order = [], []
    result = {'passed': False, 'events': events, 'source_failure_cause_claim': False,
              'core_retained_until_process_exit': True, 'equal_first_does_not_identify_restorer': True}
    fields = {
        'ready': {'event', 'mode', 'pid', 'self_handle_real', 'self_handle_error'},
        'core': {'event', 'mode', 'tbb_loaded', 'tbb_error', 'core_loaded', 'core_error', 'export_error', 'mapping_returned'},
        'sample': {'event', 'phase', 'api', 'read_status', 'equal_first', 'equal_setup', 'jump_kind',
            'rpm_attempted', 'rpm_ok', 'rpm_bytes', 'rpm_error', 'local_stable', 'rpm_equal_local', 'provider_calls', 'provider_hits'},
        'call': {'event', 'phase', 'api', 'attempted', 'status', 'source_identity', 'target_identity',
            'provider_calls_delta', 'provider_hits_delta', 'marker', 'close_ok'},
        'library': {'event', 'operation', 'attempted', 'ok', 'marker'},
        'completed': {'event', 'mode', 'checkpoints', 'core_references_held', 'self_handle_closed', 'close_failures', 'exit'}}
    bools = {'self_handle_real', 'tbb_loaded', 'core_loaded', 'mapping_returned', 'rpm_attempted', 'rpm_ok', 'attempted',
             'local_stable', 'source_identity', 'target_identity', 'close_ok', 'ok', 'core_references_held', 'self_handle_closed'}
    comparisons = {'equal_first', 'equal_setup', 'rpm_equal_local'}
    def pairs(values):
        row = {}
        for key, value in values:
            if key in row: raise ValueError('duplicate')
            row[key] = value
        return row
    try:
        if type(mode) is not int or mode not in range(3) or type(exitcode) is not int or len(lines) > 64: raise ValueError('input')
        for line in lines:
            if type(line) is not str or len(line) > 1024: raise ValueError('line')
            row = json.loads(line, object_pairs_hook=pairs)
            if type(row) is not dict or type(row.get('event')) is not str or row['event'] not in fields or set(row) != fields[row['event']]:
                raise ValueError('shape')
            for key, value in row.items():
                if key == 'event': continue
                if key in bools:
                    if type(value) is not bool: raise ValueError('boolean')
                elif key in comparisons:
                    if value is not None and type(value) is not bool: raise ValueError('comparison')
                elif key == 'status' and row['event'] == 'call' and value is None:
                    if row['attempted'] is not False: raise ValueError('missing-status')
                elif type(value) is not int or not 0 <= value <= 0xffffffff: raise ValueError('numeric')
            events.append(row)
            if row['event'] in ('sample', 'call'): order.append((row['event'], row['phase'], row['api']))
            elif row['event'] == 'library': order.append(('library', row['operation']))
            else: order.append((row['event'],))
        if order != sequence() or exitcode != 0: raise ValueError('sequence-or-exit')
        calls, hits, minimum_calls, minimum_hits = 0, 0, 0, 0
        for row in events:
            kind = row['event']
            if 'mode' in row and row['mode'] != mode: raise ValueError('mode')
            if kind == 'ready' and (not row['pid'] or row['self_handle_real'] is not True): raise ValueError('self-handle')
            if kind == 'core':
                if row['core_loaded'] is not bool(mode) or row['tbb_loaded'] is not bool(mode) or row['mapping_returned'] is not (mode == 2):
                    raise ValueError('core-load')
            if kind == 'sample':
                if (row['read_status'] != 0 or row['rpm_attempted'] is not True or row['rpm_ok'] is not True
                        or row['rpm_bytes'] != 21 or row['local_stable'] is not True or row['rpm_equal_local'] is not True
                        or row['jump_kind'] not in (0, 1, 2) or row['provider_hits'] > row['provider_calls']
                        or row['provider_calls'] < max(calls, minimum_calls)
                        or row['provider_hits'] < max(hits, minimum_hits)): raise ValueError('sample')
                calls, hits = row['provider_calls'], row['provider_hits']
                if row['phase'] == 0:
                    if row['equal_first'] is not True or row['equal_setup'] is not None or calls or hits: raise ValueError('first')
                elif (row['equal_setup'] is not True or row['equal_first'] is not (mode != 2)
                        or mode == 2 and row['jump_kind'] not in (1, 2)): raise ValueError('entry-lifetime')
                if mode != 2 and (calls or hits): raise ValueError('unexpected-provider')
            if kind == 'call':
                mapped = mode == 2
                if (row['attempted'] is not True or row['status'] != 0 or row['source_identity'] is not (not mapped) or row['target_identity'] is not mapped
                        or row['close_ok'] is not True or row['marker'] != ((0x46585232 if mapped else 0x46585231) if row['api'] == 1 else 0)
                        or row['provider_hits_delta'] > row['provider_calls_delta']
                        or (row['provider_hits_delta'] == 0 if mapped else row['provider_calls_delta'] != 0 or row['provider_hits_delta'] != 0)):
                    raise ValueError('provider-dispatch')
                minimum_calls = max(minimum_calls, calls) + row['provider_calls_delta']
                minimum_hits = max(minimum_hits, hits) + row['provider_hits_delta']
            if kind == 'library' and (row['attempted'] is not True or row['ok'] is not True or row['marker'] != ((0x46585232 if mode == 2 else 0x46585231) if row['operation'] == 1 else 0)):
                raise ValueError('own-library')
        if events[-1] != {'event': 'completed', 'mode': mode, 'checkpoints': 8,
            'core_references_held': True, 'self_handle_closed': True, 'close_failures': 0, 'exit': 0}: raise ValueError('cleanup')
        result['passed'] = True
    except (ValueError, TypeError, KeyError): result['failure'] = 'fixed-core9-contract-not-satisfied'
    return result


def self_test():
    for mode in range(3):
        rows = []
        for item in sequence():
            kind = item[0]
            if kind == 'ready': row = dict(event=kind, mode=mode, pid=32, self_handle_real=True, self_handle_error=0)
            elif kind == 'core': row = dict(event=kind, mode=mode, tbb_loaded=bool(mode), core_loaded=bool(mode),
                tbb_error=0, core_error=0, export_error=0, mapping_returned=mode == 2)
            elif kind == 'sample':
                phase, api = item[1:]
                count = (13 if phase == 7 else 10 if phase >= 3 else 3) if mode == 2 and phase >= 2 else 0
                row = dict(event=kind, phase=phase, api=api, read_status=0, equal_first=mode != 2 or phase == 0,
                    equal_setup=None if phase == 0 else True, jump_kind=int(mode == 2 and phase > 0),
                    rpm_attempted=True, rpm_ok=True, rpm_bytes=21, rpm_error=0, local_stable=True, rpm_equal_local=True,
                    provider_calls=count, provider_hits=count)
            elif kind == 'call': row = dict(event=kind, phase=item[1], api=item[2], attempted=True, status=0,
                source_identity=mode != 2, target_identity=mode == 2, provider_calls_delta=int(mode == 2),
                provider_hits_delta=int(mode == 2), marker=(0x46585232 if mode == 2 else 0x46585231) if item[2] == 1 else 0, close_ok=True)
            elif kind == 'library': row = dict(event=kind, operation=item[1], attempted=True, ok=True,
                marker=(0x46585232 if mode == 2 else 0x46585231) if item[1] == 1 else 0)
            else: row = dict(event=kind, mode=mode, checkpoints=8, core_references_held=True, self_handle_closed=True, close_failures=0, exit=0)
            rows.append(row)
        render = lambda value: [json.dumps(row) for row in value]
        assert parse_output(render(rows), 0, mode)['passed']
        for mutation in ('rpm', 'race', 'identity', 'provider', 'core', 'held', 'private', 'type'):
            changed = copy.deepcopy(rows)
            if mutation == 'rpm': next(row for row in changed if row['event'] == 'sample')['rpm_bytes'] = 20
            elif mutation == 'race': next(row for row in changed if row['event'] == 'sample')['local_stable'] = False
            elif mutation == 'identity': next(row for row in changed if row['event'] == 'call')['source_identity'] = mode == 2
            elif mutation == 'provider': next(row for row in changed if row['event'] == 'call')['provider_hits_delta'] = 0 if mode == 2 else 1
            elif mutation == 'core': next(row for row in changed if row['event'] == 'core')['core_loaded'] = not bool(mode)
            elif mutation == 'held': changed[-1]['core_references_held'] = False
            elif mutation == 'private': changed[1]['address'] = 'PRIVATE'
            else: changed[-1]['exit'] = False
            parsed = parse_output(render(changed), 0, mode)
            assert not parsed['passed'] and 'PRIVATE' not in repr(parsed)
        if mode == 2:
            changed = copy.deepcopy(rows)
            next(row for row in changed if row['event'] == 'sample' and row['phase'] == 5)['equal_first'] = True
            parsed = parse_output(render(changed), 0, mode)
            assert not parsed['passed'] and len(parsed['events']) == len(rows)
            changed = copy.deepcopy(rows)
            for row in changed:
                if row['event'] == 'sample': row.update(provider_calls=0, provider_hits=0)
            assert not parse_output(render(changed), 0, mode)['passed']
            changed = copy.deepcopy(rows)
            for row in changed:
                if row['event'] == 'sample' and row['phase'] == 7: row.update(provider_calls=10, provider_hits=10)
            assert not parse_output(render(changed), 0, mode)['passed']
    print('SELFTEST PASS: three positive and twenty-seven negative contracts; no Wine')


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('action', choices=('inspect', 'run', 'self-test'))
    args = parser.parse_args()
    if args.action == 'self-test': return self_test()
    fixture = verify_inputs()
    if args.action == 'inspect': print(json.dumps(fixture, indent=2)); return
    previous = load_previous(); control = previous.load_control(); runner = control.load_runner()
    binary = ROOT / BUILD / 'core_mapping_fixture.exe'
    cases = [{'name': name, 'binary': binary, 'cwd': binary.parent, 'arguments': ('--' + name,),
              'parse_output': lambda lines, code, mode=mode: parse_output(lines, code, mode)} for mode, name in enumerate(MODES)]
    def inputs():
        current = verify_inputs()
        if current != fixture: raise RuntimeError('Fixed own code changed before a case')
        return current
    return runner.run_cases(cases, verify_inputs=inputs, role='core-mapping-fixture')


if __name__ == '__main__': raise SystemExit(main())
