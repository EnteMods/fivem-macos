#!/usr/bin/env python3
"""Stream fixed Wine API markers and associate only observed Windows PID roles."""
import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import types

ROOT = Path(__file__).resolve().parents[2]
LABEL = re.compile(r'client-source-ui(?:-resume)?-[0-9]{8}T[0-9]{12}Z')
PARSER_PATH = 'native/wine-numeric-diagnostics/numeric_contract.py'
PARSER_SHA = 'f121fdf925ccc1a573adbdb843686b9d23b531cb430ce819bfa8d05213482c7a'
OBSERVER_SHA = '776137400dfe36ab720426009b4bfe8500e815a1413cfb89d762088fb0ac70f3'
FIELDS = {'event', 'time_ms', 'pid', 'parent_pid', 'basename', 'exit_hex'}
ROLES = {'fivem.exe': 'source-main', 'fivem_chromebrowser': 'source-cef',
         'fivem_roslauncher': 'source-ros-launcher', 'fivem_rosservice': 'source-ros-service',
         'fivem_dumpserver': 'source-dump-server', 'launcher.exe': 'rockstar-launcher',
         'launcherpatcher.exe': 'rockstar-patcher', 'rockstarservice.exe': 'rockstar-service',
         'rockstarsteamhelper.exe': 'rockstar-steam-helper', 'socialclubhelper.exe': 'socialclub-helper'}


def read_plain(path, *, binary=False):
    if not path.is_relative_to(ROOT) or '..' in path.parts:
        raise RuntimeError('Diagnostic input must stay in its fixed project role')
    current = ROOT
    for part in path.relative_to(ROOT).parts:
        current /= part
        if current.is_symlink():
            raise RuntimeError('Refusing a redirected diagnostic input')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        os.close(descriptor)
        raise RuntimeError('Require a regular single-link diagnostic input')
    return os.fdopen(descriptor, 'rb') if binary else os.fdopen(descriptor, errors='replace')


def parser_module():
    with read_plain(ROOT / PARSER_PATH, binary=True) as source:
        raw = source.read()
    if hashlib.sha256(raw).hexdigest() != PARSER_SHA:
        raise RuntimeError('Only the frozen fixed numeric parser may execute')
    module = types.ModuleType('own_fixed_source_numeric_parser')
    exec(compile(raw, str(ROOT / PARSER_PATH), 'exec'), module.__dict__)
    return module


def fixed_role(name):
    if type(name) is not str:
        return None
    folded = name.lower()
    if re.fullmatch(r'fivem_b[0-9]{1,10}_gameprocess[.]exe', folded):
        return 'source-game'
    return ROLES.get(folded)


def observer_roles(observer):
    if not isinstance(observer, dict) or not isinstance(observer.get('events'), list):
        raise RuntimeError('Require the own observer result metadata')
    observed, related, blocked, rejected = collections.defaultdict(list), collections.defaultdict(list), set(), 0

    def reject(event):
        nonlocal rejected
        rejected += 1
        if isinstance(event, dict) and type(event.get('pid')) is int and 1 <= event['pid'] <= 0xffffffff:
            blocked.add(event['pid'])

    for event in observer['events']:
        if (not isinstance(event, dict) or set(event) != FIELDS
                or any(type(event[key]) is not int or not 0 <= event[key] <= 0xffffffff
                       for key in ('pid', 'parent_pid'))
                or type(event['time_ms']) is not int or not 0 <= event['time_ms'] < 2**64
                or event['event'] not in ('ready', 'observed', 'exited', 'still_running', 'completed')
                or (event['exit_hex'] is not None and (type(event['exit_hex']) is not str
                    or re.fullmatch(r'0x[0-9a-fA-F]{8}', event['exit_hex']) is None))):
            reject(event)
            continue
        if event['event'] in ('ready', 'completed'):
            if event['basename'] != 'process_observer.exe':
                reject(event)
            continue
        role = fixed_role(event['basename'])
        if (role is None or event['pid'] == 0
                or (event['event'] == 'exited') != (event['exit_hex'] is not None)):
            reject(event)
            continue
        clean = {'role': role, 'parent_pid': event['parent_pid'], 'time_ms': event['time_ms'],
                 'event': event['event'], 'exit_code': int(event['exit_hex'], 16) if event['exit_hex'] else None}
        related[event['pid']].append(clean)
        if event['event'] == 'observed':
            observed[event['pid']].append(clean)
    result = {}
    for pid, instances in observed.items():
        unique = len(instances) == 1 and pid not in blocked
        first = instances[0]
        exits = [event for event in related[pid] if event['event'] == 'exited']
        unique = unique and len(exits) <= 1 and all(
            (event['role'], event['parent_pid']) == (first['role'], first['parent_pid']) for event in related[pid])
        result[pid] = ({'role': first['role'], 'role_association': 'unique_observed_windows_pid',
                        'parent_pid': first['parent_pid'], 'observed_time_ms': first['time_ms'],
                        'exit_time_ms': exits[0]['time_ms'] if exits else None,
                        'exit_code': exits[0]['exit_code'] if exits else None} if unique else
                       {'role': 'ambiguous', 'role_association': 'multiple_or_conflicting_observer_instances'})
    for pid in blocked:
        result[pid] = {'role': 'ambiguous', 'role_association': 'rejected_observer_event_for_pid'}
    return result, rejected


def extract(lines, observer, parser=None):
    parser = parser_module() if parser is None else parser
    roles, observer_rejects = observer_roles(observer)
    positions, scanned = [], 0

    def markers():
        nonlocal scanned
        for number, line in enumerate(lines, 1):
            scanned = number
            if '[CFX_WINE_API]' in line:
                positions.append(number)
                yield line

    parsed = parser.parse_lines(markers())
    for event in parsed['records']:
        event['line'] = positions[event['line'] - 1]
        event.update(roles.get(event['pid'], {'role': 'unobserved', 'role_association': 'no_observed_pid_match'}))
    for event in parsed['unmatched_returns']:
        event['line'] = positions[event['line'] - 1]
    for event in parsed['pending_observed_calls']:
        event['begin_line'] = positions[event['begin_line'] - 1]
    counts = collections.Counter((event['pid'], event['role'], event['api'], event['status'])
                                 for event in parsed['records'])
    return {'numeric_contract': parsed, 'source_lines_examined': scanned,
            'fixed_event_counts': [{'pid': pid, 'role': role, 'api': api, 'status': status, 'count': count}
                                   for (pid, role, api, status), count in sorted(counts.items())],
            'observer_rejected_event_count': observer_rejects,
            'observer_reader_completed_without_error': observer.get('reader_completed_without_error') is True,
            'observer_ready_before_main': observer.get('ready_before_main') is True,
            'raw_log_or_result_contents_hashed_or_copied': False,
            'authenticated_prefix_or_profile_files_read': False,
            'arbitrary_lines_paths_commands_authentication_or_error_payloads_retained': False,
            'api_failure_establishes_ros_exit_cause': False,
            'limit': 'Fixed numeric records and directly observed Windows PID roles only. Observer polling may miss process lifetimes; ambiguous or unobserved PIDs stay unassigned. Log order is not elapsed time. Missing/capped markers and Win32 failure codes alone establish no ROS cause.'}


def main(argv=None):
    argument_parser = argparse.ArgumentParser(description=__doc__)
    argument_parser.add_argument('label')
    args = argument_parser.parse_args(argv)
    if LABEL.fullmatch(args.label) is None:
        argument_parser.error('Require one exact source-controller label, not an input path')
    log_name = 'logs/' + args.label + '.log'
    result_name = 'research/' + args.label + '-results.json'
    with read_plain(ROOT / result_name) as source:
        source_result = json.load(source)
    if (source_result.get('runtime_engine_profile') != 'numeric' or source_result.get('developer_code_version') != 8
            or source_result.get('wine_debug_channels') != '-all,+cfxnum' or source_result.get('log') != log_name
            or source_result.get('stage') != 'build/windows-source-integration'
            or source_result.get('prefix') != 'prefixes/fivem-source-main'
            or source_result.get('log_contents_hashed_or_copied') is not False):
        raise RuntimeError('Require the fixed Source8 numeric controller and its exact technical log role')
    observer = source_result.get('read_only_code_process_observer')
    if (not isinstance(observer, dict) or observer.get('identity', {}).get('path') !=
            'build/windows-process-observer/process_observer.exe'
            or observer.get('identity', {}).get('sha256') != OBSERVER_SHA
            or observer.get('metadata_file') != 'logs/' + args.label + '-observer.ndjson'
            or observer.get('commandlines_profile_or_ticket_data_collected') is not False):
        raise RuntimeError('Require the exact own code-process observer identity')
    with read_plain(ROOT / log_name) as lines:
        report = extract(lines, observer)
    report.update(source_label=args.label, technical_controller_result=result_name,
                  technical_controller_log=log_name, fixed_parser_source=PARSER_PATH, fixed_parser_sha256=PARSER_SHA)
    output = ROOT / 'research' / (args.label + '-numeric-trace.json')
    if output.parent.resolve(strict=True) != ROOT / 'research':
        raise RuntimeError('Numeric extraction output must remain in its own research role')
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as target:
        json.dump(report, target, indent=2)
        target.write('\n')
    print(json.dumps({'result': str(output.relative_to(ROOT)),
                      'accepted_numeric_records': len(report['numeric_contract']['records']),
                      'rejected_numeric_marker_lines': report['numeric_contract']['rejected_marker_lines'],
                      'ros_failure_cause_established': False}, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
