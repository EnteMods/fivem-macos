#!/usr/bin/env python3
"""Summarize the exact own Windows join-reference ZIP without extracting it."""
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys
import zipfile
LIMITS = {
    'events.jsonl': 33554432,
    'markers.jsonl': 1048576,
    'collector-status.json': 16384,
    'collection-summary.json': 16384,
}
MODULES = {
    'corert.dll', 'net.dll', 'glue.dll', 'legitimacy.dll',
    'adhesive.dll', 'sticky.dll', 'nui-core.dll', 'libcef.dll',
}
ROCKSTAR = {'launcher.exe', 'launcherpatcher.exe', 'rockstarservice.exe', 'socialclubhelper.exe'}
MARKERS = {'menu', 'join', 'connected', 'rejected', 'disconnected', 'cfx_linked', 'cfx_unlinked'}
TCP_STATES = {
    'closed', 'listen', 'synsent', 'synreceived', 'established', 'finwait1',
    'finwait2', 'closewait', 'closing', 'lastack', 'timewait', 'delete',
    'deletetcb', 'bound', 'unknown',
}

class Invalid(Exception):
    pass

def pairs(items):
    out = {}
    for (key, value) in items:
        if key in out:
            raise Invalid('JSON')
        out[key] = value
    return out

def decode(raw):
    try:
        return json.loads(
            raw.decode('utf-8-sig'), object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(Invalid('JSON')),
        )
    except (UnicodeError, ValueError, RecursionError):
        raise Invalid('JSON')

def number(x, limit=4294967295):
    if type(x) is not int or x < 0 or x > limit:
        raise Invalid('NUMBER')
    return x

def fields(x, keys):
    if type(x) is not dict or set(x) != set(keys):
        raise Invalid('FIELDS')

def source_type(name):
    if type(name) is not str or len(name) > 128:
        raise Invalid('PROCESS_NAME')
    if re.fullmatch('FiveM[^\\\\/]*\\.exe', name, re.I):
        return 'FiveM'
    name = name.lower()
    if name in ROCKSTAR:
        return name
    raise Invalid('PROCESS_NAME')

def family(text):
    if type(text) is not str or len(text) > 64:
        raise Invalid('ADDRESS')
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        raise Invalid('ADDRESS')
    if addr.is_loopback:
        scope = 'loopback'
    elif addr.is_unspecified:
        scope = 'unspecified'
    elif addr.is_link_local:
        scope = 'link_local'
    elif addr.is_private:
        scope = 'private'
    elif addr.is_global:
        scope = 'public'
    else:
        scope = 'other'
    return ('ipv4' if addr.version == 4 else 'ipv6') + '_' + scope

def read_zip(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > sum(LIMITS.values()) + 1048576:
        raise Invalid('ZIP')
    try:
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
            names = [x.filename for x in entries]
            if len(names) != 4 or len(set(names)) != 4 or set(names) != set(LIMITS):
                raise Invalid('ZIP_NAMES')
            result = {}
            for info in entries:
                mode = info.external_attr >> 16 & 65535
                if (info.is_dir() or stat.S_ISLNK(mode)
                        or stat.S_IFMT(mode) not in (0, stat.S_IFREG)
                        or info.flag_bits & 1 or info.file_size > LIMITS[info.filename]):
                    raise Invalid('ZIP_ENTRY')
                with archive.open(info) as f:
                    data = f.read(LIMITS[info.filename] + 1)
                if len(data) > LIMITS[info.filename] or len(data) != info.file_size:
                    raise Invalid('ZIP_SIZE')
                result[info.filename] = data
            return result
    except (OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError, EOFError):
        raise Invalid('ZIP')

def lines(raw, maxrows):
    try:
        text = raw.decode('utf-8-sig')
    except UnicodeError:
        raise Invalid('JSON')
    data = text.splitlines()
    if len(data) > maxrows or any((not x or len(x) > 4096 for x in data)):
        raise Invalid('ROWS')
    return [decode(x.encode('utf-8')) for x in data]

def analyze(data):
    state = decode(data['collector-status.json'])
    summary = decode(data['collection-summary.json'])
    fields(state, ('state', 'rows', 'bytes', 'successful_scans', 'targets_seen', 'tcp_scans', 'udp_scans', 'unknown_count'))
    if state['state'] not in ('starting', 'ready', 'stopped', 'capped', 'failed'):
        raise Invalid('STATE')
    for k in ('rows', 'bytes', 'successful_scans', 'targets_seen', 'tcp_scans', 'udp_scans', 'unknown_count'):
        number(state[k], 33554432)
    fields(summary, ('status', 'job_state', 'collector_state'))
    job_states = ('NotStarted', 'Running', 'Completed', 'Failed', 'Stopped',
                  'Stopping', 'Blocked', 'Suspended', 'Disconnected')
    collector_states = ('starting', 'ready', 'stopped', 'capped', 'failed', 'unknown')
    if (summary['status'] not in ('complete', 'incomplete')
            or summary['job_state'] not in job_states
            or summary['collector_state'] not in collector_states):
        raise Invalid('STATE')
    events = lines(data['events.jsonl'], 50000)
    marks = lines(data['markers.jsonl'], 10000)
    snapshot_consistent = state['rows'] == len(events) and state['bytes'] == len(data['events.jsonl'])
    if summary['status'] == 'complete' and (not snapshot_consistent):
        raise Invalid('COUNTS')
    if summary['collector_state'] != state['state'] and summary['collector_state'] != 'unknown':
        raise Invalid('STATE')
    complete_status_valid = (
        summary['job_state'] == 'Completed' and summary['collector_state'] == 'stopped'
        and state['state'] == 'stopped'
        and state['successful_scans'] > 0 and state['targets_seen'] > 0
        and state['tcp_scans'] > 0 and state['udp_scans'] > 0
        and state['unknown_count'] == 0
    )
    if summary['status'] == 'complete' and not complete_status_valid:
        raise Invalid('STATE')
    processes = {}
    modules = {}
    unknown = {}
    network = {}
    scan_success_rows = 0
    target_rows = 0

    def timeline(target, key, t):
        if key not in target:
            target[key] = {'first_ms': t, 'last_ms': t, 'observations': 0}
        row = target[key]
        row['first_ms'] = min(t, row['first_ms'])
        row['last_ms'] = max(t, row['last_ms'])
        row['observations'] += 1
    for e in events:
        if type(e) is not dict or 'type' not in e or 'elapsed_ms' not in e:
            raise Invalid('EVENT')
        t = number(e['elapsed_ms'], 31557600000)
        kind = e['type']
        if kind == 'process':
            fields(e, ('type', 'elapsed_ms', 'name', 'pid', 'ppid'))
            category = source_type(e['name'])
            pid = number(e['pid'])
            ppid = number(e['ppid'])
            if not pid:
                raise Invalid('PID')
            timeline(processes, (pid, ppid, category), t)
            target_rows += 1
        elif kind == 'module':
            fields(e, ('type', 'elapsed_ms', 'pid', 'name', 'status', 'sha256'))
            pid = number(e['pid'])
            name = e['name'].lower() if type(e['name']) is str else ''
            if not pid or name not in MODULES or e['status'] not in ('ok', 'unknown'):
                raise Invalid('MODULE')
            digest = e['sha256']
            if e['status'] == 'ok' and (type(digest) is not str or re.fullmatch('[0-9a-f]{64}', digest) is None):
                raise Invalid('HASH')
            if e['status'] == 'unknown' and digest is not None:
                raise Invalid('HASH')
            if e['status'] == 'unknown':
                unknown['module'] = unknown.get('module', 0) + 1
            timeline(modules, (pid, name, e['status'], digest), t)
        elif kind in ('tcp', 'udp'):
            keys = ('type', 'elapsed_ms', 'pid', 'local_address', 'local_port')
            if kind == 'tcp':
                keys += ('remote_address', 'remote_port', 'state')
            fields(e, keys)
            pid = number(e['pid'])
            local_port = number(e['local_port'], 65535)
            if not pid:
                raise Invalid('PID')
            local = family(e['local_address'])
            remote = None
            tcpstate = None
            port = local_port
            if kind == 'tcp':
                port = number(e['remote_port'], 65535)
                remote = family(e['remote_address'])
                if type(e['state']) is not str or e['state'].lower() not in TCP_STATES:
                    raise Invalid('TCP_STATE')
                tcpstate = e['state'].lower()
            key = (pid, kind, local, remote, tcpstate, port)
            network[key] = network.get(key, 0) + 1
        elif kind in ('modules', 'process_scan', 'tcp_scan', 'udp_scan', 'rockstar_scope'):
            fields(e, ('type', 'elapsed_ms', 'status', 'pid') if kind == 'modules' else ('type', 'elapsed_ms', 'status'))
            if e['status'] not in (('ok', 'unknown') if kind == 'process_scan' else ('unknown',)):
                raise Invalid('STATUS')
            if kind == 'modules' and (not number(e['pid'])):
                raise Invalid('PID')
            if kind == 'process_scan' and e['status'] == 'ok':
                scan_success_rows += 1
            if e['status'] == 'unknown':
                unknown[kind] = unknown.get(kind, 0) + 1
        elif kind == 'collector':
            fields(e, ('type', 'elapsed_ms', 'state'))
            if e['state'] not in ('started', 'stopped'):
                raise Invalid('STATUS')
        else:
            raise Invalid('EVENT')
    observed_unknown = sum(unknown.values())
    if summary['status'] == 'complete' and (
        state['successful_scans'] != scan_success_rows
        or state['targets_seen'] != target_rows or observed_unknown != 0
    ):
        raise Invalid('COUNTS')
    markers = []
    for m in marks:
        fields(m, ('type', 'marker', 'elapsed_ms'))
        if m['type'] != 'marker' or m['marker'] not in MARKERS:
            raise Invalid('MARKER')
        markers.append({
            'marker': m['marker'],
            'elapsed_ms': number(m['elapsed_ms'], 31557600000),
            'origin': 'user_reported',
        })
    network_rows = []
    for key, count in sorted(network.items(), key=lambda item: str(item[0])):
        pid, protocol, local_scope, remote_scope, tcp_state, port = key
        row = {
            'pid': pid,
            'protocol': protocol,
            'local_scope': local_scope,
            'remote_scope': remote_scope,
            'tcp_state': tcp_state,
            'observations': count,
        }
        row['remote_port' if protocol == 'tcp' else 'local_port'] = port
        network_rows.append(row)
    return {
        'schema': 1,
        'collection': {
            'status': summary['status'],
            'job_state': summary['job_state'],
            'collector_state': state['state'],
            'rows': len(events),
            'reported_successful_scans': state['successful_scans'],
            'reported_targets_seen': state['targets_seen'],
            'reported_tcp_scans': state['tcp_scans'],
            'reported_udp_scans': state['udp_scans'],
            'reported_unknown_count': state['unknown_count'],
            'observed_unknown_count': observed_unknown,
            'unknown_count_matches': state['unknown_count'] == observed_unknown,
            'observed_successful_scan_rows': scan_success_rows,
            'observed_target_rows': target_rows,
            'scan_count_matches': state['successful_scans'] == scan_success_rows,
            'target_count_matches': state['targets_seen'] == target_rows,
            'snapshot_counts_match': snapshot_consistent,
        },
        'processes': [
            {'pid': key[0], 'ppid': key[1], 'role': key[2], **value}
            for key, value in sorted(processes.items())
        ],
        'modules': [
            {'pid': key[0], 'basename': key[1], 'status': key[2], 'sha256': key[3], **value}
            for key, value in sorted(
                modules.items(), key=lambda item: (item[0][0], item[0][1], item[0][2], item[0][3] or '')
            )
        ],
        'unknown_access_counts': unknown,
        'network_counts': network_rows,
        'markers': markers,
        'limitations': [
            'Markers are user-reported, not machine proof of server authorization.',
            'An unobserved module is not evidence of absence.',
            'Process intervals are sampled; PID reuse is not ruled out.',
            'IP addresses and TCP local ports are omitted from this summary.',
            'Protocol, ports and TCP state do not identify a ticket request.',
        ],
    }

def main(args):
    if len(args) != 4 or args[0] != '--input' or args[2] != '--output':
        print('{"status":"FAIL","code":"ARGUMENTS"}')
        return 2
    try:
        data = read_zip(args[1])
        result = analyze(data)
        output = Path(args[3])
        payload = (json.dumps(result, indent=2) + '\n').encode()
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 384)
        with os.fdopen(fd, 'wb') as f:
            f.write(payload)
        print('{"status":"OK"}')
        return 0
    except Exception:
        print('{"status":"FAIL","code":"INVALID_INPUT_OR_OUTPUT"}')
        return 1
if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
