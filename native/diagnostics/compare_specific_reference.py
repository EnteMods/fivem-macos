#!/usr/bin/env python3
"""Compare bounded Windows snapshot metadata with explicitly mapped client files."""
import argparse
import hashlib
import ipaddress
import json
import re
import zipfile
from pathlib import Path

MARKERS = ('fresh_start', 'menu_ready', 'join_result')
FILES = {'corert.dll': 'CoreRT.dll', 'net.dll': 'net.dll', 'adhesive.dll': 'adhesive.dll',
         'sticky.dll': 'sticky.dll', 'legitimacy.dll': 'legitimacy.dll', 'glue.dll': 'glue.dll',
         'libcef.dll': 'bin/libcef.dll', 'citizengame.dll': 'CitizenGame.dll',
         'citizen-game-main.dll': 'citizen-game-main.dll', 'nui-core.dll': 'nui-core.dll'}
HEX = re.compile(r'^[0-9a-f]{64}$')


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def read_archive(path):
    if path.stat().st_size > 5 * 1024 * 1024:
        raise ValueError('archive exceeds size limit')
    with zipfile.ZipFile(path) as z:
        entries = z.infolist()
        if len(entries) != 3 or {e.filename for e in entries} != {m + '.json' for m in MARKERS}:
            raise ValueError('archive must have exactly three uniquely named snapshots')
        if any(e.is_dir() or e.flag_bits & 1 or e.file_size > 1048576 for e in entries) or sum(e.file_size for e in entries) > 3 * 1048576:
            raise ValueError('invalid archive member or size')
        result = {}
        for entry in entries:
            raw = z.read(entry)
            if len(raw) != entry.file_size:
                raise ValueError('invalid archive member length')
            record = json.loads(raw)
            marker = entry.filename[:-5]
            if not isinstance(record, dict) or record.get('schema') != 1 or record.get('marker') != marker:
                raise ValueError('invalid snapshot schema or marker')
            processes, tcp = record.get('processes'), record.get('tcp')
            if not isinstance(processes, list) or len(processes) > 128 or not isinstance(tcp, list) or len(tcp) > 1000:
                raise ValueError('invalid process or TCP list')
            for process in processes:
                if not isinstance(process, dict) or not isinstance(process.get('modules'), list) or len(process['modules']) > 100:
                    raise ValueError('invalid module list')
                for module in process['modules']:
                    if not isinstance(module, dict) or not isinstance(module.get('name'), str) or module['name'].lower() not in FILES:
                        raise ValueError('invalid selected module')
                    sha = module.get('sha256')
                    if sha is not None and (not isinstance(sha, str) or not HEX.fullmatch(sha)):
                        raise ValueError('invalid module digest')
            if any(not isinstance(row, dict) for row in tcp):
                raise ValueError('invalid TCP row')
            result[marker] = record
    return result


def compare(archive, client_dir, target_ip):
    records = read_archive(archive)
    disk = {}
    for name, relative in FILES.items():
        path = client_dir / relative
        try:
            sha = digest(path)
            status = 'ok'
        except FileNotFoundError:
            sha, status = None, 'missing'
        except (OSError, ValueError):
            sha, status = None, 'inaccessible'
        disk[name] = {'relative_path': relative, 'sha256': sha, 'status': status}
    snapshots = []
    for marker in MARKERS:
        src = records[marker]
        snap = {key: src.get(key) for key in ('marker', 'time_utc', 'end_time_utc', 'process_scan', 'tcp_scan', 'manual_status', 'truncation', 'rockstar_scope_unknown')}
        snap['processes'] = []
        for proc in src['processes']:
            p = {key: proc.get(key) for key in ('name', 'pid', 'ppid', 'start_utc', 'modules_status')}
            p['modules'] = []
            for module in proc['modules']:
                name = module['name'].lower()
                win, mac = module.get('sha256'), disk[name]['sha256']
                comparison = 'UNKNOWN' if win is None or mac is None else 'MATCH' if win == mac else 'DIFFERENT'
                p['modules'].append({**{k: module.get(k) for k in ('name', 'sha256', 'hash_status', 'version', 'version_status')}, 'mac_disk_comparison': comparison})
            snap['processes'].append(p)
        target = [row for row in src['tcp'] if row.get('remote_address') == target_ip and row.get('remote_port') == 30120]
        snap['selected_tcp_rows'] = len(src['tcp'])
        snap['target_tcp_count'] = len(target)
        snap['target_tcp_rows'] = [{'pid': row.get('pid'), 'state': row.get('state'), 'remote_port': 30120} for row in target]
        snapshots.append(snap)
    return {'schema': 1, 'source_archive': {'path': str(archive), 'sha256': digest(archive), 'bytes': archive.stat().st_size},
            'client_dir': str(client_dir), 'mac_disk': disk, 'snapshots': snapshots,
            'limits': ['Windows hashes and current Mac hashes describe disk files, not process memory.',
                       'Snapshots are sequential and omit transient events and nonselected modules.',
                       'TCP metadata and manual status do not prove ticket issuance or provider registration.',
                       'Mac disk comparison does not prove which file was loaded by a prior process.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', required=True, type=Path)
    parser.add_argument('--client-dir', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--target-ip', required=True, type=ipaddress.IPv4Address)
    args = parser.parse_args()
    if not args.client_dir.is_dir():
        parser.error('client directory is unavailable')
    result = compare(args.archive, args.client_dir, str(args.target_ip))
    with args.output.open('x', encoding='utf-8') as out:
        json.dump(result, out, indent=2, ensure_ascii=False)
        out.write('\n')


if __name__ == '__main__':
    main()
