#!/usr/bin/env python3
"""Capture the exact Source ROS Error window without sending user input."""
import argparse
import datetime
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--label', required=True)
    args = parser.parse_args()
    if re.fullmatch(r'client-source-ui(?:-resume)?-\d{8}T\d{12}Z', args.label) is None:
        parser.error('Use the current Source controller label')
    spec = importlib.util.spec_from_file_location('source_windows', ROOT / 'native/diagnostics/list_source_windows.py')
    windows = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(windows)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    report = ROOT / 'research' / ('source-error-capture-' + stamp + '.json')
    directory = ROOT / 'build/window-capture'
    directory.mkdir(exist_ok=True)
    windows.plain_ancestors(directory)
    mapping = ROOT / 'logs' / (args.label + '-host-pids.ndjson')
    result = {'at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'label': args.label,
              'found': False, 'captures': [], 'input_sent': False, 'security_settings_changed': False}

    def cg_windows():
        return json.loads(subprocess.check_output([str(directory / 'list-wine-windows')], text=True, timeout=3))

    def start_identity(pid):
        return subprocess.check_output(['/bin/ps', '-p', str(pid), '-o', 'lstart=,comm='], text=True, timeout=3).strip()

    print('Waiting for a mapped Source ROS Error; report: ' + str(report), flush=True)
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline and not result['found']:
        rows = [row for row in cg_windows() if row.get('title') == 'Error' and type(row.get('native_pid')) is int]
        owners = windows.owned_processes({row['native_pid'] for row in rows})
        mapped = []
        if mapping.is_file() and not mapping.is_symlink():
            for line in mapping.read_text().splitlines():
                try:
                    value = json.loads(line)
                except ValueError:
                    continue
                if value.get('event') == 'mapped' and value.get('role') == 2:
                    mapped.append(value)
        for owner in owners:
            if owner['verified_working_directory'] != 'source-cached-rockstar-launcher':
                continue
            matches = [item for item in mapped if item.get('host_pid') == owner['native_pid']]
            selected = [row for row in rows if row['native_pid'] == owner['native_pid']]
            if len(matches) != 1 or len(selected) != 1:
                continue
            row = selected[0]
            try:
                identity = start_identity(owner['native_pid'])
            except (OSError, subprocess.SubprocessError):
                continue

            def bound():
                try:
                    return (owner in windows.owned_processes({owner['native_pid']})
                            and start_identity(owner['native_pid']) == identity and row in cg_windows())
                except (OSError, subprocess.SubprocessError, ValueError):
                    return False

            if not bound():
                continue
            result.update(found=True, window=row, process_mapping=matches[0])
            for kind in ('screencapture', 'sck_v2'):
                if not bound():
                    result['target_ended_or_changed'] = True
                    break
                output = directory / ('source-error-' + stamp + '-' + kind + '.png')
                if output.exists() or output.is_symlink():
                    raise RuntimeError('Refusing an existing capture output')
                if kind == 'screencapture':
                    command = ['/usr/sbin/screencapture', '-x', '-o', '-l', str(row['window_id']), str(output)]
                else:
                    command = [str(directory / 'capture-owned-window-v2'), str(owner['native_pid']),
                               str(row['window_id']), str(output)]
                item = {'kind': kind, 'output': str(output.relative_to(ROOT))}
                try:
                    attempt = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=12)
                    item.update(exit=attempt.returncode, diagnostic=attempt.stderr[:2048].decode('utf-8', 'replace'))
                except subprocess.TimeoutExpired:
                    item['timeout'] = True
                item.update(target_bound_after=bound(), file_written=output.is_file(),
                            pixel_or_error_text_success_claim=False)
                result['captures'].append(item)
            break
        if not result['found']:
            time.sleep(0.15)
    result['ended_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with report.open('x') as target:
        json.dump(result, target, indent=2)
        target.write('\n')
    print(json.dumps(result), flush=True)
    return 0 if result['found'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
