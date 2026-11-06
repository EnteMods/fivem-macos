#!/usr/bin/env python3
"""Observe one Error window in the fixed cached Source-Rockstar code directory."""
import datetime
import importlib.util
import json
from pathlib import Path
import signal
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('source_windows', ROOT / 'native/diagnostics/list_source_windows.py')
windows = importlib.util.module_from_spec(spec)
spec.loader.exec_module(windows)
stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
report = ROOT / 'research' / ('source-error-ax-' + stamp + '.json')
output = {'at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'target': 'source-cached-rockstar-launcher', 'window_title': 'Error',
          'found': False, 'actions': [], 'other_window_contents_read': False}
stop_requested = False
def request_stop(_number, _frame):
    global stop_requested
    stop_requested = True
signal.signal(signal.SIGINT, request_stop)
signal.signal(signal.SIGTERM, request_stop)
text_script = '''on run argv
set targetPID to (item 1 of argv) as integer
tell application "System Events"
set targetProcess to first process whose unix id is targetPID
tell targetProcess
set errorWindow to first window whose name is "Error"
set texts to value of every static text of errorWindow
set AppleScript's text item delimiters to linefeed
return texts as text
end tell
end tell
end run'''
raise_script = '''on run argv
set targetPID to (item 1 of argv) as integer
tell application "System Events"
set targetProcess to first process whose unix id is targetPID
tell targetProcess
set errorWindow to first window whose name is "Error"
perform action "AXRaise" of errorWindow
end tell
end tell
end run'''
print('Waiting for fixed Source cached-launcher Error window; report: ' + str(report), flush=True)
deadline = time.monotonic() + 3600
while time.monotonic() < deadline and not output['found'] and not stop_requested:
    visible = json.loads(subprocess.check_output([str(ROOT / 'build/window-capture/list-wine-windows')], text=True, timeout=3))
    errors = [row for row in visible if row.get('title') == 'Error' and type(row.get('native_pid')) is int]
    owners = [row for row in windows.owned_processes({row['native_pid'] for row in errors})
              if row['verified_working_directory'] == 'source-cached-rockstar-launcher']
    for owner in owners:
        selected = [row for row in errors if row['native_pid'] == owner['native_pid']]
        if not selected:
            continue
        row = selected[0]
        if owner not in windows.owned_processes({owner['native_pid']}):
            continue
        output.update(found=True, native_pid=owner['native_pid'], window=row)
        for kind, script in [('static_text', text_script), ('raise', raise_script)]:
            if owner not in windows.owned_processes({owner['native_pid']}):
                output['actions'].append({'kind': kind, 'scope_changed': True})
                break
            try:
                attempt = subprocess.run(['/usr/bin/osascript', '-e', script, str(owner['native_pid'])],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3)
                item = {'kind': kind, 'exit': attempt.returncode}
                if kind == 'static_text' and not attempt.returncode:
                    raw = attempt.stdout[:4096]
                    item.update(text=raw.decode('utf-8', 'replace').strip(), truncated=len(attempt.stdout)>4096)
                elif attempt.returncode:
                    item['diagnostic'] = attempt.stderr[:2048].decode('utf-8', 'replace')
                output['actions'].append(item)
            except subprocess.TimeoutExpired:
                output['actions'].append({'kind': kind, 'timeout': True})
            # A successful text result is sufficient; no foreground action is needed then.
            if kind == 'static_text' and output['actions'][-1].get('text'):
                break
        if owner in windows.owned_processes({owner['native_pid']}):
            activator = ROOT / 'build/window-capture/activate-known-wine-error'
            if (not any(item.get('text') for item in output['actions'])
                    and activator.is_file() and not activator.is_symlink()):
                try:
                    action = subprocess.run([str(activator), str(owner['native_pid']), str(row['window_id'])],
                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=3)
                    output['actions'].append({'kind': 'activate_exact_native_process', 'exit': action.returncode,
                                              'metadata': json.loads(action.stdout) if action.stdout else None})
                except (subprocess.TimeoutExpired, ValueError):
                    output['actions'].append({'kind': 'activate_exact_native_process', 'unavailable': True})
        if owner in windows.owned_processes({owner['native_pid']}):
            capture = ROOT / 'build/window-capture' / ('source-error-ax-' + stamp + '.png')
            try:
                attempt = subprocess.run([str(windows.CAPTURE), str(owner['native_pid']), str(row['window_id']), str(capture)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=12)
                output['capture'] = {'exit': attempt.returncode, 'path': str(capture.relative_to(ROOT))}
            except subprocess.TimeoutExpired:
                output['capture'] = {'timeout': True}
        break
    if not output['found']:
        time.sleep(0.2)
output['ended_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
output['operator_stop_requested'] = stop_requested
with report.open('x') as target:
    json.dump(output, target, indent=2)
    target.write('\n')
print(json.dumps(output), flush=True)
