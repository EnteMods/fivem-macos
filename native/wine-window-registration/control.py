#!/usr/bin/env python3
"""Compare normal and observed registration in Wine's account-free probe prefix."""

import argparse
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

from build import HERE, ROOT, sha


ROW = re.compile(r'([0-9a-f]{1,8}):([0-9a-f]{1,8}):trace:cfxwndreg:trace_registration '
                 r'phase=([1-5]) ok=([01]) error=([0-9]{1,10})')
EXPECTED = [(1, 0, 0), (2, 0, 0), (4, 1, 0), (5, 1, 0),
            (1, 0, 0), (2, 0, 0), (4, 0, 87), (5, 0, 87),
            (2, 0, 0), (4, 1, 0), (1, 0, 0), (5, 1, 0)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('provider', type=Path)
    args = parser.parse_args()
    provider = args.provider.resolve(strict=True)
    if provider.parent != ROOT/'build' or not provider.name.startswith('wine-window-registration-'):
        raise ValueError('Expected the separate User32 build output')
    report = json.loads((provider/'build.json').read_text())
    resolved = report.get('resolved_name_trace') is True
    if resolved:
        sys.path.insert(0, str(ROOT/'native/windows-client'))
        from window_registration_resolution_trace import Collector
    dll = provider/'x86_64-windows/user32.dll'
    if sha(dll) != report['candidate_sha256'] or {p.name for p in dll.parent.iterdir()} != {'user32.dll'}:
        raise ValueError('Require the build output and no other provider DLLs')

    spec = importlib.util.spec_from_file_location('wine_class_parity', ROOT/'native/wine-parity-probes/run.py')
    parity = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(parity)
    probe = provider/'window-registration-probe.exe'
    subprocess.run(['/opt/homebrew/bin/x86_64-w64-mingw32-gcc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                    '-static', str(HERE/'probe.c'), '-luser32', '-o', str(probe)], check=True)
    inputs = [parity.identity(path) for path in (probe, dll, HERE/'probe.c', HERE/'control.py')]

    def verify_inputs():
        if [parity.identity(ROOT/item['path']) for item in inputs] != inputs:
            raise ValueError('Registration fixture changed before use')
        return {'runtime_inputs': inputs}

    def run(role, overlay=False, trace=False):
        def environment(verified):
            env = parity.runtime.environment(verified)
            if overlay:
                env['WINEDLLPATH_PREPEND'] = str(provider)
                env['WINEDLLOVERRIDES'] += ';user32=b'
            if trace:
                env['WINEDEBUG'] += ',+cfxwndreg,+pid'
            return env

        pid = None

        def stdout(lines, exit_code):
            nonlocal pid
            rows = [json.loads(line) for line in lines]
            pid = rows[0]['pid'] if rows else None
            outputs = [(row['step'], row['ok'], row['error']) for row in rows]
            semantic = [(step, ok) for step, ok, _ in outputs] == [(1, 1), (2, 0), (3, 1), (4, 1)]
            passed = exit_code == 0 and semantic and outputs[1][2] == 87 and all(row['pid'] == pid for row in rows)
            if passed:
                outcomes.append(outputs)
            return {'events': rows, 'passed': passed}

        def stderr(lines, _exit_code):
            events = []
            malformed = 0
            resolution_rows = []
            if resolved:
                collector = Collector()
                for line in lines:
                    collector.accept(line)
                summary = collector.summary()
                resolution_rows = [row for row in summary['resolved_api_events'] if row['wine_pid'] == pid]
                malformed += summary['invalid_lines']
            for line in lines:
                if ':trace:cfxwndreg:' not in line:
                    continue
                if resolved and ':trace:cfxwndreg:trace_class_' in line:
                    continue
                match = ROW.fullmatch(line)
                if not match:
                    malformed += 1
                    continue
                if int(match[1], 16) == pid:
                    events.append(tuple(map(int, match.groups()[2:])))
            passed = malformed == 0 and events == (EXPECTED if trace else [])
            if resolved and trace:
                names = [row for row in resolution_rows if row.get('role') == 1]
                atoms = [row['atom'] for row in resolution_rows if 'atom' in row]
                removals = [row['ok'] for row in resolution_rows if 'ok' in row]
                passed &= (len(names) == 3 and all((row['kind'], row['units'], row['prefix'], row['atom_input']) == (1, 9, 0, 0) for row in names)
                           and len(atoms) == 3 and atoms[0] >= 0xc001 and atoms[1] == 0 and atoms[2] >= 0xc001
                           and removals == [1, 1])
            elif resolved:
                passed &= not resolution_rows
            return {'events': events, 'malformed': malformed, 'resolution_events': resolution_rows, 'passed': passed}

        return parity.run_cases([{'name': 'registration', 'binary': probe, 'cwd': provider,
                                  'parse_output': stdout, 'parse_diagnostics': stderr}],
                                role=role, verify_inputs=verify_inputs, environment_factory=environment)

    outcomes = []
    label = 'window-reg-resolved' if resolved else 'window-reg'
    if (run(label + '-baseline') or run(label + '-off', overlay=True)
            or run(label + '-on', overlay=True, trace=True)):
        return 1
    if not outcomes[0] == outcomes[1] == outcomes[2]:
        raise ValueError('Registration return values or LastError changed')
    print('Original, candidate OFF and candidate ON have identical registration outcomes and LastError')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
