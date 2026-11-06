#!/usr/bin/env python3
"""Build and measure Win32 class lookup in the account-free Wine parity prefix."""

import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
STEPS = {
    'register_local': (True, 0),
    'local_matching_module': (True, 0),
    'local_different_module': (False, 1411),
    'local_null_instance': None,
    'unregister_local': (True, 0),
    'local_after_unregister': (False, 1411),
    'register_global': (True, 0),
    'global_different_module': (True, 0),
    'unregister_global': (True, 0),
}


def parse_output(lines, exit_code):
    events = [json.loads(line) for line in lines]
    valid = (
        [event['step'] for event in events] == list(STEPS)
        and all(set(event) == {'step', 'pid', 'ok', 'error'}
                and type(event['ok']) is bool and type(event['error']) is int
                and 0 <= event['error'] <= 0xffffffff
                and type(event['pid']) is int and 0 < event['pid'] <= 0xffffffff
                for event in events)
        and len({event['pid'] for event in events}) == 1
    )
    matches = valid and all(STEPS[event['step']] in (None, (event['ok'], event['error']))
                            for event in events)
    return {'events': events, 'passed': matches and exit_code == 0}


def parse_diagnostics(lines, pid):
    sys.path.insert(0, str(ROOT/'native/windows-client'))
    from window_class_trace import parse_lines

    trace = parse_lines(lines, class_names=('FivemOwnProbeLocal', 'FivemOwnProbeGlobal'))
    events = trace['events']
    expected = [
        (1, 'registration_attempt', None, None, None, None),
        (1, 'registration_succeeded', None, None, None, None),
        (1, 'lookup_hit', 1, True, False, False),
        (1, 'create_lookup_miss', 1, False, False, False),
        (1, 'lookup_hit', 1, False, False, True),
        (1, 'unregistered', None, None, None, None),
        (1, 'create_lookup_miss', 0, None, None, False),
        (2, 'registration_attempt', None, None, None, None),
        (2, 'registration_succeeded', None, None, None, None),
        (2, 'lookup_hit', 1, False, True, False),
        (2, 'unregistered', None, None, None, None),
    ]
    actual = [(row['class_id'], row['event'], row.get('observed_registration_contexts'),
               row.get('instance_equal'), row.get('registration_global'),
               row.get('instance_is_null') if 'observed_registration_contexts' in row else None)
              for row in events]
    passed = (pid is not None and all(row['wine_pid'] == pid for row in events)
              and actual == expected and not any(trace[key] for key in
                  ('capped', 'invalid_lines', 'incomplete_lines', 'oversized_lines')))
    return {'class_trace': trace, 'passed': passed}


def main():
    spec = importlib.util.spec_from_file_location('window_class_parity', ROOT/'native/wine-parity-probes/run.py')
    parity = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(parity)
    compiler = shutil.which('x86_64-w64-mingw32-gcc')
    if not compiler:
        raise SystemExit('x86_64-w64-mingw32-gcc is required')

    build = Path(tempfile.mkdtemp(prefix='windows-window-class-', dir=ROOT/'build'))
    owner = build/'window-class-owner.dll'
    library = build/'libwindow-class-owner.dll.a'
    exe = build/'window-class-probe.exe'
    flags = [compiler, '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2', '-static']
    subprocess.run([*flags, '-shared', str(HERE/'owner.c'), '-o', str(owner),
                    '-Wl,--out-implib,' + str(library), '-luser32'], check=True)
    subprocess.run([*flags, str(HERE/'probe.c'), str(library), '-o', str(exe), '-luser32'], check=True)
    inputs = {'runtime_inputs': [parity.identity(path) for path in (exe, owner)],
              'source_inputs': [parity.identity(path) for path in (
                  HERE/'owner.c', HERE/'probe.c', HERE/'run.py', ROOT/'native/windows-client/window_class_trace.py')]}

    def verify_inputs():
        for entry in (*inputs['runtime_inputs'], *inputs['source_inputs']):
            if parity.identity(ROOT/entry['path']) != entry:
                raise RuntimeError('A compiled probe input changed')
        return inputs

    def environment(verified):
        env = parity.runtime.environment(verified)
        env['WINEDEBUG'] += ',+class,+win,+pid'
        return env

    pid = None

    def stdout(lines, exit_code):
        nonlocal pid
        result = parse_output(lines, exit_code)
        if result['passed']:
            pid = result['events'][0]['pid']
        return result

    def stderr(lines, _exit_code):
        return parse_diagnostics(lines, pid)

    return parity.run_cases([{'name': 'window_class_lookup', 'binary': exe, 'cwd': build,
                             'parse_output': stdout, 'parse_diagnostics': stderr}], role='window-class',
                            verify_inputs=verify_inputs, environment_factory=environment)


if __name__ == '__main__':
    raise SystemExit(main())
