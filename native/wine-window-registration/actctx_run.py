#!/usr/bin/env python3
"""Build and run the own activation-context probe using the Parity lifecycle."""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PROVIDER = ROOT/'build/wine-window-registration-hnyy8ikw'
PROVIDER_PINS = {
    'build.json': (526, '5431369816114ca304421f08dff8c65ac67873e57a4ae41b3a334d2bf4e5299b'),
    'x86_64-windows/user32.dll': (7339758, 'ea44ab7bdd5731d8e3b84eaf4c57b777c2b856616579b47938a8dd3b6e54cdf5'),
}
DIAGNOSTIC_ROW = re.compile(r'([0-9a-f]{1,8}):([0-9a-f]{1,8}):trace:cfxwndreg:(trace_[a-z_]+) (.*)')
DIAGNOSTIC_PAYLOADS = {
    'trace_registration': re.compile(r'phase=([1-5]) ok=([01]) error=([0-9]{1,10})'),
    'trace_class_resolution': re.compile(r'role=([12]) kind=([012]) units=([0-9]{1,3}) prefix=([0-9]{1,3}) atom_input=([01])'),
    'trace_class_atom': re.compile(r'atom=([0-9]{1,5})'),
    'trace_class_removal': re.compile(r'ok=([01]) error=([0-9]{1,10})'),
}
STEPS = {
    'create_context': (True, 0),
    'activate': (True, 0),
    'register': (True, 0),
    'active_unqualified': (True, 0),
    'destroy_active': (True, 0),
    'deactivate': (True, 0),
    'inactive_unqualified': (False, 1411),
    'inactive_versioned': (True, 0),
    'destroy_versioned': (True, 0),
    'reactivate': (True, 0),
    'reactivated_unqualified': (True, 0),
    'destroy_reactivated': (True, 0),
    'unregister': (True, 0),
    'deactivate_final': (True, 0),
}


def parse_output(lines, exit_code):
    events = [json.loads(line) for line in lines]
    valid = (
        all(type(row) is dict and set(row) == {'step', 'pid', 'ok', 'error'}
            and type(row['step']) is str and type(row['ok']) is bool
            and type(row['error']) is int and 0 <= row['error'] <= 0xffffffff
            and type(row['pid']) is int and 0 < row['pid'] <= 0xffffffff for row in events)
        and [row['step'] for row in events] == list(STEPS)
        and len({row['pid'] for row in events}) == 1
    )
    passed = valid and all(STEPS[row['step']] == (row['ok'], row['error']) for row in events)
    return {'events': events, 'passed': passed and exit_code == 0}


def parse_diagnostics(lines, expected_pid):
    events, threads, invalid = [], set(), 0
    for line in lines:
        if ':cfxwndreg:' not in line.lower():
            continue
        row = DIAGNOSTIC_ROW.fullmatch(line)
        payload = DIAGNOSTIC_PAYLOADS.get(row[3]) if row else None
        fields = payload.fullmatch(row[4]) if payload else None
        if not fields:
            invalid += 1
            continue
        pid, tid = int(row[1], 16), int(row[2], 16)
        if pid != expected_pid:
            continue
        kind, values = row[3], tuple(map(int, fields.groups()))
        # RegisterClassW scope rows also occur for unrelated classes.
        if kind == 'trace_registration' and values[0] in (1, 5):
            continue
        threads.add(tid)
        events.append((kind, values))

    atom_ok = (len(events) == 6 and events[2][0] == 'trace_class_atom'
               and 0 < events[2][1][0] <= 0xffff)
    passed = (expected_pid is not None and len(threads) == 1 and 0 not in threads and invalid == 0
              and atom_ok and events[:2] == [('trace_registration', (2, 0, 0)),
                                            ('trace_class_resolution', (1, 2, 17, 8, 0))]
              and events[3:] == [('trace_registration', (4, 1, 0)),
                                 ('trace_class_resolution', (2, 2, 17, 8, 0)),
                                 ('trace_class_removal', (1, 0))])
    return {'events': events, 'wine_tid': next(iter(threads)) if len(threads) == 1 else None,
            'invalid_records': invalid, 'passed': passed}


def verify_provider(parity):
    parity.runtime.canonical(PROVIDER/'x86_64-windows', ROOT)
    if ({path.name for path in PROVIDER.iterdir()} - {'window-registration-probe.exe'} !=
            {'build.json', 'class.c', 'class.o', 'cfx_numeric.h', 'x86_64-windows'}
            or {path.name for path in (PROVIDER/'x86_64-windows').iterdir()} != {'user32.dll'}):
        raise ValueError('Unexpected files in the fixed User32 provider')
    identities = []
    for name, pin in PROVIDER_PINS.items():
        item = parity.identity(PROVIDER/name)
        if (item['bytes'], item['sha256']) != pin:
            raise ValueError('Resolved User32 provider or report changed')
        identities.append(item)
    report = json.loads(parity.runtime.read_regular(PROVIDER/'build.json'))
    if (report.get('provider') != str(PROVIDER.relative_to(ROOT))
            or report.get('resolved_name_trace') is not True
            or report.get('candidate_sha256') != identities[1]['sha256']
            or report.get('imports_unchanged') is not True or report.get('exports_unchanged') is not True):
        raise ValueError('Require the resolved User32 provider build report')
    return identities


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--provider', type=Path, help='Enable the exact reviewed resolved User32 build')
    args = parser.parse_args()
    if args.provider is not None and ROOT/args.provider != PROVIDER:
        parser.error('Expected the exact resolved User32 provider directory')

    runner = ROOT/'native/wine-parity-probes/run.py'
    spec = importlib.util.spec_from_file_location('own_actctx_parity', runner)
    parity = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(parity)
    provider_inputs = verify_provider(parity) if args.provider is not None else []

    source, manifest = HERE/'actctx_probe.c', HERE/'actctx.manifest'
    source_inputs = [parity.identity(path) for path in (source, manifest, Path(__file__).resolve(), runner)]
    build = Path(tempfile.mkdtemp(prefix='wine-window-actctx-', dir=ROOT/'build'))
    binary = build/'actctx-probe.exe'
    with (build/manifest.name).open('xb') as output:
        output.write(parity.runtime.read_regular(manifest))
    subprocess.run(['/opt/homebrew/bin/x86_64-w64-mingw32-gcc', '-std=c11', '-O2', '-Wall', '-Wextra',
                    '-Werror', '-static', str(source), '-luser32', '-o', str(binary)], check=True)
    runtime_inputs = [parity.identity(path) for path in (binary, build/manifest.name)]

    def verify_inputs():
        for item in (*source_inputs, *runtime_inputs):
            if parity.identity(ROOT/item['path']) != item:
                raise RuntimeError('Activation-context fixture input changed')
        if provider_inputs and verify_provider(parity) != provider_inputs:
            raise RuntimeError('Activation-context provider binding changed')
        return {'source_inputs': source_inputs, 'runtime_inputs': runtime_inputs,
                **({'provider_inputs': provider_inputs} if provider_inputs else {})}

    def environment(verified):
        env = parity.runtime.environment(verified)
        env['WINEDEBUG'] += ',+class,+win,+pid'
        if provider_inputs:
            search = env.get('WINEDLLPATH_PREPEND')
            env['WINEDLLPATH_PREPEND'] = os.pathsep.join(filter(None, (str(PROVIDER), search)))
            env['WINEDLLOVERRIDES'] += ';user32=b'
            env['WINEDEBUG'] += ',+cfxwndreg'
        return env

    case = {'name': 'versioned_class', 'binary': binary, 'cwd': build, 'parse_output': parse_output}
    role = 'window-actctx'
    if provider_inputs:
        pid = None

        def stdout(lines, exit_code):
            nonlocal pid
            result = parse_output(lines, exit_code)
            if result['passed']:
                pid = result['events'][0]['pid']
            return result

        def stderr(lines, _exit_code):
            return parse_diagnostics(lines, pid)

        case.update(parse_output=stdout, parse_diagnostics=stderr)
        role = 'window-actctx-resolved'
    return parity.run_cases([case], role=role, verify_inputs=verify_inputs, environment_factory=environment)


if __name__ == '__main__':
    raise SystemExit(main())
