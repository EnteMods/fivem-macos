#!/usr/bin/env python3
"""Compare the exact Source dyld search choices in own Win32 class registration."""

import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from actctx_run import DIAGNOSTIC_PAYLOADS, DIAGNOSTIC_ROW, HERE, PROVIDER, ROOT, verify_provider


FAULT = re.compile(r'trace:seh:handle_syscall_fault code=c0000005 flags=[0-9a-f]+ '
                   r'addr=(?:0x)?0*bad4007 ip=0*bad4007 tid=([0-9a-f]{1,8})')
INFO = re.compile(r'trace:seh:handle_syscall_fault +info\[([01])\]=([0-9a-f]{16})')
RETURN = re.compile(r'trace:seh:handle_syscall_fault returning to user mode ip=[0-9a-f]{16} ret=c0000005')
COPY = re.compile(r'trace:cursor:CopyImage hnd=(?:0x)?[0-9a-fA-F]{1,16}, type=1, '
                  r'desiredx=[0-9]+, desiredy=[0-9]+, flags=[0-9a-f]+')


def parse_output(lines, exit_code, icon):
    events = [json.loads(line) for line in lines]
    valid = (all(type(row) is dict and set(row) == {'step', 'pid', 'tid', 'value', 'error'}
                 and type(row['step']) is str
                 and all(type(row[k]) is int and 0 <= row[k] <= 0xffffffff for k in ('pid', 'tid', 'value', 'error'))
                 and row['pid'] and row['tid'] for row in events)
             and len({(row['pid'], row['tid']) for row in events}) == 1
             and len({row['step'] for row in events}) == len(events)
             and events[0]['step'] == 'ready' and events[0]['value'] == icon)
    expected = (['ready', 'icon'] if icon else ['ready']) + ['register', 'create', 'destroy', 'unregister']
    if icon:
        expected.append('destroy_icon')
    outputs = {row['step']: row for row in events} if valid else {}
    atom = outputs.get('register', {}).get('value')
    passed = (valid and list(outputs) == expected and exit_code == 0
              and 0xc000 <= atom <= 0xffff
              and all(outputs[step]['value'] == 1 for step in expected if step not in ('ready', 'register')))
    return {'events': events, 'valid_metadata': valid, 'passed': passed}


def parse_diagnostics(lines, output, icon):
    if not output or not output['valid_metadata']:
        return {'matched_thread': False, 'passed': False}
    ready = output['events'][0]
    pid, tid = ready['pid'], ready['tid']
    prefix = re.compile(r'([0-9a-f]{1,8}):([0-9a-f]{1,8}):(.*)')
    records, begin, end = [], None, None
    for index, line in enumerate(lines):
        row = DIAGNOSTIC_ROW.fullmatch(line)
        if not row or (int(row[1], 16), int(row[2], 16)) != (pid, tid):
            continue
        payload = DIAGNOSTIC_PAYLOADS.get(row[3])
        fields = payload.fullmatch(row[4]) if payload else None
        if not fields:
            return {'matched_thread': True, 'passed': False}
        values = tuple(map(int, fields.groups()))
        if row[3] == 'trace_registration' and values[0] in (1, 5):
            continue
        records.append((row[3], values))
        if row[3] == 'trace_class_resolution' and values == (1, 1, 9, 0, 0):
            begin = index
        if row[3] == 'trace_class_atom':
            end = index

    atom = next((row['value'] for row in output['events'] if row['step'] == 'register'), None)
    expected = [('trace_registration', (2, 0, 0)), ('trace_class_resolution', (1, 1, 9, 0, 0)),
                ('trace_class_atom', (atom,)), ('trace_registration', (4, 1, 0)),
                ('trace_class_resolution', (2, 1, 9, 0, 0)), ('trace_class_removal', (1, 0))]
    faults, copies = [], 0
    active_fault = None
    if begin is not None and end is not None and begin < end:
        for line in lines[begin + 1:end]:
            row = prefix.fullmatch(line)
            if not row or (int(row[1], 16), int(row[2], 16)) != (pid, tid):
                continue
            body = row[3]
            fault = FAULT.fullmatch(body)
            if body.startswith('trace:seh:handle_syscall_fault code='):
                active_fault = None
                if fault and int(fault[1], 16) == tid:
                    active_fault = {'execute': False, 'fault_address_confirmed': False, 'returned_c0000005': False}
                    faults.append(active_fault)
            if active_fault is not None:
                info = INFO.fullmatch(body)
                if info and info[1] == '0':
                    active_fault['execute'] = int(info[2], 16) == 8
                elif info and info[1] == '1':
                    active_fault['fault_address_confirmed'] = int(info[2], 16) == 0x0bad4007
                elif body.startswith('trace:seh:handle_syscall_fault returning to '):
                    active_fault['returned_c0000005'] = RETURN.fullmatch(body) is not None
                    active_fault = None
            copies += bool(COPY.fullmatch(body))

    lookup_miss = any(row['step'] == 'create' and row['value'] == 0 and row['error'] == 1411
                      for row in output['events'])
    reproduced = atom == 5 and lookup_miss and any(all(fault.values()) for fault in faults)
    return {'matched_thread': begin is not None and end is not None and begin < end,
            'pid': pid, 'tid': tid, 'registration_records': records, 'sentinel_faults': faults,
            'copy_image_calls': copies, 'exact_live_failure_reproduced': reproduced,
            'passed': records == expected and not faults and bool(copies) == icon}


def main():
    runner_path = ROOT/'native/wine-parity-probes/run.py'
    spec = importlib.util.spec_from_file_location('own_host_registration_parity', runner_path)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    runtime = runner.runtime
    provider = verify_provider(runner)
    source = HERE/'host_registration_probe.c'
    build = Path(tempfile.mkdtemp(prefix='wine-host-registration-', dir=ROOT/'build'))
    binary = build/'host-registration-probe.exe'
    subprocess.run(['/opt/homebrew/bin/x86_64-w64-mingw32-gcc', '-std=c11', '-O2', '-Wall', '-Wextra',
                    '-Werror', '-static', str(source), '-luser32', '-o', str(binary)], check=True)
    runtime_inputs = [runner.identity(binary)]
    source_inputs = [runner.identity(path) for path in (source, Path(__file__).resolve(), HERE/'actctx_run.py', runner_path)]

    search = os.pathsep.join(map(str, (runtime.ENGINE/'lib/wine/x86_64-unix', runtime.MOLTENVK.parent,
                                      runtime.FRAMEWORKS, runtime.GST_LIB)))
    fallback = {'DYLD_FALLBACK_LIBRARY_PATH': search, 'DYLD_FALLBACK_FRAMEWORK_PATH': str(runtime.FRAMEWORKS)}
    validate = runner.validate_environment

    def validate_environment(env):
        if (any(env.get(key) != value for key, value in fallback.items())
                or env.get('DYLD_LIBRARY_PATH') not in (None, search)
                or env.get('DYLD_FRAMEWORK_PATH') != str(runtime.FRAMEWORKS)):
            raise ValueError('Changed Source dyld comparison paths')
        validate({key: value for key, value in env.items() if key not in fallback})

    # The Parity runner was loaded privately. Keep its original lifecycle and validate the two exact additional values.
    runner.validate_environment = validate_environment

    def run(system):
        dyld = {**fallback, 'DYLD_FRAMEWORK_PATH': str(runtime.FRAMEWORKS),
                'DYLD_LIBRARY_PATH': None if system else search}

        def verify_inputs():
            if (any(runner.identity(ROOT/item['path']) != item for item in (*source_inputs, *runtime_inputs))
                    or verify_provider(runner) != provider):
                raise ValueError('A fixed host registration probe input changed')
            return {'source_inputs': source_inputs, 'runtime_inputs': runtime_inputs, 'provider_inputs': provider,
                    'dyld_search': dyld}

        def environment(verified):
            env = runtime.environment(verified)
            env.update({key: value for key, value in dyld.items() if value is not None})
            if system:
                env.pop('DYLD_LIBRARY_PATH', None)
            env['WINEDLLPATH_PREPEND'] = str(PROVIDER)
            env['WINEDLLOVERRIDES'] += ';user32=b'
            env['WINEDEBUG'] += ',+pid,+seh,+cursor,+cfxwndreg'
            return env

        def case(name):
            output = None
            icon = name == 'icon'

            def stdout(lines, exit_code):
                nonlocal output
                output = parse_output(lines, exit_code, icon)
                return output

            def stderr(lines, _exit_code):
                return parse_diagnostics(lines, output, icon)

            return {'name': name, 'binary': binary, 'cwd': build, 'arguments': (name,),
                    'parse_output': stdout, 'parse_diagnostics': stderr}

        role = 'host-registration-system' if system else 'host-registration-override'
        return runner.run_cases([case('cold'), case('icon')], verify_inputs=verify_inputs,
                                role=role, environment_factory=environment)

    baseline = run(False)
    system = run(True)
    return max(baseline, system)


if __name__ == '__main__':
    raise SystemExit(main())
