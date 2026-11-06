#!/usr/bin/env python3
"""Own-window trace control; no client, registry, relay, or hook changes."""
import argparse
import hashlib
import json
from pathlib import Path
import stat
import types

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
BASE = 'native/windows-dxgi-swapchain/run.py'
BASE_PIN = (14290, '80a9f5078082a505824f9911cb08de13e3de614743eae00ac5188d5d9e288269')
PARSER = 'native/windows-client/window_creation_trace.py'
PARSER_PIN = (5070, 'bc3aa7429bae139d7ea5634da301b1a2d6a231fd2971491a33b2ef8321259e76')


def _load(name, pin):
    if pin is None:
        raise RuntimeError('The reviewed window parser pin is not issued')
    path = ROOT / name
    if path.resolve(strict=True) != path:
        raise RuntimeError('Require the exact own-control source path')
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise RuntimeError('Require regular single-link own-control source')
    raw = path.read_bytes()
    after = path.lstat()
    if ((len(raw), hashlib.sha256(raw).hexdigest()) != pin
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
               (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
        raise RuntimeError('Own-control source changed')
    module = types.ModuleType('_own_windowtrace_' + path.stem)
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


base = _load(BASE, BASE_PIN)


def verify_inputs():
    fixture = base.verify_inputs()
    window_parser = _load(PARSER, PARSER_PIN)
    if not callable(getattr(window_parser, 'parse_lines', None)):
        raise RuntimeError('Require the reviewed pure window-trace parser')
    return {**fixture,
        'runner_sources': [*fixture['runner_sources'],
            base._identity(PARSER), base._identity(str((HERE / 'trace_window_control.py').relative_to(ROOT)))],
        'window_trace_control': {'parser_source': base._identity(PARSER),
            'wine_debug_additions': ['win', 'pid'], 'client_started': False,
            'present_called': False, 'same_process_own_window_only': True,
            'requires_created_event_with_actual_stdout_windows_pid': True,
            'missing_created_event_proves_null': False,
            'raw_wine_log_contains_only_account_free_own_fixture_execution': True}}


def trace_environment(verified):
    env = base.graphics().graphics_environment(verified)
    env['WINEDEBUG'] += ',+win,+pid'
    return env


def cases():
    verify_inputs()
    original = base.cases()
    if len(original) != 1 or original[0]['name'] != 'own_hwnd_discard_swapchain':
        raise RuntimeError('Require exactly the unchanged own swapchain fixture')
    case = dict(original[0])
    state = {'windows_pid': None}
    window_parser = _load(PARSER, PARSER_PIN)

    def stdout(lines, code):
        result = case_stdout(lines, code)
        if result.get('metadata_capture_passed') is True:
            ready = result['events'][0]
            state['windows_pid'] = ready['windows_pid']
        return result

    def stderr(lines, code):
        provider = case_stderr(lines, code)
        trace = window_parser.parse_lines(lines)
        pid = state['windows_pid']
        created = [row for row in trace['events'] if row.get('event') == 'created'
                   and type(pid) is int and row.get('wine_pid') == pid
                   and type(row.get('hwnd')) is int and row['hwnd'] != 0]
        captured = bool(created) and trace.get('capped') is False
        return {'passed': provider.get('passed') is True and captured,
            'graphics_provider_diagnostics': provider, 'window_trace': trace,
            'actual_stdout_windows_pid': pid, 'matching_created_events': len(created),
            'created_event_control_passed': captured, 'missing_created_event_proves_null': False,
            'semantic_diagnostics_only': True, 'present_or_client_behavior_tested': False}

    case_stdout, case_stderr = case['parse_output'], case['parse_diagnostics']
    case.update(name='own_hwnd_creation_trace', parse_output=stdout, parse_diagnostics=stderr)
    return [case]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('inspect', 'run'))
    action = parser.parse_args().action
    context = base.graphics()
    if action == 'inspect':
        print(json.dumps({'runtime': context.runtime.verify_runtime(), 'fixture': verify_inputs(),
                          'runtime_or_prefix_started': False}, indent=2))
        return 0
    return context.runner.run_cases(cases(), verify_inputs=verify_inputs, role='dxgi-windowtrace-control',
        environment_factory=trace_environment, prepare_prefix=context.prepare_prefix)


if __name__ == '__main__':
    raise SystemExit(main())
