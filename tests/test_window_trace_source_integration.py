"""Optional numeric window trace controller paths, with own pipes and temp logs."""
from contextlib import ExitStack, redirect_stderr, redirect_stdout, nullcontext
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / 'native/windows-client'))
import run_source
from window_creation_stream import WindowCreationStream
from window_creation_trace import Collector
from window_class_trace import Collector as ClassCollector


class WindowTraceSourceIntegrationTests(unittest.TestCase):
    def test_system_dyld_search_is_opt_in_for_parity_and_preserves_fallback(self):
        for enabled in (False, True):
            args = ['run_source.py', 'resume', '--runtime', 'parity']
            if enabled:
                args.append('--system-dyld-search')
            with self.subTest(enabled=enabled), mock.patch.object(sys, 'argv', args), \
                    mock.patch.object(run_source, 'run', return_value=0) as run:
                self.assertEqual(run_source.main(), 0)
                self.assertEqual(run.call_args.kwargs.get('system_dyld_search', False), enabled)
        env = {'DYLD_LIBRARY_PATH': '/own/lib', 'DYLD_FALLBACK_LIBRARY_PATH': '/own/lib',
               'DYLD_FRAMEWORK_PATH': '/own/frameworks'}
        run_source.use_system_dyld_search(env)
        self.assertEqual(env, {'DYLD_FALLBACK_LIBRARY_PATH': '/own/lib',
                               'DYLD_FRAMEWORK_PATH': '/own/frameworks'})
        with self.assertRaises(RuntimeError):
            run_source.use_system_dyld_search({'DYLD_LIBRARY_PATH': '/own/lib'})
        for profile, relay in (('matched', False), ('parity', True)):
            with self.subTest(profile=profile, relay=relay), \
                    mock.patch.object(run_source, 'check_inputs') as inputs:
                with self.assertRaises(ValueError):
                    run_source.run(1, runtime_profile=profile, exit_relay=relay, system_dyld_search=True)
                inputs.assert_not_called()

    def test_cli_forwards_only_explicit_trace_and_keeps_default_off(self):
        for enabled in (False, True):
            args = ['run_source.py', 'resume', '--runtime', 'parity']
            if enabled: args += ['--trace-window-creation', '--keep-open']
            with self.subTest(enabled=enabled), mock.patch.object(sys, 'argv', args), \
                    mock.patch.object(run_source, 'window_trace_support') as support, \
                    mock.patch.object(run_source, 'run', return_value=0) as run:
                self.assertEqual(run_source.main(), 0)
            self.assertEqual(run.call_args.kwargs.get('trace_window_creation', False), enabled)
            self.assertEqual(run.call_args.kwargs.get('keep_open', False), enabled)
            self.assertEqual(run.call_args.kwargs['runtime_profile'], 'parity')
            if enabled: support.assert_called_once_with('parity', False)
            else: support.assert_not_called()

    def test_incompatible_runtime_or_relay_rejected_before_inputs_and_spawn(self):
        cases = [('matched', False), ('read', False), ('numeric', False), ('session-proxy', False), ('parity', True)]
        for profile, relay in cases:
            args = ['run_source.py', 'resume', '--runtime', profile, '--trace-window-creation']
            if relay: args.append('--exit-relay')
            with self.subTest(profile=profile, relay=relay), mock.patch.object(sys, 'argv', args), \
                    mock.patch.object(run_source, 'check_inputs') as inputs, \
                    mock.patch.object(run_source, 'sha', side_effect=AssertionError('must reject before proof reads')), \
                    mock.patch.object(run_source.subprocess, 'Popen') as spawn, redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit): run_source.main()
                inputs.assert_not_called();spawn.assert_not_called()
                with self.assertRaises(ValueError):
                    run_source.run(1, runtime_profile=profile, exit_relay=relay, trace_window_creation=True)
                inputs.assert_not_called();spawn.assert_not_called()

    def exercise(self, failure=None, *, window_class=False):
        import source_main_environment
        events, outputs, streams = [], [], []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            for name in ('logs', 'research'): (root / name).mkdir()
            stage, prefix = root / 'build/windows-source-integration', root / 'prefixes/fivem-source-main'
            runtime = SimpleNamespace(ENGINE=root / 'own-engine', WINE=root / 'own-engine/bin/wine')
            read_fd, write_fd = os.pipe()
            pipe = os.fdopen(read_fd, 'rb', buffering=0)
            self.addCleanup(lambda: pipe.close() if not pipe.closed else None)
            data = (b'0040:0044:trace:class:NtUserRegisterClassExWOW name=L"grcWindow" hinst=DEADBEEF style=0x0 clExtr=0x0 winExtr=0x0\n'
                    b'0040:0044:trace:class:NtUserRegisterClassExWOW PRIVATE_CLASS_NAME\n'
                    b'0040:0044:trace:win:WIN_CreateWindowEx L"grcWindow" 87654321 -> not found\n'
                    if window_class else b'0040:0044:trace:win:NtUserCreateWindowEx created window 0x1234\n')
            os.write(write_fd, data + b'0040:trace:win:NtUserCreateWindowEx PRIVATE_WINDOW_TITLE\nOWN_BASELINE\n')
            os.close(write_fd)
            def wait(**kwargs):
                events.append('parent-wait')
                self.assertFalse(outputs[0].closed)
                return 0
            parent = SimpleNamespace(pid=42, stdout=pipe, poll=lambda: 0, wait=mock.Mock(side_effect=wait))
            original_fdopen = os.fdopen
            class Output:
                def __init__(self, handle): self.handle = handle
                def __getattr__(self, name): return getattr(self.handle, name)
                def close(self): events.append('output-close');self.handle.close()
            def output_file(*args, **kwargs):
                value = Output(original_fdopen(*args, **kwargs));outputs.append(value)
                return value
            class Stream(WindowCreationStream):
                def __init__(self, collector): super().__init__(collector);streams.append(self)
                def attach(self, process, output):
                    events.append('attach')
                    return super().attach(process, output)
                def finish_after_wineserver_cleanup(self):
                    events.append('stream-finish')
                    self_test.assertFalse(outputs[0].closed)
                    return super().finish_after_wineserver_cleanup()
            self_test = self
            def spawn(command, **kwargs):
                events.append('spawn')
                self.assertEqual(command, [str(runtime.WINE), str(stage / 'FiveM.exe')])
                self.assertEqual(kwargs['stdout'], run_source.subprocess.PIPE)
                self.assertEqual(kwargs['stderr'], run_source.subprocess.STDOUT)
                self.assertEqual(kwargs['env']['WINEDEBUG'], '-all,+win,+pid' + (',+class' if window_class else ''))
                if failure == 'popen': raise OSError('OWN_POPEN_FAILURE')
                return parent
            def cleanup(command, **kwargs):
                events.append(command[-1]);self.assertFalse(outputs[0].closed)
                if failure == 'cleanup' and command[-1] == '-w': raise RuntimeError('OWN_CLEANUP_FAILURE')
                return SimpleNamespace(returncode=0)
            observer = SimpleNamespace(wait_ready=lambda: None, finish_after_wineserver_cleanup=lambda: {})
            replacements = dict(ROOT=root, STAGE=stage, PREFIX=prefix,
                **{name: root / 'research' / (name + '.json') for name in ('MANIFEST', 'INITIAL_MANIFEST', 'USER_LOGIN', 'PREFLIGHT')})
            with ExitStack() as stack:
                for name, value in replacements.items(): stack.enter_context(mock.patch.object(run_source, name, value))
                for module, name, options in (
                    (run_source, 'check_inputs', {'return_value': {'developer_code_version': 10, 'files': []}}),
                    (run_source, 'game_mapping', {}), (run_source, 'select_runtime_profile', {'return_value': (runtime, {})}),
                    (run_source, 'source_runtime_environment', {'return_value': {'WINEDEBUG': '-all'}}),
                    (run_source, 'window_trace_support', {'return_value': (
                        ClassCollector if window_class else Collector, Stream, {'own_control': True})}),
                    (run_source, 'ProcessObserver', {'return_value': observer}),
                    (run_source, 'code_only_snapshot', {'return_value': {}}), (run_source, 'sha', {'return_value': 'a'*64}),
                    (source_main_environment, 'source_main_prefix', {'return_value': nullcontext()}),
                    (source_main_environment, 'assert_source_main_prefix', {}),
                    (run_source.subprocess, 'Popen', {'side_effect': spawn}),
                    (run_source.subprocess, 'run', {'side_effect': cleanup}),
                    (run_source.time, 'monotonic', {'side_effect': [100, 102, 103, 104]}),
                    (run_source.os, 'fdopen', {'side_effect': output_file})):
                    stack.enter_context(mock.patch.object(module, name, **options))
                if failure == 'attach':
                    stack.enter_context(mock.patch('window_creation_stream.threading.Thread.start', side_effect=RuntimeError('OWN_ATTACH_FAILURE')))
                with redirect_stdout(io.StringIO()):
                    if failure:
                        kind = OSError if failure == 'popen' else RuntimeError
                        with self.assertRaisesRegex(kind, 'OWN_' + failure.upper() + '_FAILURE'):
                            run_source.run(1, resume=True, runtime_profile='parity', trace_window_creation=True)
                    else:
                        self.assertEqual(run_source.run(1, resume=True, runtime_profile='parity',
                            trace_window_creation=not window_class, trace_window_class=window_class), 0)
            self.assertTrue(outputs[0].closed)
            self.assertLess(events.index('-w'), events.index('stream-finish'))
            self.assertLess(events.index('stream-finish'), events.index('output-close'))
            text = next((root / 'logs').glob('*.log')).read_text()
            self.assertNotIn('PRIVATE_WINDOW_TITLE', text)
            reports = list((root / 'research').glob('*-results.json'))
            record = json.loads(reports[0].read_bytes()) if reports else None
            if failure != 'cleanup': self.assertIsNotNone(record)
            return events, record, text

    def test_trace_stream_filters_titles_and_log_stays_open_through_cleanup(self):
        events, record, text = self.exercise()
        self.assertEqual(text, 'OWN_BASELINE\n')
        self.assertLess(events.index('-w'), events.index('parent-wait'))
        self.assertLess(events.index('parent-wait'), events.index('stream-finish'))
        self.assertTrue(record['window_creation_trace']['stream']['capture_complete'])
        self.assertEqual(record['window_creation_trace']['stream']['numeric_window_trace']['accepted_events'], 1)

    def test_window_class_trace_persists_only_class_metadata(self):
        _, record, text = self.exercise(window_class=True)
        self.assertEqual(text, 'OWN_BASELINE\n')
        stream = record['window_class_trace']['stream']
        self.assertTrue(stream['capture_complete'])
        rows = stream['numeric_window_trace']['events']
        self.assertEqual([row['event'] for row in rows], ['registration_attempt', 'create_lookup_miss'])
        self.assertEqual(rows[1]['observed_registration_contexts'], 0)
        self.assertNotIn('DEADBEEF', repr(record))
        self.assertNotIn('87654321', repr(record))

    def test_popen_failure_closes_unattached_log_after_cleanup_and_retains_failure(self):
        events, record, _ = self.exercise('popen')
        self.assertNotIn('attach', events)
        self.assertEqual(record['runner_failure']['type'], 'OSError')
        self.assertFalse(record['window_creation_trace']['stream']['capture_complete'])

    def test_attach_failure_reaps_parent_and_finishes_stream_after_cleanup(self):
        events, record, _ = self.exercise('attach')
        self.assertIn('parent-wait', events)
        self.assertEqual(record['runner_failure']['type'], 'RuntimeError')
        self.assertFalse(record['window_creation_trace']['stream']['capture_complete'])

    def test_cleanup_exception_preserves_exception_and_still_finishes_filtered_log(self):
        events, _, _ = self.exercise('cleanup')
        self.assertLess(events.index('-w'), events.index('stream-finish'))


if __name__ == '__main__':
    unittest.main()
