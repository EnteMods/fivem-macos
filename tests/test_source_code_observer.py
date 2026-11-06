"""Mock/own-pipe checks for the opt-in Source code helper; never start Wine."""
from contextlib import contextmanager, redirect_stderr
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'native/windows-client'))
import source_code_observer as bridge
import run_source
import test_source_exit_relay as exit_cases


def parser_type():
    spec = importlib.util.spec_from_file_location('own_source_record_test', ROOT / bridge.PARSER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.SourceCodeRecords


def rows():
    base = 0x140000000
    return [
        {'event': 'ready', 'mode': 'source', 'pid': 104, 'duration_ms': 1000,
         'rva': 0x3203b0, 'length': 64, 'poll_ms': 250, 'record_limit': 20},
        {'event': 'module', 'time_ms': 1, 'pid': 100, 'creation': 1234, 'base': base, 'size': 0x35d0000},
        {'event': 'code', 'time_ms': 2, 'pid': 100, 'creation': 1234,
         'sample': 1, 'rva': 0x3203b0, 'length': 64, 'hex': '90' * 64},
        {'event': 'process_completed', 'time_ms': 750, 'pid': 100, 'creation': 1234,
         'polls': 3, 'read_calls': 3, 'code_records': 1, 'record_limit_reached': False},
        {'event': 'completed', 'mode': 'source', 'polls': 3, 'processes': 1, 'failures': 0, 'exit': 0},
    ]


class SourceCodeObserverTests(unittest.TestCase):
    def test_actual_positive_control_artifacts_and_final_source_parser_bind_without_runtime(self):
        parser, inputs = bridge.load_binding()
        self.assertEqual(parser.__name__, 'SourceCodeRecords')
        observer = next(row for row in inputs if row['path'] == bridge.OBSERVER)
        self.assertEqual(observer['sha256'], '6c9feb2722cbacb232496b1325c5ca5b9797f91c3fa722b27cc04ab7ae9fad10')
        self.assertEqual(next(row for row in inputs if row['path'] == bridge.PARSER)['sha256'],
                         '4bef480b3b5931d18428c9e9cf2224c6fb8e3c7598433cfde61f48f79ea133d4')

    def observer(self):
        runtime = SimpleNamespace(ENGINE=bridge.ENGINE, WINE=bridge.ENGINE / 'bin/wine',
                                  source_runtime_profile={'profile': 'parity'})
        env = {'WINEPREFIX': str(bridge.PREFIX), 'WINESERVER': str(bridge.ENGINE / 'bin/wineserver'),
               'WINEDEBUG': '-all,+pid,FiveM_ROSLauncher:trace+relay', 'CitizenFX_NoTenUI': '1'}
        context = SimpleNamespace(runtime=runtime, environment=env, prepared=True,
                                  _assert_held_context=mock.Mock(), verify_sources=mock.Mock())
        with mock.patch.object(bridge, 'load_binding', return_value=(parser_type(), [])), \
                mock.patch.object(bridge, 'identity', side_effect=lambda name: {'path': name}):
            value = bridge.SourceCodeObserver(runtime, env, bridge.STAGE,
                'client-source-ui-resume-20261102T200000000000Z', 3600, context)
        value.verify_sources = mock.Mock()
        return value

    def test_observation_requires_prepared_same_exit_context_and_exact_parity_scope(self):
        value = self.observer()
        for field in ('prefix', 'stage', 'engine', 'prepared', 'context'):
            env = dict(value.environment)
            runtime = SimpleNamespace(**value.runtime.__dict__)
            context = SimpleNamespace(runtime=runtime, environment=env, prepared=True)
            stage = bridge.STAGE
            if field == 'prefix': env['WINEPREFIX'] = str(ROOT / 'prefixes/rockstar-legacy')
            if field == 'stage': stage = ROOT / 'build/fivem-official'
            if field == 'engine': runtime.ENGINE = ROOT / 'runtime/wine-read-diagnostics/engine'
            if field == 'prepared': context.prepared = False
            if field == 'context': context.runtime = object()
            with self.subTest(field=field), mock.patch.object(bridge, 'load_binding') as binding:
                with self.assertRaises(RuntimeError):
                    bridge.SourceCodeObserver(runtime, env, stage, value.label, 60, context)
                binding.assert_not_called()

    def test_only_parser_return_values_reach_sink_and_code_frames_remain_separate(self):
        value = self.observer()
        value.output = io.StringIO()
        for row in rows(): value._accept(json.dumps(row).encode())
        value._accept(b'PRIVATE_AUTH_VALUE')
        value._accept(json.dumps({**rows()[2], 'path': 'PRIVATE_AUTH_VALUE'}).encode())
        persisted = [json.loads(line) for line in value.output.getvalue().splitlines()]
        self.assertEqual(persisted, rows())
        self.assertNotIn('PRIVATE', value.output.getvalue())
        result = value.result()
        self.assertEqual(result['code_frames'], [rows()[2]])
        self.assertEqual(len(result['metadata_events']), 4)
        self.assertFalse(result['actual_ros_exit_caller_or_cause_claim'])
        self.assertFalse(result['target_process_termination_by_observer'])
        self.assertEqual(result['parser_summary']['rejected_records'], 2)

    def test_incremental_pipe_filter_rejects_unknown_or_unterminated_data(self):
        value = self.observer()
        reader, writer = os.pipe()
        value.process = SimpleNamespace(stdout=os.fdopen(reader, 'rb'))
        value.output = io.StringIO()
        try:
            raw = ('\n'.join(json.dumps(row) for row in rows()) + '\n').encode()
            # Feed through real own pipe I/O, without a subprocess or prefix.
            os.write(writer, raw[:37]); os.write(writer, raw[37:])
            os.write(writer, b'PRIVATE_UNTERMINATED')
            os.close(writer); writer = None
            value._drain()
            self.assertTrue(value.ready.is_set())
            self.assertEqual(len(value.output.getvalue().splitlines()), 5)
            self.assertNotIn('PRIVATE', value.output.getvalue())
            self.assertEqual(value.records.summary()['rejected_records'], 1)
        finally:
            value.process.stdout.close()
            if writer is not None: os.close(writer)

    def test_open_inherited_writer_cannot_hold_reader_after_stop(self):
        value = self.observer()
        reader, writer = os.pipe()
        value.process = SimpleNamespace(stdout=os.fdopen(reader, 'rb'))
        value.output = io.StringIO()
        thread = threading.Thread(target=value._drain)
        thread.start()
        try:
            value.stop.set()
            thread.join(timeout=1)
            self.assertFalse(thread.is_alive())
            os.write(writer, b'own-writer-still-open')
        finally:
            value.stop.set(); thread.join(timeout=1)
            value.process.stdout.close(); os.close(writer)

    def test_start_has_fixed_source_arguments_quiet_helper_and_no_stderr_persistence(self):
        value = self.observer()
        process = SimpleNamespace(stdout=io.BytesIO(), wait=mock.Mock(return_value=0))
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(bridge, 'ROOT', Path(directory).resolve()):
            (Path(directory) / 'logs').mkdir()
            value.path = Path(directory) / 'logs' / (value.label + '-ros-code.ndjson')
            with mock.patch.object(bridge.subprocess, 'Popen', return_value=process) as popen, \
                    mock.patch.object(bridge.threading.Thread, 'start'):
                value.start()
            options = popen.call_args.kwargs
            self.assertEqual(options['env']['WINEDEBUG'], '-all')
            self.assertNotIn('CitizenFX_NoTenUI', options['env'])
            self.assertIs(options['stderr'], bridge.subprocess.DEVNULL)
            self.assertIs(options['stdout'], bridge.subprocess.PIPE)
            command = popen.call_args.args[0]
            self.assertEqual(command[-2:], ['--duration-ms', '600000'])
            self.assertEqual(command[2], '--source-root')
            self.assertNotIn('--fixture-pid', command)
            value.finish_after_wineserver_cleanup()
            self.assertTrue(value.output.closed)

    def test_thread_start_failure_still_reaps_only_owned_helper_after_cleanup(self):
        value = self.observer()
        observed = []
        process = SimpleNamespace(stdout=io.BytesIO(), wait=mock.Mock(side_effect=lambda **kw: observed.append('own-wait') or 0))
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(bridge, 'ROOT', Path(directory).resolve()):
            (Path(directory) / 'logs').mkdir()
            value.path = Path(directory) / 'logs' / (value.label + '-ros-code.ndjson')
            with mock.patch.object(bridge.subprocess, 'Popen', return_value=process), \
                    mock.patch.object(bridge.threading.Thread, 'start', side_effect=RuntimeError('INERT-THREAD-START')), \
                    mock.patch.object(bridge.threading.Thread, 'join') as join:
                with self.assertRaisesRegex(RuntimeError, 'INERT-THREAD-START'):
                    try:
                        value.start()
                    finally:
                        with value.finishing_after_cleanup():
                            observed.extend(['server-k', 'server-w'])
                join.assert_not_called()
            self.assertEqual(observed, ['server-k', 'server-w', 'own-wait'])
            self.assertTrue(value.output.closed and process.stdout.closed)

    def test_timeout_terminates_only_the_bridge_owned_helper(self):
        value = self.observer()
        value.output = io.StringIO()
        value.process = SimpleNamespace(stdout=io.BytesIO(), terminate=mock.Mock(),
            wait=mock.Mock(side_effect=[bridge.subprocess.TimeoutExpired('own-helper', 10), 0]))
        value.finish_after_wineserver_cleanup()
        value.process.terminate.assert_called_once_with()
        self.assertEqual(value.process.wait.call_args_list, [mock.call(timeout=10), mock.call(timeout=5)])
        self.assertTrue(value.result()['own_observer_terminated_after_source_cleanup'])
        self.assertFalse(value.result()['target_process_termination_by_observer'])

    def test_source_helper_integrates_before_main_and_finalizes_on_source_start_failure(self):
        events = []
        @contextmanager
        def finishing():
            try: yield
            finally: events.append('code-finish')
        observer = SimpleNamespace(start=lambda: events.append('code-start'),
            wait_ready=lambda: events.append('code-ready'), finishing_after_cleanup=finishing,
            result=lambda: {'enabled': True, 'code_frames': []}, reader_error=None, lifecycle_error=None, start_error=None)
        original_run = run_source.run
        def code_run(*args, **kwargs):
            return original_run(*args, **dict(kwargs, observe_ros_code=True))
        fixture = exit_cases.SourceExitControllerTests('test_sink_remains_open_through_server_cleanup_and_pump_finish')
        with mock.patch.object(run_source, 'run', side_effect=code_run), \
                mock.patch.object(bridge, 'SourceCodeObserver', return_value=observer):
            lifecycle = fixture.exercise(thread_start_failure=True)
        self.assertIn('main', lifecycle)
        self.assertEqual(events, ['code-start', 'code-ready', 'code-finish'])

    def test_cli_rejects_source_observer_without_both_parity_and_exit_before_inputs(self):
        for args in (['resume', '--observe-ros-code'], ['resume', '--runtime', 'parity', '--observe-ros-code'],
                     ['resume', '--runtime', 'read', '--exit-relay', '--observe-ros-code']):
            with mock.patch.object(sys, 'argv', ['run_source.py', *args]), \
                    mock.patch.object(run_source, 'check_inputs') as inputs, redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit): run_source.main()
                inputs.assert_not_called()
        with mock.patch.object(sys, 'argv', ['run_source.py', 'resume', '--runtime', 'parity', '--exit-relay', '--observe-ros-code']), \
                mock.patch.object(run_source, 'run', return_value=0) as run:
            self.assertEqual(run_source.main(), 0)
        self.assertTrue(run.call_args.kwargs['observe_ros_code'])


if __name__ == '__main__':
    unittest.main()
