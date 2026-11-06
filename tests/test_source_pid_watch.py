"""Source PID-watch guards and own-pipe lifecycle checks; never start Wine."""
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'native/windows-client'))
import source_pid_watch as bridge


def parser_type():
    return bridge._execute(bridge.CONTRACT, bridge._bound(bridge.CONTRACT)).WatchRecords


def ready(host=5000):
    return {'event': 'ready', 'mode': 'source', 'protocol': 1810, 'windows_pid': 104,
            'host_pid': host, 'creation': 1234, 'duration_ms': 600000, 'poll_ms': 250, 'record_limit': 128}


def mapping():
    return {'event': 'mapped', 'time_ms': 1, 'role': 7, 'windows_pid': 100, 'host_pid': 7000, 'creation': 5678}


def complete():
    return {'event': 'completed', 'polls': 3, 'mapped_records': 1, 'query_failures': 0,
            'close_failures': 0, 'capped': False, 'exit': 0}


class SourcePidWatchTests(unittest.TestCase):
    def watcher(self, with_records=True):
        runtime = SimpleNamespace(ENGINE=bridge.ENGINE, WINE=bridge.ENGINE / 'bin/wine',
                                  source_runtime_profile={'profile': 'parity'})
        env = {'WINEPREFIX': str(bridge.PREFIX), 'WINESERVER': str(bridge.ENGINE / 'bin/wineserver'),
               'WINEDEBUG': '-all,+pid,FiveM_ROSLauncher:trace+relay', 'CitizenFX_NoTenUI': '1',
               'cItIzEnFx_INERT_TEST': ''}
        context = SimpleNamespace(runtime=runtime, environment=env, prepared=True,
                                  _assert_held_context=mock.Mock(), verify_sources=mock.Mock())
        with mock.patch.object(bridge, 'load_binding', return_value=(parser_type(), [])), \
                mock.patch.object(bridge._base, 'identity', side_effect=lambda name: {'path': name}):
            value = bridge.SourcePidWatcher(runtime, env, bridge.STAGE,
                'client-source-ui-resume-20261102T210000000000Z', 3600, context)
        value.verify_sources = mock.Mock()
        if with_records: value.records = value.record_type('source', native_pid=5000)
        return value

    def test_actual_completed_multirole_control_and_relative_inputs_bind_without_runtime(self):
        parser, inputs = bridge.load_binding()
        self.assertEqual(parser.__name__, 'WatchRecords')
        by_path = {item['path']: item for item in inputs}
        self.assertEqual(len(by_path), len(inputs))
        self.assertEqual(by_path[bridge.CONTROL]['sha256'],
                         '3e9d97bebe507903c66b34b04b7984885ed6195745d2d95a7e6c84b6b419e4d3')
        self.assertEqual(by_path[bridge.V1_CONTROL]['sha256'], bridge.PINS[bridge.V1_CONTROL][1])
        self.assertEqual(by_path[bridge.OBSERVER]['sha256'],
                         'fd56c84af7cd2e26a0809336d73b711b04df54e9d1f5b32299ab6e8417d47f7d')
        self.assertTrue(all(not Path(item['path']).is_absolute() for item in inputs))

    def test_incomplete_or_unmatched_actual_control_rejects_before_adapter_execution(self):
        original = bridge._bound
        for field in ('completion', 'actual_host'):
            def changed(name):
                raw = original(name)
                if name == bridge.CONTROL:
                    value = json.loads(raw)
                    if field == 'completion': value['runs'][0]['observer']['completed'] = False
                    else: value['runs'][0]['driver_host_matches_actual_popen'] = False
                    return json.dumps(value).encode()
                return raw
            with self.subTest(field=field), mock.patch.object(bridge, '_bound', side_effect=changed), \
                    mock.patch.object(bridge, '_execute') as execute:
                with self.assertRaisesRegex(RuntimeError, 'exact actual'):
                    bridge.load_binding()
                execute.assert_not_called()

    def test_missing_actual_new_own_control_refuses_before_provider_reads(self):
        with mock.patch.object(bridge, 'CONTROL', None), mock.patch.object(bridge, '_bound') as read:
            with self.assertRaisesRegex(RuntimeError, 'actual completed own control'):
                bridge.load_binding()
            read.assert_not_called()

    def test_source_scope_exit_context_and_main_lock_before_binding(self):
        good = self.watcher()
        for field in ('prefix', 'stage', 'engine', 'prepared', 'context', 'lock'):
            env = dict(good.environment); runtime = SimpleNamespace(**good.runtime.__dict__)
            context = SimpleNamespace(runtime=runtime, environment=env, prepared=True, _assert_held_context=mock.Mock())
            stage = bridge.STAGE
            if field == 'prefix': env['WINEPREFIX'] = str(ROOT / 'prefixes/rockstar-legacy')
            if field == 'stage': stage = ROOT / 'build/other-client'
            if field == 'engine': runtime.ENGINE = ROOT / 'runtime/wine-read-diagnostics/engine'
            if field == 'prepared': context.prepared = False
            if field == 'context': context.runtime = object()
            if field == 'lock': context._assert_held_context.side_effect = RuntimeError('INERT-unheld-lock')
            with self.subTest(field=field), mock.patch.object(bridge, 'load_binding') as binding:
                with self.assertRaises(RuntimeError):
                    bridge.SourcePidWatcher(runtime, env, stage, good.label, 60, context)
                binding.assert_not_called()
        for profile, enabled in [('matched', True), ('read', True), ('parity', False), ('parity', 1)]:
            with self.assertRaises(ValueError): bridge.validate_selection(profile, enabled)
        bridge.validate_selection('parity', True)

    def test_only_admitted_numeric_roles_reach_persistence(self):
        value = self.watcher(); value.output = io.StringIO()
        value._accept(json.dumps(ready()).encode())
        value._accept(json.dumps({**mapping(), 'path': 'PRIVATE_SENTINEL'}).encode())
        value._accept(json.dumps({**mapping(), 'role': 101}).encode())
        value._accept(json.dumps(mapping()).encode())
        value._accept(json.dumps(complete()).encode())
        self.assertEqual([json.loads(line) for line in value.output.getvalue().splitlines()], [ready(), mapping(), complete()])
        self.assertNotIn('PRIVATE', value.output.getvalue())
        result = value.result()
        self.assertEqual(result['pid_mappings'], [mapping()])
        self.assertEqual(result['pid_mappings_summary']['rejected'], 2)
        self.assertFalse(result['native_completion_succeeded'])
        self.assertTrue(result['native_completion_observed'])

    def test_ready_from_wrong_native_host_is_never_persisted_or_ready(self):
        value = self.watcher(); value.output = io.StringIO()
        value._accept(json.dumps(ready(9152)).encode())
        self.assertEqual(value.output.getvalue(), '')
        self.assertFalse(value.ready.is_set())
        self.assertFalse(value.result()['ready_host_bound_to_actual_helper_popen_pid'])
        value._accept(json.dumps(ready()).encode())
        self.assertTrue(value.ready.is_set())

    def test_incremental_1024_byte_framer_rejects_oversized_and_partial_frames(self):
        value = self.watcher(); value.output = io.StringIO()
        reader, writer = os.pipe(); value.process = SimpleNamespace(stdout=os.fdopen(reader, 'rb'), pid=5000)
        raw = (json.dumps(ready()) + '\n').encode() + b'X' * 1025 + b'\n' + \
            ('\n'.join(map(json.dumps, [mapping(), complete()])) + '\nPRIVATE_UNTERMINATED').encode()
        def feed():
            try:
                for offset in range(0, len(raw), 137): os.write(writer, raw[offset:offset + 137])
            finally: os.close(writer)
        thread = threading.Thread(target=feed); thread.start()
        try:
            value._drain(); thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertEqual([json.loads(line) for line in value.output.getvalue().splitlines()], [ready(), mapping(), complete()])
            self.assertEqual(value.records.summary()['rejected'], 2)
            self.assertNotIn('PRIVATE', value.output.getvalue())
        finally:
            value.process.stdout.close(); thread.join(timeout=2)

    def test_live_inherited_pipe_writer_cannot_postpone_requested_stop(self):
        value = self.watcher(); value.output = io.StringIO()
        reader, writer = os.pipe(); value.process = SimpleNamespace(stdout=os.fdopen(reader, 'rb'))
        thread = threading.Thread(target=value._drain); thread.start()
        try:
            value.stop.set(); thread.join(timeout=1)
            self.assertFalse(thread.is_alive())
            os.write(writer, b'own-writer-remains-open')
        finally:
            value.stop.set(); thread.join(timeout=1)
            value.process.stdout.close(); os.close(writer)

    def test_actual_popen_pid_bound_before_reader_thread_and_quiet_source_only_start(self):
        value = self.watcher(with_records=False)
        process = SimpleNamespace(stdout=io.BytesIO(), pid=5000, wait=mock.Mock(return_value=0))
        original = value.record_type; calls = []
        def construct(mode, *, native_pid):
            calls.append(('parser', mode, native_pid))
            return original(mode, native_pid=native_pid)
        value.record_type = construct
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(bridge, 'ROOT', Path(directory).resolve()):
            temp = Path(directory).resolve(); (temp / 'logs').mkdir()
            value.path = temp / 'logs' / (value.label + '-host-pids.ndjson')
            with mock.patch.object(bridge.subprocess, 'Popen', return_value=process) as popen, \
                    mock.patch.object(bridge.threading.Thread, 'start', side_effect=lambda: calls.append(('thread', value.records is not None))):
                value.start()
            self.assertEqual(calls, [('parser', 'source', 5000), ('thread', True)])
            command, options = popen.call_args.args[0], popen.call_args.kwargs
            self.assertEqual(command[2:], ['--source-root', 'Z:' + str(bridge.STAGE).replace('/', '\\'), '--duration-ms', '600000'])
            self.assertTrue(command[1].endswith('/build/windows-wine-pid-watch/pid_watch.exe'))
            self.assertEqual(options['env']['WINEDEBUG'], '-all')
            self.assertFalse(any(k.lower().startswith('citizenfx_') for k in options['env']))
            self.assertIs(options['stderr'], bridge.subprocess.DEVNULL)
            value.finish_after_wineserver_cleanup()
            self.assertTrue(value.output.closed)

    def test_thread_start_failure_still_reaps_only_owned_helper_after_cleanup(self):
        value = self.watcher(with_records=False); events = []
        process = SimpleNamespace(stdout=io.BytesIO(), pid=5000,
            wait=mock.Mock(side_effect=lambda **kw: events.append('own-wait') or 0))
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(bridge, 'ROOT', Path(directory).resolve()):
            temp = Path(directory).resolve(); (temp / 'logs').mkdir()
            value.path = temp / 'logs' / (value.label + '-host-pids.ndjson')
            with mock.patch.object(bridge.subprocess, 'Popen', return_value=process), \
                    mock.patch.object(bridge.threading.Thread, 'start', side_effect=RuntimeError('INERT-thread-start')), \
                    mock.patch.object(bridge.threading.Thread, 'join') as join:
                with self.assertRaisesRegex(RuntimeError, 'INERT-thread-start'):
                    try: value.start()
                    finally:
                        with value.finishing_after_cleanup(): events.extend(['server-k', 'server-w'])
                join.assert_not_called()
            self.assertEqual(events, ['server-k', 'server-w', 'own-wait'])
            self.assertTrue(value.output.closed and process.stdout.closed)

    def test_partial_start_and_exit0_do_not_invent_ready_or_completed(self):
        value = self.watcher(with_records=False)
        self.assertFalse(value.result()['native_completion_observed'])
        self.assertTrue(value.result()['pid_mappings_summary']['capture_not_started'])
        value.output = io.StringIO()
        value.process = SimpleNamespace(stdout=io.BytesIO(), pid=5000, terminate=mock.Mock(),
            wait=mock.Mock(side_effect=[bridge.subprocess.TimeoutExpired('own-helper', 10), 0]))
        value.records = value.record_type('source', native_pid=5000)
        value._accept(json.dumps(ready()).encode())
        value.finish_after_wineserver_cleanup()
        value.process.terminate.assert_called_once_with()
        result = value.result()
        self.assertEqual(result['observer_exit'], 0)
        self.assertFalse(result['native_completion_observed'])
        self.assertFalse(result['native_completion_succeeded'])
        self.assertFalse(result['target_process_termination_by_observer'])

    def test_bound_sources_and_exit_context_rechecked_before_spawn(self):
        value = self.watcher(); value.inputs = [{'path': 'native/windows-client/source_pid_watch.py', 'sha256': 'INERT-ORIGINAL'}]
        value.verify_sources = bridge._base.SourceCodeObserver.verify_sources.__get__(value)
        with mock.patch.object(bridge._base, 'identity', return_value={'path': value.inputs[0]['path'], 'sha256': 'INERT-CHANGED'}), \
                mock.patch.object(bridge.subprocess, 'Popen') as popen:
            with self.assertRaisesRegex(RuntimeError, 'changed'): value.start()
            popen.assert_not_called()
        value.context.verify_sources.assert_called_once_with()


if __name__ == '__main__':
    unittest.main()
