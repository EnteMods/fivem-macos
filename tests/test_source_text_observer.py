"""Bound-source/mock/own-pipe checks only: no Wine, UI or authenticated prefix access."""
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
import source_text_observer as bridge


def parser_type():
    return bridge._execute(bridge.CONTRACT, bridge._bound(bridge.CONTRACT)).TextRecords


def ready():
    return {'event': 'ready', 'mode': 'source', 'pid': 104, 'duration_ms': 600000,
            'poll_ms': 250, 'record_limit': 128, 'text_chars': 1023, 'timeout_ms': 250}


def text(value='OWN_SOURCE_ERROR'):
    return {'event': 'error_text', 'time_ms': 1, 'pid': 100, 'creation': 1234, 'text': value}


def complete():
    return {'event': 'completed', 'polls': 3, 'processes': 1, 'text_queries': 1, 'text_records': 1,
            'denied': 0, 'enumeration_failures': 0, 'close_failures': 0, 'capped': False, 'exit': 0}


class SourceTextObserverTests(unittest.TestCase):
    def observer(self):
        runtime = SimpleNamespace(ENGINE=bridge.ENGINE, WINE=bridge.ENGINE / 'bin/wine',
                                  source_runtime_profile={'profile': 'parity'})
        env = {'WINEPREFIX': str(bridge.PREFIX), 'WINESERVER': str(bridge.ENGINE / 'bin/wineserver'),
               'WINEDEBUG': '-all,+pid,FiveM_ROSLauncher:trace+relay', 'CitizenFX_NoTenUI': '1',
               'cItIzEnFx_INERT_TEST': ''}
        context = SimpleNamespace(runtime=runtime, environment=env, prepared=True,
                                  _assert_held_context=mock.Mock(), verify_sources=mock.Mock())
        with mock.patch.object(bridge, 'load_binding', return_value=(parser_type(), [])), \
                mock.patch.object(bridge._base, 'identity', side_effect=lambda name: {'path': name}):
            value = bridge.SourceTextObserver(runtime, env, bridge.STAGE,
                'client-source-ui-resume-20261102T200000000000Z', 3600, context)
        value.verify_sources = mock.Mock()
        return value

    def test_actual_completed_own_control_and_all_frozen_inputs_bind_without_runtime(self):
        parser, inputs = bridge.load_binding()
        self.assertEqual(parser.__name__, 'TextRecords')
        by_path = {item['path']: item for item in inputs}
        self.assertEqual(by_path[bridge.OBSERVER]['sha256'],
                         '7963a595a3bc666b306f7f5af406b0d25d560c9892781be6373265122f927de5')
        self.assertEqual(by_path[bridge.CONTROL]['sha256'], bridge.PINS[bridge.CONTROL][1])
        self.assertEqual(by_path[bridge.BASE]['sha256'], bridge.PINS[bridge.BASE][1])
        self.assertEqual(by_path[bridge.CONTRACT]['sha256'], bridge.PINS[bridge.CONTRACT][1])
        self.assertEqual(len(inputs), len(by_path))

    def test_failed_or_missing_actual_own_control_never_executes_adapter(self):
        original = bridge._bound
        def changed(name):
            raw = original(name)
            if name == bridge.CONTROL:
                value = json.loads(raw); value['runs'][0]['observer']['completed'] = False
                return json.dumps(value).encode()
            return raw
        with mock.patch.object(bridge, '_bound', side_effect=changed), mock.patch.object(bridge, '_execute') as execute:
            with self.assertRaisesRegex(RuntimeError, 'exact actual'):
                bridge.load_binding()
            execute.assert_not_called()
        with mock.patch.object(bridge, '_bound', side_effect=FileNotFoundError('INERT')), mock.patch.object(bridge, '_execute') as execute:
            with self.assertRaises(FileNotFoundError): bridge.load_binding()
            execute.assert_not_called()

    def test_exact_parity_prepared_context_prefix_and_held_lock_before_binding(self):
        good = self.observer()
        for field in ('prefix', 'stage', 'engine', 'prepared', 'context', 'lock'):
            env = dict(good.environment)
            runtime = SimpleNamespace(**good.runtime.__dict__)
            context = SimpleNamespace(runtime=runtime, environment=env, prepared=True, _assert_held_context=mock.Mock())
            stage = bridge.STAGE
            if field == 'prefix': env['WINEPREFIX'] = str(ROOT / 'prefixes/rockstar-legacy')
            if field == 'stage': stage = ROOT / 'build/fivem-official'
            if field == 'engine': runtime.ENGINE = ROOT / 'runtime/wine-read-diagnostics/engine'
            if field == 'prepared': context.prepared = False
            if field == 'context': context.runtime = object()
            if field == 'lock': context._assert_held_context.side_effect = RuntimeError('INERT-unheld-lock')
            with self.subTest(field=field), mock.patch.object(bridge, 'load_binding') as binding:
                with self.assertRaises(RuntimeError):
                    bridge.SourceTextObserver(runtime, env, stage, good.label, 60, context)
                binding.assert_not_called()
        for profile, relay in [('matched', True), ('read', True), ('parity', False), ('parity', 1)]:
            with self.assertRaises(ValueError): bridge.validate_selection(profile, relay)
        bridge.validate_selection('parity', True)

    def test_only_textrecords_accept_returns_reach_persistence(self):
        value = self.observer(); value.output = io.StringIO()
        rows = [ready(), text(), complete()]
        for row in rows: value._accept(json.dumps(row).encode())
        value._accept(b'PRIVATE_AUTH_SENTINEL')
        value._accept(json.dumps({**text(), 'path': 'PRIVATE_AUTH_SENTINEL'}).encode())
        self.assertEqual([json.loads(line) for line in value.output.getvalue().splitlines()], rows)
        self.assertNotIn('PRIVATE_AUTH', value.output.getvalue())
        result = value.result()
        self.assertEqual(result['text_records'], [text()])
        self.assertEqual(result['metadata_events'], [ready(), complete()])
        self.assertEqual(result['text_records_summary']['rejected'], 2)
        self.assertFalse(result['ui_text_is_error_cause_claim'])

    def test_incremental_8192_byte_framer_admits_long_escaped_text_and_rejects_oversized_or_partial(self):
        value = self.observer(); value.output = io.StringIO()
        reader, writer = os.pipe()
        value.process = SimpleNamespace(stdout=os.fdopen(reader, 'rb'))
        rows = [ready(), text('\x01' * 1023), complete()]
        payload = ('\n'.join(json.dumps(row) for row in rows) + '\n').encode()
        self.assertGreater(len(json.dumps(rows[1])), 2048)
        self.assertLess(len(json.dumps(rows[1])), 8192)
        def feed():
            try:
                raw = payload + b'X' * 8193 + b'\nPRIVATE_UNTERMINATED'
                for at in range(0, len(raw), 317): os.write(writer, raw[at:at + 317])
            finally: os.close(writer)
        thread = threading.Thread(target=feed); thread.start()
        try:
            value._drain(); thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertEqual([json.loads(line) for line in value.output.getvalue().splitlines()], rows)
            self.assertNotIn('PRIVATE', value.output.getvalue())
            self.assertTrue(value.ready.is_set())
            self.assertEqual(value.records.summary()['rejected'], 2)
        finally:
            value.process.stdout.close(); thread.join(timeout=2)

    def test_inherited_open_writer_does_not_prevent_bounded_stop(self):
        value = self.observer(); value.output = io.StringIO()
        reader, writer = os.pipe()
        value.process = SimpleNamespace(stdout=os.fdopen(reader, 'rb'))
        thread = threading.Thread(target=value._drain); thread.start()
        try:
            value.stop.set(); thread.join(timeout=1)
            self.assertFalse(thread.is_alive())
            os.write(writer, b'own-writer-still-open')
        finally:
            value.stop.set(); thread.join(timeout=1)
            value.process.stdout.close(); os.close(writer)

    def test_start_is_quiet_fixed_source_scope_and_capped_at600seconds(self):
        value = self.observer()
        process = SimpleNamespace(stdout=io.BytesIO(), wait=mock.Mock(return_value=0))
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(bridge, 'ROOT', Path(directory).resolve()):
            (Path(directory) / 'logs').mkdir()
            value.path = Path(directory).resolve() / 'logs' / (value.label + '-ros-text.ndjson')
            with mock.patch.object(bridge.subprocess, 'Popen', return_value=process) as popen, \
                    mock.patch.object(bridge.threading.Thread, 'start'):
                value.start()
            command, options = popen.call_args.args[0], popen.call_args.kwargs
            self.assertEqual(command[2:], ['--source-root', 'Z:' + str(bridge.STAGE).replace('/', '\\'), '--duration-ms', '600000'])
            self.assertTrue(command[1].endswith('/build/windows-text-observer/text_observer.exe'))
            self.assertEqual(options['env']['WINEDEBUG'], '-all')
            self.assertFalse(any(key.lower().startswith('citizenfx_') for key in options['env']))
            self.assertIs(options['stdout'], bridge.subprocess.PIPE)
            self.assertIs(options['stderr'], bridge.subprocess.DEVNULL)
            value.finish_after_wineserver_cleanup()
            self.assertTrue(value.output.closed)

    def test_readiness_requires_live_helper_before_main(self):
        value = self.observer(); value.ready.set()
        value.process = SimpleNamespace(poll=mock.Mock(return_value=0))
        with self.assertRaises(RuntimeError): value.wait_ready()
        value.process.poll.return_value = None
        value.wait_ready()
        value.reader_error = 'INERT-FAILED-READER'
        with self.assertRaises(RuntimeError): value.wait_ready()

    def test_thread_start_exception_still_finishes_only_after_server_cleanup(self):
        value = self.observer(); events = []
        process = SimpleNamespace(stdout=io.BytesIO(), wait=mock.Mock(side_effect=lambda **kw: events.append('own-wait') or 0))
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(bridge, 'ROOT', Path(directory).resolve()):
            (Path(directory) / 'logs').mkdir()
            value.path = Path(directory).resolve() / 'logs' / (value.label + '-ros-text.ndjson')
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
            self.assertEqual(value.result()['start_failure'], 'RuntimeError')

    def test_timeout_terminates_only_owned_helper_and_exit0_is_not_native_completion(self):
        value = self.observer(); value.output = io.StringIO()
        value._accept(json.dumps(ready()).encode())
        value.process = SimpleNamespace(stdout=io.BytesIO(), terminate=mock.Mock(),
            wait=mock.Mock(side_effect=[bridge.subprocess.TimeoutExpired('own-text-helper', 10), 0]))
        value.finish_after_wineserver_cleanup()
        value.process.terminate.assert_called_once_with()
        result = value.result()
        self.assertEqual(result['observer_exit'], 0)
        self.assertFalse(result['native_completion_observed'])
        self.assertFalse(result['native_completion_succeeded'])
        self.assertTrue(result['own_observer_terminated_after_source_cleanup'])
        self.assertFalse(result['target_process_termination_by_observer'])

    def test_bound_helpers_and_exit_context_are_rechecked_before_spawn(self):
        value = self.observer()
        value.inputs = [{'path': 'native/windows-client/source_text_observer.py', 'sha256': 'INERT-ORIGINAL'}]
        original = bridge._base.SourceCodeObserver.verify_sources.__get__(value)
        value.verify_sources = original
        with mock.patch.object(bridge._base, 'identity', return_value={'path': value.inputs[0]['path'], 'sha256': 'INERT-CHANGED'}), \
                mock.patch.object(bridge.subprocess, 'Popen') as popen:
            with self.assertRaisesRegex(RuntimeError, 'changed'):
                value.start()
            popen.assert_not_called()
        value.context.verify_sources.assert_called_once_with()
        self.assertGreaterEqual(value.context._assert_held_context.call_count, 2)


if __name__ == '__main__':
    unittest.main()
