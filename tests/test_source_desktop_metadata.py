"""Own-pipe and mock Source desktop-metadata checks; no Wine, desktop or UI actions."""
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
import source_desktop_metadata as bridge


def parser_type():
    return bridge._execute(bridge.CONTRACT, bridge._bound(bridge.CONTRACT)).MetaRecords


def ready(host=5000):
    return {'event': 'ready', 'mode': 'source', 'protocol': 1810, 'windows_pid': 104,
            'host_pid': host, 'creation': 1234, 'duration_ms': 600000, 'poll_ms': 100, 'record_limit': 256}


def identity():
    return {'time_ms': 1, 'role': 2, 'windows_pid': 100, 'host_pid': 7000, 'creation': 5678}


def target():
    return {'event': 'target', **identity()}


def desktop():
    return {'event': 'desktop_probe', **identity(), 'time_ms': 2, 'view': 1, 'tid': 108,
            'desktop_relation': 2, 'desktop_returned': True, 'compare_error': 1656,
            'enum_ok': True, 'enum_error': 0, 'target_windows': 1, 'error_windows': 1,
            'other_windows': 0, 'foreign_children': 0, 'localized': True, 'localize_stage': 3, 'localize_error': 0}


def window(count=3):
    return {'event': 'window', **identity(), 'time_ms': 3, 'view': 1, 'tid': 108, 'desktop_relation': 2,
            'window_index': 1, 'window_tid': 108, 'class_kind': 4, 'style': 0xffffffff,
            'exstyle': 0xffffffff, 'foreign_children': 0,
            'children': [{'tid': 108, 'class_kind': 1, 'style': 0xffffffff, 'exstyle': 0xffffffff} for unused in range(count)]}


def complete(api_failures=0):
    return {'event': 'completed', 'polls': 3, 'records': 3, 'api_failures': api_failures,
            'infrastructure_failures': 0, 'close_failures': 0, 'capped': False, 'exit': 0}


class SourceDesktopMetadataTests(unittest.TestCase):
    def observer(self, with_records=True):
        runtime = SimpleNamespace(ENGINE=bridge.ENGINE, WINE=bridge.ENGINE / 'bin/wine',
                                  source_runtime_profile={'profile': 'parity'})
        env = {'WINEPREFIX': str(bridge.PREFIX), 'WINESERVER': str(bridge.ENGINE / 'bin/wineserver'),
               'WINEDEBUG': '-all,+pid,FiveM_ROSLauncher:trace+relay', 'CitizenFX_NoTenUI': '1',
               'cItIzEnFx_INERT_TEST': ''}
        context = SimpleNamespace(runtime=runtime, environment=env, prepared=True,
                                  _assert_held_context=mock.Mock(), verify_sources=mock.Mock())
        with mock.patch.object(bridge, 'load_binding', return_value=(parser_type(), [])), \
                mock.patch.object(bridge._base, 'identity', side_effect=lambda name: {'path': name}):
            value = bridge.SourceDesktopMetadata(runtime, env, bridge.STAGE,
                'client-source-ui-resume-20261102T220000000000Z', 3600, context)
        value.verify_sources = mock.Mock()
        if with_records: value.records = value.record_type('source', native_pid=5000)
        return value

    def test_actual_complete_default_and_alt_control_binds_all_relative_inputs_without_runtime(self):
        parser, inputs = bridge.load_binding()
        self.assertEqual(parser.__name__, 'MetaRecords')
        by_path = {item['path']: item for item in inputs}
        self.assertEqual(len(inputs), len(by_path))
        self.assertTrue(all(not Path(item['path']).is_absolute() for item in inputs))
        self.assertEqual(by_path[bridge.CONTROL]['sha256'],
                         'c1b1ca714422bfc5067185651568e602cd37703d963ce4d763a1c79b4a8a087a')
        self.assertEqual(by_path[bridge.BUILD]['sha256'], bridge.PINS[bridge.BUILD][1])
        self.assertEqual(by_path[bridge.CONTRACT]['sha256'], bridge.PINS[bridge.CONTRACT][1])

    def test_missing_or_failed_foreign_desktop_own_control_refuses_before_adapter_execution(self):
        with mock.patch.object(bridge, 'CONTROL', None), mock.patch.object(bridge, '_bound') as read:
            with self.assertRaisesRegex(RuntimeError, 'actual successful'): bridge.load_binding()
            read.assert_not_called()
        original = bridge._bound
        for field in ('alternate_error_on_target_desktop', 'api_failures'):
            def changed(name):
                raw = original(name)
                if name == bridge.CONTROL:
                    record = json.loads(raw)
                    if field == 'api_failures': record['runs'][0]['observer']['api_failures'] = 1
                    else: record['runs'][0]['control_expectations'][field] = False
                    return json.dumps(record).encode()
                return raw
            with self.subTest(field=field), mock.patch.object(bridge, '_bound', side_effect=changed), \
                    mock.patch.object(bridge, '_execute') as execute:
                with self.assertRaisesRegex(RuntimeError, 'own proof is missing'): bridge.load_binding()
                execute.assert_not_called()

    def test_exact_parity_prefix_and_prepared_exit_context_with_held_main_lock(self):
        good = self.observer()
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
                with self.assertRaises(RuntimeError): bridge.SourceDesktopMetadata(runtime, env, stage, good.label, 60, context)
                binding.assert_not_called()
        for profile, relay in [('matched', True), ('read', True), ('parity', False), ('parity', 1)]:
            with self.assertRaises(ValueError): bridge.validate_selection(profile, relay)
        bridge.validate_selection('parity', True)

    def test_only_accepted_numeric_child_metadata_persists_never_text_or_other_roles(self):
        value = self.observer(); value.output = io.StringIO()
        value._accept(json.dumps(ready()).encode())
        value._accept(json.dumps({**target(), 'role': 7}).encode())
        value._accept(json.dumps(target()).encode())
        value._accept(json.dumps(desktop()).encode())
        extra = window(); extra['children'][0]['text'] = 'PRIVATE_SENTINEL'
        value._accept(json.dumps(extra).encode())
        value._accept(json.dumps(window()).encode())
        value._accept(json.dumps(complete()).encode())
        rows = [ready(), target(), desktop(), window(), complete()]
        self.assertEqual([json.loads(line) for line in value.output.getvalue().splitlines()], rows)
        self.assertNotIn('PRIVATE', value.output.getvalue())
        result = value.result()
        self.assertEqual(result['window_metadata'], [window()])
        self.assertEqual(result['desktop_probes'], [desktop()])
        self.assertEqual(result['desktop_metadata_summary']['rejected'], 2)
        self.assertFalse(result['native_completion_succeeded'])

    def test_8192_framer_accepts64_children_and_discards_oversized_or_partial_input(self):
        value = self.observer(); value.output = io.StringIO()
        reader, writer = os.pipe(); value.process = SimpleNamespace(stdout=os.fdopen(reader, 'rb'), pid=5000)
        rows = [ready(), target(), desktop(), window(64), complete()]
        self.assertGreater(len(json.dumps(rows[3])), 2048)
        self.assertLess(len(json.dumps(rows[3])), 8192)
        raw = ('\n'.join(map(json.dumps, rows)) + '\n').encode() + b'X' * 8193 + b'\nPRIVATE_PARTIAL'
        def feed():
            try:
                for offset in range(0, len(raw), 337): os.write(writer, raw[offset:offset + 337])
            finally: os.close(writer)
        thread = threading.Thread(target=feed); thread.start()
        try:
            value._drain(); thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertEqual([json.loads(line) for line in value.output.getvalue().splitlines()], rows)
            self.assertEqual(value.records.summary()['rejected'], 2)
            self.assertNotIn('PRIVATE', value.output.getvalue())
        finally:
            value.process.stdout.close(); thread.join(timeout=2)

    def test_ready_wrong_actual_host_and_unlocalized_foreign_handle_are_not_persisted(self):
        value = self.observer(); value.output = io.StringIO()
        value._accept(json.dumps(ready(9152)).encode())
        self.assertFalse(value.ready.is_set())
        value._accept(json.dumps(ready()).encode()); value._accept(json.dumps(target()).encode())
        value._accept(json.dumps({**desktop(), 'localized': False}).encode())
        self.assertEqual([json.loads(line) for line in value.output.getvalue().splitlines()], [ready(), target()])
        self.assertTrue(value.ready.is_set())

    def test_actual_popen_host_is_bound_before_reader_start_and_environment_is_quiet(self):
        value = self.observer(with_records=False)
        process = SimpleNamespace(stdout=io.BytesIO(), pid=5000, wait=mock.Mock(return_value=0))
        original = value.record_type; calls = []
        def construct(mode, *, native_pid):
            calls.append(('parser', mode, native_pid)); return original(mode, native_pid=native_pid)
        value.record_type = construct
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(bridge, 'ROOT', Path(directory).resolve()):
            temp = Path(directory).resolve(); (temp / 'logs').mkdir()
            value.path = temp / 'logs' / (value.label + '-desktop-metadata.ndjson')
            with mock.patch.object(bridge.subprocess, 'Popen', return_value=process) as popen, \
                    mock.patch.object(bridge.threading.Thread, 'start', side_effect=lambda: calls.append(('thread', value.records is not None))):
                value.start()
            self.assertEqual(calls, [('parser', 'source', 5000), ('thread', True)])
            command, options = popen.call_args.args[0], popen.call_args.kwargs
            self.assertEqual(command[2:], ['--source-root', 'Z:' + str(bridge.STAGE).replace('/', '\\'), '--duration-ms', '600000'])
            self.assertTrue(command[1].endswith('/build/windows-desktop-metadata-localized/desktop_probe.exe'))
            self.assertEqual(options['env']['WINEDEBUG'], '-all')
            self.assertFalse(any(key.lower().startswith('citizenfx_') for key in options['env']))
            self.assertIs(options['stderr'], bridge.subprocess.DEVNULL)
            value.finish_after_wineserver_cleanup(); self.assertTrue(value.output.closed)

    def test_open_inherited_writer_cannot_prevent_bounded_stop(self):
        value = self.observer(); value.output = io.StringIO()
        reader, writer = os.pipe(); value.process = SimpleNamespace(stdout=os.fdopen(reader, 'rb'))
        thread = threading.Thread(target=value._drain); thread.start()
        try:
            value.stop.set(); thread.join(timeout=1)
            self.assertFalse(thread.is_alive()); os.write(writer, b'own-writer-remains-open')
        finally:
            value.stop.set(); thread.join(timeout=1)
            value.process.stdout.close(); os.close(writer)

    def test_thread_start_failure_reaps_only_owned_helper_after_source_cleanup(self):
        value = self.observer(with_records=False); events = []
        process = SimpleNamespace(stdout=io.BytesIO(), pid=5000,
            wait=mock.Mock(side_effect=lambda **kw: events.append('own-wait') or 0))
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(bridge, 'ROOT', Path(directory).resolve()):
            temp = Path(directory).resolve(); (temp / 'logs').mkdir()
            value.path = temp / 'logs' / (value.label + '-desktop-metadata.ndjson')
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

    def test_exit0_without_completed_and_api_failures_remain_distinct_failures(self):
        value = self.observer(); value.output = io.StringIO()
        value._accept(json.dumps(ready()).encode())
        value.process = SimpleNamespace(stdout=io.BytesIO(), pid=5000, terminate=mock.Mock(),
            wait=mock.Mock(side_effect=[bridge.subprocess.TimeoutExpired('own-metadata-helper', 10), 0]))
        value.finish_after_wineserver_cleanup(); value.process.terminate.assert_called_once_with()
        self.assertEqual(value.result()['observer_exit'], 0)
        self.assertFalse(value.result()['native_completion_observed'])
        other = self.observer(); other.output = io.StringIO()
        for row in [ready(), target(), desktop(), window(), complete(api_failures=1)]: other._accept(json.dumps(row).encode())
        self.assertTrue(other.result()['native_completion_observed'])
        self.assertFalse(other.result()['native_completion_succeeded'])
        self.assertEqual(other.result()['desktop_metadata_summary']['api_failures'], 1)

    def test_source_input_drift_refuses_spawn_and_partial_start_result_has_no_completion(self):
        value = self.observer(with_records=False)
        self.assertTrue(value.result()['desktop_metadata_summary']['capture_not_started'])
        self.assertFalse(value.result()['native_completion_observed'])
        value.inputs = [{'path': 'native/windows-client/source_desktop_metadata.py', 'sha256': 'INERT-OLD'}]
        value.verify_sources = bridge._base.SourceCodeObserver.verify_sources.__get__(value)
        with mock.patch.object(bridge._base, 'identity', return_value={'path': value.inputs[0]['path'], 'sha256': 'INERT-NEW'}), \
                mock.patch.object(bridge.subprocess, 'Popen') as popen:
            with self.assertRaisesRegex(RuntimeError, 'changed'): value.start()
            popen.assert_not_called()
        value.context.verify_sources.assert_called_once_with()


if __name__ == '__main__':
    unittest.main()
