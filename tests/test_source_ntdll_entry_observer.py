"""Inert Source entry-observer binding, stream and lifecycle regressions."""
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
path = ROOT / 'native/windows-client/source_ntdll_entry_observer.py'
spec = importlib.util.spec_from_file_location('test_source_ntdll_entries', path)
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)
contract = bridge.execute(bridge.CONTRACT, bridge.bound(bridge.CONTRACT))


def ready(duration=180000):
    return {'event': 'ready', 'mode': 'source', 'pid': 100, 'poll_ms': 25,
            'read_width': 21, 'duration_ms': duration, 'api_count': 3}


def done():
    return {'event': 'completed', 'processes': 0, 'read_calls': 0, 'state_records': 0,
            'stopped_processes': 0, 'failures': 0, 'close_failures': 0,
            'duration_completed': True, 'exit': 0}


def code_identity(name):
    return {'path': name, 'bytes': 1, 'sha256': 'a' * 64}


class SourceEntryTests(unittest.TestCase):
    def runtime(self):
        return SimpleNamespace(ENGINE=bridge.ENGINE, WINE=bridge.ENGINE/'bin/wine',
                               source_runtime_profile={'profile': 'parity'})

    def environment(self):
        return {'WINEPREFIX': str(bridge.PREFIX), 'WINESERVER': str(bridge.ENGINE/'bin/wineserver'),
                'CitizenFX_NoTenUI': '1', 'cItIzEnFx_unwanted': 'own-test', 'WINEDEBUG': '+loaddll'}

    def create(self, duration=180):
        return bridge.SourceNtdllEntryObserver(self.runtime(), self.environment(), bridge.STAGE,
                                              'client-source-ui-resume-20261103T120000000000Z', duration)

    def test_selection_is_exact_parity_without_exit_relay(self):
        bridge.validate_selection('parity', False)
        for profile, relay in (('matched', False), ('session-proxy', False), ('parity', True), ('parity', 0)):
            with self.subTest(profile=profile, relay=relay), self.assertRaises(ValueError):
                bridge.validate_selection(profile, relay)

    def test_foreign_role_and_missing_shared_lock_stop_before_binding(self):
        load = Mock(side_effect=AssertionError('No binding for another Source role'))
        with patch.object(bridge, 'load_binding', load):
            runtime = self.runtime();runtime.ENGINE = ROOT/'runtime/not-parity'
            with self.assertRaises(RuntimeError):
                bridge.SourceNtdllEntryObserver(runtime, self.environment(), bridge.STAGE, 'bad', 180)
            with patch.dict(bridge.sys.modules, {'source_main_environment': None}):
                with self.assertRaises(RuntimeError):
                    self.create()
        load.assert_not_called()

    def test_constructor_binds_only_and_caps_own_deadline(self):
        spawn = Mock(side_effect=AssertionError('Constructor must not spawn'))
        with patch.object(bridge.SourceNtdllEntryObserver, '_assert_held_context'), patch.object(bridge, 'load_binding', return_value=(contract, [])), patch.object(bridge, 'identity', side_effect=code_identity), patch.object(bridge.subprocess, 'Popen', spawn):
            observer = self.create(3600)
        spawn.assert_not_called()
        self.assertIsNone(observer.process)
        self.assertIsNone(observer.output)
        self.assertEqual(observer.duration, 300)

    def test_invalid_rows_never_persist_and_exit_zero_does_not_complete_partial(self):
        with patch.object(bridge.SourceNtdllEntryObserver, '_assert_held_context'), patch.object(bridge, 'load_binding', return_value=(contract, [])), patch.object(bridge, 'identity', side_effect=code_identity):
            observer = self.create()
        observer.output = io.StringIO()
        invalid = dict(ready(), arguments='must-never-persist')
        observer._accept(json.dumps(invalid).encode())
        self.assertEqual(observer.output.getvalue(), '')
        self.assertEqual(observer.records.events, [])
        observer._accept(json.dumps(ready()).encode())
        observer.exit = 0
        partial = observer.result()
        self.assertFalse(partial['native_completion_observed'])
        self.assertFalse(partial['native_completion_succeeded'])
        self.assertTrue(partial['entry_comparison_summary']['capture_incomplete'])
        self.assertNotIn('must-never-persist', observer.output.getvalue())
        observer._accept(json.dumps(done()).encode())
        final = observer.result()
        self.assertTrue(final['native_completion_observed'])
        self.assertFalse(final['native_completion_succeeded'])
        self.assertTrue(final['entry_comparison_summary']['capture_incomplete'])

    def test_wrong_duration_and_completed_stream_are_distinguished(self):
        records = bridge.EntryRecords(contract, 180000)
        self.assertIsNone(records.accept(json.dumps(ready(100))))
        self.assertFalse(records.ready)
        records = bridge.EntryRecords(contract, 180000)
        self.assertIsNotNone(records.accept(json.dumps(ready())))
        self.assertFalse(records.summary(0)['passed'])
        self.assertIsNotNone(records.accept(json.dumps(done())))
        self.assertTrue(records.summary(0)['passed'])
        self.assertFalse(records.summary(-15)['passed'])

    def test_helper_start_is_quiet_fixed_and_has_no_exit_context(self):
        fake_process = SimpleNamespace(pid=123, stdout=None)
        fake_thread = SimpleNamespace(ident=321, start=Mock(), is_alive=Mock(return_value=False))
        spawn = Mock(return_value=fake_process)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve();(root/'logs').mkdir()
            with patch.object(bridge.SourceNtdllEntryObserver, '_assert_held_context'), patch.object(bridge, 'load_binding', return_value=(contract, [])), patch.object(bridge, 'identity', side_effect=code_identity):
                observer = self.create()
                observer.path = root/'logs/own.ndjson'
                with patch.object(bridge, 'ROOT', root), patch.object(bridge.subprocess, 'Popen', spawn), patch.object(bridge.threading, 'Thread', return_value=fake_thread):
                    observer.start()
                observer.output.close()
        args, keywords = spawn.call_args
        self.assertEqual(args[0][-2:], ['--duration-ms', '180000'])
        self.assertEqual(keywords['stderr'], bridge.subprocess.DEVNULL)
        self.assertEqual(keywords['env']['WINEDEBUG'], '-all')
        self.assertFalse(any(k.lower().startswith('citizenfx_') for k in keywords['env']))

    def test_cleanup_failure_is_metadata_and_result_is_idempotent_without_reads(self):
        with patch.object(bridge.SourceNtdllEntryObserver, '_assert_held_context'), patch.object(bridge, 'load_binding', return_value=(contract, [])), patch.object(bridge, 'identity', side_effect=code_identity):
            observer = self.create()
        with patch.object(bridge._base.SourceCodeObserver, 'finish_after_wineserver_cleanup', side_effect=RuntimeError('own cleanup')), patch.object(bridge, 'read', side_effect=AssertionError('No result I/O')):
            result = observer.finish_after_wineserver_cleanup()
            self.assertEqual(result, observer.result())
        self.assertEqual(result['own_lifecycle_failure'], 'RuntimeError')
        self.assertFalse(result['native_completion_succeeded'])
        self.assertFalse(result['target_process_terminated_or_modified'])

    def test_foreign_control_log_path_rejected_before_code_execution(self):
        actual = json.loads((ROOT/bridge.CONTROL).read_bytes())
        actual['runs'][0]['log'] = 'prefixes/fivem-source-main/user.reg'
        raw = json.dumps(actual).encode()
        execute = Mock(side_effect=AssertionError('Must not execute after foreign log admission'))
        with patch.object(bridge, 'bound', side_effect=lambda name: raw if name == bridge.CONTROL else b'unused'), patch.object(bridge, 'execute', execute):
            with self.assertRaises(RuntimeError):
                bridge.load_binding()
        execute.assert_not_called()


if __name__ == '__main__':
    unittest.main()
