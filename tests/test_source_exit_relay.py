"""Mock-only Source exit mode checks; no Wine, registry or actual prefix access."""
from contextlib import contextmanager, redirect_stderr, redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'native/windows-client'))
import run_source
import source_exit_relay as bridge
import source_main_environment as policy


class SourceExitBridgeTests(unittest.TestCase):
    def fake_capture(self):
        helper, relay, _ = bridge.load_helpers()
        runtime = SimpleNamespace(ENGINE=bridge.ENGINE, WINE=bridge.ENGINE / 'bin/wine',
                                  source_runtime_profile={'profile': 'parity'})
        env = {'WINEPREFIX': str(bridge.PREFIX), 'WINESERVER': str(bridge.ENGINE / 'bin/wineserver'),
               'WINEDEBUG': bridge.DEBUG, 'CitizenFX_NoTenUI': '1'}
        with mock.patch.object(bridge.SourceExitRelay, '_assert_held_context'), \
                mock.patch.object(bridge, 'load_helpers', return_value=(helper, relay, [])), \
                mock.patch.object(bridge, 'identity', side_effect=lambda name: {'path': name}):
            value = bridge.SourceExitRelay(runtime, env, bridge.PREFIX, bridge.STAGE, 30)
        value._assert_held_context = mock.Mock()
        value.verify_sources = mock.Mock()
        return value

    def test_actual_control_and_exact_helper_bytes_verify_without_runtime(self):
        helper, relay, inputs = bridge.load_helpers()
        self.assertEqual(len(inputs), 3)
        self.assertEqual(relay.relay_debug('FiveM_ROSLauncher', source_authorized=True), bridge.DEBUG)
        self.assertEqual(helper.KEY, r'HKCU\Software\Wine\Debug')

    def test_invalid_profile_or_process_trace_reject_before_inputs_or_helpers(self):
        with mock.patch.object(run_source, 'check_inputs') as inputs:
            for profile, process_trace in (('matched', False), ('read', False), ('numeric', False), ('parity', True)):
                with self.subTest(profile=profile, trace=process_trace), self.assertRaises(ValueError):
                    run_source.run(30, runtime_profile=profile, process_trace=process_trace, exit_relay=True)
            inputs.assert_not_called()

    def test_unknown_prefix_engine_and_environment_reject_before_loading_helpers(self):
        env = {'WINEPREFIX': str(bridge.PREFIX), 'WINESERVER': str(bridge.ENGINE / 'bin/wineserver'),
               'WINEDEBUG': bridge.DEBUG}
        for field in ('prefix', 'stage', 'engine', 'profile', 'debug'):
            runtime = SimpleNamespace(ENGINE=bridge.ENGINE, WINE=bridge.ENGINE / 'bin/wine',
                                      source_runtime_profile={'profile': 'parity'})
            prefix, stage, values = bridge.PREFIX, bridge.STAGE, dict(env)
            if field == 'prefix': prefix = ROOT / 'prefixes/wine-parity-regression'
            if field == 'stage': stage = ROOT / 'build/fivem-official'
            if field == 'engine': runtime.ENGINE = ROOT / 'runtime/wine-read-diagnostics/engine'
            if field == 'profile': runtime.source_runtime_profile = {'profile': 'read'}
            if field == 'debug': values['WINEDEBUG'] = '+process'
            with mock.patch.object(bridge, 'load_helpers') as helpers, self.assertRaises(RuntimeError):
                bridge.SourceExitRelay(runtime, values, prefix, stage, 30)
            helpers.assert_not_called()

    def test_lock_is_already_held_by_this_process_and_prefix_inode_is_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            prefix = root / 'prefixes/fivem-source-main'
            prefix.mkdir(parents=True)
            lock = (root / 'lock').open('w')
            value = bridge.SourceExitRelay.__new__(bridge.SourceExitRelay)
            value.prefix_identity = None
            try:
                with mock.patch.object(bridge, 'ROOT', root), mock.patch.object(bridge, 'PREFIX', prefix), \
                        mock.patch.object(policy, 'ROOT', root), mock.patch.object(policy, '_ACTIVE_MAIN_LOCKS', {}):
                    with self.assertRaisesRegex(RuntimeError, 'already held'):
                        value._assert_held_context()
                    policy._ACTIVE_MAIN_LOCKS[str(prefix)] = (os.getpid() + 1, lock.fileno())
                    with self.assertRaisesRegex(RuntimeError, 'already held'):
                        value._assert_held_context()
                    policy._ACTIVE_MAIN_LOCKS[str(prefix)] = (os.getpid(), lock.fileno())
                    value._assert_held_context()
                    self.assertEqual(value.prefix_identity, (prefix.stat().st_dev, prefix.stat().st_ino))
                    value.prefix_identity = (-1, -1)
                    with self.assertRaisesRegex(RuntimeError, 'directory changed'):
                        value._assert_held_context()
            finally:
                lock.close()

    def test_registry_has_only_fixed_two_values_quiet_environment_and_bounded_call(self):
        value = self.fake_capture()
        with mock.patch.object(bridge.subprocess, 'run', return_value=SimpleNamespace(returncode=1)) as run:
            value.registry('query', value.helper.KEY, '/v', 'RelayInclude', capture=True)
            with self.assertRaises(RuntimeError):
                value.registry('query', value.helper.KEY, '/v', 'PRIVATE_ACCOUNT_VALUE', capture=True)
            with self.assertRaises(RuntimeError):
                value.registry('delete', value.helper.KEY, '/v', 'RelayExclude', '/f')
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[0], [str(bridge.ENGINE / 'bin/wine'), 'reg.exe',
                         'query', value.helper.KEY, '/v', 'RelayInclude'])
        self.assertEqual(run.call_args.kwargs['env']['WINEDEBUG'], '-all')
        self.assertNotIn('CitizenFX_NoTenUI', run.call_args.kwargs['env'])
        self.assertEqual(run.call_args.kwargs['timeout'], 20)
        self.assertIs(run.call_args.kwargs['stderr'], subprocess.DEVNULL)

    def test_exact_existing_default_is_preserved_and_only_include_is_added_deleted(self):
        value = self.fake_capture()
        raw = (r'HKEY_CURRENT_USER\Software\Wine\Debug' + '\r\n    RelayExclude    REG_SZ    '
               + value.helper.DEFAULT_RELAY_EXCLUDE + '\r\n').encode()
        responses = [SimpleNamespace(returncode=1), SimpleNamespace(returncode=0, stdout=raw),
                     SimpleNamespace(returncode=0), SimpleNamespace(returncode=0)]
        with mock.patch.object(value, 'registry', side_effect=responses) as registry:
            value.prepare()
            value.restore()
        self.assertTrue(value.prepared and value.restored)
        self.assertEqual(value.exclude_state, 'unchanged_exact_wine_default')
        writes = [call.args for call in registry.call_args_list if call.args[0] in ('add', 'delete')]
        self.assertEqual([args[0] for args in writes], ['add', 'delete'])
        self.assertTrue(all(args[3] == 'RelayInclude' for args in writes))

    def test_unknown_existing_filters_never_allow_an_add_or_delete(self):
        for responses in ([SimpleNamespace(returncode=0)],
                          [SimpleNamespace(returncode=1), SimpleNamespace(returncode=0, stdout=b'PRIVATE')]):
            value = self.fake_capture()
            with mock.patch.object(value, 'registry', side_effect=responses) as registry:
                with self.assertRaises(RuntimeError): value.prepare()
                value.restore()
            self.assertTrue(all(call.args[0] == 'query' for call in registry.call_args_list))
            self.assertFalse(value.change_attempted)

    def test_interrupted_or_failed_add_is_still_restored_by_finally(self):
        value = self.fake_capture()
        with mock.patch.object(value, 'registry', side_effect=[SimpleNamespace(returncode=1),
                SimpleNamespace(returncode=1), OSError('INERT-ADD-FAILURE'), SimpleNamespace(returncode=0)]) as registry:
            with self.assertRaises(OSError):
                try:
                    value.prepare()
                finally:
                    value.restore()
        self.assertTrue(value.change_attempted and value.restored)
        self.assertFalse(value.prepared)
        self.assertEqual(registry.call_args.args[0], 'delete')

    def test_main_spawn_is_exact_stdout_discarded_and_only_stderr_is_filtered(self):
        value = self.fake_capture()
        value.prepared = True
        process = SimpleNamespace(stderr=io.BytesIO(b'INERT'))
        sink = io.BytesIO()
        value.relay.pump = mock.Mock(return_value={'accepted_records': 1})
        with mock.patch.object(bridge.subprocess, 'Popen', return_value=process) as popen:
            self.assertIs(value.start(sink), process)
            with value.finishing_after_cleanup(sink):
                self.assertFalse(sink.closed)
        self.assertEqual(popen.call_args.args[0], [str(bridge.ENGINE / 'bin/wine'), str(bridge.STAGE / 'FiveM.exe')])
        self.assertIs(popen.call_args.kwargs['stdout'], subprocess.DEVNULL)
        self.assertIs(popen.call_args.kwargs['stderr'], subprocess.PIPE)
        self.assertTrue(sink.closed and process.stderr.closed)
        self.assertTrue(value.result()['stream_thread_stopped'])
        self.assertEqual(value.result()['stream'], {'accepted_records': 1})

    def test_thread_start_failure_cannot_mask_original_error_or_skip_sink_close(self):
        value = self.fake_capture()
        value.prepared = True
        process = SimpleNamespace(stderr=io.BytesIO(b'INERT'))
        sink = io.BytesIO()
        with mock.patch.object(bridge.subprocess, 'Popen', return_value=process), \
                mock.patch.object(bridge.threading.Thread, 'start', side_effect=RuntimeError('INERT-THREAD-START')), \
                mock.patch.object(bridge.threading.Thread, 'join') as join:
            with self.assertRaisesRegex(RuntimeError, 'INERT-THREAD-START'):
                try:
                    value.start(sink)
                finally:
                    with value.finishing_after_cleanup(sink):
                        pass
        join.assert_not_called()
        self.assertTrue(sink.closed and process.stderr.closed)
        self.assertTrue(value.result()['stream_thread_stopped'])


class SourceExitControllerTests(unittest.TestCase):
    def exercise(self, observer_failure=False, cleanup_timeout=False, thread_start_failure=False):
        observed, saved = [], []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / 'logs').mkdir()
            (root / 'research').mkdir()
            stage = root / 'build/windows-source-integration'
            prefix = root / 'prefixes/fivem-source-main'
            parent = SimpleNamespace(pid=1234, poll=mock.Mock(return_value=0),
                wait=mock.Mock(side_effect=lambda **kwargs: observed.append('parent-wait') or 0))
            runtime = SimpleNamespace(ENGINE=root / 'engine', WINE=root / 'engine/bin/wine',
                before_source_spawn=lambda: observed.append('guard'))
            capture = SimpleNamespace(restore_failure=None, pump_failure=None, change_attempted=True,
                                      restored=False, process=None)
            def prepare(): observed.append('prepare')
            def restore():
                observed.append('restore')
                capture.restored = True
            def start(sink):
                capture.sink = sink
                observed.append('main')
                capture.process = parent
                if thread_start_failure:
                    raise RuntimeError('INERT-THREAD-START-FAILURE')
                return parent
            @contextmanager
            def finishing(output):
                try:
                    yield
                finally:
                    observed.append('pumpstop')
                    if output is not None:
                        self.assertFalse(output.closed)
                        output.buffer.write(b'{"kind":"exit_api_call"}\n')
                        output.close()
            capture.prepare, capture.restore, capture.start = prepare, restore, start
            capture.finishing_after_cleanup = finishing
            capture.result = lambda: {'enabled': True, 'stream_thread_stopped': True}
            def wait_ready():
                observed.append('observer-ready')
                if observer_failure: raise RuntimeError('INERT-OBSERVER-GUARD-FAILURE')
            observer = SimpleNamespace(wait_ready=wait_ready,
                finish_after_wineserver_cleanup=lambda: observed.append('observer-finished'))
            def cleanup(command, **kwargs):
                observed.append(command[-1])
                if cleanup_timeout and command[-1] == '-w': raise subprocess.TimeoutExpired(command, 15)
                return SimpleNamespace(returncode=0)
            @contextmanager
            def locked(*args, **kwargs):
                observed.append('lock')
                try: yield
                finally: observed.append('unlock')
            patches = [mock.patch.object(run_source, 'ROOT', root), mock.patch.object(run_source, 'STAGE', stage),
                mock.patch.object(run_source, 'PREFIX', prefix), mock.patch.object(run_source, 'check_inputs',
                    return_value={'developer_code_version': 8}), mock.patch.object(run_source, 'game_mapping'),
                mock.patch.object(run_source, 'select_runtime_profile', return_value=(runtime, {})),
                mock.patch.object(run_source, 'source_runtime_environment', return_value={}),
                mock.patch.object(run_source, 'ProcessObserver', return_value=observer),
                mock.patch.object(run_source, 'code_only_snapshot', return_value={}),
                mock.patch.object(run_source, 'sha', return_value='a'*64),
                mock.patch.object(policy, 'source_main_prefix', locked),
                mock.patch.object(policy, 'assert_source_main_prefix'),
                mock.patch.object(bridge, 'SourceExitRelay', return_value=capture),
                mock.patch.object(run_source.subprocess, 'run', side_effect=cleanup),
                mock.patch.object(run_source.subprocess, 'Popen')]
            for name in ('MANIFEST', 'INITIAL_MANIFEST', 'USER_LOGIN', 'PREFLIGHT'):
                patches.append(mock.patch.object(run_source, name, root / 'research' / name))
            for name in ('mapping_metadata', 'hook_metadata', 'file_policy_metadata'):
                patches.append(mock.patch.object(run_source, name, side_effect=AssertionError('disabled parser called')))
            from contextlib import ExitStack
            with ExitStack() as stack:
                for patch in patches: stack.enter_context(patch)
                stack.enter_context(mock.patch.object(run_source.time, 'monotonic', side_effect=[100, 102, 103]))
                stack.enter_context(redirect_stdout(io.StringIO()))
                if observer_failure or thread_start_failure:
                    with self.assertRaisesRegex(RuntimeError, 'INERT-(OBSERVER|THREAD)'):
                        run_source.run(1, runtime_profile='parity', exit_relay=True)
                else:
                    code = run_source.run(1, runtime_profile='parity', exit_relay=True)
                    self.assertEqual(code, 1 if cleanup_timeout else 0)
                run_source.subprocess.Popen.assert_not_called()
            if thread_start_failure:
                parent.wait.assert_called_once_with(timeout=10)
                self.assertLess(observed.index('-w'), observed.index('parent-wait'))
                self.assertLess(observed.index('parent-wait'), observed.index('pumpstop'))
            reports = list((root / 'research').glob('*-results.json'))
            self.assertEqual(len(reports), 1)
            saved.append(json.loads(reports[0].read_bytes()))
        self.assertLess(observed.index('prepare'), observed.index('observer-ready'))
        self.assertLess(observed.index('restore'), observed.index('-k'))
        self.assertLess(observed.index('-w'), observed.index('pumpstop'))
        self.assertLess(observed.index('pumpstop'), observed.index('unlock'))
        for name in ('mapping_diagnostics_enabled', 'hook_diagnostics_enabled', 'file_policy_diagnostics_enabled',
                     'toolmode_diagnostics_enabled', 'private_wine_process_trace_enabled'):
            self.assertFalse(saved[0][name])
        self.assertTrue(saved[0]['source_exit_relay']['enabled'])
        return observed

    def test_sink_remains_open_through_server_cleanup_and_pump_finish(self):
        self.assertIn('main', self.exercise())

    def test_pre_start_observer_guard_failure_still_restores_and_cleans(self):
        self.assertNotIn('main', self.exercise(observer_failure=True))

    def test_cleanup_wait_timeout_still_stops_pump_and_preserves_failed_cleanup_record(self):
        self.assertIn('main', self.exercise(cleanup_timeout=True))

    def test_thread_start_failure_reaps_already_created_parent_after_server_cleanup(self):
        self.assertIn('main', self.exercise(thread_start_failure=True))

    def test_cli_rejects_bad_combinations_before_any_prefix_or_stage_access(self):
        for args in (['resume', '--exit-relay'], ['resume', '--exit-relay', '--runtime', 'read'],
                     ['resume', '--exit-relay', '--runtime', 'parity', '--process-exit-trace']):
            with mock.patch.object(sys, 'argv', ['run_source.py', *args]), \
                    mock.patch.object(run_source, 'check_inputs') as inputs, redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit): run_source.main()
                inputs.assert_not_called()
        with mock.patch.object(sys, 'argv', ['run_source.py', 'resume', '--runtime', 'parity', '--exit-relay']), \
                mock.patch.object(run_source, 'run', return_value=0) as run:
            self.assertEqual(run_source.main(), 0)
        self.assertTrue(run.call_args.kwargs['exit_relay'])


if __name__ == '__main__':
    unittest.main()
