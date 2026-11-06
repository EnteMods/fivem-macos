"""Own exit-runner controls with mocks only; no Wine, registry or prefix actions."""
import importlib.util
from contextlib import nullcontext, redirect_stdout
import datetime
import io
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace, ModuleType
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('own_exit_relay_runner_tests',
    ROOT / 'native/diagnostics/run_own_exit_relay.py')
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


def exit_event(pid, status, api='RtlExitUserProcess'):
    return {'kind': 'exit_api_call', 'api': api, 'pid': pid, 'tid': pid + 4,
            'status': status, 'caller_address': 0x180001000}


class OwnExitParserTests(unittest.TestCase):
    def parse(self, events, code=0):
        return runner.parse_exit_events(list(map(json.dumps, events)), code)

    def test_distinct_parent0_and_child17_are_a_positive_control(self):
        parsed = self.parse([exit_event(32, 0), exit_event(204, 17)])
        self.assertTrue(parsed['passed'])
        self.assertTrue(parsed['positive_parent0_and_child17_observed'])
        self.assertFalse(parsed['caller_module_or_ros_cause_established'])
        self.assertFalse(self.parse([exit_event(32, 0), exit_event(204, 17)], 1)['passed'])
        self.assertFalse(self.parse([exit_event(32, 0, 'NtTerminateProcess'),
                                     exit_event(204, 17, 'NtTerminateProcess')])['passed'])

    def test_same_pid_cannot_prove_distinct_parent_and_child_exits(self):
        parsed = self.parse([exit_event(32, 0), exit_event(32, 17)])
        self.assertFalse(parsed['passed'])
        self.assertFalse(parsed['positive_parent0_and_child17_observed'])

    def test_invalid_windows_ids_status_or_address_cannot_satisfy_control(self):
        for key, invalid in (('pid', 0), ('pid', -1), ('pid', 2**32), ('tid', 0), ('tid', True),
                              ('status', -1), ('status', 2**32), ('caller_address', -1),
                              ('caller_address', 2**64)):
            events = [exit_event(32, 0), exit_event(204, 17)]
            events.append({**exit_event(32, 0), key: invalid})
            with self.subTest(key=key, invalid=invalid):
                self.assertFalse(self.parse(events)['passed'])

    def test_unknown_payload_or_api_is_not_retained(self):
        for row in ({**exit_event(32, 0), 'payload': 'PRIVATE_SECRET'},
                    {**exit_event(32, 0), 'api': 'PRIVATE_SECRET'}):
            parsed = self.parse([row, exit_event(204, 17)])
            self.assertFalse(parsed['passed'])
            self.assertNotIn('PRIVATE_SECRET', json.dumps(parsed))


class OwnExitProcessAdapterTests(unittest.TestCase):
    def setUp(self):
        self.engine = Path('/own/engine')
        self.binary = Path('/own/build/named_pipe_probe.exe')
        self.runtime = SimpleNamespace(runtime=SimpleNamespace(ENGINE=self.engine))
        self.relay = SimpleNamespace(RELAY_INCLUDE='kernel32.ExitProcess;ntdll.RtlExitUserProcess;ntdll.NtTerminateProcess',
            relay_debug=lambda image: 'own-fixed-exit-debug', pump=mock.Mock(return_value={'own_fixture': True}))
        self.adapter = runner.OwnProcessAdapter(self.runtime, self.binary, self.relay)
        self.command = [str(self.engine / 'bin/wine'), str(self.binary)]
        self.options = {'env': {'WINEDEBUG': 'own-fixed-exit-debug'}, 'cwd': self.binary.parent,
                        'stdout': io.StringIO(), 'stderr': SimpleNamespace(buffer=io.BytesIO()), 'timeout': 45}

    def process(self, wait=None):
        return SimpleNamespace(stderr=io.BytesIO(b'OWN-INERT-INPUT'),
            wait=mock.Mock(return_value=0) if wait is None else wait,
            kill=mock.Mock(), terminate=mock.Mock())

    def test_non_case_commands_are_not_redirected_into_filtered_trace(self):
        command = [str(self.engine / 'bin/wineserver'), '-w']
        completed = subprocess.CompletedProcess(command, 0)
        with mock.patch.object(runner.subprocess, 'run', return_value=completed) as delegated, \
                mock.patch.object(runner.subprocess, 'Popen') as popen:
            self.assertIs(self.adapter.run(command, env={'WINEDEBUG': '-all'}), completed)
        delegated.assert_called_once_with(command, env={'WINEDEBUG': '-all'})
        popen.assert_not_called(); self.relay.pump.assert_not_called()

    def test_prepare_touches_only_two_own_debug_values_and_sets_fixed_filter(self):
        with mock.patch.object(self.adapter, 'registry', side_effect=[SimpleNamespace(returncode=value)
                   for value in (1, 1, 0)]) as registry:
            record = self.adapter.prepare({}, self.options['env'])
        self.assertTrue(self.adapter.prepared)
        self.assertFalse(record['account_or_client_registry_read'])
        self.assertEqual(registry.call_args_list[0].args[1:], ('query', runner.KEY, '/v', 'RelayInclude'))
        self.assertEqual(registry.call_args_list[1].args[1:], ('query', runner.KEY, '/v', 'RelayExclude'))
        self.assertEqual(registry.call_args_list[2].args[1:],
            ('add', runner.KEY, '/v', 'RelayInclude', '/t', 'REG_SZ', '/d', self.relay.RELAY_INCLUDE, '/f'))
        self.assertTrue(all('HKCU\\Software\\Wine\\Debug' in call.args for call in registry.call_args_list))

    def test_exact_default_exclude_is_accepted_preserved_and_never_written(self):
        raw = (r'HKEY_CURRENT_USER\Software\Wine\Debug' + '\r\n    RelayExclude    REG_SZ    '
               + runner.DEFAULT_RELAY_EXCLUDE + '\r\n\r\n').encode()
        responses = [SimpleNamespace(returncode=1, stdout=b''), SimpleNamespace(returncode=0, stdout=raw),
                     SimpleNamespace(returncode=0), SimpleNamespace(returncode=0)]
        with mock.patch.object(self.adapter, 'registry', side_effect=responses) as registry:
            record = self.adapter.prepare({}, self.options['env'])
            self.adapter.restore_on_cleanup(self.options['env'])
        self.assertEqual(record['existing_relay_exclude_state'], 'unchanged_exact_wine_default')
        self.assertFalse(record['existing_relay_exclude_modified'])
        self.assertTrue(self.adapter.restored)
        writes = [call.args[1:] for call in registry.call_args_list if call.args[1] in ('add', 'delete')]
        self.assertEqual([args[0] for args in writes], ['add', 'delete'])
        self.assertTrue(all(args[3] == 'RelayInclude' for args in writes))
        self.assertFalse(any('RelayExclude' in args for args in writes))

    def test_unknown_or_malformed_successful_exclude_query_rejects_before_writes(self):
        valid = (r'HKEY_CURRENT_USER\Software\Wine\Debug' + '\r\n    RelayExclude    REG_SZ    '
                 + runner.DEFAULT_RELAY_EXCLUDE + '\r\n').encode()
        malformed = [b'', b'\xff', None, valid.decode(),
            valid.replace(b'HKEY_CURRENT_USER', b'HKEY_LOCAL_MACHINE'),
            valid.replace(b'RelayExclude', b'RelayInclude'), valid.replace(b'REG_SZ', b'REG_MULTI_SZ'),
            valid.replace(b'ntdll.RtlEnterCriticalSection', b'PRIVATE_UNKNOWN'),
            valid + b'    RelayInclude    REG_SZ    PRIVATE_UNKNOWN\r\n',
            valid.replace(b'kernel32.SetLastError\r\n', b'kernel32.SetLastError \r\n')]
        for index, raw in enumerate(malformed):
            self.adapter.prepared = False
            with self.subTest(case=index, raw_type=type(raw).__name__), \
                    mock.patch.object(self.adapter, 'registry', side_effect=[SimpleNamespace(returncode=1),
                        SimpleNamespace(returncode=0, stdout=raw), SimpleNamespace(returncode=0)]) as registry:
                with self.assertRaises(RuntimeError) as error:
                    self.adapter.prepare({}, self.options['env'])
                self.assertEqual([call.args[1] for call in registry.call_args_list], ['query', 'query'])
                self.assertFalse(self.adapter.prepared)
                self.assertNotIn('PRIVATE_UNKNOWN', str(error.exception))

    def test_existing_include_or_unexpected_query_exit_rejects_before_any_write(self):
        for code in (0, 2, -1):
            with self.subTest(code=code), mock.patch.object(self.adapter, 'registry',
                    return_value=SimpleNamespace(returncode=code, stdout=b'PRIVATE_UNKNOWN')) as registry:
                with self.assertRaises(RuntimeError): self.adapter.prepare({}, self.options['env'])
            self.assertEqual(registry.call_count, 1)
            self.assertEqual(registry.call_args.args[1], 'query')

    def test_exact_case_pipes_stderr_through_filter_and_restores_before_return(self):
        self.adapter.prepared = True
        process = self.process()
        with mock.patch.object(runner.subprocess, 'Popen', return_value=process) as popen, \
                mock.patch.object(self.adapter, 'registry', return_value=SimpleNamespace(returncode=0)) as registry:
            completed = self.adapter.run(self.command, **self.options)
        self.assertEqual(completed.returncode, 0)
        self.assertIs(popen.call_args.kwargs['stderr'], subprocess.PIPE)
        self.relay.pump.assert_called_once()
        self.assertIs(self.relay.pump.call_args.args[1], self.options['stderr'].buffer)
        registry.assert_called_once_with(self.options['env'], 'delete', runner.KEY, '/v', runner.VALUE, '/f')
        self.assertTrue(self.adapter.restored)

    def test_failed_restore_cannot_report_success(self):
        self.adapter.prepared = True
        with mock.patch.object(runner.subprocess, 'Popen', return_value=self.process()), \
                mock.patch.object(self.adapter, 'registry', return_value=SimpleNamespace(returncode=1)):
            with self.assertRaises(RuntimeError): self.adapter.run(self.command, **self.options)
        self.assertFalse(self.adapter.restored)

    def test_failed_popen_still_restores_prepared_debug_filter(self):
        self.adapter.prepared = True
        with mock.patch.object(runner.subprocess, 'Popen', side_effect=OSError('OWN-SPAWN-FAILURE')), \
                mock.patch.object(self.adapter, 'registry', return_value=SimpleNamespace(returncode=0)) as registry:
            with self.assertRaises(OSError): self.adapter.run(self.command, **self.options)
        registry.assert_called_once_with(self.options['env'], 'delete', runner.KEY, '/v', runner.VALUE, '/f')
        self.assertTrue(self.adapter.restored)

    def test_wait_timeout_terminates_and_reaps_only_owned_process_before_restoration(self):
        self.adapter.prepared = True
        process = self.process(mock.Mock(side_effect=[subprocess.TimeoutExpired(self.command, 45), 0]))
        with mock.patch.object(runner.subprocess, 'Popen', return_value=process), \
                mock.patch.object(self.adapter, 'registry', return_value=SimpleNamespace(returncode=0)):
            with self.assertRaises(subprocess.TimeoutExpired): self.adapter.run(self.command, **self.options)
        self.assertTrue(process.kill.called or process.terminate.called)
        self.assertGreaterEqual(process.wait.call_count, 2)
        self.assertTrue(self.adapter.restored)


class OwnExitCleanupExtensionTests(unittest.TestCase):
    def exercise_pre_case_guard_failure(self, restore_error=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            prefix = root / 'own-prefix'; prefix.mkdir(); (prefix / 'system.reg').write_bytes(b'OWN-INERT')
            (root / 'logs').mkdir(); (root / 'research').mkdir()
            quarantine = root / 'own-quarantine'; quarantine.write_bytes(b'OWN-INERT')
            binary = root / 'build/own.exe'
            fixture = {'runtime_inputs': [{'path': 'build/own.exe'}]}
            lifecycle = ModuleType('own_inert_extended_lifecycle')
            observed, saved = [], []
            bridge = runner.OwnProcessAdapter(lifecycle, binary, SimpleNamespace())

            def registry(env, *args, **kwargs):
                observed.append('restore')
                if restore_error is not None: raise restore_error
                return SimpleNamespace(returncode=0)

            bridge.registry = registry

            def prepare(verified, env):
                observed.append('prepare')
                bridge.prepared = True
                bridge.registry_used = True
                return {'own_inert_fixture': True}

            def cleanup(command, **kwargs):
                observed.append(command[-1])
                return SimpleNamespace(returncode=0)

            environment = {'WINEPREFIX': str(prefix)}
            lifecycle.__dict__.update(ROOT=root, PREFIX=prefix, BUILD=root / 'build', datetime=datetime,
                time=SimpleNamespace(monotonic=mock.Mock(side_effect=[100, 101])),
                runtime=SimpleNamespace(ROLE='own-inert-role', PROTOCOL=1810, ENGINE=root / 'own-engine',
                    verify_runtime=lambda: {}, environment=lambda verified: dict(environment), canonical=lambda *args: None),
                verify_jobs=lambda: fixture, validate_environment=lambda env: None,
                refuse_quarantine=lambda: None, probe_prefix=lambda *args, **kwargs: nullcontext(),
                bind_prefix=lambda existed: {}, quarantine=lambda path: None,
                quarantine_path=lambda: quarantine, assert_account_free_prefix=lambda *args, **kwargs: None,
                subprocess=SimpleNamespace(run=cleanup, DEVNULL=subprocess.DEVNULL),
                save_result=lambda path, record: saved.append(record))
            proof = runner.install_cleanup_extension(lifecycle, bridge)
            verify = mock.Mock(side_effect=[fixture, RuntimeError('OWN-PRE-CASE-GUARD-FAILURE')])
            case = {'binary': binary, 'cwd': binary.parent, 'name': 'own-inert-case'}
            with redirect_stdout(io.StringIO()):
                code = lifecycle.run_cases([case], verify_inputs=verify, prepare_prefix=prepare)
            self.assertEqual(code, 1)
            self.assertEqual(observed, ['prepare', 'restore', '-k', '-w'])
            self.assertEqual(len(saved), 1)
            self.assertFalse(saved[0]['passed'])
            self.assertEqual(saved[0]['runs'], [])
            self.assertEqual(saved[0]['cleanup'], [{'flag': '-k', 'exit': 0}, {'flag': '-w', 'exit': 0}])
            self.assertEqual(proof['exact_cleanup_insertion_count'], 1)
            self.assertTrue(proof['extension_reversible'])
            self.assertTrue(proof['restoration_precedes_existing_server_cleanup'])
            return bridge

    def test_pre_case_guard_failure_restores_before_existing_server_cleanup(self):
        bridge = self.exercise_pre_case_guard_failure()
        self.assertTrue(bridge.restored)
        self.assertIsNone(bridge.restore_failure)

    def test_restore_exception_is_recorded_without_skipping_server_cleanup(self):
        bridge = self.exercise_pre_case_guard_failure(OSError('OWN-RESTORE-FAILURE'))
        self.assertFalse(bridge.restored)
        self.assertEqual(bridge.restore_failure, 'OSError')


if __name__ == '__main__':
    unittest.main()
