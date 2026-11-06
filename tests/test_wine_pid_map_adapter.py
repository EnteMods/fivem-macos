"""Inert exact ABI/provenance and Popen-PID controls; never execute Wine."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('own_pidmap_adapter', ROOT / 'native/windows-wine-pid-map/run.py')
adapter = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(adapter)


class PidMapperAdapterTests(unittest.TestCase):
    def test_real_69_fixed_inputs_verify_without_execution(self):
        fixture = adapter.verify_inputs()
        self.assertEqual(len(fixture['source_inputs']) + len(fixture['runtime_inputs']), 69)
        self.assertEqual([x['path'] for x in fixture['runtime_inputs']], [adapter.BINARY])
        self.assertFalse(fixture['source_mode_selected'])

    def test_changed_report_rejected_before_selected_reads(self):
        base = adapter.utilities()
        with mock.patch.object(base, 'read', return_value=b'{}') as read, mock.patch.object(base, 'identity') as identity:
            with self.assertRaisesRegex(RuntimeError, 'report changed'):
                adapter.verify_inputs(base)
            self.assertEqual(read.call_args_list, [mock.call(adapter.REPORT)])
            identity.assert_not_called()

    def test_complete_scope_before_any_selected_header_compiler_or_log_hash(self):
        base = adapter.utilities(); original = json.loads(base.read(adapter.REPORT))
        for role in ('closure', 'build_log', 'compiler', 'source'):
            record = copy.deepcopy(original)
            if role == 'closure': record['original_header_layout']['dependency_closure'][-1]['path'] = 'prefixes/fivem-source-main/foreign.h'
            elif role == 'build_log': record['build']['log']['path'] = 'prefixes/fivem-source-main/foreign'
            elif role == 'compiler': record['host_compiler']['path'] = '/private/foreign'
            else: record['source_evidence'][-1]['path'] = 'prefixes/fivem-source-main/foreign'
            raw = json.dumps(record).encode()
            with self.subTest(role=role), mock.patch.object(adapter, 'REPORT_SHA', hashlib.sha256(raw).hexdigest()), \
                    mock.patch.object(adapter, 'REPORT_BYTES', len(raw)), mock.patch.object(base, 'read', return_value=raw), \
                    mock.patch.object(base, 'identity') as identity, mock.patch.object(adapter, 'external_identity') as external:
                with self.assertRaises(RuntimeError): adapter.verify_inputs(base)
                identity.assert_not_called(); external.assert_not_called()

    def test_empty_success_logs_allowed_only_for_exact_two_roles(self):
        base = adapter.utilities(); empty = hashlib.sha256(b'').hexdigest()
        for name in adapter.EMPTY_LOGS:
            adapter.shape(base, {'path': name, 'bytes': 0, 'sha256': empty}, name)
        with self.assertRaises(RuntimeError):
            adapter.shape(base, {'path': 'foreign', 'bytes': 0, 'sha256': empty}, 'foreign')

    def test_actual_popen_pid_is_captured_only_for_exact_own_self_command(self):
        command = ['wine', 'own.exe', '--self']
        process = SimpleNamespace(pid=9152, returncode=0, wait=mock.Mock(), kill=mock.Mock())
        original = SimpleNamespace(Popen=mock.Mock(return_value=process), run=mock.Mock(return_value='delegated'), CompletedProcess=subprocess.CompletedProcess)
        capture = adapter.OwnRunCapture(original, command)
        kwargs = {'cwd': '/own', 'env': {}, 'stdout': object(), 'stderr': object(), 'timeout': 45}
        result = capture.run(command, **kwargs)
        self.assertEqual(result.returncode, 0); self.assertEqual(capture.pids, [9152])
        original.Popen.assert_called_once(); process.wait.assert_called_once_with(timeout=45); process.kill.assert_not_called()
        with self.assertRaises(RuntimeError): capture.run(command, **kwargs)
        self.assertEqual(capture.run(['wine', 'wineboot'], timeout=60), 'delegated')
        self.assertEqual(capture.pids, [9152])

    def test_timeout_kills_only_own_popen_with_bounded_reap(self):
        command = ['wine', 'own.exe', '--self']
        process = SimpleNamespace(pid=9152, returncode=0,
            wait=mock.Mock(side_effect=[subprocess.TimeoutExpired(command, 45), None]), kill=mock.Mock())
        original = SimpleNamespace(Popen=mock.Mock(return_value=process), run=mock.Mock(), CompletedProcess=subprocess.CompletedProcess)
        capture = adapter.OwnRunCapture(original, command)
        with self.assertRaises(subprocess.TimeoutExpired):
            capture.run(command, cwd='/own', env={}, stdout=object(), stderr=object(), timeout=45)
        process.kill.assert_called_once(); self.assertEqual(process.wait.call_args_list, [mock.call(timeout=45), mock.call(timeout=5)])
        original.run.assert_not_called()

    def test_actual_engine_must_be_e4fc_protocol1810_before_any_run(self):
        base = adapter.utilities()
        for digest, protocol in [('wrong', 1810), (adapter.MANIFEST_SHA, 1811)]:
            runner = SimpleNamespace(runtime=SimpleNamespace(PROTOCOL=protocol))
            helper = SimpleNamespace(select_runner=lambda mode: (runner, {'manifest_sha256': digest}, None))
            with mock.patch.object(adapter, 'utilities', return_value=base), mock.patch.object(adapter, 'verify_inputs', return_value={}), \
                    mock.patch.object(base, 'load_helper', return_value=helper):
                with self.assertRaisesRegex(RuntimeError, 'E4fc/protocol1810'): adapter.select()

    def test_late_log_scope_failure_preserves_result_and_private_subprocess_restored(self):
        base = adapter.utilities(); fixture = adapter.verify_inputs(base); saved = []
        original = SimpleNamespace()
        runtime = SimpleNamespace(ENGINE=ROOT / 'runtime/wine-job-query-parity/engine')
        runner = SimpleNamespace(subprocess=original, runtime=runtime, save_result=lambda p, r: saved.append(copy.deepcopy(r)))
        label = 'wine-parity-wine-pid-map-20261102T200000000000Z'
        def cases(cases, **kwargs):
            self.assertEqual(kwargs['role'], 'wine-pid-map')
            self.assertEqual([x['arguments'] for x in cases], [('--self',), ('--unsupported',)])
            self.assertNotIn('--source-root', repr(cases))
            result = {'probe_role': 'wine-pid-map', 'prefix': 'prefixes/wine-parity-regression', 'profile': 'wine-parity-api-probes',
                'client_cef_rockstar_game_or_account_code_started': False, 'passed': True,
                'runs': [{'name': 'self_map', 'binary': adapter.BINARY, 'log': 'logs/' + label + '-self_map.ndjson',
                          'wine_log': 'logs/' + label + '-self_map-wine.log'},
                         {'name': 'invalid_option', 'binary': adapter.BINARY, 'log': 'logs/' + label + '-invalid_option.ndjson',
                          'wine_log': 'prefixes/fivem-source-main/foreign'}]}
            runner.save_result(ROOT / 'research' / (label + '-results.json'), result)
            return 0 if result['passed'] else 1
        runner.run_cases = cases
        original_identity = base.identity
        def identity(name, raw=None):
            if name.startswith('logs/'):
                raise AssertionError('No log hash before full role admission')
            return original_identity(name, raw)
        with mock.patch.object(adapter, 'select', return_value=(base, fixture, runner, {}, [])), mock.patch.object(base, 'identity', side_effect=identity):
            self.assertEqual(adapter.run(), 1)
        self.assertIs(runner.subprocess, original)
        self.assertFalse(saved[0]['passed']); self.assertIn('pid_mapper_guard_failure', saved[0])
        self.assertFalse(saved[0]['source_mode_selected'])

    def test_foreign_result_path_never_reaches_original_save(self):
        base = adapter.utilities(); fixture = adapter.verify_inputs(base)
        original = SimpleNamespace()
        runtime = SimpleNamespace(ENGINE=ROOT / 'runtime/wine-job-query-parity/engine')
        saved = mock.Mock()
        runner = SimpleNamespace(subprocess=original, runtime=runtime, save_result=saved)
        def cases(cases, **kwargs):
            runner.save_result(ROOT / 'research' / 'foreign-results.json', {'passed': True})
        runner.run_cases = cases
        with mock.patch.object(adapter, 'select', return_value=(base, fixture, runner, {}, [])):
            with self.assertRaisesRegex(RuntimeError, 'result path'):
                adapter.run()
        saved.assert_not_called()
        self.assertIs(runner.subprocess, original)


if __name__ == '__main__': unittest.main()
