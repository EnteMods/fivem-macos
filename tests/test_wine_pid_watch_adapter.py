"""Inert own multi-role fixture binding/lifecycle checks; no Wine or Source starts."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('own_pidwatch_adapter', ROOT / 'native/windows-wine-pid-watch/run.py')
adapter = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(adapter)


class PidWatchAdapterTests(unittest.TestCase):
    def test_real_104_inputs_bind_new_and_immutable_v1_artifacts(self):
        value = adapter.verify_inputs()
        self.assertEqual(len(value['runtime_inputs']) + len(value['source_inputs']), 102)
        self.assertEqual(len(value['external_compiler_provenance']), 2)
        self.assertTrue(all(not Path(x['path']).is_absolute() for x in value['source_inputs']))
        self.assertTrue(all(Path(x['path']).is_absolute() for x in value['external_compiler_provenance']))
        self.assertEqual({Path(x['path']).name for x in value['runtime_inputs']}, {'pid_watch.exe', 'fixture.exe', 'child.exe'})
        self.assertFalse(value['source_mode_selected'])
        self.assertEqual(value['build_reports'][1]['sha256'], '04217219ea99f5a8d99cade8fe8b0c17db189c4468b1e358726f98f8b154ee07')

    def test_changed_report_fails_before_selected_artifact_reads(self):
        base = adapter.frozen_v1().utilities()
        with mock.patch.object(base, 'read', return_value=b'{}') as read, mock.patch.object(base, 'identity') as identity:
            with self.assertRaisesRegex(RuntimeError, 'report changed'): adapter.verify_inputs(base)
            self.assertEqual(read.call_args_list, [mock.call(adapter.REPORT)]); identity.assert_not_called()

    def test_complete_scope_including_abi_original_and_last_log_before_hashes(self):
        base = adapter.frozen_v1().utilities(); original = json.loads(base.read(adapter.REPORT))
        for role in ('source', 'reference', 'abi', 'log'):
            record = copy.deepcopy(original)
            if role == 'source': record['source_evidence'][-1]['path'] = 'prefixes/fivem-source-main/foreign'
            elif role == 'reference': record['references'][-1]['path'] = 'prefixes/fivem-source-main/foreign'
            elif role == 'abi': record['abi_header_copies'][-1]['original']['path'] = 'prefixes/fivem-source-main/foreign'
            else: record['no_wine_tests']['log']['path'] = 'prefixes/fivem-source-main/foreign'
            raw = json.dumps(record).encode()
            with self.subTest(role=role), mock.patch.object(adapter, 'REPORT_BYTES', len(raw)), \
                    mock.patch.object(adapter, 'REPORT_SHA', hashlib.sha256(raw).hexdigest()), \
                    mock.patch.object(base, 'read', return_value=raw) as read, mock.patch.object(base, 'identity') as identity:
                with self.assertRaises(RuntimeError): adapter.verify_inputs(base)
                self.assertEqual(read.call_args_list, [mock.call(adapter.REPORT)]); identity.assert_not_called()

    def test_v1_is_byte_pinned_before_execution(self):
        base = SimpleNamespace(read=mock.Mock(return_value=b'raise AssertionError("executed")'))
        with mock.patch.object(adapter, 'execute', return_value=base) as execute:
            with self.assertRaisesRegex(RuntimeError, 'v1 adapter changed'): adapter.frozen_v1()
            self.assertEqual(execute.call_count, 1)
            self.assertEqual(execute.call_args.args[0], adapter.UTILITY)

    def test_late_provider_drift_not_executed(self):
        base = adapter.frozen_v1().utilities(); real_read = base.read
        count = 0
        def read(name):
            nonlocal count
            if name == adapter.HERE + 'role_inputs.py':
                count += 1
                if count > 1: return b'raise AssertionError("executed")'
            return real_read(name)
        with mock.patch.object(base, 'read', side_effect=read), \
                mock.patch.object(adapter, 'execute') as execute:
            with self.assertRaisesRegex(RuntimeError, 'provider changed'): adapter.verify_inputs(base)
            execute.assert_not_called()

    def fixture_runner(self, path_mode='valid', foreign_log=False):
        old = adapter.frozen_v1(); base = old.utilities(); fixture = adapter.verify_inputs(base); saved = mock.Mock()
        original = SimpleNamespace(); runtime = SimpleNamespace(ENGINE=ROOT / 'runtime/wine-job-query-parity/engine')
        runner = SimpleNamespace(subprocess=original, runtime=runtime, save_result=saved)
        label = 'wine-parity-wine-pid-watch-20261102T200000000000Z'
        def run_cases(cases, **kwargs):
            self.assertEqual(kwargs['role'], 'wine-pid-watch')
            self.assertEqual([(x['name'], x['arguments']) for x in cases], [('multi_role_fixture', ('--self',))])
            self.assertNotIn('--source-root', repr(cases))
            result = {'profile': 'wine-parity-api-probes', 'probe_role': 'wine-pid-watch', 'prefix': 'prefixes/wine-parity-regression',
                      'only_own_fixtures_and_builtin_initialization': True, 'client_cef_rockstar_game_or_account_code_started': False, 'passed': True,
                      'runs': [{'name': 'multi_role_fixture', 'binary': adapter.BINARY,
                                'log': 'logs/' + label + '-multi_role_fixture.ndjson',
                                'wine_log': 'prefixes/fivem-source-main/foreign' if foreign_log else 'logs/' + label + '-multi_role_fixture-wine.log'}]}
            path = ROOT / 'research' / ((label if path_mode == 'valid' else 'foreign') + '-results.json')
            runner.save_result(path, result)
            return 0 if result['passed'] else 1
        runner.run_cases = run_cases
        return old, base, fixture, runner, original, saved

    def test_foreign_result_never_saved_and_private_capture_restored(self):
        old, base, fixture, runner, original, saved = self.fixture_runner(path_mode='foreign')
        with mock.patch.object(adapter, 'select', return_value=(old, base, fixture, runner, {}, [])):
            with self.assertRaisesRegex(RuntimeError, 'result path'): adapter.run()
        saved.assert_not_called(); self.assertIs(runner.subprocess, original)

    def test_late_foreign_log_records_failure_before_any_log_hash(self):
        old, base, fixture, runner, original, saved = self.fixture_runner(foreign_log=True)
        real_identity = base.identity
        def identity(name, raw=None):
            if name.startswith('logs/'): raise AssertionError('No log hashes before all roles admitted')
            return real_identity(name, raw)
        with mock.patch.object(adapter, 'select', return_value=(old, base, fixture, runner, {}, [])), mock.patch.object(base, 'identity', side_effect=identity):
            self.assertEqual(adapter.run(), 1)
        result = saved.call_args.args[1]
        self.assertFalse(result['passed']); self.assertIn('pid_watcher_guard_failure', result)
        self.assertFalse(result['source_mode_selected']); self.assertIs(runner.subprocess, original)

    def test_cli_has_only_inspect_run_no_source_or_arbitrary_runtime_option(self):
        import contextlib
        import io
        for args in (['source'], ['run', '--source-root', '/private'], ['run', '--runtime', 'matched']):
            with mock.patch.object(adapter, 'run') as run, contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit): adapter.main(args)
                run.assert_not_called()


if __name__ == '__main__': unittest.main()
