"""Inert metadata artifact/lifecycle and strict two-desktop API acceptance."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('desktop_meta_adapter', ROOT / 'native/windows-desktop-metadata/run.py')
adapter = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(adapter)


class MetadataAdapterTests(unittest.TestCase):
    def test_actual_134_relative_plus_two_external_inputs_verify_without_runtime(self):
        fixture = adapter.verify_inputs()
        self.assertEqual(len(fixture['runtime_inputs']) + len(fixture['source_inputs']), 134)
        self.assertEqual(len(fixture['external_compiler_provenance']), 2)
        self.assertTrue(all(not Path(i['path']).is_absolute() for i in fixture['source_inputs']))
        self.assertFalse(fixture['source_mode_selected'])

    def test_all_paths_including_library_and_last_log_admitted_before_hashes(self):
        base = adapter.provider().frozen_v1().utilities(); original = json.loads(base.read(adapter.REPORT))
        for role in ('reference', 'source', 'copy', 'log'):
            record = copy.deepcopy(original)
            if role == 'reference': record['references'][-1]['path'] = 'prefixes/fivem-source-main/foreign'
            elif role == 'source': record['source_evidence'][-1]['path'] = 'prefixes/fivem-source-main/foreign'
            elif role == 'copy': record['abi_header_copies'][-1]['original']['path'] = 'prefixes/fivem-source-main/foreign'
            else: record['no_wine_tests']['log']['path'] = 'prefixes/fivem-source-main/foreign'
            raw = json.dumps(record).encode()
            with self.subTest(role=role), mock.patch.object(adapter, 'REPORT_BYTES', len(raw)), mock.patch.object(adapter, 'REPORT_SHA', hashlib.sha256(raw).hexdigest()), \
                    mock.patch.object(base, 'read', return_value=raw) as read, mock.patch.object(base, 'identity') as identity:
                with self.assertRaises(RuntimeError): adapter.verify_inputs(base)
                self.assertEqual(read.call_args_list, [mock.call(adapter.REPORT)]); identity.assert_not_called()

    def test_compare_always_false_or_invalid_handle_cannot_pass_own_control(self):
        observations = [{'role': 101, 'view': 0, 'enum_ok': True, 'desktop_returned': True, 'desktop_relation': 1, 'compare_error': 0},
                        {'role': 102, 'view': 1, 'enum_ok': True, 'desktop_returned': True, 'desktop_relation': 2, 'compare_error': 1656}]
        def result(rows):
            contract = SimpleNamespace(parse_output=lambda *a, **k: {'passed': True, 'control_expectations': {}, 'desktop_api_observations': rows})
            return adapter.parse_control(contract, [], 0, 100)
        self.assertTrue(result(observations)['passed'])
        bad = copy.deepcopy(observations); bad[0].update(desktop_relation=2, compare_error=1656)
        self.assertFalse(result(bad)['passed'])
        bad = copy.deepcopy(observations); bad[1]['compare_error'] = 6
        parsed = result(bad)
        self.assertFalse(parsed['passed']); self.assertEqual(parsed['desktop_api_observations'], bad)

    def test_valid_alternate_frame_does_not_hide_later_enum_failure_counter_zero(self):
        observations = [{'role': 101, 'view': 0, 'enum_ok': True, 'desktop_returned': True, 'desktop_relation': 1, 'compare_error': 0},
                        {'role': 102, 'view': 1, 'enum_ok': True, 'desktop_returned': True, 'desktop_relation': 2, 'compare_error': 1656},
                        {'role': 102, 'view': 1, 'enum_ok': False, 'desktop_returned': True, 'desktop_relation': 2, 'compare_error': 1656}]
        contract = SimpleNamespace(parse_output=lambda *a, **k: {'passed': True, 'control_expectations': {}, 'desktop_api_observations': observations, 'observer': {'api_failures': 0}})
        parsed = adapter.parse_control(contract, [], 0, 100)
        self.assertFalse(parsed['passed']); self.assertEqual(parsed['desktop_api_observations'], observations)

    def test_late_reuse_provider_change_never_executed(self):
        base = adapter.provider().frozen_v1().utilities(); real_read = base.read; count = 0
        def read(name):
            nonlocal count
            if name == adapter.HERE + 'reuse.py':
                count += 1
                if count > 1: return b'raise AssertionError("executed")'
            return real_read(name)
        with mock.patch.object(base, 'read', side_effect=read), mock.patch.object(adapter, 'execute') as execute:
            with self.assertRaisesRegex(RuntimeError, 'before execution'): adapter.verify_inputs(base)
            execute.assert_not_called()

    def mock_runner(self, foreign_result=False, foreign_log=False):
        provider = adapter.provider(); old = provider.frozen_v1(); base = old.utilities(); fixture = adapter.verify_inputs(base)
        saved = mock.Mock(); original = SimpleNamespace()
        runner = SimpleNamespace(subprocess=original, runtime=SimpleNamespace(ENGINE=ROOT / 'runtime/wine-job-query-parity/engine'), save_result=saved)
        label = 'wine-parity-desktop-metadata-20261102T200000000000Z'
        def cases(cases, **kwargs):
            self.assertEqual(kwargs['role'], 'desktop-metadata')
            self.assertEqual([(c['name'], c['arguments']) for c in cases], [('desktop_fixture', ('--self',))])
            self.assertNotIn('--source-root', repr(cases))
            result = {'profile': 'wine-parity-api-probes', 'probe_role': 'desktop-metadata', 'prefix': 'prefixes/wine-parity-regression',
                      'only_own_fixtures_and_builtin_initialization': True, 'client_cef_rockstar_game_or_account_code_started': False, 'passed': True,
                      'runs': [{'name': 'desktop_fixture', 'binary': adapter.BINARY, 'log': 'logs/' + label + '-desktop_fixture.ndjson',
                                'wine_log': 'prefixes/fivem-source-main/foreign' if foreign_log else 'logs/' + label + '-desktop_fixture-wine.log'}]}
            runner.save_result(ROOT / 'research' / (('foreign' if foreign_result else label) + '-results.json'), result)
            return 0 if result['passed'] else 1
        runner.run_cases = cases
        return old, base, fixture, runner, original, saved

    def test_foreign_output_path_never_persisted_and_private_capture_restored(self):
        old, base, fixture, runner, original, saved = self.mock_runner(foreign_result=True)
        with mock.patch.object(adapter, 'select', return_value=(old, base, fixture, runner, {}, [])):
            with self.assertRaisesRegex(RuntimeError, 'result path'): adapter.run()
        saved.assert_not_called(); self.assertIs(runner.subprocess, original)

    def test_late_log_scope_failure_retains_failed_result_without_hashing_logs(self):
        old, base, fixture, runner, original, saved = self.mock_runner(foreign_log=True); real = base.identity
        def identify(name, raw=None):
            if name.startswith('logs/'): raise AssertionError('No log read before complete admission')
            return real(name, raw)
        with mock.patch.object(adapter, 'select', return_value=(old, base, fixture, runner, {}, [])), mock.patch.object(base, 'identity', side_effect=identify):
            self.assertEqual(adapter.run(), 1)
        result = saved.call_args.args[1]
        self.assertFalse(result['passed']); self.assertIn('metadata_guard_failure', result); self.assertIs(runner.subprocess, original)


if __name__ == '__main__': unittest.main()
