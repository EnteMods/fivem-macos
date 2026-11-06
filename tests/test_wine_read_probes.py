"""Inert read-probe routing, source binding and fixed numeric acceptance tests."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('own_read_probe_adapter_test',
                                            ROOT / 'native/wine-read-diagnostics/run_probes.py')
adapter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(adapter)


def row(api, status=0):
    return f'0024:[CFX_WINE_API] pid=32 tid=36 api={api} status={status} access=0'


def pipe_rows():
    result = []
    for _ in range(2):
        result += [row(56), row(58, 997), row(60), row(62, 996)]
    return result + [row(56), row(57), row(60), row(61)]


class ReadProbeTests(unittest.TestCase):
    def verifier(self):
        raw = adapter.read(adapter.ENV)
        return adapter.identity(adapter.ENV, raw), raw

    def test_exact_frozen_derivation_roundtrips_three_literal_sites(self):
        raw = adapter.read(adapter.BASE)
        text = adapter.derive(raw)
        for before, after, count in reversed(adapter.EDITS):
            self.assertEqual(text.count(after), count)
            text = text.replace(after, before)
        self.assertEqual(text.encode(), raw)
        self.assertEqual(sum(row[2] for row in adapter.EDITS), 3)
        with self.assertRaises(RuntimeError):
            adapter.derive(raw + b'\n')

    def test_missing_root_pin_stops_before_any_runtime_or_lifecycle_selection(self):
        module = adapter.load_adapter()
        original = adapter.read
        def read(name):
            if name == adapter.PIN:
                raise FileNotFoundError('own missing code pin')
            return original(name)
        with mock.patch.object(adapter, 'read', side_effect=read), \
                mock.patch.object(module, 'isolated_runner') as lifecycle, \
                mock.patch.object(adapter, 'execute') as execute:
            with self.assertRaises(FileNotFoundError):
                module.main(['inspect'])
        lifecycle.assert_not_called()
        execute.assert_not_called()

    def test_root_pin_admits_only_fixed_verifier_role_before_its_read_or_execution(self):
        item, _ = self.verifier()
        pin = {'schema_version': 1, 'profile': adapter.ROLE, 'protocol_version': 1810, 'verifier': item}
        for changed in ({**pin, 'profile': 'wine-numeric-api-probes'},
                        {**pin, 'protocol_version': 1809},
                        {**pin, 'verifier': {**item, 'path': 'prefixes/fivem-source-main/private'}}):
            with mock.patch.object(adapter, 'read', return_value=json.dumps(changed).encode()) as read, \
                    mock.patch.object(adapter, 'execute') as execute:
                with self.assertRaises(RuntimeError):
                    adapter.load_environment()
            self.assertEqual(read.call_args_list, [mock.call(adapter.PIN)])
            execute.assert_not_called()

    def test_changed_root_pinned_verifier_bytes_are_rejected_before_execution(self):
        item, _ = self.verifier()
        pin = {'schema_version': 1, 'profile': adapter.ROLE, 'protocol_version': 1810, 'verifier': item}
        with mock.patch.object(adapter, 'read', side_effect=[json.dumps(pin).encode(), b'changed']), \
                mock.patch.object(adapter, 'execute') as execute:
            with self.assertRaisesRegex(RuntimeError, 'Root-issued code identity'):
                adapter.load_environment()
        execute.assert_not_called()

    def test_private_modes_and_prefix_do_not_modify_original_adapter(self):
        first, second = adapter.load_adapter(), adapter.load_adapter()
        self.assertEqual(len(first.MODES), 10)
        self.assertEqual(first.MODES[-2:], ('pipe-off', 'pipe-on'))
        self.assertEqual(first.PREFIX, adapter.PREFIX)
        first.PINNED_CODE['own-sentinel'] = '0' * 64
        self.assertNotIn('own-sentinel', second.PINNED_CODE)
        self.assertEqual(hashlib.sha256(adapter.read(adapter.BASE)).hexdigest(), adapter.BASE_SHA)

    def test_only_old_environment_and_parser_roles_are_routed_to_actual_new_sources(self):
        module = adapter.load_adapter()
        sentinel = object()
        with mock.patch.object(adapter, 'load_environment', return_value=sentinel) as load:
            self.assertIs(module.load_code(adapter.OLD_ENV), sentinel)
        load.assert_called_once_with()
        parser = module.load_code('native/wine-numeric-diagnostics/numeric_contract.py')
        self.assertEqual(parser.__file__, str(ROOT / adapter.PARSER))
        self.assertEqual(parser.OPERATIONS[14], ('ReadFile', 2))
        self.assertEqual(parser.OPERATIONS[15], ('GetOverlappedResult', 2))

    def test_all_fifteen_source_identities_have_their_actual_paths_and_bytes(self):
        module = adapter.load_adapter()
        with mock.patch.object(adapter, 'verifier_input', side_effect=self.verifier):
            values = module.verify_adapter_sources()
        self.assertEqual(len(values), 15)
        self.assertEqual(len({value['path'] for value in values}), 15)
        for value in values:
            self.assertEqual(value, adapter.identity(value['path']))
        by_path = {value['path']: value for value in values}
        self.assertEqual(by_path[adapter.PARSER]['sha256'], adapter.PARSER_SHA)
        self.assertEqual(by_path['native/wine-numeric-diagnostics/numeric_contract.py']['sha256'],
                         module.PINNED_CODE['native/wine-numeric-diagnostics/numeric_contract.py'])

    def test_unknown_helper_roles_fail_before_any_selected_read(self):
        module = adapter.load_adapter()
        with mock.patch.object(module, 'read_code') as read:
            with self.assertRaises(RuntimeError):
                module.load_code('prefixes/fivem-source-main/private')
        read.assert_not_called()

    def test_pipe_on_requires_both_pending_types_and_positive_read_completion(self):
        result = adapter.pipe_diagnostics(pipe_rows(), 'pipe-on', 0)
        self.assertTrue(result['passed'])
        self.assertEqual(result['completed_call_pairs'], 6)
        self.assertEqual(result['fixed_read_completion_controls'],
                         {'14': {'positive': 1, 'pending': 2}, '15': {'positive': 1, 'pending': 2}})
        self.assertFalse(result['ros_failure_cause_established'])

    def test_pipe_off_requires_zero_numeric_lines_and_a_successful_process(self):
        self.assertTrue(adapter.pipe_diagnostics([], 'pipe-off', 0)['passed'])
        self.assertFalse(adapter.pipe_diagnostics(pipe_rows(), 'pipe-off', 0)['passed'])
        self.assertFalse(adapter.pipe_diagnostics([], 'pipe-off', 1)['passed'])

    def test_foreign_api_reject_cap_unpaired_and_wrong_exit_cannot_pass_pipe_on(self):
        variants = [pipe_rows() + [row(52), row(53)], pipe_rows() + [row(56)],
                    pipe_rows() + [row(0xf002, 4096)], pipe_rows() + [row(56) + ' payload=discard']]
        for lines in variants:
            with self.subTest(lines=lines[-1]):
                self.assertFalse(adapter.pipe_diagnostics(lines, 'pipe-on', 0)['passed'])
        self.assertFalse(adapter.pipe_diagnostics(pipe_rows(), 'pipe-on', 1)['passed'])

    def test_missing_negative_or_positive_control_cannot_pass(self):
        for target in (57, 61, 58, 62):
            values = pipe_rows()
            positions = [i for i, value in enumerate(values) if f'api={target} ' in value]
            index = positions[0]
            del values[index - 1:index + 1]
            self.assertFalse(adapter.pipe_diagnostics(values, 'pipe-on', 0)['passed'])

    def test_pipe_helper_is_exact_v3_and_never_selects_an_old_engine(self):
        helper = adapter.load_pipe()
        self.assertEqual(helper.PIN, adapter.PIPE_PIN)
        with mock.patch.object(adapter, 'execute', return_value=SimpleNamespace(PIN='old-pin')):
            with self.assertRaises(RuntimeError):
                adapter.load_pipe()

    def pipe_fixture(self):
        state = {'contract': {'stage_count': 59, 'event_count': 60},
                 'root_fixture_pin': {'path': adapter.PIPE_PIN}, 'runtime_inputs': []}
        helper = SimpleNamespace(verify_inputs=mock.Mock(side_effect=lambda: copy.deepcopy(state)),
            make_cases=mock.Mock(return_value=[{'name': 'named_pipe', 'parse_output': lambda lines, code: {'passed': True}}]),
            select_runner=mock.Mock(side_effect=AssertionError('runtime selection is forbidden')))
        runner = SimpleNamespace(runtime=SimpleNamespace(MANIFEST_SHA='a' * 64, environment=lambda current: {}))
        return state, helper, runner

    def test_pipe_case_uses_only_fixture_helpers_and_inherits_the_bound_lifecycle_environment(self):
        _, helper, runner = self.pipe_fixture()
        module = adapter.load_adapter()
        with mock.patch.object(adapter, 'load_pipe', return_value=helper), \
                mock.patch.object(adapter, 'verifier_input', side_effect=self.verifier):
            cases, inputs, factory, prepare = module.select_cases('pipe-on', runner)
            result = inputs()
        self.assertEqual(result['numeric_probe_mode'], 'pipe-on')
        self.assertEqual(result['tested_engine_manifest_sha256'], 'a' * 64)
        self.assertIs(factory, runner.runtime.environment)
        self.assertIsNone(prepare)
        self.assertTrue(cases[0]['parse_diagnostics'](pipe_rows(), 0)['passed'])
        helper.select_runner.assert_not_called()

    def test_changed_v3_fixture_stops_before_case_execution(self):
        state, helper, runner = self.pipe_fixture()
        module = adapter.load_adapter()
        with mock.patch.object(adapter, 'load_pipe', return_value=helper):
            _, inputs, _, _ = module.select_cases('pipe-off', runner)
        state['contract']['event_count'] = 57
        with self.assertRaisesRegex(RuntimeError, 'fixture changed'):
            inputs()

    def test_late_root_pin_failure_still_preserves_a_failed_own_result(self):
        module = adapter.load_adapter()
        retained = []
        runner = SimpleNamespace(validate_environment=lambda env: None,
                                 save_result=lambda path, result: retained.append(copy.deepcopy(result)))
        environment = SimpleNamespace(ROLE=adapter.ROLE, ENGINE=ROOT / 'runtime/wine-read-diagnostics/engine',
            environment=lambda current, diagnostics: {}, verify_runtime=lambda: {})
        verified = {'manifest_sha256': 'a' * 64, 'root_pin': {'own': True}}
        with mock.patch.object(module, 'verify_adapter_sources', return_value=[]), \
                mock.patch.object(module, 'load_code', return_value=runner):
            selected = module.isolated_runner(environment, verified, 'pipe-on')
        result = {'profile': adapter.ROLE, 'prefix': 'prefixes/wine-read-regression',
                  'only_own_fixtures_and_builtin_initialization': True,
                  'client_cef_rockstar_game_or_account_code_started': False, 'passed': True, 'runs': []}
        path = ROOT / 'research/wine-parity-numeric-pipe-on-20261102T160000000000Z-results.json'
        with mock.patch.object(adapter, 'verifier_input', side_effect=RuntimeError('changed own pin')), \
                mock.patch.object(module, 'verify_adapter_sources', return_value=[]):
            selected.save_result(path, result)
        self.assertEqual(len(retained), 1)
        self.assertFalse(retained[0]['passed'])
        self.assertIn('read_adapter_guard_failure', retained[0])


if __name__ == '__main__':
    unittest.main()
