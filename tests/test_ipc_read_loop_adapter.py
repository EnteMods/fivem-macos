"""Inert boundary checks for the three own reader comparisons; never launch Wine."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('own_ipc_read_adapter', ROOT / 'native/windows-ipc-read-loop/run.py')
adapter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(adapter)


def item(path):
    return {'path': path, 'bytes': 1, 'sha256': 'a' * 64}


def trace(base, success, error=0):
    return [f'0024:[CFX_WINE_API] pid=32 tid=36 api={4 * base} status=0 access=0',
            f'0024:[CFX_WINE_API] pid=32 tid=36 api={4 * base + (1 if success else 2)} status={error} access=0']


def good_events():
    parser = adapter.execute(adapter.PARSER, adapter.bound(adapter.PARSER, adapter.PARSER_SHA))
    events = [{'kind': 'step', 'stage': stage, 'api': parser.API_BY_STAGE[stage - 1],
               'iteration': 1 if 18 <= stage <= 26 else 2 if 27 <= stage <= 33 else 0,
               'succeeded': stage not in parser.FALSE_ERRORS, 'last_error': parser.ERRORS.get(stage, 0),
               'count': parser.COUNTS.get(stage, 0), 'wait': 258 if stage == 19 else 0, 'check': True}
              for stage in range(1, 39)]
    return events + [{'kind': 'result', 'passed': True, 'failed_stage': 0, 'child_exit': 17,
                      'child_reaped': True, 'child_forced': False, 'close_attempts': 10, 'close_successes': 10}]


class IpcReadLoopAdapterTests(unittest.TestCase):
    def test_noncanonical_relative_paths_fail_before_open(self):
        with mock.patch.object(adapter.os, 'open') as opened:
            for path in ('/tmp/foreign', '../foreign', 'native/../foreign', 'native//foreign', './foreign'):
                with self.assertRaises(RuntimeError):
                    adapter.read(path)
            opened.assert_not_called()

    def test_symlink_and_hardlink_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(adapter, 'ROOT', Path(directory).resolve()):
            root = Path(directory).resolve()
            (root / 'own').write_bytes(b'own\r\n')
            self.assertEqual(adapter.identity('own'),
                             {'path': 'own', 'bytes': 5, 'sha256': hashlib.sha256(b'own\r\n').hexdigest()})
            (root / 'alias').symlink_to(root / 'own')
            with self.assertRaises(RuntimeError):
                adapter.read('alias')
            os.link(root / 'own', root / 'linked')
            with self.assertRaises(RuntimeError):
                adapter.read('linked')

    def test_real_frozen_fixture_admits_all_25_identities_without_runtime(self):
        value = adapter.verify_inputs()
        self.assertEqual(value['declared_input_identity_count'], 25)
        self.assertEqual(len(value['source_inputs']), 24)
        self.assertEqual(value['runtime_inputs'], [{'path': adapter.BINARY, 'bytes': adapter.BINARY_BYTES,
                                                 'sha256': adapter.BINARY_SHA}])
        self.assertTrue(value['contract']['buffered_true_read_requires_seeded_stale_last_error997'])

    def test_changed_report_is_rejected_before_any_selected_reads(self):
        with mock.patch.object(adapter, 'read', return_value=b'{}') as read, \
                mock.patch.object(adapter, 'identity') as identity:
            with self.assertRaisesRegex(RuntimeError, 'pinned'):
                adapter.verify_inputs()
            self.assertEqual(read.call_args_list, [mock.call(adapter.REPORT)])
            identity.assert_not_called()

    def test_every_late_path_role_is_admitted_before_selected_reads(self):
        original = json.loads(adapter.read(adapter.REPORT))
        for field in ('reader_form_references', 'preserved_existing_named_pipe_inputs', 'build_log', 'test_log'):
            with self.subTest(field=field):
                report = copy.deepcopy(original)
                if field == 'build_log':
                    report['build']['log']['path'] = 'prefixes/fivem-source-main/foreign'
                elif field == 'test_log':
                    report['no_wine_contract_tests']['log']['path'] = 'prefixes/fivem-source-main/foreign'
                else:
                    report[field][-1]['path'] = 'prefixes/fivem-source-main/foreign'
                raw = json.dumps(report).encode()
                with mock.patch.object(adapter, 'REPORT_SHA', hashlib.sha256(raw).hexdigest()), \
                        mock.patch.object(adapter, 'REPORT_BYTES', len(raw)), \
                        mock.patch.object(adapter, 'read', return_value=raw) as read, \
                        mock.patch.object(adapter, 'identity') as identity:
                    with self.assertRaises(RuntimeError):
                        adapter.verify_inputs()
                    self.assertEqual(read.call_args_list, [mock.call(adapter.REPORT)])
                    identity.assert_not_called()

    def test_selected_identity_mismatch_fails_the_fixture(self):
        original = adapter.identity
        with mock.patch.object(adapter, 'identity', side_effect=lambda name, data=None:
                               item(name) if name == adapter.BINARY else original(name, data)):
            with self.assertRaisesRegex(RuntimeError, 'changed after'):
                adapter.verify_inputs()

    def test_unknown_variant_fails_before_loading_helpers(self):
        with mock.patch.object(adapter, 'bound') as bound:
            with self.assertRaisesRegex(RuntimeError, 'Only parity'):
                adapter.select_runner('numeric')
            bound.assert_not_called()

    def test_changed_helper_and_parser_are_never_executed(self):
        with mock.patch.object(adapter, 'read', return_value=b'raise AssertionError("executed")'), \
                mock.patch.object(adapter, 'execute') as execute:
            with self.assertRaises(RuntimeError):
                adapter.select_runner('parity')
            with self.assertRaises(RuntimeError):
                adapter.cases({'parser_source': item(adapter.PARSER)}, 'read-on')
            execute.assert_not_called()

    def fake_runner(self, variant):
        role, prefix, engine, digest = adapter.VARIANTS[variant]
        verified = {'profile': role, 'protocol_version': 1810, 'manifest_sha256': digest,
                    'root_pin': item('research/wine-read-engine-code-inputs.json')} if variant != 'parity' else {
                        'profile': role, 'protocol_version': 1810, 'manifest_sha256': digest}
        provider = SimpleNamespace(ROLE=role, PREFIX=ROOT / 'prefixes' / prefix,
                                   ENGINE=ROOT / 'runtime' / engine / 'engine',
                                   MOLTENVK=ROOT / 'runtime/MoltenVK/libMoltenVK.dylib',
                                   FRAMEWORKS=ROOT / 'runtime/Frameworks', GST_LIB=ROOT / 'runtime/GStreamer/lib')
        provider.verify_runtime = mock.Mock(return_value=verified)
        provider.environment = mock.Mock(return_value={'WINEDEBUG': '-all'})
        runner = SimpleNamespace(runtime=provider, validate_environment=mock.Mock())
        helper = SimpleNamespace(load_code=mock.Mock(return_value=runner))
        read_helper = SimpleNamespace(load_environment=mock.Mock(return_value=provider))
        execute = lambda name, raw: helper if name == adapter.HELPER else read_helper
        return runner, provider, helper, read_helper, verified, execute

    def test_three_variants_select_exact_manifest_prefix_and_explicit_read_channel(self):
        for variant in adapter.VARIANTS:
            with self.subTest(variant=variant):
                runner, provider, helper, read_helper, verified, execute = self.fake_runner(variant)
                with mock.patch.object(adapter, 'bound', return_value=b'fixed'), \
                        mock.patch.object(adapter, 'execute', side_effect=execute):
                    selected, result, selected_helper = adapter.select_runner(variant)
                self.assertIs(selected, runner)
                self.assertIs(selected_helper, helper)
                self.assertEqual(result, verified)
                self.assertEqual(selected.PREFIX, provider.PREFIX)
                self.assertEqual(selected.runtime.MANIFEST_SHA, adapter.VARIANTS[variant][3])
                selected.runtime.environment(result)
                if variant == 'parity':
                    read_helper.load_environment.assert_not_called()
                    provider.environment.assert_called_once_with(result)
                else:
                    read_helper.load_environment.assert_called_once_with()
                    provider.environment.assert_called_once_with(result, diagnostics=variant == 'read-on')
                changed = {**verified, 'manifest_sha256': 'f' * 64}
                provider.verify_runtime.return_value = changed
                with self.assertRaisesRegex(RuntimeError, 'changed during'):
                    selected.runtime.verify_runtime()

    def test_foreign_role_prefix_or_manifest_cannot_select_a_runner(self):
        for change in ('profile', 'protocol_version', 'manifest_sha256', 'prefix', 'engine'):
            runner, provider, helper, read_helper, verified, execute = self.fake_runner('read-on')
            if change == 'prefix':
                provider.PREFIX = ROOT / 'prefixes/fivem-source-main'
            elif change == 'engine':
                provider.ENGINE = ROOT / 'runtime/matched-wine11-r29'
            else:
                verified[change] = 'foreign'
            with mock.patch.object(adapter, 'bound', return_value=b'fixed'), \
                    mock.patch.object(adapter, 'execute', side_effect=execute):
                with self.assertRaisesRegex(RuntimeError, 'unreviewed engine'):
                    adapter.select_runner('read-on')

    def test_read_fallback_paths_are_exact_before_original_environment_validation(self):
        runner, provider, helper, read_helper, verified, execute = self.fake_runner('read-off')
        original = runner.validate_environment
        with mock.patch.object(adapter, 'bound', return_value=b'fixed'), \
                mock.patch.object(adapter, 'execute', side_effect=execute):
            adapter.select_runner('read-off')
        env = {'WINEDEBUG': '-all', 'DYLD_FALLBACK_LIBRARY_PATH': os.pathsep.join(map(str, (
            provider.ENGINE / 'lib/wine/x86_64-unix', provider.MOLTENVK.parent,
            provider.FRAMEWORKS, provider.GST_LIB))), 'DYLD_FALLBACK_FRAMEWORK_PATH': str(provider.FRAMEWORKS)}
        runner.validate_environment(env)
        original.assert_called_once_with({'WINEDEBUG': '-all'})
        with self.assertRaisesRegex(RuntimeError, 'fallback'):
            runner.validate_environment({**env, 'DYLD_FALLBACK_LIBRARY_PATH': '/tmp/foreign'})
        self.assertEqual(original.call_count, 1)

    def test_fixed_case_preserves_true997_and_exact_39_event_contract(self):
        fixture = adapter.verify_inputs()
        cases = adapter.cases(fixture, 'read-on')
        self.assertEqual(len(cases), 1)
        case = cases[0]
        self.assertEqual((case['name'], case['binary'], case['cwd'], case['arguments']),
                         ('ipc_read_loop', ROOT / adapter.BINARY, (ROOT / adapter.BINARY).parent, ()))
        events = good_events()
        value = case['parse_output']([json.dumps(event) for event in events], 0)
        self.assertTrue(value['passed'])
        self.assertEqual((value['event_count'], value['stage_count']), (39, 38))
        self.assertTrue(value['observed_true_read_with_last_error997'])
        self.assertFalse(value['private_reader_live_callsite_or_ros_cause_established'])
        events[29]['last_error'] = 0
        self.assertFalse(case['parse_output']([json.dumps(event) for event in events], 0)['passed'])

    def test_read_on_requires_both_pending_controls_positive_returns_and_complete_pairs(self):
        good = trace(14, False, 997) + trace(15, False, 996) + trace(14, True) + trace(15, True)
        value = adapter.diagnostics(good, 'read-on', 0)
        self.assertTrue(value['passed'])
        self.assertEqual(value['completed_call_pairs'], 4)
        self.assertTrue(value['true_return_with_stale_last_error_is_not_failure'])
        for bad in ([], good[:-1], good + trace(13, True), good + [good[0] + ' PRIVATE'],
                    good + ['0024:[CFX_WINE_API] pid=32 tid=36 api=61442 status=4096 access=0'],
                    trace(14, False, 995) + trace(15, False, 996) + trace(14, True) + trace(15, True)):
            self.assertFalse(adapter.diagnostics(bad, 'read-on', 0)['passed'])
        self.assertFalse(adapter.diagnostics(good, 'read-on', 1)['passed'])
        self.assertFalse(adapter.diagnostics(good, 'read-on', False)['passed'])

    def test_off_variants_accept_only_absent_numeric_records(self):
        for variant in ('parity', 'read-off'):
            self.assertTrue(adapter.diagnostics(['unrelated Wine initialization'], variant, 0)['passed'])
            self.assertFalse(adapter.diagnostics(trace(14, True), variant, 0)['passed'])
            self.assertFalse(adapter.diagnostics(['[CFX_WINE_API] invalid'], variant, 0)['passed'])

    def test_foreign_last_raw_log_is_not_read_and_failure_report_is_preserved(self):
        label = 'wine-parity-ipc-read-loop-20261102T160000000000Z'
        fixture = {'own': True}
        retained = []
        runner = SimpleNamespace(runtime=SimpleNamespace(ROLE='wine-read-api-probes'),
                                 PREFIX=ROOT / 'prefixes/wine-read-regression',
                                 save_result=lambda path, result: retained.append(copy.deepcopy(result)))

        def run_cases(cases, **kwargs):
            self.assertEqual(kwargs['role'], 'ipc-read-loop')
            result = {'profile': runner.runtime.ROLE, 'probe_role': 'ipc-read-loop',
                      'prefix': 'prefixes/wine-read-regression', 'passed': True,
                      'only_own_fixtures_and_builtin_initialization': True,
                      'client_cef_rockstar_game_or_account_code_started': False,
                      'runs': [{'name': 'ipc_read_loop', 'binary': adapter.BINARY,
                                'log': 'logs/' + label + '-ipc_read_loop.ndjson',
                                'wine_log': 'prefixes/fivem-source-main/foreign'}]}
            runner.save_result(ROOT / 'research' / (label + '-results.json'), result)
            return 0 if result['passed'] else 1

        runner.run_cases = run_cases
        with mock.patch.object(adapter, 'verify_inputs', return_value=fixture), \
                mock.patch.object(adapter, 'select_runner', return_value=(runner, {'manifest_sha256': 'b' * 64}, None)), \
                mock.patch.object(adapter, 'sources', return_value=[]), \
                mock.patch.object(adapter, 'cases', return_value=[]), \
                mock.patch.object(adapter, 'identity') as identify:
            self.assertEqual(adapter.run('read-on'), 1)
            identify.assert_not_called()
        self.assertFalse(retained[0]['passed'])
        self.assertEqual(retained[0]['ipc_read_adapter_guard_failure'], {'failure_type': 'RuntimeError'})
        self.assertEqual(retained[0]['ipc_read_runtime_variant'], 'read-on')
        self.assertFalse(retained[0]['source_or_authenticated_prefix_accessed'])

    def test_late_fixture_guard_failure_still_writes_a_failed_result(self):
        fixture = {'own': True}
        saved = []
        runner = SimpleNamespace(runtime=SimpleNamespace(ROLE='wine-read-api-probes'),
                                 PREFIX=ROOT / 'prefixes/wine-read-regression',
                                 save_result=lambda path, result: saved.append(copy.deepcopy(result)))
        def run_cases(cases, **kwargs):
            result = {'passed': True}
            runner.save_result(ROOT / 'research/wine-parity-ipc-read-loop-20261102T160000000000Z-results.json', result)
            return 0 if result['passed'] else 1
        runner.run_cases = run_cases
        with mock.patch.object(adapter, 'verify_inputs', side_effect=[fixture, RuntimeError('changed')]), \
                mock.patch.object(adapter, 'select_runner', return_value=(runner, {'manifest_sha256': 'b' * 64}, None)), \
                mock.patch.object(adapter, 'sources', return_value=[]), \
                mock.patch.object(adapter, 'cases', return_value=[]):
            self.assertEqual(adapter.run('read-off'), 1)
        self.assertFalse(saved[0]['passed'])
        self.assertIn('ipc_read_adapter_guard_failure', saved[0])


if __name__ == '__main__':
    unittest.main()
