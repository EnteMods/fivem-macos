"""Inert own-text artifact/lifecycle controls; never start Wine or clients."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('own_text_adapter', ROOT / 'native/windows-text-observer/run.py')
adapter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(adapter)


def success():
    return [
        {'event': 'fixture_ready', 'pid': 32, 'creation': 123, 'allowed_controls': 2, 'excluded_controls': 5},
        {'event': 'ready', 'mode': 'fixture', 'pid': 44, 'duration_ms': 750, 'poll_ms': 250, 'record_limit': 128, 'text_chars': 1023, 'timeout_ms': 250},
        {'event': 'error_text', 'pid': 32, 'creation': 123, 'time_ms': 5, 'text': 'OWN_ERROR_FIXTURE\nExit status 17.'},
        {'event': 'error_text', 'pid': 32, 'creation': 123, 'time_ms': 6, 'text': 'UI test: Ä'},
        {'event': 'completed', 'polls': 3, 'processes': 1, 'text_queries': 6, 'text_records': 2, 'denied': 0,
         'enumeration_failures': 0, 'close_failures': 0, 'capped': False, 'exit': 0},
        {'event': 'fixture_completed', 'child_exit': 0, 'handles_closed': True, 'windows_destroyed': True, 'excluded_text_queries': 0, 'exit': 0},
    ]


class TextAdapterTests(unittest.TestCase):
    def test_real_23_artifacts_without_runtime_and_private_derivation(self):
        value = adapter.verify_inputs()
        self.assertEqual(value['declared_input_identity_count'], 23)
        self.assertEqual(len(value['runtime_inputs']), 2)
        self.assertEqual(len(value['source_inputs']), 21)
        self.assertFalse(value['source_mode_selected'])
        proof = value['adapter_derivation']
        self.assertEqual(proof['original']['sha256'], adapter.ORIGINAL_SHA)
        self.assertEqual(len(proof['literal_edits']), 7)
        self.assertTrue(proof['private_namespace'])
        self.assertFalse(proof['original_file_or_globals_modified'])
        raw = adapter.original_bytes()
        self.assertEqual(adapter.derive(raw), adapter.derive(raw))
        self.assertNotIn("role='code-observer'", adapter.derive(raw))

    def test_changed_original_is_never_executed_and_scope_is_exact(self):
        with self.assertRaises(RuntimeError):
            adapter.derive(b'raise AssertionError("executed")')
        raw = adapter.original_bytes()
        with mock.patch.object(adapter, 'EDITS', [('missing literal', 'replacement', 1)]):
            with self.assertRaisesRegex(RuntimeError, 'literal scope'):
                adapter.derive(raw)

    def test_report_pin_fails_before_selected_reads(self):
        base = adapter.load_adapter()
        with mock.patch.object(base, 'read', return_value=b'{}') as read, mock.patch.object(base, 'identity') as identity:
            with self.assertRaisesRegex(RuntimeError, 'report changed'):
                adapter.verify_inputs(base)
            self.assertEqual(read.call_args_list, [mock.call(adapter.REPORT)])
            identity.assert_not_called()

    def test_complete_path_admission_including_last_log_before_hashing(self):
        base = adapter.load_adapter()
        source = json.loads(base.read(adapter.REPORT))
        for role in ('source_evidence', 'maps', 'source_role_report', 'test_log'):
            value = copy.deepcopy(source)
            if role in ('source_evidence', 'maps'):
                value[role][-1]['path'] = 'prefixes/fivem-source-main/foreign'
            elif role == 'test_log':
                value['no_wine_tests']['log']['path'] = 'prefixes/fivem-source-main/foreign'
            else:
                value[role]['path'] = 'prefixes/fivem-source-main/foreign'
            raw = json.dumps(value).encode()
            with self.subTest(role=role), mock.patch.object(adapter, 'REPORT_SHA', hashlib.sha256(raw).hexdigest()), \
                    mock.patch.object(adapter, 'REPORT_BYTES', len(raw)), mock.patch.object(base, 'read', return_value=raw) as read, \
                    mock.patch.object(base, 'identity') as identity:
                with self.assertRaises(RuntimeError):
                    adapter.verify_inputs(base)
                self.assertEqual(read.call_args_list, [mock.call(adapter.REPORT)])
                identity.assert_not_called()

    def test_fixed_cases_exact_text_negative_queries_and_wrong_root(self):
        base = adapter.load_adapter()
        cases = base.make_cases(base.verify_inputs())
        self.assertEqual([row['name'] for row in cases], ['text_fixture', 'outside_root'])
        self.assertEqual(cases[0]['arguments'], ())
        self.assertEqual(cases[1]['arguments'], ('--fixture-root', adapter.OUTSIDE_ROOT, '--duration-ms', '750'))
        self.assertTrue(all('--source-root' not in row['arguments'] for row in cases))
        values = success()
        parse = lambda data: cases[0]['parse_output']([json.dumps(row) for row in data], 0)
        self.assertTrue(parse(values)['passed'])
        values[-1]['excluded_text_queries'] = 1
        self.assertFalse(parse(values)['passed'])
        values = success(); values[2]['text'] = 'DO_NOT_READ_EDIT_SECRET'
        self.assertFalse(parse(values)['passed'])
        self.assertTrue(cases[1]['parse_output'](['{"event":"rejected","reason":1,"text_queries":0}'], 2)['passed'])

    def test_parser_pin_before_execution(self):
        base = adapter.load_adapter(); value = base.verify_inputs()
        with mock.patch.object(base, 'read', return_value=b'raise AssertionError("executed")'):
            with self.assertRaisesRegex(RuntimeError, 'parser changed'):
                base.make_cases(value)

    def test_cli_offers_no_source_or_runtime_switch(self):
        from contextlib import redirect_stderr
        base = adapter.load_adapter()
        for args in (['source'], ['run', '--source-root', '/private'], ['run', '--runtime', 'read']):
            with mock.patch.object(base, 'run') as run, redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    base.main(args)
                run.assert_not_called()

    def test_late_foreign_log_preserves_failure_without_any_log_hash(self):
        module = adapter.load_adapter(); saved = []
        runner = SimpleNamespace(save_result=lambda path, result: saved.append(copy.deepcopy(result)))
        label = 'wine-parity-text-observer-20261102T200000000000Z'
        def run_cases(cases, **options):
            self.assertEqual(options['role'], 'text-observer')
            result = {'profile': 'wine-parity-api-probes', 'probe_role': 'text-observer',
                      'prefix': 'prefixes/wine-parity-regression', 'passed': True,
                      'only_own_fixtures_and_builtin_initialization': True,
                      'client_cef_rockstar_game_or_account_code_started': False,
                      'runs': [{'name': 'text_fixture', 'binary': adapter.FIXTURE,
                                'log': 'logs/' + label + '-text_fixture.ndjson',
                                'wine_log': 'logs/' + label + '-text_fixture-wine.log'},
                               {'name': 'outside_root', 'binary': adapter.OBSERVER,
                                'log': 'logs/' + label + '-outside_root.ndjson',
                                'wine_log': 'prefixes/fivem-source-main/foreign'}]}
            runner.save_result(ROOT / 'research' / (label + '-results.json'), result)
            return 0 if result['passed'] else 1
        runner.run_cases = run_cases
        base = SimpleNamespace(select_runner=mock.Mock(return_value=(runner, {}, None)))
        with mock.patch.object(module, 'verify_inputs', return_value={'own': True}), \
                mock.patch.object(module, 'load_helper', return_value=base), mock.patch.object(module, 'code_inputs', return_value=[]), \
                mock.patch.object(module, 'make_cases', return_value=[]), mock.patch.object(module, 'identity') as identity:
            self.assertEqual(module.run(), 1)
            identity.assert_not_called()
        base.select_runner.assert_called_once_with('parity')
        self.assertFalse(saved[0]['passed'])
        self.assertFalse(saved[0]['source_mode_selected'])
        self.assertIn('text_observer_guard_failure', saved[0])


if __name__ == '__main__':
    unittest.main()
