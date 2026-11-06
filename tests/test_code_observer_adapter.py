"""Inert artifact/scope/known-code controls; no Wine, clients or real prefixes."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('own_code_observer_adapter', ROOT / 'native/windows-code-observer/run.py')
adapter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(adapter)


def success(fixture):
    expected = fixture['fixture_code_window']
    base, pid, creation, size = 0x140000000, 100, 1234, 0x200000
    return [
        {'event': 'fixture_ready', 'pid': pid, 'creation': creation, 'image_base': base, 'image_size': size,
         'code_address': base + expected['rva'], 'code_rva': expected['rva'],
         'data_rva': fixture['fixture_negative_data']['rva']},
        {'event': 'ready', 'mode': 'fixture', 'pid': 104, 'duration_ms': 750, 'rva': expected['rva'],
         'length': 64, 'poll_ms': 250, 'record_limit': 20},
        {'event': 'module', 'time_ms': 1, 'pid': pid, 'creation': creation, 'base': base, 'size': size},
        {'event': 'denied', 'time_ms': 1, 'pid': pid, 'creation': creation, 'probe': 1, 'reason': 5,
         'state': 0x1000, 'protect': 4, 'type': 0x1000000, 'allocation_base': base,
         'read_attempted': False, 'error': 0},
        {'event': 'code', 'time_ms': 1, 'pid': pid, 'creation': creation, 'sample': 1,
         'rva': expected['rva'], 'length': 64, 'hex': expected['hex']},
        {'event': 'process_completed', 'time_ms': 750, 'pid': pid, 'creation': creation, 'polls': 3,
         'read_calls': 3, 'code_records': 1, 'record_limit_reached': False},
        {'event': 'completed', 'mode': 'fixture', 'polls': 3, 'processes': 1, 'failures': 0, 'exit': 0},
        {'event': 'fixture_completed', 'wait': 0, 'child_exit': 0, 'handles_closed': True, 'exit': 0},
    ]


class CodeObserverAdapterTests(unittest.TestCase):
    def test_real_22_artifact_bindings_verify_without_any_runtime(self):
        fixture = adapter.verify_inputs()
        self.assertEqual(fixture['declared_input_identity_count'], 22)
        self.assertEqual(len(fixture['runtime_inputs']), 2)
        self.assertEqual(len(fixture['source_inputs']), 20)
        self.assertFalse(fixture['source_mode_selected'])
        self.assertEqual(fixture['fixture_code_window']['length'], 64)

    def test_changed_report_fails_before_any_selected_artifact_read(self):
        with mock.patch.object(adapter, 'read', return_value=b'{}') as read, \
                mock.patch.object(adapter, 'identity') as identity:
            with self.assertRaisesRegex(RuntimeError, 'frozen'):
                adapter.verify_inputs()
            self.assertEqual(read.call_args_list, [mock.call(adapter.REPORT)])
            identity.assert_not_called()

    def test_all_path_groups_and_late_build_roles_precede_selected_reads(self):
        original = json.loads(adapter.read(adapter.REPORT))
        for field in ('source_evidence', 'maps', 'generated_role_header', 'test_log'):
            report = copy.deepcopy(original)
            if field in ('source_evidence', 'maps'):
                report[field][-1]['path'] = 'prefixes/fivem-source-main/foreign'
            elif field == 'test_log':
                report['no_wine_tests']['log']['path'] = 'prefixes/fivem-source-main/foreign'
            else:
                report[field]['path'] = 'prefixes/fivem-source-main/foreign'
            raw = json.dumps(report).encode()
            with self.subTest(field=field), \
                    mock.patch.object(adapter, 'REPORT_SHA', hashlib.sha256(raw).hexdigest()), \
                    mock.patch.object(adapter, 'REPORT_BYTES', len(raw)), \
                    mock.patch.object(adapter, 'read', return_value=raw) as read, \
                    mock.patch.object(adapter, 'identity') as identity:
                with self.assertRaises(RuntimeError):
                    adapter.verify_inputs()
                self.assertEqual(read.call_args_list, [mock.call(adapter.REPORT)])
                identity.assert_not_called()

    def test_relative_escape_symlink_and_hardlink_roles_fail_closed(self):
        with mock.patch.object(adapter.os, 'open') as opened:
            for name in ('/tmp/foreign', '../foreign', 'native//foreign', 'native/../foreign'):
                with self.assertRaises(RuntimeError): adapter.read(name)
            opened.assert_not_called()
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(adapter, 'ROOT', Path(directory).resolve()):
            root = Path(directory).resolve()
            (root / 'own').write_bytes(b'own')
            (root / 'alias').symlink_to(root / 'own')
            with self.assertRaises(RuntimeError): adapter.read('alias')
            os.link(root / 'own', root / 'hardlink')
            with self.assertRaises(RuntimeError): adapter.read('hardlink')

    def test_changed_helper_is_never_executed(self):
        with mock.patch.object(adapter, 'read', return_value=b'raise AssertionError("executed")'):
            with self.assertRaisesRegex(RuntimeError, 'unchanged parity'):
                adapter.load_helper()

    def test_fixed_cases_require_actual_known_64_bytes_and_nx_no_read(self):
        fixture = adapter.verify_inputs()
        cases = adapter.make_cases(fixture)
        self.assertEqual([row['name'] for row in cases], ['code_fixture', 'outside_root'])
        self.assertEqual(cases[0]['arguments'], ())
        self.assertEqual(cases[1]['arguments'], ('--fixture-root', adapter.OUTSIDE_ROOT, '--duration-ms', '750'))
        self.assertTrue(all('--source-root' not in row['arguments'] for row in cases))
        rows = success(fixture)
        parse = lambda data: cases[0]['parse_output']([json.dumps(row) for row in data], 0)
        self.assertTrue(parse(rows)['passed'])
        changed = copy.deepcopy(rows); changed[4]['hex'] = '90' * 64
        self.assertFalse(parse(changed)['passed'])
        changed = copy.deepcopy(rows); changed[3]['read_attempted'] = True
        self.assertFalse(parse(changed)['passed'])
        rejected = ['{"event":"rejected","reason":1,"process_reads":0}']
        self.assertTrue(cases[1]['parse_output'](rejected, 2)['passed'])
        self.assertFalse(cases[1]['parse_output'](rejected, 0)['passed'])

    def test_changed_parser_is_rejected_before_execute(self):
        fixture = adapter.verify_inputs()
        with mock.patch.object(adapter, 'read', return_value=b'raise AssertionError("executed")'):
            with self.assertRaisesRegex(RuntimeError, 'parser changed'):
                adapter.make_cases(fixture)

    def test_cli_offers_no_source_mode_or_arbitrary_argument_option(self):
        from contextlib import redirect_stderr
        for args in (['source'], ['run', '--source-root', '/private'], ['run', '--runtime', 'read']):
            with mock.patch.object(adapter, 'run') as run, redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit): adapter.main(args)
                run.assert_not_called()

    def test_late_foreign_log_fails_before_hashing_any_own_log_and_preserves_result(self):
        fixture, saved = {'own': True}, []
        runner = SimpleNamespace(save_result=lambda path, result: saved.append(copy.deepcopy(result)))
        label = 'wine-parity-code-observer-20261102T200000000000Z'
        def run_cases(cases, **options):
            self.assertEqual(options['role'], 'code-observer')
            result = {'profile': 'wine-parity-api-probes', 'probe_role': 'code-observer',
                      'prefix': 'prefixes/wine-parity-regression', 'passed': True,
                      'only_own_fixtures_and_builtin_initialization': True,
                      'client_cef_rockstar_game_or_account_code_started': False,
                      'runs': [{'name': 'code_fixture', 'binary': adapter.FIXTURE,
                                'log': 'logs/' + label + '-code_fixture.ndjson',
                                'wine_log': 'logs/' + label + '-code_fixture-wine.log'},
                               {'name': 'outside_root', 'binary': adapter.OBSERVER,
                                'log': 'logs/' + label + '-outside_root.ndjson',
                                'wine_log': 'prefixes/fivem-source-main/foreign'}]}
            runner.save_result(ROOT / 'research' / (label + '-results.json'), result)
            return 0 if result['passed'] else 1
        runner.run_cases = run_cases
        base = SimpleNamespace(select_runner=mock.Mock(return_value=(runner, {}, None)))
        with mock.patch.object(adapter, 'verify_inputs', return_value=fixture), \
                mock.patch.object(adapter, 'load_helper', return_value=base), \
                mock.patch.object(adapter, 'code_inputs', return_value=[]), \
                mock.patch.object(adapter, 'make_cases', return_value=[]), \
                mock.patch.object(adapter, 'identity') as identify:
            self.assertEqual(adapter.run(), 1)
            identify.assert_not_called()
        base.select_runner.assert_called_once_with('parity')
        self.assertFalse(saved[0]['passed'])
        self.assertFalse(saved[0]['source_mode_selected'])
        self.assertIn('code_observer_guard_failure', saved[0])


if __name__ == '__main__':
    unittest.main()
