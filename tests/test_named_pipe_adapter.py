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
spec = importlib.util.spec_from_file_location('own_pipe_adapter', ROOT / 'native/windows-named-pipe-probe/run.py')
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)


def item(path):
    return {'path': path, 'bytes': 1, 'sha256': 'a' * 64}


class NamedPipeAdapterTests(unittest.TestCase):
    def test_relative_roles_reject_foreign_paths_before_open(self):
        with mock.patch.object(adapter.os, 'open') as opened:
            for path in ('/tmp/foreign', '../foreign', 'native/../foreign', 'native//foreign'):
                with self.assertRaises(RuntimeError):
                    adapter.read_own(path)
            opened.assert_not_called()

    def test_symlink_and_hardlink_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(adapter, 'ROOT', Path(directory).resolve()):
            root = Path(directory).resolve()
            (root / 'own').write_bytes(b'own')
            (root / 'alias').symlink_to(root / 'own')
            with self.assertRaises(RuntimeError):
                adapter.read_own('alias')
            os.link(root / 'own', root / 'linked')
            with self.assertRaises(RuntimeError):
                adapter.read_own('linked')

    def test_regular_own_code_identity_uses_exact_bytes(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(adapter, 'ROOT', Path(directory).resolve()):
            raw = b'own\r\n'
            (Path(directory) / 'own').write_bytes(raw)
            self.assertEqual(adapter.identity('own'),
                             {'path': 'own', 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})

    def test_root_pin_admits_only_literal_build_pe_and_parser_roles(self):
        base = {'schema_version': 1, 'profile': 'own-named-pipe-build',
                'client_or_authenticated_inputs_used': False, 'contract': {},
                'build_report': item(adapter.REPORT), 'runtime_input': item(adapter.BINARY),
                'parser_source': item(adapter.PARSER)}
        for field in ('build_report', 'runtime_input', 'parser_source'):
            value = copy.deepcopy(base)
            value[field]['path'] = 'prefixes/fivem-source-main/foreign'
            with mock.patch.object(adapter, 'read_own', return_value=json.dumps(value).encode()) as read:
                with self.assertRaises(RuntimeError):
                    adapter.read_pin()
                self.assertEqual(read.call_args_list, [mock.call(adapter.PIN)])

    def fake_report(self):
        report = {'schema_version': 1, 'compiled': True, 'architecture': 'AMD64', 'runtime': '/MT',
                  'imports': ['KERNEL32.dll'], 'contract': {'own': True},
                  'runtime_inputs': [item(adapter.BINARY)],
                  'source_evidence': [item(name) for name in sorted(adapter.SOURCES)],
                  'public_source_references': [item(name) for name in sorted(adapter.REFERENCES)],
                  'wine_source_references': [item(name) for name in sorted(adapter.WINE_REFERENCES)],
                  'toolchain': item('native/windows-core/toolchain.cmake'),
                  'object': item(adapter.BUILD + 'CMakeFiles/named_pipe_probe.dir/probe.cpp.obj'),
                  'pe_inspection': item(adapter.BUILD + 'pe-inspection.txt'),
                  'build': {'exit': 0, 'log': item(adapter.BUILD + 'build.log'),
                            'compile_commands': item(adapter.BUILD + 'compile_commands.json')},
                  'no_wine_contract_tests': {'exit': 0, 'passed': 8,
                                            'log': item(adapter.BUILD + 'contract-tests.log')},
                  'runtime_tested': False, 'wine_or_prefix_started': False,
                  'actual_client_game_or_account_code_used': False}
        return report

    def test_all_report_path_roles_are_admitted_before_selected_reads(self):
        report = self.fake_report()
        report['public_source_references'][-1]['path'] = 'prefixes/fivem-source-main/foreign'
        raw = json.dumps(report).encode()
        pin = {'build_report': adapter.identity_from(raw, adapter.REPORT),
               'runtime_input': item(adapter.BINARY), 'parser_source': item(adapter.PARSER),
               'contract': report['contract']}
        with mock.patch.object(adapter, 'read_pin', return_value=pin), \
                mock.patch.object(adapter, 'read_own', return_value=raw) as read, \
                mock.patch.object(adapter, 'identity') as identify:
            with self.assertRaises(RuntimeError):
                adapter.verify_inputs()
            self.assertEqual(read.call_args_list, [mock.call(adapter.REPORT)])
            identify.assert_not_called()

    def test_changed_root_pinned_build_report_is_rejected(self):
        with mock.patch.object(adapter, 'read_pin', return_value={'build_report': item(adapter.REPORT)}), \
                mock.patch.object(adapter, 'read_own', return_value=b'{}'), \
                mock.patch.object(adapter, 'identity') as identify:
            with self.assertRaisesRegex(RuntimeError, 'Root pin'):
                adapter.verify_inputs()
            identify.assert_not_called()

    def test_unretained_runtime_fails_before_loading_any_helper(self):
        with mock.patch.object(adapter, 'load_helpers') as helper:
            with self.assertRaises(RuntimeError):
                adapter.select_runner('matched')
            helper.assert_not_called()

    def test_changed_helper_bytes_are_never_executed(self):
        with mock.patch.object(adapter, 'read_own', return_value=b'raise AssertionError("executed")'), \
                mock.patch.object(adapter, 'identity') as identify:
            with self.assertRaisesRegex(RuntimeError, 'unchanged reviewed numeric helper'):
                adapter.load_helpers()
            identify.assert_not_called()

    def test_changed_pipe_parser_is_never_executed(self):
        with mock.patch.object(adapter, 'read_own', return_value=b'raise AssertionError("executed")'):
            with self.assertRaisesRegex(RuntimeError, 'reviewed own pipe parser'):
                adapter.make_cases({'parser_source': item(adapter.PARSER)})

    def test_foreign_last_raw_log_is_not_read_or_hashed(self):
        label = 'wine-parity-named-pipe-20261102T160000000000Z'
        fixture = {'root_fixture_pin': item(adapter.PIN)}
        retained = []
        runner = SimpleNamespace(runtime=SimpleNamespace(ROLE='wine-numeric-api-probes'),
                                 PREFIX=adapter.ROOT / 'prefixes/wine-numeric-regression',
                                 save_result=lambda path, result: retained.append(result))

        def run_cases(cases, **kwargs):
            report = {'profile': runner.runtime.ROLE, 'probe_role': 'named-pipe',
                      'prefix': 'prefixes/wine-numeric-regression', 'passed': True,
                      'client_cef_rockstar_game_or_account_code_started': False,
                      'only_own_fixtures_and_builtin_initialization': True,
                      'runs': [{'name': 'named_pipe', 'binary': adapter.BINARY,
                                'log': 'logs/' + label + '-named_pipe.ndjson',
                                'wine_log': 'prefixes/fivem-source-main/foreign'}]}
            runner.save_result(adapter.ROOT / 'research' / (label + '-results.json'), report)
            return 1

        runner.run_cases = run_cases
        with mock.patch.object(adapter, 'verify_inputs', return_value=fixture), \
                mock.patch.object(adapter, 'select_runner', return_value=(runner, {})), \
                mock.patch.object(adapter, 'make_cases', return_value=[]), \
                mock.patch.object(adapter, 'identity') as identify:
            self.assertEqual(adapter.run('numeric'), 1)
            identify.assert_not_called()
        self.assertFalse(retained[0]['passed'])
        self.assertIn('named_pipe_guard_failure', retained[0])
        self.assertFalse(retained[0]['source_or_authenticated_prefix_accessed'])


if __name__ == '__main__':
    unittest.main()
