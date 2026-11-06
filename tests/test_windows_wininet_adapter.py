"""Own WinINet adapter admission/lifecycle boundaries, without Wine or network."""
from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('own_wininet_adapter_test', PROJECT / 'native/windows-wininet-probe/run.py')
adapter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(adapter)


class WinInetAdapterTests(unittest.TestCase):
    def test_changed_report_refused_before_any_report_selected_source_read(self):
        with mock.patch.object(adapter.runtime, 'read_regular', return_value=b'not admitted') as read, \
                mock.patch.object(adapter.runner, 'identity') as identity:
            with self.assertRaisesRegex(RuntimeError, 'build report changed'):
                adapter.verify_inputs()
        self.assertEqual(read.call_count, 1)
        self.assertEqual(read.call_args.args[0], adapter.ROOT / adapter.REPORT)
        identity.assert_not_called()

    def test_dynamic_private_path_or_target_rejected_before_selected_read(self):
        original = json.loads((PROJECT / adapter.REPORT).read_bytes())
        for field in ('source', 'target_source', 'object', 'rea_report', 'url'):
            report = json.loads(json.dumps(original))
            if field == 'source':
                report['source_evidence'][0]['path'] = 'prefixes/private/user.reg'
            elif field == 'target_source':
                report['target']['original_url_sources'][0]['path'] = '/private/foreign'
            elif field == 'object':
                report['object']['path'] = '../foreign'
            elif field == 'rea_report':
                report['api_relevance']['report']['path'] = 'prefixes/private/user.reg'
            else:
                report['target']['url'] = 'https://private.example.invalid/'
            raw = json.dumps(report).encode()
            with self.subTest(field=field), mock.patch.object(adapter, 'REPORT_BYTES', len(raw)), \
                    mock.patch.object(adapter, 'REPORT_SHA', hashlib.sha256(raw).hexdigest()), \
                    mock.patch.object(adapter.runtime, 'read_regular', return_value=raw), \
                    mock.patch.object(adapter.runner, 'identity') as identity:
                with self.assertRaises(RuntimeError):
                    adapter.verify_inputs()
                identity.assert_not_called()

    def test_changed_parser_refused_without_executing_arbitrary_source(self):
        with mock.patch.object(adapter.runtime, 'read_regular', return_value=b'raise AssertionError("executed")'):
            with self.assertRaisesRegex(RuntimeError, 'parser code'):
                adapter.load_contract()

    def test_cases_have_only_bound_own_pe_no_args_and_preserve_failure(self):
        parse = mock.Mock(return_value={'passed': False, 'api_contract_succeeded': True})
        with mock.patch.object(adapter, 'load_contract', return_value=parse):
            case, = adapter.cases()
        self.assertEqual(case['binary'], adapter.ROOT / adapter.BUILD_ROOT / 'wininet_probe.exe')
        self.assertEqual(case['cwd'], case['binary'].parent)
        self.assertEqual(case['arguments'], ())
        self.assertFalse(case['parse_output'](['own numeric line'], 1)['passed'])
        parse.assert_called_once_with('own numeric line', 1)

    def test_run_reuses_only_existing_guarded_account_free_lifecycle(self):
        own_cases = [{'own': 'case'}]
        with mock.patch.object(adapter, 'cases', return_value=own_cases), \
                mock.patch.object(adapter.runner, 'run_cases', return_value=1) as run:
            self.assertEqual(adapter.main(['run']), 1)
        run.assert_called_once_with(own_cases, verify_inputs=adapter.verify_inputs, role='wininet')

    def test_inspect_cannot_start_lifecycle_or_prefix(self):
        engine = {'manifest_sha256': adapter.ENGINE_MANIFEST_SHA, 'entries': 1761}
        with mock.patch.object(adapter.runtime, 'verify_runtime', return_value=engine), \
                mock.patch.object(adapter, 'verify_inputs', return_value={'own': 'fixture'}), \
                mock.patch.object(adapter.runner, 'run_cases') as run, redirect_stdout(io.StringIO()) as output:
            self.assertEqual(adapter.main(['inspect']), 0)
        run.assert_not_called()
        self.assertFalse(json.loads(output.getvalue())['runtime_or_prefix_started'])
        self.assertFalse(json.loads(output.getvalue())['network_request_performed'])

    def test_e4fc_engine_is_required_and_own_option_failures_are_labeled_separately(self):
        with mock.patch.object(adapter.runtime, 'verify_runtime', return_value={'manifest_sha256': 'foreign', 'entries': 0}), \
                mock.patch.object(adapter, 'verify_inputs') as verify:
            with self.assertRaisesRegex(RuntimeError, 'engine manifest'):
                adapter.main(['inspect'])
        verify.assert_not_called()
        self.assertEqual(adapter.STAGES['6'], 'own CONNECT_RETRIES helper')
        self.assertTrue(adapter.STAGES['1'].endswith('observation only'))
        self.assertEqual(adapter.REA_APIS, ['InternetOpenW', 'HttpQueryInfoW', 'InternetGetConnectedState'])


if __name__ == '__main__':
    unittest.main()
