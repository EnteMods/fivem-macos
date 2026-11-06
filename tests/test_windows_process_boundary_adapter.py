"""Mocked boundary-adapter checks; no Wine, prefix, account or network access."""
from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('own_process_boundary_adapter_test',
                                              PROJECT/'native/windows-process-boundary/run.py')
adapter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(adapter)


class BoundaryAdapterTests(unittest.TestCase):
    def test_changed_report_stops_before_selected_source_or_parser_execution(self):
        with mock.patch.object(adapter.runtime,'read_regular',return_value=b'not admitted') as read:
            with mock.patch.object(adapter.runner,'identity') as selected:
                with self.assertRaisesRegex(RuntimeError,'report changed'):
                    adapter.verify_inputs()
        self.assertEqual(read.call_count,1)
        self.assertEqual(read.call_args.args[0],adapter.ROOT/adapter.REPORT)
        selected.assert_not_called()

    def test_manifest_cannot_select_foreign_source_even_with_a_self_consistent_report_digest(self):
        report = json.loads((PROJECT/adapter.REPORT).read_bytes())
        report['source_evidence'][-1]['path']='/private/foreign'
        raw = json.dumps(report).encode()
        with mock.patch.object(adapter,'REPORT_BYTES',len(raw)), mock.patch.object(
                adapter,'REPORT_SHA',hashlib.sha256(raw).hexdigest()):
            with mock.patch.object(adapter.runtime,'read_regular',return_value=raw):
                with mock.patch.object(adapter.runner,'identity') as selected:
                    with self.assertRaisesRegex(RuntimeError,'path set'):
                        adapter.verify_inputs()
        selected.assert_not_called()

    def test_parser_rejects_changed_bytes_before_execution(self):
        with mock.patch.object(adapter.runtime,'read_regular',return_value=b'raise AssertionError("executed")'):
            with self.assertRaisesRegex(RuntimeError,'parser code'):
                adapter.load_contract()

    def test_case_is_only_parent_pe_without_cli_parameters_and_preserves_parser_failure(self):
        parser = mock.Mock(return_value={'passed':False})
        with mock.patch.object(adapter,'load_contract',return_value=parser):
            case, = adapter.cases()
        self.assertEqual(case['binary'],adapter.ROOT/adapter.BUILD_ROOT/'process_boundary_probe.exe')
        self.assertEqual(case['arguments'],())
        self.assertEqual(case['cwd'],case['binary'].parent)
        self.assertFalse(case['parse_output'](['only own metadata'],1)['passed'])
        parser.assert_called_once_with('only own metadata',1)

    def test_run_delegates_only_to_existing_guarded_account_free_lifecycle(self):
        cases = [{'own':'case'}]
        with mock.patch.object(adapter,'cases',return_value=cases):
            with mock.patch.object(adapter.runner,'run_cases',return_value=1) as run:
                self.assertEqual(adapter.main(['run']),1)
        run.assert_called_once_with(cases,verify_inputs=adapter.verify_inputs,role='process-boundary')

    def test_inspection_never_calls_lifecycle_or_changes_runtime(self):
        with mock.patch.object(adapter.runtime,'verify_runtime',return_value={'manifest_sha256':'fixed','entries':1761}):
            with mock.patch.object(adapter,'verify_inputs',return_value={'own':'fixture'}):
                with mock.patch.object(adapter.runner,'run_cases') as run:
                    with redirect_stdout(io.StringIO()) as output:
                        self.assertEqual(adapter.main(['inspect']),0)
        run.assert_not_called()
        self.assertFalse(json.loads(output.getvalue())['runtime_or_prefix_started'])


if __name__=='__main__':
    unittest.main()
