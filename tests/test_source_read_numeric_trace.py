"""Inert adaptation checks; no real Source logs, engine, prefix or client access."""
from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('own_read_numeric_extractor_adapter',
    PROJECT / 'native/diagnostics/source_read_numeric_trace.py')
adapter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(adapter)


def marker(api, status=0, pid=48, tid=52):
    return f'{pid:04x}:{tid:04x}:[CFX_WINE_API] pid={pid} tid={tid} api={api} status={status} access=0\n'


def event(kind='observed', name='FiveM_ROSLauncher', time=10, code=None):
    return {'event': kind, 'time_ms': time, 'pid': 48, 'parent_pid': 44, 'basename': name, 'exit_hex': code}


class ReadNumericExtractorTests(unittest.TestCase):
    def setUp(self):
        self.original = adapter.frozen_reader()
        self.reader = adapter.load_reader()

    def test_four_literal_derivations_recover_exact_frozen_source(self):
        rendered = adapter.derive(self.original).decode()
        self.assertEqual(len(adapter.EDITS), 4)
        for before, after in reversed(adapter.EDITS):
            self.assertEqual(rendered.count(after), 1)
            rendered = rendered.replace(after, before, 1)
        self.assertEqual(rendered.encode(), self.original)
        self.assertEqual(hashlib.sha256(self.original).hexdigest(), adapter.BASE_SHA)
        with self.assertRaises(RuntimeError): adapter.derive(self.original + b'\n')

    def test_private_namespace_and_all_scope_role_and_streaming_functions_are_unchanged(self):
        old = types.ModuleType('own_old_extractor_review_reference')
        old.__file__ = str(adapter.BASE)
        exec(compile(self.original, str(adapter.BASE), 'exec'), old.__dict__)
        self.assertIsNot(old.__dict__, self.reader.__dict__)
        self.assertEqual(old.PARSER_PATH, 'native/wine-numeric-diagnostics/numeric_contract.py')
        self.assertEqual(self.reader.PARSER_PATH, 'native/wine-read-diagnostics/numeric_contract.py')
        for name in ('read_plain', 'parser_module', 'fixed_role', 'observer_roles', 'extract'):
            original, derived = getattr(old, name).__code__, getattr(self.reader, name).__code__
            self.assertEqual(original.co_code, derived.co_code)
            self.assertEqual(original.co_consts, derived.co_consts)
        for name in ('LABEL', 'OBSERVER_SHA', 'FIELDS', 'ROLES'):
            self.assertEqual(getattr(old, name), getattr(self.reader, name))

    def test_new_fixed_parser_supports_read_and_completion_without_hashing_raw_inputs(self):
        parser = self.reader.parser_module()
        self.assertEqual(parser.OPERATIONS[14], ('ReadFile', 2))
        self.assertEqual(parser.OPERATIONS[15], ('GetOverlappedResult', 2))
        observer = {'events': [event()], 'ready_before_main': True, 'reader_completed_without_error': True}
        with mock.patch.object(self.reader.hashlib, 'sha256') as hasher:
            result = self.reader.extract(iter(['PRIVATE_SECRET\n', marker(56), marker(58, 997),
                                               marker(60), marker(62, 996)]), observer, parser)
        hasher.assert_not_called()
        self.assertEqual(result['numeric_contract']['completed_call_pairs'], 2)
        self.assertEqual([row['line'] for row in result['numeric_contract']['records']], [2, 3, 4, 5])
        self.assertTrue(all(row['role'] == 'source-ros-launcher' for row in result['numeric_contract']['records']))
        self.assertNotIn('PRIVATE', json.dumps(result))
        self.assertFalse(result['raw_log_or_result_contents_hashed_or_copied'])
        self.assertFalse(result['api_failure_establishes_ros_exit_cause'])

    def test_reused_or_rejected_windows_pid_is_ambiguous_and_native_pid_is_ignored(self):
        parser = self.reader.parser_module()
        for events in ([event(), event(time=99)], [event(), event(name='PRIVATE_UNKNOWN')]):
            own = {'events': events, 'identity': {'native_observer_pid': 48}}
            result = self.reader.extract([marker(56), marker(57)], own, parser)
            self.assertTrue(all(row['role'] == 'ambiguous' for row in result['numeric_contract']['records']))
            self.assertNotIn('PRIVATE', json.dumps(result))
        own = {'events': [], 'identity': {'native_observer_pid': 48}}
        result = self.reader.extract([marker(60), marker(61)], own, parser)
        self.assertTrue(all(row['role'] == 'unobserved' for row in result['numeric_contract']['records']))

    def test_temp_controller_uses_only_read_profile_label_inputs_and_new_no_clobber_output(self):
        parser = self.reader.parser_module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); (root / 'research').mkdir(); (root / 'logs').mkdir()
            label = 'client-source-ui-resume-20261102T150000000000Z'
            observer = {'events': [event()], 'ready_before_main': True, 'reader_completed_without_error': True,
                'identity': {'path': 'build/windows-process-observer/process_observer.exe',
                             'sha256': self.reader.OBSERVER_SHA, 'native_observer_pid': 9999},
                'metadata_file': 'logs/' + label + '-observer.ndjson',
                'commandlines_profile_or_ticket_data_collected': False}
            result = {'runtime_engine_profile': 'read', 'developer_code_version': 8,
                'wine_debug_channels': '-all,+cfxnum', 'log': 'logs/' + label + '.log',
                'stage': 'build/windows-source-integration', 'prefix': 'prefixes/fivem-source-main',
                'log_contents_hashed_or_copied': False, 'read_only_code_process_observer': observer,
                'wine_pid': 9999, 'unused_private': 'PRIVATE_SECRET'}
            result_path = root / 'research' / (label + '-results.json')
            log_path = root / 'logs' / (label + '.log')
            result_path.write_text(json.dumps(result)); log_path.write_text('PRIVATE_SECRET\n' + marker(56) + marker(58, 997))
            output = root / 'research' / (label + '-read-numeric-trace.json')
            opened = []
            original_read = self.reader.read_plain

            def read(path, **kwargs):
                opened.append(path)
                self.assertIn(path, (result_path, log_path))
                return original_read(path, **kwargs)

            with mock.patch.object(self.reader, 'ROOT', root), mock.patch.object(self.reader, 'parser_module', return_value=parser), \
                    mock.patch.object(self.reader, 'read_plain', side_effect=read), redirect_stdout(io.StringIO()):
                self.assertEqual(self.reader.main([label]), 0)
                report = json.loads(output.read_bytes())
                self.assertEqual(report['fixed_parser_sha256'], self.reader.PARSER_SHA)
                self.assertEqual(report['numeric_contract']['completed_call_pairs'], 1)
                self.assertNotIn('PRIVATE', json.dumps(report)); self.assertNotIn('9999', json.dumps(report))
                self.assertEqual(opened, [result_path, log_path])
                self.assertFalse((root / 'research' / (label + '-numeric-trace.json')).exists())
                with self.assertRaises(FileExistsError): self.reader.main([label])
                before = len(opened)
                result['runtime_engine_profile'] = 'numeric'; result_path.write_text(json.dumps(result))
                with self.assertRaises(RuntimeError): self.reader.main([label])
                self.assertEqual(opened[before:], [result_path])

    def test_arbitrary_label_is_rejected_before_reads(self):
        with mock.patch.object(self.reader, 'read_plain') as read, \
                mock.patch('sys.stderr', new=io.StringIO()), self.assertRaises(SystemExit):
            self.reader.main(['prefixes/fivem-source-main/user.reg'])
        read.assert_not_called()


if __name__ == '__main__':
    unittest.main()
