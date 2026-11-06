"""Inert source-controller extraction contracts; no client, Wine or account reads."""
from contextlib import redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('own_source_numeric_extractor',
    PROJECT / 'native/diagnostics/source_numeric_trace.py')
trace = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(trace)
PARSER = trace.parser_module()


def marker(api, status=0, pid=48, tid=52):
    return f'{pid:04x}:{tid:04x}:[CFX_WINE_API] pid={pid} tid={tid} api={api} status={status} access=0\n'


def event(kind='observed', pid=48, parent=44, name='FiveM_ROSLauncher', time=10, code=None):
    return {'event': kind, 'time_ms': time, 'pid': pid, 'parent_pid': parent,
            'basename': name, 'exit_hex': code}


def observer(events):
    return {'events': events, 'ready_before_main': True, 'reader_completed_without_error': True}


class SourceNumericExtractionTests(unittest.TestCase):
    def test_only_fixed_markers_survive_and_original_numeric_line_positions_remain(self):
        lines = ['PRIVATE token=SECRET\n', marker(40), 'PRIVATE path=/account/profile\n', marker(42, 2)]
        own = observer([event(), event('exited', time=27, code='0x00000001')])
        with mock.patch.object(trace.hashlib, 'sha256') as hasher:
            report = trace.extract(iter(lines), own, PARSER)
        hasher.assert_not_called()
        self.assertNotIn('PRIVATE', json.dumps(report))
        self.assertNotIn('SECRET', json.dumps(report))
        rows = report['numeric_contract']['records']
        self.assertEqual([row['line'] for row in rows], [2, 4])
        self.assertTrue(all(row['role'] == 'source-ros-launcher' for row in rows))
        self.assertTrue(all(row['exit_code'] == 1 for row in rows))
        self.assertEqual(report['numeric_contract']['completed_call_pairs'], 1)
        self.assertFalse(report['api_failure_establishes_ros_exit_cause'])

    def test_native_pid_and_thread_or_parent_match_never_assign_a_windows_pid_role(self):
        own = observer([event(pid=99, parent=48)])
        own['identity'] = {'native_observer_pid': 48}
        rows = trace.extract([marker(40), marker(41)], own, PARSER)['numeric_contract']['records']
        self.assertTrue(all(row['role'] == 'unobserved' for row in rows))
        self.assertTrue(all(row['role_association'] == 'no_observed_pid_match' for row in rows))

    def test_reused_or_conflicting_pids_remain_ambiguous_even_when_basename_matches(self):
        for events in ([event(), event(time=99)],
                       [event(), event('exited', name='FiveM.exe', code='0x00000001')],
                       [event(), event('still_running', parent=999)]):
            rows = trace.extract([marker(40), marker(41)], observer(events), PARSER)['numeric_contract']['records']
            self.assertTrue(all(row['role'] == 'ambiguous' for row in rows))
            self.assertTrue(all('parent_pid' not in row for row in rows))

    def test_rejected_or_unknown_second_observation_blocks_a_previously_known_pid_role(self):
        for unknown in (event(name='PRIVATE_UNKNOWN_IMAGE'), {**event(), 'unexpected': 'PRIVATE_SECRET'}):
            report = trace.extract([marker(40), marker(41)], observer([event(), unknown]), PARSER)
            self.assertEqual(report['observer_rejected_event_count'], 1)
            rows = report['numeric_contract']['records']
            self.assertTrue(all(row['role'] == 'ambiguous' for row in rows))
            self.assertTrue(all(row['role_association'] == 'rejected_observer_event_for_pid' for row in rows))
            self.assertNotIn('PRIVATE', json.dumps(report))

    def test_malformed_marker_and_unknown_observer_payloads_are_not_retained(self):
        own = observer([event(name='PRIVATE_ACCOUNT_NAME'), {**event(), 'secret': 'SECRET'}])
        report = trace.extract([marker(40).rstrip() + ' cookie=SECRET\n', marker(40), marker(41)], own, PARSER)
        self.assertEqual(report['numeric_contract']['rejected_marker_lines'], 1)
        self.assertEqual(report['observer_rejected_event_count'], 2)
        self.assertNotIn('SECRET', json.dumps(report))
        self.assertNotIn('PRIVATE_ACCOUNT_NAME', json.dumps(report))

    def test_truncated_and_absent_markers_do_not_imply_api_success_or_ros_cause(self):
        report = trace.extract(['arbitrary ignored\n', marker(40)], observer([]), PARSER)
        self.assertEqual(report['numeric_contract']['pending_observed_calls'][0]['begin_line'], 2)
        self.assertFalse(report['numeric_contract']['all_observed_begins_paired'])
        empty = trace.extract(['PRIVATE\n'], observer([]), PARSER)
        self.assertFalse(empty['numeric_contract']['observed_any_records'])
        self.assertFalse(empty['api_failure_establishes_ros_exit_cause'])

    def test_only_the_fixed_code_basename_vocabulary_is_accepted(self):
        for name, role in (('FiveM_b3258_GameProcess.exe', 'source-game'),
                           ('Launcher.exe', 'rockstar-launcher'), ('SocialClubHelper.exe', 'socialclub-helper')):
            self.assertEqual(trace.fixed_role(name), role)
        for name in ('/private/FiveM.exe', 'FiveM.exe token=SECRET', 'FiveM_babc_GameProcess.exe', None):
            self.assertIsNone(trace.fixed_role(name))

    def test_cli_rejects_arbitrary_input_paths_without_reading(self):
        with mock.patch.object(trace, 'read_plain') as read, redirect_stdout(io.StringIO()), \
                mock.patch('sys.stderr', new=io.StringIO()), self.assertRaises(SystemExit):
            trace.main(['prefixes/fivem-source-main/user.reg'])
        read.assert_not_called()


class SourceNumericRoleBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.boundary = mock.patch.object(trace, 'ROOT', self.root)
        self.boundary.start()
        (self.root / 'research').mkdir()
        (self.root / 'logs').mkdir()
        self.label = 'client-source-ui-resume-20261102T150000000000Z'

    def tearDown(self):
        self.boundary.stop()
        self.temporary.cleanup()

    def source_result(self):
        own = observer([event(), event('exited', code='0x00000001')])
        own.update(identity={'path': 'build/windows-process-observer/process_observer.exe',
                             'sha256': trace.OBSERVER_SHA, 'native_observer_pid': 9999},
                   metadata_file='logs/' + self.label + '-observer.ndjson',
                   commandlines_profile_or_ticket_data_collected=False)
        return {'runtime_engine_profile': 'numeric', 'developer_code_version': 8,
                'wine_debug_channels': '-all,+cfxnum', 'log': 'logs/' + self.label + '.log',
                'stage': 'build/windows-source-integration', 'prefix': 'prefixes/fivem-source-main',
                'log_contents_hashed_or_copied': False, 'wine_pid': 9999,
                'private_unused_field': 'PRIVATE_SECRET', 'read_only_code_process_observer': own}

    def save_result(self, value):
        path = self.root / 'research' / (self.label + '-results.json')
        path.write_text(json.dumps(value))
        return path

    def test_cli_streams_own_controller_log_and_never_opens_prefix_or_observer_files(self):
        self.save_result(self.source_result())
        log = self.root / 'logs' / (self.label + '.log')
        log.write_text('PRIVATE_SECRET\n' + marker(40) + marker(42, 2))
        opened = []
        original = trace.read_plain

        def only_owned(path):
            opened.append(path)
            self.assertNotIn('prefixes', path.parts)
            self.assertNotIn('observer.ndjson', path.name)
            return original(path)

        with mock.patch.object(trace, 'parser_module', return_value=PARSER), \
                mock.patch.object(trace, 'read_plain', side_effect=only_owned), redirect_stdout(io.StringIO()):
            self.assertEqual(trace.main([self.label]), 0)
        self.assertEqual(len(opened), 2)
        report = json.loads((self.root / 'research' / (self.label + '-numeric-trace.json')).read_text())
        self.assertNotIn('PRIVATE_SECRET', json.dumps(report))
        self.assertNotIn('9999', json.dumps(report))
        self.assertEqual(report['numeric_contract']['records'][0]['role'], 'source-ros-launcher')
        self.assertFalse(report['raw_log_or_result_contents_hashed_or_copied'])

    def test_foreign_log_or_observer_binding_is_rejected_before_log_read(self):
        for field in ('log', 'observer'):
            result = self.source_result()
            if field == 'log':
                result['log'] = 'prefixes/fivem-source-main/user.reg'
            else:
                result['read_only_code_process_observer']['metadata_file'] = 'logs/another-session-observer.ndjson'
            path = self.save_result(result)
            original = trace.read_plain

            def only_result(current):
                self.assertEqual(current, path)
                return original(current)

            with mock.patch.object(trace, 'read_plain', side_effect=only_result), self.assertRaises(RuntimeError):
                trace.main([self.label])

    def test_plain_reader_refuses_linked_or_redirected_inputs(self):
        own = self.root / 'logs' / 'own.log'
        own.write_text('PRIVATE_SECRET')
        alias = self.root / 'logs' / 'alias.log'
        alias.symlink_to(own)
        with self.assertRaises(RuntimeError):
            trace.read_plain(alias)
        linked = self.root / 'logs' / 'linked.log'
        os.link(own, linked)
        with self.assertRaises(RuntimeError):
            trace.read_plain(linked)

    def test_parser_identity_uses_raw_bytes_and_rejects_newline_normalization(self):
        source = PROJECT / trace.PARSER_PATH
        destination = self.root / trace.PARSER_PATH
        destination.parent.mkdir(parents=True)
        raw = source.read_bytes()
        destination.write_bytes(raw)
        self.assertTrue(callable(trace.parser_module().parse_lines))
        destination.write_bytes(raw.replace(b'\n', b'\r\n'))
        with self.assertRaisesRegex(RuntimeError, 'frozen fixed numeric parser'):
            trace.parser_module()


if __name__ == '__main__':
    unittest.main()
