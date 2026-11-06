"""Pure synthetic lines only; no Wine, windows, logs, or account data."""
import importlib.util
from pathlib import Path
import unittest

PATH = Path(__file__).resolve().parents[1] / 'native/windows-client/window_creation_trace.py'
SPEC = importlib.util.spec_from_file_location('window_creation_trace', PATH)
trace = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(trace)

CREATED = '0010:0020:trace:win:NtUserCreateWindowEx created window 0000000000012345'
ERROR = '0010:0020:warn:win:create_window_handle error 1407 creating window'
ABORTED = '0010:0020:warn:win:NtUserCreateWindowEx 0x12345: aborted by WM_NCCREATE'


class WindowCreationTraceTests(unittest.TestCase):
    def test_exact_three_events_and_numeric_shapes(self):
        result = trace.parse_lines([CREATED, ERROR + '\n', ABORTED + '\r\n'])
        self.assertEqual(result['events'], [
            {'event': 'created', 'wine_pid': 16, 'wine_tid': 32, 'hwnd': 0x12345},
            {'event': 'server_error', 'wine_pid': 16, 'wine_tid': 32, 'win32_error': 1407},
            {'event': 'nccreate_aborted', 'wine_pid': 16, 'wine_tid': 32, 'hwnd': 0x12345}])
        self.assertEqual(result['accepted_events'], 3)
        self.assertEqual(result['dropped_win_lines'], 0)

    def test_single_prefix_does_not_invent_a_pid(self):
        result = trace.parse_lines([CREATED.removeprefix('0010:')])
        self.assertIsNone(result['events'][0]['wine_pid'])
        self.assertEqual(result['events'][0]['wine_tid'], 32)
        self.assertFalse(result['unknown_pid_attributed'])

    def test_only_passthrough_may_retain_original_baseline_line(self):
        collector = trace.Collector()
        self.assertEqual(collector.accept('0010:0020:trace:loaddll:build_module baseline'), 'passthrough')
        self.assertEqual(collector.accept(CREATED), 'accepted')
        self.assertEqual(collector.accept('0010:0020:trace:win:Other PRIVATE_TITLE'), 'drop')
        result = collector.summary()
        self.assertEqual(result['passthrough_lines'], 1)
        self.assertNotIn('PRIVATE', repr(result))
        self.assertNotIn('baseline', repr(result))

    def test_window_titles_classes_messages_and_other_levels_are_dropped(self):
        lines = ['0010:0020:trace:win:NtUserCreateWindowEx window_name PRIVATE_TITLE class PRIVATE_CLASS',
                 '0010:warn:win:Other PRIVATE_MESSAGE',
                 '0010:0020:err:win:NtUserCreateWindowEx PRIVATE_ERROR',
                 '0010:fixme:win:Other PRIVATE_FIXME']
        result = trace.parse_lines(lines)
        self.assertEqual(result['events'], [])
        self.assertEqual(result['dropped_win_lines'], len(lines))
        self.assertEqual(result['passthrough_lines'], 0)
        self.assertNotIn('PRIVATE', repr(result))

    def test_bad_prefix_ranges_functions_levels_and_trailing_payload_rejected(self):
        bad = [CREATED.replace('0010:', 'junk:', 1), '0001:' + CREATED,
               CREATED.replace('0010:', '100000000:', 1), CREATED.replace('0020:', '0000:'),
               CREATED.replace('0010:', '0000:', 1), CREATED.replace('created window', 'created  window'),
               CREATED.replace('trace:', 'warn:'), ERROR.replace('warn:', 'trace:'),
               CREATED.replace('NtUserCreateWindowEx', 'CreateWindowExW'),
               CREATED + ' PRIVATE', CREATED + ' {"private_key":"PRIVATE"}',
               CREATED.replace('0000000000012345', '10000000000000000'),
               CREATED.replace('0000000000012345', '0'), ERROR.replace('1407', '4294967296'),
               ERROR.replace('1407', '-1')]
        result = trace.parse_lines(bad)
        self.assertEqual(result['accepted_events'], 0)
        self.assertEqual(result['rejected_win_lines'], len(bad))
        self.assertEqual(result['passthrough_lines'], 0)
        self.assertNotIn('PRIVATE', repr(result))

    def test_u32_u64_limits_and_unknown_pid(self):
        row = 'ffffffff:FFFFFFFF:trace:win:NtUserCreateWindowEx created window FFFFFFFFFFFFFFFF'
        result = trace.parse_lines([row, ERROR.replace('1407', '4294967295')])
        self.assertEqual(result['events'][0]['hwnd'], trace.QWORD_MAX)
        self.assertEqual(result['events'][0]['wine_pid'], trace.DWORD_MAX)
        self.assertEqual(result['events'][1]['win32_error'], trace.DWORD_MAX)

    def test_interleaving_multiline_nul_and_incomplete_are_never_persisted(self):
        collector = trace.Collector()
        for line in (CREATED + ERROR, CREATED + '\n' + ERROR, CREATED + '\0PRIVATE', CREATED + '\rPRIVATE'):
            self.assertEqual(collector.accept(line), 'drop')
        self.assertEqual(collector.accept(CREATED, complete=False), 'drop')
        self.assertEqual(collector.accept(None), 'drop')
        self.assertEqual(collector.summary()['events'], [])
        self.assertNotIn('PRIVATE', repr(collector.summary()))
        self.assertEqual(trace.parse_lines(CREATED)['incomplete_lines'], 1)
        self.assertEqual(trace.parse_lines(CREATED + '\n')['accepted_events'], 1)

    def test_line_event_budgets_and_baseline_after_cap(self):
        collector = trace.Collector()
        self.assertEqual(collector.accept('PRIVATE' * trace.MAX_LINE_CHARS), 'drop')
        for _ in range(trace.MAX_EVENTS):
            self.assertEqual(collector.accept(CREATED), 'accepted')
        self.assertEqual(collector.accept(CREATED), 'drop')
        self.assertEqual(collector.accept('0020:trace:loaddll:build_module baseline'), 'passthrough')
        result = collector.summary()
        self.assertTrue(result['capped'])
        self.assertEqual(len(result['events']), trace.MAX_EVENTS)
        self.assertEqual(result['oversized_lines'], 1)
        self.assertEqual(result['capped_win_lines'], 1)

    def test_duplicates_are_not_invented_unique_windows_and_summary_is_detached(self):
        collector = trace.Collector()
        collector.accept(CREATED);collector.accept(CREATED)
        first = collector.summary()
        self.assertEqual(len(first['events']), 2)
        first['events'][0]['hwnd'] = 999
        self.assertEqual(collector.summary()['events'][0]['hwnd'], 0x12345)
        self.assertFalse(first['missing_created_event_proves_null'])
        self.assertFalse(first['api_return_trace_complete'])


if __name__ == '__main__':
    unittest.main()
