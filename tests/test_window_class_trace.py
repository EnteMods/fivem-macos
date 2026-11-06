"""Synthetic Wine class-channel frames."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1] / 'native/windows-client/window_class_trace.py'
SPEC = importlib.util.spec_from_file_location('window_class_trace', PATH)
trace = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(trace)

ATTEMPT = ('0010:0020:trace:class:NtUserRegisterClassExWOW name=L"grcWindow" '
           'hinst=0x111110000 style=0x3 clExtr=0x0 winExtr=0x8')
SUCCESS = ('0010:0020:trace:class:NtUserRegisterClassExWOW name=L"grcWindow"->L"grcWindow" '
           'atom=c040 wndproc=0x1234 hinst=0x111110000 bg=(nil) '
           'style=00000003 clsExt=0 winExt=8 class=0x8765')
HIT = '0010:0021:trace:class:find_class L"grcWindow" 111110000 -> 0x8765'
MISS = '0010:0021:trace:win:WIN_CreateWindowEx L"grcWindow" 0000000111120000 -> not found'
UNREGISTER = '0010:0020:trace:class:NtUserUnregisterClass 0x8765'


class WindowClassTraceTests(unittest.TestCase):
    def test_same_process_join_and_unregister_keep_only_numeric_context(self):
        rows = trace.parse_lines([ATTEMPT, SUCCESS, HIT, MISS, UNREGISTER, MISS])['events']
        self.assertEqual([row['event'] for row in rows], ['registration_attempt',
            'registration_succeeded', 'lookup_hit', 'create_lookup_miss', 'unregistered',
            'create_lookup_miss'])
        self.assertEqual(rows[0], {'event': 'registration_attempt', 'wine_pid': 16,
            'wine_tid': 32, 'class_id': 1, 'instance_is_null': False, 'global_class': False})
        self.assertIs(rows[2]['instance_equal'], True)
        self.assertIs(rows[2]['instance_same_64k'], True)
        self.assertIs(rows[3]['instance_equal'], False)
        self.assertIs(rows[3]['instance_same_64k'], False)
        self.assertIs(rows[5]['instance_equal'], None)
        for raw in ('0x1234', '111110000', '0x8765', 'grcWindow', 'c040'):
            self.assertNotIn(raw, repr(rows))

    def test_unknown_and_foreign_pid_do_not_inherit_context(self):
        foreign = MISS.replace('0010:', '0011:', 1)
        unknown = HIT.removeprefix('0010:')
        rows = trace.parse_lines([SUCCESS, foreign, unknown])['events']
        self.assertEqual([row['wine_pid'] for row in rows], [16, 17, None])
        for row in rows[1:]:
            self.assertIsNone(row['instance_equal'])
            self.assertEqual(row['observed_registration_contexts'], 0)

    def test_configured_class_global_context_64k_and_duplicate_rows(self):
        name = 'OwnWindowClass'
        success = SUCCESS.replace('grcWindow', name).replace('00000003', '00004003')
        success = success.replace(f'L"{name}"->', 'L"\\4f4f"->')
        hit = HIT.replace('grcWindow', name).replace('111110000', '111110008')
        result = trace.parse_lines([success, success, hit], ('UnusedOwnClass', name))
        rows = result['events']
        self.assertEqual(result['accepted'], 3)
        self.assertEqual([row['class_id'] for row in rows], [2, 2, 2])
        self.assertEqual(rows[2]['observed_registration_contexts'], 1)
        self.assertIs(rows[2]['instance_equal'], False)
        self.assertIs(rows[2]['instance_same_64k'], True)
        self.assertIs(rows[2]['registration_global'], True)
        self.assertTrue(result['repeated_rows_preserved'])
        self.assertFalse(result['missing_registration_proves_absence'])
        self.assertNotIn(name, repr(result))

    def test_distinct_module_contexts_are_ambiguous_for_a_miss(self):
        second = SUCCESS.replace('111110000', '111130000').replace('8765', '8766')
        rows = trace.parse_lines([SUCCESS, second, MISS, HIT])['events']
        self.assertEqual(rows[2]['observed_registration_contexts'], 2)
        self.assertIsNone(rows[2]['instance_equal'])
        self.assertEqual(rows[3]['observed_registration_contexts'], 1)
        self.assertIs(rows[3]['instance_equal'], True)

    def test_drop_class_and_create_records_even_when_they_do_not_parse(self):
        collector = trace.Collector()
        for row in ('junk:trace:class:Other PRIVATE', '0010:CLASS:Other PRIVATE',
                    'extra:0010:0020:warn:win:WIN_CreateWindowEx PRIVATE',
                    ATTEMPT.replace('grcWindow', 'PrivateClass'),
                    ATTEMPT.replace('0020:', '0000:'), 'abcd:' + SUCCESS,
                    SUCCESS.replace('c040', '0000'), SUCCESS.replace('0x8765', '(nil)'),
                    HIT.replace('0x8765', '0x10000000000000000'),
                    MISS + ' PRIVATE'):
            self.assertTrue(trace.is_sensitive_line(row))
            self.assertEqual(collector.accept(row), 'drop')
        self.assertEqual(collector.accept('0010:0020:trace:loaddll:build_module baseline'),
                         'passthrough')
        result = collector.summary()
        self.assertEqual(result['rejected'], 10)
        self.assertEqual(result['events'], [])
        self.assertNotIn('PRIVATE', repr(result))

    def test_framing_and_capacity_keep_summary_detached(self):
        collector = trace.Collector()
        self.assertEqual(collector.accept(SUCCESS, complete=False), 'drop')
        self.assertEqual(collector.accept(SUCCESS + '\0PRIVATE'), 'drop')
        self.assertEqual(collector.accept(SUCCESS + 'a' * trace.MAX_LINE_CHARS), 'drop')
        with patch.object(trace, 'MAX_EVENTS', 1):
            self.assertEqual(collector.accept(ATTEMPT), 'accepted')
            self.assertEqual(collector.accept(SUCCESS), 'drop')
            self.assertEqual(collector.accept('baseline'), 'passthrough')
        result = collector.summary()
        self.assertTrue(result['capped'])
        self.assertEqual(result['incomplete_lines'], 1)
        self.assertEqual(result['invalid_lines'], 1)
        self.assertEqual(result['oversized_lines'], 1)
        result['events'][0]['class_id'] = 99
        self.assertEqual(collector.summary()['events'][0]['class_id'], 1)
        self.assertEqual(trace.parse_lines(SUCCESS)['accepted'], 0)
        self.assertEqual(trace.parse_lines(SUCCESS + '\n')['accepted'], 1)


if __name__ == '__main__':
    unittest.main()
