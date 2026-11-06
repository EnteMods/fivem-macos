"""Synthetic WND markers and own temporary log-role files; no real logs."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

FILE = Path(__file__).resolve().parents[1] / 'native/windows-client/graphics_window_metadata.py'
SPEC = importlib.util.spec_from_file_location('graphics_window_metadata', FILE)
parser = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(parser)
WINDOW = '[CFX_GRAPHICS_WND] pid=16 tid=32 phase=1 returned=1 error=0 style=2147483648 exstyle=0 parent_nonnull=0'
QUERY = '[CFX_GRAPHICS_WND] pid=16 tid=32 phase=2 swapchain_requested=1 count=2 capped=0 enum_ok=1 query_failures=0'


class GraphicsWindowMetadataTests(unittest.TestCase):
    def test_exact_raw_and_wine_transport_schema(self):
        result = parser.parse_lines([WINDOW + '\n', QUERY,
            '0010:0020:trace:debugstr:OutputDebugStringA "' + WINDOW + '\\n"',
            '0020:warn:debugstr:OutputDebugStringA "' + QUERY + '\\n"\r\n',
            '0010:0020:warn:seh:dispatch_exception "' + QUERY + '\\n"'])
        self.assertEqual(result['accepted'], 5)
        self.assertEqual(result['rejected'], 0)
        self.assertEqual(result['events'][0], {'pid': 16, 'tid': 32, 'phase': 1, 'returned': 1,
            'error': 0, 'style': 2147483648, 'exstyle': 0, 'parent_nonnull': 0})
        self.assertEqual(result['events'][1], {'pid': 16, 'tid': 32, 'phase': 2,
            'swapchain_requested': 1, 'count': 2, 'capped': 0, 'enum_ok': 1, 'query_failures': 0})
        self.assertTrue(result['top_level_windows_only'])

    def test_private_extra_fields_wrong_prefixes_and_boolean_ranges_rejected(self):
        wrapped = '0010:0020:warn:debugstr:OutputDebugStringA "' + WINDOW + '\\n"'
        rows = [WINDOW + ' PRIVATE_TITLE', QUERY + ' {"private_key":"PRIVATE"}',
            WINDOW.replace('returned=1', 'returned=2'), WINDOW.replace('parent_nonnull=0', 'parent_nonnull=2'),
            QUERY.replace('swapchain_requested=1', 'swapchain_requested=2'), QUERY.replace('count=2', 'count=257'),
            QUERY.replace('capped=0', 'capped=2'), QUERY.replace('enum_ok=1', 'enum_ok=2'),
            QUERY.replace('query_failures=0', 'query_failures=4294967296'),
            WINDOW.replace('pid=16', 'pid=0'), WINDOW.replace('tid=32', 'tid=4294967296'),
            WINDOW.replace('error=0', 'error=-1'), WINDOW.replace('style=2147483648', 'style=4294967296'),
            wrapped.replace('0010:', '0011:'), wrapped.replace('0020:', '0021:'), '0001:' + wrapped,
            wrapped.replace('warn:debugstr', 'warn:win'), wrapped.replace('0010:', 'invalid:'),
            WINDOW + '\n' + QUERY, QUERY.replace('phase=2', 'phase=3')]
        result = parser.parse_lines(rows)
        self.assertEqual(result['accepted'], 0)
        self.assertEqual(result['rejected'], len(rows))
        self.assertNotIn('PRIVATE', repr(result))

    def test_u32_limits_zero_fields_and_query_cap_preserved_as_observation(self):
        window = WINDOW.replace('pid=16 tid=32', 'pid=4294967295 tid=4294967295')
        window = window.replace('returned=1', 'returned=0').replace('error=0', 'error=4294967295')
        window = window.replace('2147483648', '4294967295').replace('exstyle=0', 'exstyle=4294967295')
        window = window.replace('parent_nonnull=0', 'parent_nonnull=1')
        query = QUERY.replace('swapchain_requested=1', 'swapchain_requested=0').replace('count=2', 'count=256')
        query = query.replace('capped=0', 'capped=1').replace('enum_ok=1', 'enum_ok=0').replace('query_failures=0', 'query_failures=4294967295')
        result = parser.parse_lines([window, query])
        self.assertEqual(result['accepted'], 2)
        self.assertEqual(result['events'][0]['error'], 0xffffffff)
        self.assertEqual(result['events'][0]['exstyle'], 0xffffffff)
        self.assertEqual(result['events'][1]['count'], 256)
        self.assertEqual(result['events'][1]['swapchain_requested'], 0)
        self.assertFalse(result['capped'])

    def test_duplicate_or_interleaved_phases_are_not_calls(self):
        result = parser.parse_lines([WINDOW, WINDOW, QUERY.replace('tid=32', 'tid=33'), QUERY])
        self.assertEqual(result['accepted'], 4)
        self.assertFalse(result['calls_paired'])
        self.assertFalse(result['exception_cause_established'])
        self.assertFalse(result['functional_success_established'])

    def test_event_and_line_caps_without_global_log_cutoff(self):
        result = parser.parse_lines([WINDOW] * 257)
        self.assertEqual(result['accepted'], 256)
        self.assertTrue(result['capped'])
        result = parser.parse_lines([QUERY + ' PRIVATE' * parser.MAX_LINE_CHARS])
        self.assertEqual(result['oversized_lines'], 1)
        self.assertNotIn('PRIVATE', repr(result))
        def late_marker():
            yield from ('unrelated\n' for _ in range(100000))
            yield QUERY
        self.assertEqual(parser.parse_lines(late_marker())['accepted'], 1)

    def test_bound_log_role_discards_oversized_whole_line_and_eof_fragment(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve();(root / 'logs').mkdir()
            path = root / 'logs/client-source-ui-resume-20261103T204404123456Z.log'
            with mock.patch.object(parser, 'ROOT', root):
                path.write_bytes((WINDOW + '\n' + 'PRIVATE' * parser.MAX_LINE_CHARS + QUERY + '\n' + QUERY).encode())
                result = parser.parse_log(path)
                self.assertEqual(result['accepted'], 1)
                self.assertEqual(result['oversized_lines'], 1)
                self.assertEqual(result['incomplete_lines'], 1)
                self.assertNotIn('PRIVATE', repr(result))
                alias = path.with_name('client-source-ui-resume-20261103T204404123457Z.log')
                alias.symlink_to(path)
                with self.assertRaises(OSError): parser.parse_log(alias)
                linked = path.with_name('client-source-ui-resume-20261103T204404123458Z.log')
                os.link(path, linked)
                with self.assertRaises(ValueError): parser.parse_log(linked)
                with self.assertRaises(ValueError): parser.parse_log(root / 'private.log')


if __name__ == '__main__':
    unittest.main()
