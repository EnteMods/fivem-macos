"""Synthetic graphics marker lines and temporary local log-role files only."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

FILE = Path(__file__).resolve().parents[1] / 'native/windows-client/graphics_swapchain_metadata.py'
SPEC = importlib.util.spec_from_file_location('graphics_swapchain_metadata', FILE)
parser = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(parser)
BEFORE = '[CFX_GRAPHICS_SC] pid=16 tid=32 phase=1 mask=15'
AFTER = '[CFX_GRAPHICS_SC] pid=16 tid=32 phase=2 status=2289696769 out_nonnull=0'


class GraphicsSwapchainMetadataTests(unittest.TestCase):
    def test_raw_and_each_exact_wine_transport(self):
        rows = [BEFORE + '\n', AFTER,
                '0010:0020:trace:debugstr:OutputDebugStringA "' + BEFORE + '\\n"\n',
                '0020:warn:debugstr:OutputDebugStringA "' + AFTER + '\\n"',
                '0010:0020:warn:seh:dispatch_exception "' + BEFORE + '\\n"\r\n']
        result = parser.parse_lines(rows)
        self.assertEqual(result['accepted'], 5)
        self.assertEqual(result['rejected'], 0)
        self.assertEqual(result['events'][0], {'pid': 16, 'tid': 32, 'phase': 1, 'mask': 15})
        self.assertEqual(result['events'][1], {'pid': 16, 'tid': 32, 'phase': 2,
                                             'status': 2289696769, 'out_nonnull': 0})

    def test_wrong_numbers_phases_prefixes_and_extra_private_data(self):
        wrapped = '0010:0020:warn:debugstr:OutputDebugStringA "' + BEFORE + '\\n"'
        bad = [BEFORE.replace('mask=15', 'mask=16'), BEFORE.replace('pid=16', 'pid=0'),
               BEFORE.replace('tid=32', 'tid=4294967296'), AFTER.replace('2289696769', '4294967296'),
               AFTER.replace('out_nonnull=0', 'out_nonnull=2'), AFTER.replace('phase=2', 'phase=3'),
               BEFORE + ' PRIVATE_TITLE', BEFORE + ' {"private_key":"PRIVATE"}',
               wrapped.replace('0020:', '0021:'), wrapped.replace('0010:', '0011:'),
               '0001:' + wrapped, wrapped.replace('0010:', 'badprefix:'),
               wrapped.replace('warn:debugstr', 'warn:win'), wrapped.replace('\\n"', '\\nPRIVATE"'),
               BEFORE + '\n' + AFTER, BEFORE.replace('pid=16', 'pid=-1')]
        result = parser.parse_lines(bad)
        self.assertEqual(result['accepted'], 0)
        self.assertEqual(result['rejected'], len(bad))
        self.assertNotIn('PRIVATE', repr(result))

    def test_u32_endpoints_mask_and_output_boolean(self):
        a = BEFORE.replace('pid=16 tid=32', 'pid=4294967295 tid=4294967295').replace('mask=15', 'mask=0')
        b = AFTER.replace('2289696769', '4294967295').replace('out_nonnull=0', 'out_nonnull=1')
        result = parser.parse_lines([a, b])
        self.assertEqual(result['events'][0]['pid'], 0xffffffff)
        self.assertEqual(result['events'][0]['mask'], 0)
        self.assertEqual(result['events'][1]['status'], 0xffffffff)
        self.assertEqual(result['events'][1]['out_nonnull'], 1)

    def test_duplicates_and_interleaved_threads_are_not_paired(self):
        result = parser.parse_lines([BEFORE, BEFORE, AFTER.replace('tid=32', 'tid=33'), AFTER])
        self.assertEqual(result['accepted'], 4)
        self.assertFalse(result['calls_paired'])
        self.assertFalse(result['exception_cause_established'])
        self.assertFalse(result['functional_success_established'])

    def test_event_and_line_length_caps_without_global_line_cutoff(self):
        result = parser.parse_lines([BEFORE] * 257)
        self.assertEqual(result['accepted'], 256)
        self.assertTrue(result['capped'])
        result = parser.parse_lines([BEFORE + ' PRIVATE' * parser.MAX_LINE_CHARS])
        self.assertEqual(result['oversized_lines'], 1)
        self.assertNotIn('PRIVATE', repr(result))
        def late_marker():
            yield from ('baseline\n' for _ in range(100000))
            yield BEFORE
        result = parser.parse_lines(late_marker())
        self.assertFalse(result['capped'])
        self.assertEqual(result['accepted'], 1)

    def test_direct_log_role_no_symlinks_and_bounded_unterminated_or_oversized_lines(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve();(root / 'logs').mkdir()
            path = root / 'logs/client-source-ui-resume-20261103T200255815673Z.log'
            with mock.patch.object(parser, 'ROOT', root):
                path.write_bytes((BEFORE + '\n' + 'PRIVATE' * parser.MAX_LINE_CHARS + AFTER + '\n' + AFTER).encode())
                result = parser.parse_log(path)
                self.assertEqual(result['accepted'], 1)
                self.assertEqual(result['oversized_lines'], 1)
                self.assertEqual(result['incomplete_lines'], 1)
                self.assertNotIn('PRIVATE', repr(result))
                alias = path.with_name('client-source-ui-resume-20261103T200255815674Z.log')
                alias.symlink_to(path)
                with self.assertRaises(OSError): parser.parse_log(alias)
                linked = path.with_name('client-source-ui-resume-20261103T200255815675Z.log')
                os.link(path, linked)
                with self.assertRaises(ValueError): parser.parse_log(linked)
                with self.assertRaises(ValueError): parser.parse_log(root / 'private.log')


if __name__ == '__main__':
    unittest.main()
