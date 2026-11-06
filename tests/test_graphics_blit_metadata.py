"""Exercise blit marker transport and snapshot bounds without a runtime or live log."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


FILE = Path(__file__).resolve().parents[1] / 'native/windows-client/graphics_blit_metadata.py'
SPEC = importlib.util.spec_from_file_location('graphics_blit_metadata', FILE)
parser = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(parser)
BLIT = ('[CFX_GRAPHICS_BLIT] pid=16 tid=32 quad_w=1512 quad_h=982 vp_count=1 vp_valid=1 '
        'vp_x16=-16 vp_y16=1408 vp_w16=19104 vp_h16=14288 rt_w=1512 rt_h=982')
EXPECTED = {'pid': 16, 'tid': 32, 'quad_w': 1512, 'quad_h': 982, 'vp_count': 1, 'vp_valid': 1,
            'vp_x16': -16, 'vp_y16': 1408, 'vp_w16': 19104, 'vp_h16': 14288, 'rt_w': 1512, 'rt_h': 982}
UNKNOWN = ('[CFX_GRAPHICS_BLIT] pid=16 tid=32 quad_w=1512 quad_h=982 vp_count=16 vp_valid=0 '
           'vp_x16=0 vp_y16=0 vp_w16=0 vp_h16=0 rt_w=0 rt_h=0')


def wrapped(marker, prefix='0010:0020:', channel='trace:debugstr:OutputDebugStringA'):
    return f'{prefix}{channel} "{marker}\\n"'


class GraphicsBlitMetadataTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        (self.root / 'logs').mkdir()
        self.path = self.root / 'logs/client-source-ui-resume-20261104T201230123456Z.log'
        patch = mock.patch.object(parser, 'ROOT', self.root)
        patch.start()
        self.addCleanup(patch.stop)

    def test_exact_transports_preserve_duplicate_rows(self):
        result = parser.parse_lines([BLIT + '\n', wrapped(BLIT),
            wrapped(BLIT, prefix='0020:', channel='warn:debugstr:OutputDebugStringA') + '\r\n',
            wrapped(BLIT, channel='warn:seh:dispatch_exception'), UNKNOWN])
        self.assertEqual(result['accepted'], 5)
        self.assertEqual(result['rejected'], 0)
        self.assertEqual(result['events'][:4], [EXPECTED] * 4)
        self.assertEqual(result['events'][4]['vp_count'], 16)
        self.assertEqual(result['events'][4]['vp_valid'], 0)
        self.assertFalse(result['rendered_frame_established'])

    def test_exact_numeric_fields_ranges_and_bound_prefix(self):
        fields = {'pid=16': 'pid=0', 'tid=32': 'tid=4294967296', 'quad_w=1512': 'quad_w=65536',
                  'quad_h=982': 'quad_h=0', 'vp_count=1': 'vp_count=17', 'vp_valid=1': 'vp_valid=0',
                  'vp_x16=-16': 'vp_x16=-1048577', 'vp_y16=1408': 'vp_y16=+1408',
                  'vp_w16=19104': 'vp_w16=019104', 'vp_h16=14288': 'vp_h16=-0',
                  'rt_w=1512': 'rt_w=4294967296', 'rt_h=982': 'rt_h=0'}
        rows = [BLIT.replace(old, new) for old, new in fields.items()]
        rows += [BLIT.replace('vp_count=1', 'vp_count=2'), BLIT + ' title=PRIVATE', 'PRIVATE ' + BLIT,
                 wrapped(BLIT, prefix='0011:0020:'), wrapped(BLIT, prefix='0021:'),
                 wrapped(BLIT, prefix='0001:0010:0020:'), wrapped(BLIT, channel='trace:win:unknown'),
                 BLIT + '\v' + BLIT]
        result = parser.parse_lines(rows)
        self.assertEqual(result['events'], [])
        self.assertEqual(result['rejected'], len(rows))
        self.assertNotIn('PRIVATE', repr(result))
        edge = BLIT.replace('pid=16', 'pid=4294967295').replace('vp_x16=-16', 'vp_x16=-1048576')
        self.assertEqual(parser.parse_lines([edge])['events'][0]['vp_x16'], -1048576)

    def test_late_rows_and_event_cap(self):
        def rows():
            yield from ('ordinary data\n' for _ in range(100000))
            yield from (BLIT for _ in range(parser.MAX_EVENTS + 1))
        result = parser.parse_lines(rows())
        self.assertEqual(result['accepted'], parser.MAX_EVENTS)
        self.assertTrue(result['capped'])

    def test_direct_completed_file_bounds_and_refuses_aliases(self):
        self.path.write_bytes((BLIT + '\n' + 'PRIVATE' * parser._CHUNK_BYTES + BLIT + '\n' + BLIT).encode())
        result = parser.parse_log(self.path.relative_to(self.root))
        self.assertEqual(result['events'], [EXPECTED])
        self.assertEqual((result['oversized_lines'], result['incomplete_lines']), (1, 1))
        self.assertNotIn('PRIVATE', repr(result))
        self.assertFalse(result['live_snapshot'])
        alias = self.path.with_name('client-source-ui-resume-20261104T201230123457Z.log')
        alias.symlink_to(self.path)
        with self.assertRaises(OSError):
            parser.parse_log(alias)
        alias.unlink()
        os.link(self.path, alias)
        with self.assertRaises(ValueError):
            parser.parse_log(alias)
        with self.assertRaises(ValueError):
            parser.parse_log(self.root / 'private.log')

    def test_live_only_reads_initial_extent_and_allows_append(self):
        initial = (BLIT + '\n' + UNKNOWN).encode()
        for live in (False, True):
            with self.subTest(live=live):
                self.path.write_bytes(initial)
                original_pread = os.pread
                reads = []

                def append_after_read(descriptor, length, offset):
                    reads.append((length, offset))
                    data = original_pread(descriptor, length, offset)
                    with self.path.open('ab') as output:
                        output.write(('\n' + BLIT + '\n').encode())
                    return data

                with mock.patch.object(parser.os, 'pread', side_effect=append_after_read):
                    if live:
                        result = parser.parse_log(self.path, live=True)
                        self.assertEqual(result['events'], [EXPECTED])
                        self.assertEqual(result['incomplete_lines'], 1)
                        self.assertTrue(result['log_grew_during_read'])
                    else:
                        with self.assertRaises(ValueError):
                            parser.parse_log(self.path)
                self.assertEqual(reads, [(len(initial), 0)])

    def test_live_rejects_replaced_file(self):
        self.path.write_text(BLIT + '\n')
        original_pread = os.pread

        def replace_after_read(descriptor, length, offset):
            data = original_pread(descriptor, length, offset)
            replacement = self.path.with_suffix('.replacement')
            replacement.write_text(BLIT + '\n')
            replacement.replace(self.path)
            return data

        with mock.patch.object(parser.os, 'pread', side_effect=replace_after_read):
            with self.assertRaises(ValueError):
                parser.parse_log(self.path, live=True)


if __name__ == '__main__':
    unittest.main()
