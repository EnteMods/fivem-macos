from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'native/windows-client'))
import graphics_blit_gate_metadata as parser


class GraphicsBlitGateMetadataTests(unittest.TestCase):
    row = '[CFX_GRAPHICS_BLIT_GATE] pid=1800 tid=2860 gate=6'

    def test_deduplicates_wine_channels_without_merging_distinct_threads(self):
        result = parser.parse_lines([
            f'0b2c:warn:debugstr:OutputDebugStringA "{self.row}\\n"\n',
            f'0708:0b2c:warn:seh:dispatch_exception "{self.row}\\n"\n',
            self.row.replace('tid=2860', 'tid=2861'),
        ])
        self.assertEqual(result['accepted'], 2)
        self.assertEqual(result['duplicates'], 1)
        self.assertEqual(result['rejected'], 0)
        self.assertEqual([row['tid'] for row in result['events']], [2860, 2861])

    def test_rejects_mismatched_identities_and_extra_text(self):
        result = parser.parse_lines([
            f'0709:0b2c:trace:debugstr:OutputDebugStringA "{self.row}\\n"',
            f'0708:0b2d:warn:seh:dispatch_exception "{self.row}\\n"',
            self.row + ' private_sentinel',
            self.row.replace('gate=6', 'gate=17'),
            self.row.replace('pid=1800', 'pid=4294967296'),
        ])
        self.assertEqual(result['events'], [])
        self.assertEqual(result['rejected'], 5)
        self.assertEqual(result['identity_mismatches'], 2)
        self.assertNotIn('private_sentinel', repr(result))

    def test_snapshot_requires_prefix_and_reports_truncation(self):
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(parser, 'ROOT', Path(folder).resolve()):
            log = parser.ROOT / 'logs/client-source-ui-resume-20261104T203230381363Z.log'
            log.parent.mkdir()
            wrapped = f'0b2c:warn:debugstr:OutputDebugStringA "{self.row}\\n"\n'
            log.write_text(wrapped + self.row + '\n')
            self.assertEqual(parser.parse_log(log)['rejected'], 1)
            with mock.patch.object(parser, 'MAX_SNAPSHOT_BYTES', len(wrapped) + 1):
                result = parser.parse_log(log)
                self.assertTrue(result['snapshot_capped'])
                self.assertEqual(result['accepted'], 1)
                self.assertEqual(result['incomplete_lines'], 1)


if __name__ == '__main__':
    unittest.main()
