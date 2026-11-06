from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'native/windows-client'))
from graphics_blit_vertex_metadata import parse_lines


VERTICES = ('[CFX_GRAPHICS_BLIT_VERTICES] pid=1800 tid=2860 id=1 legacy=0 '
            'v=0,15712,0,0,0,24192,15712,0,4096,0,0,0,0,0,4096,24192,0,0,4096,4096')
CONTEXT = ('[CFX_GRAPHICS_BLIT_VERTEX_CONTEXT] pid=1800 tid=2860 id=1 ctx=15 vp_count=1 vp_valid=1 '
           'vp_x16=0 vp_y16=1424 vp_w16=19056 vp_h16=14288 rt_w=1512 rt_h=982 '
           'sc_enabled=0 sc_count=0 sc_l=0 sc_t=0 sc_r=0 sc_b=0')


def wrap(payload, identity='0708:0b2c'):
    return f'{identity}:warn:debugstr:OutputDebugStringA "{payload}\\n"\n'


class GraphicsBlitVertexMetadataTests(unittest.TestCase):
    def test_joins_context_in_either_order_and_deduplicates(self):
        result = parse_lines(map(wrap, (CONTEXT, VERTICES, VERTICES)))
        self.assertEqual((result['accepted'], result['duplicates'], result['rejected']), (1, 1, 0))
        self.assertEqual(result['events'][0]['vertices'][0][:2], [0, 15712])
        self.assertEqual(result['events'][0]['context']['rt_w'], 1512)

    def test_identity_mismatch_and_conflicts_never_yield_a_pair(self):
        result = parse_lines([wrap(VERTICES, '0707:0b2c'), wrap(CONTEXT)])
        self.assertEqual((result['accepted'], result['incomplete_pairs'], result['rejected']), (0, 1, 1))
        result = parse_lines(map(wrap, (CONTEXT, VERTICES, VERTICES.replace('legacy=0', 'legacy=1'))))
        self.assertEqual((result['accepted'], result['rejected']), (0, 1))
