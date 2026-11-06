from pathlib import Path
import unittest

import sharpness_overlay as sharpness


ROOT = Path(__file__).resolve().parents[2]
BASELINE = ROOT / 'build/windows-graphics-blit-projection-aligned/overlay/DrawCommands.cpp'


class SharpnessOverlayTests(unittest.TestCase):
    def test_reversible_and_bound_to_aligned_bytes(self):
        aligned = BASELINE.read_bytes()
        candidate = sharpness.apply(aligned)
        self.assertEqual(sharpness.strip(candidate), aligned)
        with self.assertRaises(ValueError):
            sharpness.apply(aligned + b' ')
        with self.assertRaises(ValueError):
            sharpness.strip(candidate.replace(b'PSGetSamplers(0, 1,', b'PSGetSamplers(1, 1,'))

    def test_existing_calls_remain_single_and_guard_comes_before_metadata_reads(self):
        aligned = BASELINE.read_bytes()
        candidate = sharpness.apply(aligned).decode('ascii')
        for call in ('setTextureGtaIm(texture);', 'drawImVertices();', 'popImShaderAndResetParams();',
                     'addImVertex(v.x, v.y, v.z, v.nX, v.nY, v.nZ, v.color, v.u, v.v);'):
            self.assertEqual(candidate.count(call), aligned.count(call.encode('ascii')))
        self.assertLess(candidate.index('setTextureGtaIm(texture);'), candidate.index('RememberSharpnessInput(texture,'))
        self.assertLess(candidate.index('SampleSharpness(projectionSize);'), candidate.index('drawImVertices();'))
        self.assertLess(candidate.index('drawImVertices();'), candidate.index('EmitSharpness(sharpness);'))
        self.assertLess(candidate.index('!size.width || !input.armed'), candidate.index('input.view->GetResource('))
        for mutation in ('PSSet', 'CopyResource(', 'CopySubresourceRegion(', 'GenerateMips(', '->Map('):
            self.assertNotIn(mutation, sharpness.SAMPLE)


if __name__ == '__main__':
    unittest.main()
