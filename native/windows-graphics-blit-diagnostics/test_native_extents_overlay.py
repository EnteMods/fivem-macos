from pathlib import Path
import subprocess
import tempfile
import unittest

import native_extents_overlay as overlay


HERE = Path(__file__).resolve().parent
UNIT = HERE.parents[1] / 'build/windows-graphics-blit-projection-sharpness/overlay/DrawCommands.cpp'
HEADER = HERE / 'GraphicsBlitProjection.h'


class NativeExtentsTests(unittest.TestCase):
    def test_exact_reversal_preserves_texture_measurement(self):
        original = UNIT.read_bytes(), HEADER.read_bytes()
        unit, header = overlay.apply(*original)
        self.assertEqual(overlay.strip(unit, header), original)
        for token in (b'SampleSharpness(projectionSize);', b'EmitSharpness(sharpness);', b'drawImVertices();',
                      b'addImVertex(v.x, v.y, v.z, v.nX, v.nY, v.nZ, v.color, v.u, v.v);'):
            self.assertEqual(unit.count(token), original[0].count(token))
        self.assertIn(b'AppendUnsigned(out, size.adjusted);', unit)
        with self.assertRaises(ValueError):
            overlay.apply(original[0] + b' ', original[1])
        with self.assertRaises(ValueError):
            overlay.strip(unit, header + b' ')

    def test_independent_axes_and_preexisting_raster_guards(self):
        _, header = overlay.apply(UNIT.read_bytes(), HEADER.read_bytes())
        source = r'''
#include "GraphicsBlitProjection.h"
#include <cassert>
#include <cstring>
using namespace cfx::blit::projection;

int main()
{
    struct Case { unsigned width, height; float right, top, bottom; };
    const Case cases[]{
        {1280,720,1920,720,-360}, {1512,982,1920,982,-98},
        {3016,1694,3016,1694,0}, {2776,1514,2776,1514,0},
        {2560,720,2560,720,-360}, {1280,1440,1920,1440,0}, {1920,1080,1920,1080,0},
    };
    for (const auto& shape : cases)
    {
        const float w = float(shape.width), h = float(shape.height);
        Vertex quad[4]{{-0.0f,h,0,0,0,-1,11,0,0}, {w,h,0,0,0,-1,22,1,0},
                       {0,0,0,0,0,-1,33,0,1}, {w,0,0,0,0,-1,44,1,1}};
        Vertex expected[4];
        std::memcpy(expected, quad, sizeof(quad));
        expected[1].x = expected[3].x = shape.right;
        expected[0].y = expected[1].y = shape.top;
        expected[2].y = expected[3].y = shape.bottom;
        Geometry g;
        g.width = shape.width;
        g.height = shape.height;
        g.menuOutputBound = true;
        g.viewportCount = 1;
        g.viewportWidth = w;
        g.viewportHeight = h;
        g.scissor = ScissorMode::enabled;
        g.scissorCount = 1;
        g.scissorRight = int(w);
        g.scissorBottom = int(h);
        auto clipped = g;
        --clipped.scissorRight;
        Vertex old[4];
        std::memcpy(old, quad, sizeof(quad));
        assert(!Scale(quad, clipped, 1920, 1080));
        assert(!std::memcmp(quad, old, sizeof(quad)));
        auto unrelated = g;
        unrelated.menuOutputBound = false;
        assert(!Scale(quad, unrelated, 1920, 1080));
        assert(!std::memcmp(quad, old, sizeof(quad)));
        assert(Scale(quad, g, 1920, 1080));
        assert(!std::memcmp(quad, expected, sizeof(quad)));
    }
}
'''
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            (folder / HEADER.name).write_bytes(header)
            binary = folder / 'native-extents-test'
            subprocess.run(['/usr/bin/c++', '-std=c++17', '-Wall', '-Wextra', '-Werror', '-I', directory,
                            '-x', 'c++', '-', '-o', str(binary)], input=source, text=True, check=True, timeout=30)
            subprocess.run([binary], check=True, timeout=10)


if __name__ == '__main__':
    unittest.main()
