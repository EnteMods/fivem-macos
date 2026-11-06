from pathlib import Path
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent


class ProjectionScaleTests(unittest.TestCase):
    def test_native_exact_geometry_and_all_or_none_rejection(self):
        source = r'''
#include "GraphicsBlitProjection.h"
#include <cassert>
#include <cstring>
#include <initializer_list>
#include <limits>
using namespace cfx::blit::projection;

static Geometry full(unsigned width, unsigned height)
{
    Geometry result;
    result.width = width;
    result.height = height;
    result.viewportCount = 1;
    result.viewportWidth = float(width);
    result.viewportHeight = float(height);
    result.scissor = ScissorMode::enabled;
    result.scissorCount = 1;
    result.scissorRight = int(width);
    result.scissorBottom = int(height);
    result.menuOutputBound = true;
    return result;
}

int main()
{
    for (auto dimensions : {full(1512, 982), full(1280, 720), full(1600, 1000), full(2560, 1440)})
    {
        const float w = float(dimensions.width), h = float(dimensions.height);
        Vertex quad[4]{{-0.0f,h,0,0,0,-1,11,0,0}, {w,h,0,0,0,-1,22,1,0},
                       {0,0,0,0,0,-1,33,0,1}, {w,-0.0f,0,0,0,-1,44,1,1}};
        Vertex original[4], expected[4];
        std::memcpy(original, quad, sizeof(quad));
        std::memcpy(expected, quad, sizeof(quad));
        expected[1].x = expected[3].x = 1920;
        expected[0].y = expected[1].y = 1080;
        for (unsigned i = 0; i < 4; ++i) assert(Expected(quad, i, quad[i]));
        assert(!Expected(quad, 4, quad[0]));

        assert(Scale(quad, dimensions, 1920, 1080));
        assert(!std::memcmp(quad, expected, sizeof(quad)));

        std::memcpy(quad, original, sizeof(quad));
        dimensions.scissor = ScissorMode::disabled;
        dimensions.scissorCount = 2; // Stale rectangles are irrelevant while scissor testing is off.
        assert(Scale(quad, dimensions, 1920, 1080));
        assert(!std::memcmp(quad, expected, sizeof(quad)));
    }

    const Geometry geometry = full(1512, 982);
    Vertex quad[4]{{0,982,0,0,0,-1,11,0,0}, {1512,982,0,0,0,-1,22,1,0},
                   {0,0,0,0,0,-1,33,0,1}, {1512,0,0,0,0,-1,44,1,1}};
    const auto decline = [&](Geometry candidate, unsigned refWidth = 1920, unsigned refHeight = 1080) {
        Vertex before[4];
        std::memcpy(before, quad, sizeof(quad));
        assert(!Scale(quad, candidate, refWidth, refHeight));
        assert(!std::memcmp(quad, before, sizeof(quad)));
    };
    decline(geometry, 1512, 982);
    decline(geometry, 0, 1080);
    decline(geometry, 1920, 16385);
    auto other = geometry;
    other.menuOutputBound = false; decline(other); // Same-size unrelated or offscreen target.
    other = geometry; other.scissor = ScissorMode::unavailable; decline(other);
    other = geometry; other.scissorLeft = 1; decline(other);
    other = geometry; other.scissorCount = 2; decline(other);
    other = geometry; other.viewportCount = 2; decline(other);
    other = geometry; other.viewportY = 0.25f; decline(other);
    other = geometry; other.viewportWidth = std::numeric_limits<float>::quiet_NaN(); decline(other);
    other = geometry; other.width = 1600; decline(other);
    quad[3].u = 0; decline(geometry); quad[3].u = 1;
    quad[3].nZ = 0; decline(geometry); quad[3].nZ = -1;
    quad[3].z = 0.125f; decline(geometry); quad[3].z = 0;
    quad[3].x = 1511.99f; decline(geometry); quad[3].x = 1512;
    quad[0].x = quad[2].x = -116;
    quad[1].x = quad[3].x = 1628;
    assert(!Expected(quad, 0, quad[0]));
    decline(geometry); // Centered, overwide background.
    quad[0].x = quad[2].x = 0;
    quad[1].x = quad[3].x = 1512;
    quad[0].y = quad[1].y = 0;
    quad[2].y = quad[3].y = 982;
    decline(geometry); // Opposite orientation.
}
'''
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / 'projection-scale-test'
            subprocess.run(['/usr/bin/c++', '-std=c++17', '-Wall', '-Wextra', '-Werror', '-I', str(HERE),
                            '-x', 'c++', '-', '-o', str(executable)], input=source, text=True, check=True, timeout=30)
            subprocess.run([executable], check=True, timeout=10)


if __name__ == '__main__':
    unittest.main()
