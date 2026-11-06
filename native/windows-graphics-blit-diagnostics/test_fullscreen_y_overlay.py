from pathlib import Path
import subprocess
import tempfile
import unittest

import fullscreen_y_overlay as overlay


HERE = Path(__file__).resolve().parent
BASE = HERE.parents[1] / 'build/windows-graphics-blit-projection-native-extents-fast/overlay/DrawCommands.cpp'


class FullscreenYTests(unittest.TestCase):
    def test_reversal_preserves_low_axis_and_original_draw_paths(self):
        original = BASE.read_bytes()
        candidate = overlay.apply(original)
        self.assertEqual(overlay.strip(candidate), original)
        for token in (b'pending.vertices[1].x < ProjectionReferenceWidth', b'drawImVertices();',
                      b'addImVertex(v.x, v.y, v.z, v.nX, v.nY, v.nZ, v.color, v.u, v.v);'):
            self.assertEqual(candidate.count(token), original.count(token))
        self.assertIn(b'else if (allowScaling && pending.active && pending.count == 4)\r\n\t\tReplayFullscreenY', candidate)

    def test_native_dynamic_height_and_monitor_geometry(self):
        source = r'''
#include "GraphicsBlitFullscreenY.h"
#include <cassert>
#include <cstring>
using namespace cfx::blit::projection;

static void transition(unsigned startup, unsigned fullWidth, unsigned fullHeight)
{
    int chain = 0, window = 0, otherChain = 0, otherWindow = 0;
    FullscreenYReference reference;
    assert(reference.Learn(&chain, &window, startup, false));
    assert(!reference.Learn(&chain, &window, startup + 1, false));
    const float w = float(fullWidth), h = float(fullHeight);
    Vertex quad[4]{{0,h,0,0,0,-1,11,0,0},{w,h,0,0,0,-1,22,1,0},
                   {0,-0.0f,0,0,0,-1,33,0,1},{w,0,0,0,0,-1,44,1,1}};
    Vertex unchanged[4];
    std::memcpy(unchanged, quad, sizeof(quad));
    assert(!reference.Apply(quad, &otherChain, &window, fullHeight, true));
    assert(!reference.Apply(quad, &chain, &otherWindow, fullHeight, true));
    assert(!reference.Apply(quad, &chain, &window, fullHeight, false));
    assert(!reference.Apply(quad, &chain, &window, startup, true));
    assert(!std::memcmp(quad, unchanged, sizeof(quad)));
    assert(reference.Apply(quad, &chain, &window, fullHeight, true));
    unchanged[0].y = unchanged[1].y = float(startup);
    assert(!std::memcmp(quad, unchanged, sizeof(quad)));

    FullscreenYReference startedFullscreen;
    assert(!startedFullscreen.Learn(&chain, &window, fullHeight, true));
    assert(startedFullscreen.observed && !startedFullscreen.Learn(&chain, &window, startup, false));
    assert(!startedFullscreen.Apply(quad, &chain, &window, fullHeight, true));
}

int main()
{
    const Bounds monitor{0,0,3024,1964};
    assert(SpansMonitor({0,66,3024,1964}, monitor));
    assert(SpansMonitor({0,128,3024,1964}, monitor));
    assert(SpansMonitor({-2560,-40,0,1440}, {-2560,-40,0,1440}));
    assert(!SpansMonitor({4,66,3020,1964}, monitor));
    assert(!SpansMonitor({0,66,3024,1900}, monitor));
    assert(!SpansMonitor({0,129,3024,1964}, monitor));
    assert(!SpansMonitor({0,-1,3024,1964}, monitor));
    transition(1694,3024,1898);
    transition(1514,2880,1800);
}
'''
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'fullscreen-y-test'
            subprocess.run(['/usr/bin/c++', '-std=c++17', '-Wall', '-Wextra', '-Werror', '-I', str(HERE),
                            '-x', 'c++', '-', '-o', str(binary)], input=source, text=True, check=True, timeout=30)
            subprocess.run([binary], check=True, timeout=10)


if __name__ == '__main__':
    unittest.main()
