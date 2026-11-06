from pathlib import Path
import subprocess
import tempfile
import unittest

import gate_overlay
import overlay
import vertex_overlay

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


class VertexOverlayTests(unittest.TestCase):
    def test_exact_reversal_preserves_original_draw_calls(self):
        original = (ROOT / overlay.SOURCE).read_bytes()
        gate = gate_overlay.apply(overlay.apply(original))
        candidate = vertex_overlay.apply(gate)
        self.assertEqual(vertex_overlay.strip(candidate), gate)
        for call in (b'beginImVertices(type, count);', b'addImVertex(x, y, z, nX, nY, nZ, color, u, v);',
                     b'drawImVertices();', b'popImShaderAndResetParams();'):
            self.assertEqual(candidate.count(call), 1)
        with self.assertRaises(ValueError):
            vertex_overlay.apply(gate + b' ')
        with self.assertRaises(ValueError):
            vertex_overlay.strip(candidate.replace(b'vertices::Emit(pattern', b'other::Emit(pattern'))

    def test_native_capture_outlasts_legacy_reject_and_reserves_large_patterns(self):
        source = r'''
#include "GraphicsBlitVertexDiagnostics.h"
#include <cassert>
#include <limits>
using cfx::blit::Quad;
using namespace cfx::blit::gate;
using namespace cfx::blit::vertices;

int main()
{
    Quad old;
    Capture capture;
    Pattern pattern{};
    auto begin = [&](int count, bool glue) {
        old.Push();
        const auto stage = Begin(old, 4, count, []{ return true; }, [=]{ return glue; });
        capture.Begin(stage);
    };
    auto vertex = [&](float x, float y, float z, float u, float v) {
        capture.Vertex(x, y, z, u, v);
        return Vertex(old, x, y, z, u, v);
    };
    begin(4, true);
    assert(vertex(0, 982, -0.03125f, 0, 0) == Stage::vertexRejected);
    assert(vertex(1512, 982, 0, 1, 0) == Stage::none);
    assert(vertex(0, 0, 0, 0, 1) == Stage::none);
    assert(vertex(1512, 0, 0, 1, 1) == Stage::none);
    assert(End(old) != Stage::quadComplete);
    assert(capture.Finish(pattern) == 4 && !capture.Active());
    const Pattern reversed{0,15712,-128,0,0, 24192,15712,0,4096,0, 0,0,0,0,4096, 24192,0,0,4096,4096};
    assert(pattern == reversed);

    begin(3, true); vertex(0, 0, 0, 0, 0); assert(capture.Finish(pattern) == Inactive);
    begin(4, false); vertex(0, 0, 0, 0, 0); assert(capture.Finish(pattern) == Inactive);
    begin(4, true); vertex(0, 0, 0, 0, 0); assert(capture.Finish(pattern) == 1);
    begin(4, true); capture.Reset(); assert(capture.Finish(pattern) == Inactive);
    begin(4, true);
    for (int i = 0; i < 8; ++i) vertex(0, 0, 0, 0, 0);
    assert(capture.Finish(pattern) == Extra);
    for (float bad : {std::numeric_limits<float>::quiet_NaN(), std::numeric_limits<float>::infinity(), 65537.f})
    {
        begin(4, true);
        for (int i = 0; i < 4; ++i) vertex(bad, 0, 0, 0, 0);
        assert(capture.Finish(pattern) == Invalid);
    }

    UniquePatterns unique;
    for (int i = 0; i < 4; ++i)
    {
        Pattern small{};
        small[2] = i;
        assert(unique.First(small) == unsigned(i + 1) && !unique.First(small));
    }
    Pattern small{};
    small[2] = 4;
    assert(!unique.First(small));
    for (int i = 0; i < 4; ++i)
    {
        auto large = reversed;
        large[2] = i;
        assert(unique.First(large) == unsigned(i + 5) && !unique.First(large));
    }
    assert(!unique.First(reversed));
}
'''
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'vertex-test'
            subprocess.run(['/usr/bin/c++', '-std=c++17', '-Wall', '-Wextra', '-Werror',
                            '-I', str(HERE), '-x', 'c++', '-', '-o', str(binary)],
                           input=source, text=True, check=True, timeout=30)
            subprocess.run([binary], check=True, timeout=10)


if __name__ == '__main__':
    unittest.main()
