from pathlib import Path
import subprocess
import tempfile
import unittest

import native_extents_fast_overlay as overlay


HERE = Path(__file__).resolve().parent
BASE = HERE.parents[1] / 'build/windows-graphics-blit-projection-sharpness-native-extents/overlay'


class NativeExtentsFastTests(unittest.TestCase):
    def test_actual_replay_skips_geometry_only_if_both_axes_are_native(self):
        original = (BASE / 'DrawCommands.cpp').read_bytes()
        patched = overlay.apply(original)
        self.assertEqual(overlay.strip(patched), original)
        with self.assertRaises(ValueError):
            overlay.apply(original + b' ')
        unit = patched.decode('ascii')
        replay = unit[unit.index('ProjectionSize ReplayProjection('):unit.index('void EmitProjection(')]
        source = r'''
#include "GraphicsBlitProjection.h"
#include <cassert>
#include <cstring>
namespace projection = cfx::blit::projection;
namespace cfx::blit { struct PreserveError { ~PreserveError() {} }; }
constexpr unsigned ProjectionReferenceWidth = 1920, ProjectionReferenceHeight = 1080;
struct ProjectionSize { unsigned width = 0, height = 0; bool adjusted = false; };
struct ProjectionDraw { projection::Vertex vertices[4]{}; unsigned count = 0; bool armed = false, active = false; };
ProjectionDraw cfxProjection;
projection::Geometry geometry;
projection::Vertex forwarded[4];
unsigned queries, calls;
projection::Geometry ProjectionGeometry() { ++queries; return geometry; }
void addImVertex(float x, float y, float z, float nx, float ny, float nz, std::uint32_t color, float u, float v)
{
    assert(calls < 4);
    forwarded[calls++] = {x,y,z,nx,ny,nz,color,u,v};
}
''' + replay + r'''
static void check(unsigned w, unsigned h, unsigned expectedQueries, bool expectedChange)
{
    geometry = {w,h,1,0,0,float(w),float(h),projection::ScissorMode::disabled,0,0,0,0,0,true};
    projection::Vertex original[4]{{-0.0f,float(h),0,0,0,-1,11,0,0},{float(w),float(h),0,0,0,-1,22,1,0},
                                   {0,0,0,0,0,-1,33,0,1},{float(w),0,0,0,0,-1,44,1,1}};
    cfxProjection.count = 4;
    cfxProjection.active = true;
    std::memcpy(cfxProjection.vertices, original, sizeof(original));
    queries = calls = 0;
    auto result = ReplayProjection(true);
    assert(queries == expectedQueries && calls == 4 && result.adjusted == expectedChange);
    assert(result.width == (expectedChange ? w : 0));
    if (w < 1920) original[1].x = original[3].x = 1920;
    if (h < 1080) original[2].y = original[3].y = float(h) - 1080;
    assert(!std::memcmp(forwarded, original, sizeof(original)));
}
int main()
{
    check(3016,1694,0,false);
    check(1920,1080,0,false);
    check(1280,720,1,true);
    check(3016,720,1,true);
    check(1280,1694,1,true);
}
'''
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'fast-replay-test'
            subprocess.run(['/usr/bin/c++', '-std=c++17', '-Wall', '-Wextra', '-Werror', '-I', str(BASE),
                            '-x', 'c++', '-', '-o', str(binary)], input=source, text=True, check=True, timeout=30)
            subprocess.run([binary], check=True, timeout=10)


if __name__ == '__main__':
    unittest.main()
