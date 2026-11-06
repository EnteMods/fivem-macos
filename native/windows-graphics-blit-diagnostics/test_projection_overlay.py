from pathlib import Path
import subprocess
import tempfile
import unittest

import gate_overlay
import overlay
import projection_overlay
import vertex_overlay


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def vertex_source():
    source = (ROOT / overlay.SOURCE).read_bytes()
    return vertex_overlay.apply(gate_overlay.apply(overlay.apply(source)))


class ProjectionOverlayTests(unittest.TestCase):
    def test_exact_reversal_and_off_path(self):
        original = vertex_source()
        candidate = projection_overlay.apply(original)
        self.assertEqual(projection_overlay.strip(candidate), original)
        for call in (b'beginImVertices(type, count);', b'addImVertex(x, y, z, nX, nY, nZ, color, u, v);',
                     b'drawImVertices();', b'popImShaderAndResetParams();'):
            self.assertEqual(candidate.count(call), original.count(call))
        with self.assertRaises(ValueError):
            projection_overlay.apply(original + b' ')
        with self.assertRaises(ValueError):
            projection_overlay.strip(candidate.replace(b'GetBuffer(0,', b'GetBuffer(1,'))

    def test_native_buffer_replays_original_arguments_once_on_rejection(self):
        candidate = projection_overlay.apply(vertex_source()).decode().replace('\r\n', '\n')
        first = candidate.index('#ifdef CFX_GRAPHICS_BLIT_PROJECTION\nnamespace\n')
        end = candidate.index('static hook::cdecl_stub<void(void*, void*, bool)> setScreenSpaceMatrix', first)
        wrappers = candidate[first:end]
        source = r'''
#include "GraphicsBlitProjection.h"
#include <atomic>
#include <cassert>
#include <cstdint>
#include <vector>
#define CFX_GRAPHICS_BLIT_PROJECTION
#define __declspec(x)
#define _ReturnAddress() nullptr
using cfx::blit::projection::Vertex;
bool glue = true;
unsigned emitted = 0;
std::vector<Vertex> seen;
std::vector<unsigned> calls;
namespace cfx::blit {
struct PreserveError {};
bool GlueCaller(const void*) { return glue; }
void Append(char*&, const char*) {}
void AppendUnsigned(char*&, unsigned) {}
}
unsigned GetCurrentProcessId() { return 1; }
unsigned GetCurrentThreadId() { return 2; }
void OutputDebugStringA(const char*) { assert(calls.back() == 3); ++emitted; }
uint32_t _rotl(uint32_t v, unsigned shift) { return (v << shift) | (v >> (32 - shift)); }
void beginImVertices(int, int) { calls.push_back(1); }
void drawImVertices() { calls.push_back(3); }
void addImVertex(float x, float y, float z, float nx, float ny, float nz, uint32_t color, float u, float v)
{
    calls.push_back(2);
    seen.push_back({x, y, z, nx, ny, nz, color, u, v});
}
''' + wrappers + r'''
namespace {
projection::Geometry geometry;
projection::Geometry ProjectionGeometry() { return geometry; }
}

void start(bool arm = true)
{
    seen.clear();
    calls.clear();
    cfxProjection.armed = arm;
    rage::grcBegin(4, 4);
}
void vertex(unsigned i, float x = 0)
{
    const bool right = i & 1, bottom = i & 2;
    rage::grcVertex(x + (right ? 1512 : 0), bottom ? 0 : 982, 0, 0, 0, -1,
        0xaabbccdd, right ? 1 : 0, bottom ? 1 : 0);
}
void quad() { for (unsigned i = 0; i < 4; ++i) vertex(i); }
void check(unsigned i, float x, float y)
{
    const auto& v = seen.at(i);
    assert(v.x == x && v.y == y && v.z == 0 && v.nX == 0 && v.nY == 0 && v.nZ == -1);
    assert(v.color == 0xaaddccbb && v.u == (i & 1 ? 1 : 0) && v.v == (i & 2 ? 1 : 0));
}
int main()
{
    geometry.width = geometry.viewportWidth = geometry.scissorRight = 1512;
    geometry.height = geometry.viewportHeight = geometry.scissorBottom = 982;
    geometry.viewportCount = geometry.scissorCount = 1;
    geometry.scissor = projection::ScissorMode::enabled;
    geometry.menuOutputBound = true;

    start(false); quad(); assert(seen.size() == 4); rage::grcEnd();
    check(0, 0, 982); check(1, 1512, 982); assert(emitted == 0);

    start(); quad(); assert(seen.empty()); rage::grcEnd();
    assert((calls == std::vector<unsigned>{1, 2, 2, 2, 2, 3}));
    check(0, 0, 1080); check(1, 1920, 1080); check(2, 0, 0); check(3, 1920, 0);
    assert(emitted == 1);

    geometry.scissorRight = 1511;
    start(); quad(); rage::grcEnd();
    assert(seen.size() == 4); check(0, 0, 982); check(1, 1512, 982); assert(emitted == 1);
    geometry.scissorRight = 1512;

    start(); vertex(0); vertex(1, -163); vertex(2); vertex(3);
    assert(seen.size() == 4); rage::grcEnd();
    check(0, 0, 982); check(1, 1349, 982); assert(emitted == 1);

    start(); quad(); vertex(0); assert(seen.size() == 5); rage::grcEnd();
    check(0, 0, 982); check(1, 1512, 982); assert(emitted == 1);

    start(); vertex(0); glue = false; vertex(1); assert(seen.size() == 2);
    glue = true; vertex(2); vertex(3); rage::grcEnd(); check(1, 1512, 982);

    start(); vertex(0); rage::grcBegin(4, 4);
    assert((calls == std::vector<unsigned>{1, 2, 1}));
    quad(); rage::grcEnd(); assert(seen.size() == 5 && emitted == 1);

    start(); vertex(0); rage::grcEnd();
    assert(seen.size() == 1 && emitted == 1); check(0, 0, 982);
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / 'projection-control'
            subprocess.run(['clang++', '-std=c++17', '-I', str(HERE), '-x', 'c++', '-', '-o', str(binary)],
                           input=source, text=True, check=True)
            subprocess.run([str(binary)], cwd=tmp, check=True)


if __name__ == '__main__':
    unittest.main()
