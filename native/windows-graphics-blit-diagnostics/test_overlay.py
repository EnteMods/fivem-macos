import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import overlay

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


class OverlayTests(unittest.TestCase):
    def test_exact_roundtrip_and_original_forwards(self):
        original = (ROOT / overlay.SOURCE).read_bytes()
        patched = overlay.apply(original)
        self.assertEqual(overlay.strip(patched), original)
        for anchor in (b'beginImVertices(type, count);',
                       b'addImVertex(x, y, z, nX, nY, nZ, color, u, v);',
                       b'drawImVertices();', b'popImShaderAndResetParams();',
                       b'setSubShaderUnk(*gtaImShader, 0);'):
            self.assertEqual(patched.count(anchor), 1)

    def test_reject_modified_original_and_overlay(self):
        original = (ROOT / overlay.SOURCE).read_bytes()
        with self.assertRaises(ValueError):
            overlay.apply(original + b' ')
        with self.assertRaises(ValueError):
            overlay.strip(overlay.apply(original).replace(b'cfxBlitQuad.End()', b'false'))

    def test_native_quad_and_subpixels(self):
        source = r'''
#include "GraphicsBlitDiagnostics.h"
#include <cassert>
#include <limits>
using cfx::blit::Quad;

void begin(Quad& q)
{
    q.Push();
    assert(q.WantsBegin(4, 4) && !q.WantsBegin(4, 3));
    q.Begin(true);
}

void vertices(Quad& q, float width = 1512, float x = 1512, float u = 1)
{
    q.Vertex(0, 0, 0, 0, 0);
    q.Vertex(width, 0, 0, 1, 0);
    q.Vertex(0, 982, 0, 0, 1);
    q.Vertex(x, 982, 0, u, 1);
}

int main()
{
    Quad q;
    q.Begin(true); vertices(q); assert(!q.End());
    q.Push(); q.Begin(false); vertices(q); assert(!q.End());
    begin(q); vertices(q); assert(q.End() && q.width == 1512 && q.height == 982);
    assert(!q.WantsBegin(4, 4) && !q.End());
    begin(q); vertices(q, 1512, 1511); assert(!q.End());
    begin(q); vertices(q, 1512, 1512, 0); assert(!q.End());
    begin(q); vertices(q, std::numeric_limits<float>::quiet_NaN()); assert(!q.End());
    begin(q); vertices(q); q.Vertex(0, 0, 0, 0, 0); assert(!q.End());
    begin(q); q.Pop(); vertices(q); assert(!q.End());
    bool valid = true;
    assert(cfx::blit::Subpixels(-0.125f, valid) == -2 && valid);
    assert(cfx::blit::Subpixels(1512.5f, valid) == 24200 && valid);
    assert(cfx::blit::Subpixels(std::numeric_limits<float>::infinity(), valid) == 0 && !valid);
}
'''
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'test'
            subprocess.run(['/usr/bin/c++', '-std=c++17', '-Wall', '-Wextra', '-Werror',
                            '-I', os.fspath(HERE), '-x', 'c++', '-', '-o', os.fspath(binary)],
                           input=source, text=True, check=True)
            subprocess.run([binary], check=True, timeout=10)


if __name__ == '__main__':
    unittest.main()
