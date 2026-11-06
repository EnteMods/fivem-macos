from pathlib import Path
import subprocess
import tempfile
import unittest

import gate_overlay
import overlay

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


class GateOverlayTests(unittest.TestCase):
    def test_reverses_both_overlays(self):
        original = (ROOT / overlay.SOURCE).read_bytes()
        baseline = overlay.apply(original)
        candidate = gate_overlay.apply(baseline)
        self.assertEqual(gate_overlay.strip(candidate), baseline)
        self.assertEqual(overlay.strip(gate_overlay.strip(candidate)), original)
        for anchor in (b'beginImVertices(type, count);', b'drawImVertices();',
                       b'addImVertex(x, y, z, nX, nY, nZ, color, u, v);',
                       b'setScreenSpaceMatrix(nullptr, nullptr, true);', b'popImShaderAndResetParams();'):
            self.assertEqual(candidate.count(anchor), 1)

    def test_refuses_changed_input_or_output(self):
        baseline = overlay.apply((ROOT / overlay.SOURCE).read_bytes())
        with self.assertRaises(ValueError):
            gate_overlay.apply(baseline + b' ')
        with self.assertRaises(ValueError):
            gate_overlay.strip(gate_overlay.apply(baseline).replace(b'Emit(offsets);', b'Emit(thread);'))

    def test_native_classifies_negative_paths_and_emits_each_gate_once(self):
        source = r'''
#include "GraphicsBlitGateDiagnostics.h"
#include <cassert>
using cfx::blit::Quad;
using namespace cfx::blit::gate;

int main()
{
    Quad q;
    unsigned budgetCalls = 0, glueCalls = 0;
    bool budget = true, glue = true;
    const auto hasBudget = [&] { ++budgetCalls; return budget; };
    const auto isGlue = [&] { ++glueCalls; return glue; };
    assert(Begin(q, 4, 4, hasBudget, isGlue) == Stage::none);
    q.Push();
    assert(Begin(q, 4, 3, hasBudget, isGlue) == Stage::beginPrimitive && !q.armed);
    assert(budgetCalls == 0 && glueCalls == 0);
    q.Push(); budget = false;
    assert(Begin(q, 4, 4, hasBudget, isGlue) == Stage::beginBudget && !q.armed);
    assert(budgetCalls == 1 && glueCalls == 0);
    q.Push(); budget = true; glue = false;
    assert(Begin(q, 4, 4, hasBudget, isGlue) == Stage::beginCaller && !q.armed);
    assert(budgetCalls == 2 && glueCalls == 1);
    glue = true;
    const auto admit = [&] { q.Push(); assert(Begin(q, 4, 4, hasBudget, isGlue) == Stage::beginAdmitted); };
    admit();
    assert(Vertex(q, 0, 1, 0, 0, 0) == Stage::vertexRejected && End(q) == Stage::none);
    admit();
    assert(Vertex(q, 0, 0, 0, 0, 0) == Stage::none && End(q) == Stage::endIncomplete);
    admit();
    assert(Vertex(q, 0, 0, 0, 0, 0) == Stage::none);
    assert(Vertex(q, 1280, 0, 0, 1, 0) == Stage::none);
    assert(Vertex(q, 0, 720, 0, 0, 1) == Stage::none);
    assert(Vertex(q, 1280, 720, 0, 1, 1) == Stage::none);
    assert(End(q) == Stage::quadComplete && q.width == 1280 && q.height == 720);
    assert(Offsets(false, 0, 0) == Stage::deviceSlotMissing);
    assert(Offsets(true, 0, 0) == Stage::renderIndexNonpositive);
    assert(Offsets(true, 1, 0) == Stage::contextOffsetNonpositive);
    assert(Offsets(true, 1, 1) == Stage::none);
    assert(Thread(false, true) == Stage::gameTlsMissing);
    assert(Thread(true, false) == Stage::renderThreadBitUnset);
    assert(Thread(true, true) == Stage::none);
    assert(Context(false) == Stage::contextNull && Context(true) == Stage::contextReady);
    std::atomic<unsigned> seen{0};
    assert(!First(seen, Stage::none));
    for (unsigned i = 1; i <= 16; ++i)
    {
        auto stage = static_cast<Stage>(i);
        assert(First(seen, stage) && !First(seen, stage));
    }
    assert(seen.load() == 0xffff);
}
'''
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'gate-test'
            subprocess.run(['/usr/bin/c++', '-std=c++17', '-Wall', '-Wextra', '-Werror',
                            '-I', str(HERE), '-x', 'c++', '-', '-o', str(binary)],
                           input=source, text=True, check=True, timeout=30)
            subprocess.run([binary], check=True, timeout=10)


if __name__ == '__main__':
    unittest.main()
