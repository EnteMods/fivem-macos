"""Reversible, diagnostics-only changes to the pinned DrawCommands translation unit."""
import hashlib

SOURCE = 'port/fivem/code/components/rage-graphics-five/src/DrawCommands.cpp'
SOURCE_PIN = (22498, '8a0eca3062d5f7e3020b558f8b650cf80fe68f7d7db4aa234b47b3340202f323')
HEADER = 'GraphicsBlitDiagnostics.h'
DEFINE = 'CFX_GRAPHICS_BLIT_DIAGNOSTICS'
GUARD = '#ifdef ' + DEFINE


def code(value):
    return value.replace('\n', '\r\n').encode('ascii')


def append(before, diagnostic):
    return before, before + f'{GUARD}\n{diagnostic}\n#endif\n'


CHANGES = tuple((code(before), code(after)) for before, after in (
    append('#include "DrawCommands.h"\n', '#include "GraphicsBlitDiagnostics.h"'),
    append('static int32_t g_renderThreadTlsIndex;\n',
           'static thread_local cfx::blit::Quad cfxBlitQuad;\nstatic void TraceBlitSubmission();'),
    ('\tvoid grcBegin(int type, int count)\n',
     f'{GUARD}\n\t__declspec(noinline)\n#endif\n\tvoid grcBegin(int type, int count)\n'),
    ('\t\tbeginImVertices(type, count);\n',
     f'{GUARD}\n\t\tcfxBlitQuad.Begin(cfxBlitQuad.WantsBegin(type, count)\n'
     '\t\t\t&& cfx::blit::HasBudget() && cfx::blit::GlueCaller(_ReturnAddress()));\n'
     '#endif\n\t\tbeginImVertices(type, count);\n'),
    ('\t\taddImVertex(x, y, z, nX, nY, nZ, color, u, v);\n',
     f'{GUARD}\n\t\tcfxBlitQuad.Vertex(x, y, z, u, v);\n'
     '#endif\n\t\taddImVertex(x, y, z, nX, nY, nZ, color, u, v);\n'),
    ('\t\tdrawImVertices();\n',
     f'{GUARD}\n\t\tif (cfxBlitQuad.End()) TraceBlitSubmission();\n'
     '#endif\n\t\tdrawImVertices();\n'),
    append('\tsetSubShaderUnk(*gtaImShader, 0);\n', '\tcfxBlitQuad.Push();'),
    ('\tpopImShaderAndResetParams();\n',
     f'{GUARD}\n\tcfxBlitQuad.Pop();\n#endif\n\tpopImShaderAndResetParams();\n'),
    append('ID3D11DeviceContext* GetD3D11DeviceContext()\n{\n'
           '\treturn *(ID3D11DeviceContext**)(hook::get_tls() + g_d3d11DeviceContextOffset);\n}\n',
           '''
static void TraceBlitSubmission()
{
\tcfx::blit::PreserveError saved;
\tif (!g_d3d11Device || g_renderThreadTlsIndex <= 0 || g_d3d11DeviceContextOffset <= 0)
\t\treturn;
\tconst auto tls = hook::get_tls();
\tif (!tls || (*reinterpret_cast<const int32_t*>(tls + g_renderThreadTlsIndex) & 2) == 0)
\t\treturn;
\tcfx::blit::Record(*reinterpret_cast<ID3D11DeviceContext* const*>(tls + g_d3d11DeviceContextOffset), cfxBlitQuad);
}'''),
))


def require_source(data):
    if type(data) is not bytes or (len(data), hashlib.sha256(data).hexdigest()) != SOURCE_PIN:
        raise ValueError('Require pinned DrawCommands bytes')


def apply(data):
    require_source(data)
    for before, after in CHANGES:
        if data.count(before) != 1 or after in data:
            raise ValueError('Unexpected DrawCommands anchor scope')
        data = data.replace(before, after, 1)
    return data


def strip(data):
    for before, after in reversed(CHANGES):
        if data.count(after) != 1:
            raise ValueError('Unexpected DrawCommands diagnostic scope')
        data = data.replace(after, before, 1)
    require_source(data)
    return data
