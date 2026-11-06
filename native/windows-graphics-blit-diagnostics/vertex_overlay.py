"""Add bounded actual vertex and pre-draw context metadata to the exact gate overlay."""
import hashlib

SOURCE_PIN = (25382, 'c0add772f5cf5a7d034938036461db9055af6d811b0e416acbb0187b426ca35c')
HEADER = 'GraphicsBlitVertexDiagnostics.h'
DEFINE = 'CFX_GRAPHICS_BLIT_VERTEX_DIAGNOSTICS'


def append(before, extra):
    return before, before + f'#ifdef {DEFINE}\n{extra}#endif\n'


BEGIN = ('\t\tcfx::blit::gate::Emit(cfx::blit::gate::Begin(cfxBlitQuad, type, count,\n'
         '\t\t\tcfx::blit::HasBudget, [caller] { return cfx::blit::GlueCaller(caller); }));\n')
TRACE_END = ('\tcfx::blit::Record(*reinterpret_cast<ID3D11DeviceContext* const*>(tls + g_d3d11DeviceContextOffset), cfxBlitQuad);\n'
             '#endif\n}\n')
TRACE = '''
static void TraceBlitVertices(bool legacy)
{
\tusing namespace cfx::blit;
\tif (!cfxBlitVertices.Active())
\t\treturn;
\tPreserveError saved;
\tvertices::Pattern pattern;
\tconst auto seen = cfxBlitVertices.Finish(pattern);
\tif (seen != 4)
\t{
\t\tvertices::EmitCount(seen);
\t\treturn;
\t}
\tstatic vertices::UniquePatterns patterns;
\tconst auto id = patterns.First(pattern);
\tif (!id)
\t\treturn;

\tauto status = gate::Offsets(g_d3d11Device != nullptr, g_renderThreadTlsIndex, g_d3d11DeviceContextOffset);
\tID3D11DeviceContext* context = nullptr;
\tif (status == gate::Stage::none)
\t{
\t\tconst auto tls = hook::get_tls();
\t\tstatus = gate::Thread(tls != nullptr, tls && (*reinterpret_cast<const int32_t*>(tls + g_renderThreadTlsIndex) & 2) != 0);
\t\tif (status == gate::Stage::none)
\t\t{
\t\t\tcontext = *reinterpret_cast<ID3D11DeviceContext* const*>(tls + g_d3d11DeviceContextOffset);
\t\t\tstatus = gate::Context(context != nullptr);
\t\t}
\t}
\tvertices::Emit(pattern, id, legacy, status, context);
}
'''


CHANGES = tuple((before.replace('\n', '\r\n').encode('ascii'), after.replace('\n', '\r\n').encode('ascii'))
                for before, after in (
    append('#include "GraphicsBlitGateDiagnostics.h"\n', f'#include "{HEADER}"\n'),
    append('static void TraceBlitSubmission();\n',
           'static thread_local cfx::blit::vertices::Capture cfxBlitVertices;\n'
           'static void TraceBlitVertices(bool legacy);\n'),
    (BEGIN, f'#ifdef {DEFINE}\n'
     '\t\tconst auto stage = cfx::blit::gate::Begin(cfxBlitQuad, type, count,\n'
     '\t\t\tcfx::blit::HasBudget, [caller] { return cfx::blit::GlueCaller(caller); });\n'
     '\t\tcfxBlitVertices.Begin(stage);\n'
     '\t\tcfx::blit::gate::Emit(stage);\n'
     f'#else\n{BEGIN}#endif\n'),
    ('\t\tcfx::blit::gate::Emit(cfx::blit::gate::Vertex(cfxBlitQuad, x, y, z, u, v));\n',
     f'#ifdef {DEFINE}\n\t\tcfxBlitVertices.Vertex(x, y, z, u, v);\n#endif\n'
     '\t\tcfx::blit::gate::Emit(cfx::blit::gate::Vertex(cfxBlitQuad, x, y, z, u, v));\n'),
    append('\t\tif (stage == cfx::blit::gate::Stage::quadComplete) TraceBlitSubmission();\n',
           '\t\tTraceBlitVertices(stage == cfx::blit::gate::Stage::quadComplete);\n'),
    append('\tcfxBlitQuad.Push();\n', '\tcfxBlitVertices.Reset();\n'),
    append('\tcfxBlitQuad.Pop();\n', '\tcfxBlitVertices.Reset();\n'),
    append(TRACE_END, TRACE),
))


def require_source(data):
    if type(data) is not bytes or (len(data), hashlib.sha256(data).hexdigest()) != SOURCE_PIN:
        raise ValueError('Require exact gate DrawCommands overlay')


def apply(data):
    require_source(data)
    for before, after in CHANGES:
        if data.count(before) != 1 or after in data:
            raise ValueError('Unexpected DrawCommands vertex anchor scope')
        data = data.replace(before, after, 1)
    return data


def strip(data):
    for before, after in reversed(CHANGES):
        if data.count(after) != 1:
            raise ValueError('Unexpected DrawCommands vertex diagnostic scope')
        data = data.replace(after, before, 1)
    require_source(data)
    return data
