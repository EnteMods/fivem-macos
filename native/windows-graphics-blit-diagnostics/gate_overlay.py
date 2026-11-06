"""Add bounded rejection metadata to the exact V1 DrawCommands overlay."""
import hashlib

SOURCE_PIN = (23750, 'b2fb405fa89923103d5a4ed01c7eb5f82e2c973be48b59a38e2b51145d6dc826')
HEADER = 'GraphicsBlitGateDiagnostics.h'
DEFINE = 'CFX_GRAPHICS_BLIT_GATE_DIAGNOSTICS'


def conditional(before, diagnostic):
    return before, f'#ifdef {DEFINE}\n{diagnostic}#else\n{before}#endif\n'


def append(before, diagnostic):
    return before, before + f'#ifdef {DEFINE}\n{diagnostic}#endif\n'


def crlf(text):
    return text.replace('\n', '\r\n').encode('ascii')


CHANGES = tuple((crlf(before), crlf(after)) for before, after in (
    append('#include "GraphicsBlitDiagnostics.h"\n', '#include "GraphicsBlitGateDiagnostics.h"\n'),
    conditional(
        '\t\tcfxBlitQuad.Begin(cfxBlitQuad.WantsBegin(type, count)\n'
        '\t\t\t&& cfx::blit::HasBudget() && cfx::blit::GlueCaller(_ReturnAddress()));\n',
        '\t\tconst auto caller = _ReturnAddress();\n'
        '\t\tcfx::blit::gate::Emit(cfx::blit::gate::Begin(cfxBlitQuad, type, count,\n'
        '\t\t\tcfx::blit::HasBudget, [caller] { return cfx::blit::GlueCaller(caller); }));\n'),
    conditional(
        '\t\tcfxBlitQuad.Vertex(x, y, z, u, v);\n',
        '\t\tcfx::blit::gate::Emit(cfx::blit::gate::Vertex(cfxBlitQuad, x, y, z, u, v));\n'),
    conditional(
        '\t\tif (cfxBlitQuad.End()) TraceBlitSubmission();\n',
        '\t\tconst auto stage = cfx::blit::gate::End(cfxBlitQuad);\n'
        '\t\tcfx::blit::gate::Emit(stage);\n'
        '\t\tif (stage == cfx::blit::gate::Stage::quadComplete) TraceBlitSubmission();\n'),
    append('\tcfxBlitQuad.Push();\n', '\tcfx::blit::gate::Emit(cfx::blit::gate::Stage::push);\n'),
    ('\tcfxBlitQuad.Pop();\n',
     f'#ifdef {DEFINE}\n'
     '\tif (cfxBlitQuad.armed) cfx::blit::gate::Emit(cfx::blit::gate::Stage::popWhileArmed);\n'
     '#endif\n\tcfxBlitQuad.Pop();\n'),
    conditional(
        '\tif (!g_d3d11Device || g_renderThreadTlsIndex <= 0 || g_d3d11DeviceContextOffset <= 0)\n'
        '\t\treturn;\n'
        '\tconst auto tls = hook::get_tls();\n'
        '\tif (!tls || (*reinterpret_cast<const int32_t*>(tls + g_renderThreadTlsIndex) & 2) == 0)\n'
        '\t\treturn;\n'
        '\tcfx::blit::Record(*reinterpret_cast<ID3D11DeviceContext* const*>(tls + g_d3d11DeviceContextOffset), cfxBlitQuad);\n',
        '\tusing namespace cfx::blit::gate;\n'
        '\tconst auto offsets = Offsets(g_d3d11Device != nullptr, g_renderThreadTlsIndex, g_d3d11DeviceContextOffset);\n'
        '\tif (offsets != Stage::none)\n'
        '\t{\n\t\tEmit(offsets);\n\t\treturn;\n\t}\n'
        '\tconst auto tls = hook::get_tls();\n'
        '\tconst auto thread = Thread(tls != nullptr, tls && (*reinterpret_cast<const int32_t*>(tls + g_renderThreadTlsIndex) & 2) != 0);\n'
        '\tif (thread != Stage::none)\n'
        '\t{\n\t\tEmit(thread);\n\t\treturn;\n\t}\n'
        '\tauto* context = *reinterpret_cast<ID3D11DeviceContext* const*>(tls + g_d3d11DeviceContextOffset);\n'
        '\tEmit(Context(context != nullptr));\n'
        '\tcfx::blit::Record(context, cfxBlitQuad);\n'),
))


def require_source(data):
    if type(data) is not bytes or (len(data), hashlib.sha256(data).hexdigest()) != SOURCE_PIN:
        raise ValueError('Require exact V1 DrawCommands overlay')


def apply(data):
    require_source(data)
    for before, after in CHANGES:
        if data.count(before) != 1 or after in data:
            raise ValueError('Unexpected DrawCommands gate anchor scope')
        data = data.replace(before, after, 1)
    return data


def strip(data):
    for before, after in reversed(CHANGES):
        if data.count(after) != 1:
            raise ValueError('Unexpected DrawCommands gate diagnostic scope')
        data = data.replace(after, before, 1)
    require_source(data)
    return data
