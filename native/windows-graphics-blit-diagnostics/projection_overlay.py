"""Opt-in coordinate A/B over the exact existing vertex census translation unit."""
import hashlib

SOURCE_PIN = (27359, '1e90d3540cd4b690938a5534529d01958be7e7189846fe0dde3190946d823a53')
HEADER = 'GraphicsBlitProjection.h'
DEFINE = 'CFX_GRAPHICS_BLIT_PROJECTION'


def guarded(code):
    return f'#ifdef {DEFINE}\n{code}#endif\n'


INCLUDES = f'''#if !defined(CFX_GRAPHICS_BLIT_DIAGNOSTICS) || !defined(CFX_GRAPHICS_BLIT_GATE_DIAGNOSTICS) || !defined(CFX_GRAPHICS_BLIT_VERTEX_DIAGNOSTICS)
#error The projection candidate requires the existing vertex census.
#endif
#include "{HEADER}"
#include <wrl/client.h>
'''

BUFFER = r'''namespace
{
namespace projection = cfx::blit::projection;
constexpr unsigned ProjectionReferenceWidth = 1920, ProjectionReferenceHeight = 1080;

struct ProjectionSize
{
	unsigned width = 0, height = 0;
};

struct ProjectionDraw
{
	projection::Vertex vertices[4]{};
	unsigned count = 0;
	bool armed = false, active = false;
};

thread_local ProjectionDraw cfxProjection;
projection::Geometry ProjectionGeometry();

ProjectionSize ReplayProjection(bool allowScaling)
{
	ProjectionSize size;
	if (!cfxProjection.count)
	{
		cfxProjection.armed = cfxProjection.active = false;
		return size;
	}
	// Disarm before forwarding so a nested call cannot replay these vertices twice.
	auto pending = cfxProjection;
	cfxProjection = {};
	if (allowScaling && pending.active && pending.count == 4)
	{
		cfx::blit::PreserveError saved;
		const auto geometry = ProjectionGeometry();
		if (projection::Scale(pending.vertices, geometry, ProjectionReferenceWidth, ProjectionReferenceHeight))
			size = {geometry.width, geometry.height};
	}
	for (unsigned i = 0; i < pending.count; ++i)
	{
		const auto& v = pending.vertices[i];
		addImVertex(v.x, v.y, v.z, v.nX, v.nY, v.nZ, v.color, v.u, v.v);
	}
	return size;
}

void EmitProjection(ProjectionSize size)
{
	if (!size.width)
		return;
	static thread_local ProjectionSize previous;
	if (previous.width == size.width && previous.height == size.height)
		return;
	previous = size;
	static std::atomic<unsigned> remaining{8};
	auto budget = remaining.load(std::memory_order_relaxed);
	if (!budget || !remaining.compare_exchange_strong(budget, budget - 1, std::memory_order_relaxed))
		return;

	using namespace cfx::blit;
	PreserveError saved;
	char line[160], *out = line;
	static_assert(sizeof("[CFX_GRAPHICS_BLIT_PROJECTION] pid= tid= applied=1 width= height= ref_width= ref_height=\n") + 60 <= sizeof(line));
	Append(out, "[CFX_GRAPHICS_BLIT_PROJECTION] pid="); AppendUnsigned(out, GetCurrentProcessId());
	Append(out, " tid="); AppendUnsigned(out, GetCurrentThreadId());
	Append(out, " applied=1 width="); AppendUnsigned(out, size.width);
	Append(out, " height="); AppendUnsigned(out, size.height);
	Append(out, " ref_width="); AppendUnsigned(out, ProjectionReferenceWidth);
	Append(out, " ref_height="); AppendUnsigned(out, ProjectionReferenceHeight);
	*out++ = '\n'; *out = '\0';
	OutputDebugStringA(line);
}
}
'''

GEOMETRY = '''extern IDXGISwapChain** g_dxgiSwapChain;

namespace
{
projection::Geometry ProjectionGeometry()
{
	using Microsoft::WRL::ComPtr;
	using namespace cfx::blit;
	projection::Geometry geometry;
	if (gate::Offsets(g_d3d11Device != nullptr, g_renderThreadTlsIndex, g_d3d11DeviceContextOffset) != gate::Stage::none)
		return geometry;
	const auto tls = hook::get_tls();
	if (!tls || (*reinterpret_cast<const int32_t*>(tls + g_renderThreadTlsIndex) & 2) == 0)
		return geometry;
	auto* context = *reinterpret_cast<ID3D11DeviceContext* const*>(tls + g_d3d11DeviceContextOffset);
	auto* swapChain = g_dxgiSwapChain ? *g_dxgiSwapChain : nullptr;
	if (!context || !swapChain)
		return geometry;

	ComPtr<ID3D11RenderTargetView> view;
	context->OMGetRenderTargets(1, view.GetAddressOf(), nullptr);
	if (!view)
		return geometry;
	D3D11_RENDER_TARGET_VIEW_DESC viewDesc{};
	view->GetDesc(&viewDesc);
	if (!(viewDesc.ViewDimension == D3D11_RTV_DIMENSION_TEXTURE2D && viewDesc.Texture2D.MipSlice == 0)
		&& viewDesc.ViewDimension != D3D11_RTV_DIMENSION_TEXTURE2DMS)
		return geometry;
	ComPtr<ID3D11Resource> resource;
	view->GetResource(resource.GetAddressOf());
	ComPtr<ID3D11Texture2D> backBuffer;
	if (!resource || FAILED(swapChain->GetBuffer(0, IID_PPV_ARGS(backBuffer.GetAddressOf()))) || !backBuffer)
		return geometry;
	ComPtr<IUnknown> targetIdentity, bufferIdentity;
	if (FAILED(resource.As(&targetIdentity)) || FAILED(backBuffer.As(&bufferIdentity)) || !targetIdentity
		|| targetIdentity.Get() != bufferIdentity.Get())
		return geometry;

	D3D11_TEXTURE2D_DESC texture{};
	backBuffer->GetDesc(&texture);
	geometry.width = texture.Width;
	geometry.height = texture.Height;
	geometry.menuOutputBound = true;

	constexpr unsigned slots = D3D11_VIEWPORT_AND_SCISSORRECT_OBJECT_COUNT_PER_PIPELINE;
	D3D11_VIEWPORT viewports[slots]{};
	geometry.viewportCount = slots;
	context->RSGetViewports(&geometry.viewportCount, viewports);
	geometry.viewportX = viewports[0].TopLeftX;
	geometry.viewportY = viewports[0].TopLeftY;
	geometry.viewportWidth = viewports[0].Width;
	geometry.viewportHeight = viewports[0].Height;

	ComPtr<ID3D11RasterizerState> rasterizer;
	context->RSGetState(rasterizer.GetAddressOf());
	if (!rasterizer)
		return geometry;
	D3D11_RASTERIZER_DESC rasterizerDesc{};
	rasterizer->GetDesc(&rasterizerDesc);
	geometry.scissor = rasterizerDesc.ScissorEnable ? projection::ScissorMode::enabled : projection::ScissorMode::disabled;
	if (geometry.scissor == projection::ScissorMode::enabled)
	{
		D3D11_RECT scissors[slots]{};
		geometry.scissorCount = slots;
		context->RSGetScissorRects(&geometry.scissorCount, scissors);
		geometry.scissorLeft = scissors[0].left;
		geometry.scissorTop = scissors[0].top;
		geometry.scissorRight = scissors[0].right;
		geometry.scissorBottom = scissors[0].bottom;
	}
	return geometry;
}
}
'''


def append(anchor, code):
    return anchor, anchor + guarded(code)


def before(anchor, code):
    return anchor, guarded(code) + anchor


BEGIN = '''		const bool armed = cfxProjection.armed;
		ReplayProjection(false);
		cfxProjection.active = armed && type == 4 && count == 4 && cfx::blit::GlueCaller(_ReturnAddress());
'''
VERTEX = '''		if (cfxProjection.active)
		{
			const projection::Vertex vertex{x, y, z, nX, nY, nZ, color, u, v};
			if (cfxProjection.count < 4 && projection::Expected(cfxProjection.vertices, cfxProjection.count, vertex)
				&& cfx::blit::GlueCaller(_ReturnAddress()))
			{
				cfxProjection.vertices[cfxProjection.count++] = vertex;
				return;
			}
			ReplayProjection(false);
		}
'''
END = '\t\tconst auto projectionSize = ReplayProjection(cfxProjection.active && cfx::blit::GlueCaller(_ReturnAddress()));\n'

CHANGES = tuple((old.replace('\n', '\r\n').encode('ascii'), new.replace('\n', '\r\n').encode('ascii'))
                for old, new in (
    append('#include "CfxRect.h"\n', INCLUDES),
    before('namespace rage\n{\n#ifdef CFX_GRAPHICS_BLIT_DIAGNOSTICS\n\t__declspec(noinline)\n', BUFFER),
    append('\tvoid grcBegin(int type, int count)\n\t{\n', BEGIN),
    before('\tvoid grcVertex(float x, float y, float z, float nX, float nY, float nZ, uint32_t color, float u, float v)\n',
           '\t__declspec(noinline)\n'),
    before('\t\taddImVertex(x, y, z, nX, nY, nZ, color, u, v);\n', VERTEX),
    before('\tvoid grcEnd()\n', '\t__declspec(noinline)\n'),
    ('\t\tdrawImVertices();\n\t}\n}\n', guarded(END) + '\t\tdrawImVertices();\n' + guarded('\t\tEmitProjection(projectionSize);\n') + '\t}\n}\n'),
    append('void PushDrawBlitImShader()\n{\n', '\tReplayProjection(false);\n'),
    append('\tsetSubShaderUnk(*gtaImShader, 0);\n', '\tcfxProjection.armed = true;\n'),
    append('void PopDrawBlitImShader()\n{\n', '\tReplayProjection(false);\n'),
    before('static void TraceBlitSubmission()\n{\n', GEOMETRY),
))


def require_source(data):
    if type(data) is not bytes or (len(data), hashlib.sha256(data).hexdigest()) != SOURCE_PIN:
        raise ValueError('Require the exact vertex census DrawCommands overlay')


def apply(data):
    require_source(data)
    for before, after in CHANGES:
        if data.count(before) != 1:
            raise ValueError('Unexpected projection overlay anchor scope')
        data = data.replace(before, after, 1)
    return data


def strip(data):
    for before, after in reversed(CHANGES):
        if data.count(after) != 1:
            raise ValueError('Unexpected projection overlay scope')
        data = data.replace(after, before, 1)
    require_source(data)
    return data
