"""Describe the submitted NUI texture and fixed pre-draw PS slots for aligned draws."""
import hashlib

SOURCE_PIN = (34470, '602b56c7e60a5d599efca705f3876b2b2fd1add2d0120fbc618e56d8b9d2f176')
DEFINE = 'CFX_GRAPHICS_BLIT_SHARPNESS'


def guarded(code):
    return f'#ifdef {DEFINE}\n{code}#endif\n'


STATE = r'''
using Microsoft::WRL::ComPtr;

struct SharpnessInput
{
	ComPtr<ID3D11ShaderResourceView> view;
	ComPtr<ID3D11Resource> resource;
	bool pending = false, armed = false;
};

struct SharpnessSample
{
	unsigned bw = 0, bh = 0;
	unsigned source = 0, sw = 0, sh = 0, format = 0, dimension = 0, mip = 0, vw = 0, vh = 0;
	unsigned t0 = 0, match = 0, s0 = 0, filter = 0;
};

thread_local SharpnessInput sharpnessInput;

void RememberSharpnessInput(rage::grcTexture* texture, const void* caller)
{
	cfx::blit::PreserveError saved;
	sharpnessInput = {};
	if (!cfx::blit::GlueCaller(caller))
		return;
	sharpnessInput.pending = true;
	if (texture && texture->srv)
		sharpnessInput.view = texture->srv;
	else if (texture)
		sharpnessInput.resource = texture->texture;
}

void ArmSharpnessInput()
{
	cfx::blit::PreserveError saved;
	if (!sharpnessInput.pending)
	{
		sharpnessInput = {};
		return;
	}
	sharpnessInput.pending = false;
	sharpnessInput.armed = true;
}

SharpnessSample SampleSharpness(ProjectionSize size);

void EmitSharpness(const SharpnessSample& s)
{
	if (!s.bw)
		return;
	const std::array<unsigned, 14> fields = {
		s.bw, s.bh, s.source, s.sw, s.sh, s.format, s.dimension, s.mip, s.vw, s.vh, s.t0, s.match, s.s0, s.filter
	};
	static thread_local std::array<unsigned, 14> previous{};
	if (fields == previous)
		return;
	previous = fields;
	static std::atomic<unsigned> remaining{8};
	auto budget = remaining.load(std::memory_order_relaxed);
	if (!budget || !remaining.compare_exchange_strong(budget, budget - 1, std::memory_order_relaxed))
		return;

	using namespace cfx::blit;
	PreserveError saved;
	char line[280], *out = line;
	static_assert(sizeof("[CFX_GRAPHICS_BLIT_SHARPNESS] pid= tid= bw= bh= src= sw= sh= fmt= dim= mip= vw= vh= t0= match= s0= filter=\n")
		+ 16 * 10 <= sizeof(line));
	Append(out, "[CFX_GRAPHICS_BLIT_SHARPNESS] pid="); AppendUnsigned(out, GetCurrentProcessId());
	Append(out, " tid="); AppendUnsigned(out, GetCurrentThreadId());
	static constexpr const char* keys[] = {" bw=", " bh=", " src=", " sw=", " sh=", " fmt=", " dim=", " mip=",
		" vw=", " vh=", " t0=", " match=", " s0=", " filter="};
	for (unsigned i = 0; i < fields.size(); ++i)
	{
		Append(out, keys[i]);
		AppendUnsigned(out, fields[i]);
	}
	*out++ = '\n'; *out = '\0';
	OutputDebugStringA(line);
}
'''

SAMPLE = '''namespace
{
template<typename T>
bool SameSharpnessObject(const ComPtr<T>& a, const ComPtr<T>& b)
{
	ComPtr<IUnknown> x, y;
	return a && b && SUCCEEDED(a.As(&x)) && SUCCEEDED(b.As(&y)) && x && x.Get() == y.Get();
}

SharpnessSample SampleSharpness(ProjectionSize size)
{
	cfx::blit::PreserveError saved;
	auto input = std::move(sharpnessInput);
	sharpnessInput = {};
	SharpnessSample sample;
	if (!size.width || !input.armed || g_renderThreadTlsIndex <= 0 || g_d3d11DeviceContextOffset <= 0)
		return sample;
	const auto tls = hook::get_tls();
	if (!tls || (*reinterpret_cast<const int32_t*>(tls + g_renderThreadTlsIndex) & 2) == 0)
		return sample;
	auto* context = *reinterpret_cast<ID3D11DeviceContext* const*>(tls + g_d3d11DeviceContextOffset);
	if (!context)
		return sample;
	sample.bw = size.width;
	sample.bh = size.height;

	ComPtr<ID3D11Resource> resource = std::move(input.resource);
	if (input.view)
		input.view->GetResource(resource.GetAddressOf());
	ComPtr<ID3D11Texture2D> texture;
	if (resource && SUCCEEDED(resource.As(&texture)) && texture)
	{
		D3D11_TEXTURE2D_DESC desc{};
		texture->GetDesc(&desc);
		sample.source = 1;
		sample.sw = desc.Width;
		sample.sh = desc.Height;
		sample.format = desc.Format;
		if (input.view)
		{
			D3D11_SHADER_RESOURCE_VIEW_DESC viewDesc{};
			input.view->GetDesc(&viewDesc);
			sample.dimension = viewDesc.ViewDimension;
			const bool view2d = viewDesc.ViewDimension == D3D11_SRV_DIMENSION_TEXTURE2D;
			const unsigned mip = view2d ? viewDesc.Texture2D.MostDetailedMip : 0;
			if ((view2d || viewDesc.ViewDimension == D3D11_SRV_DIMENSION_TEXTURE2DMS)
				&& desc.Width && desc.Height && mip < desc.MipLevels && mip < 32)
			{
				sample.source = 2;
				sample.format = viewDesc.Format;
				sample.mip = mip;
				sample.vw = (std::max)(1u, desc.Width >> mip);
				sample.vh = (std::max)(1u, desc.Height >> mip);
			}
		}
	}

	// These are independent pre-draw CPU context bindings, not shader-use claims.
	ComPtr<ID3D11ShaderResourceView> t0;
	context->PSGetShaderResources(0, 1, t0.GetAddressOf());
	sample.t0 = t0 ? 1 : 0;
	if (input.view)
		sample.match = SameSharpnessObject(input.view, t0) ? 1 : 0;
	else if (resource && t0)
	{
		ComPtr<ID3D11Resource> t0Resource;
		t0->GetResource(t0Resource.GetAddressOf());
		sample.match = SameSharpnessObject(resource, t0Resource) ? 2 : 0;
	}
	ComPtr<ID3D11SamplerState> s0;
	context->PSGetSamplers(0, 1, s0.GetAddressOf());
	if (s0)
	{
		D3D11_SAMPLER_DESC desc{};
		s0->GetDesc(&desc);
		sample.s0 = 1;
		sample.filter = desc.Filter;
	}
	return sample;
}
}
'''


def append(anchor, code):
    return anchor, anchor + guarded(code)


def before(anchor, code):
    return anchor, guarded(code) + anchor


CHANGES = tuple((a.replace('\n', '\r\n').encode('ascii'), b.replace('\n', '\r\n').encode('ascii'))
                for a, b in (
    append('#include "CfxRect.h"\n', '#ifndef CFX_GRAPHICS_BLIT_PROJECTION\n'
           '#error Sharpness telemetry requires the aligned projection overlay.\n#endif\n'),
    append('projection::Geometry ProjectionGeometry();\n', STATE),
    before('void SetTextureGtaIm(rage::grcTexture* texture)\n', '__declspec(noinline)\n'),
    append('\tsetTextureGtaIm(texture);\n', '\tRememberSharpnessInput(texture, _ReturnAddress());\n'),
    append('\tcfxProjection.armed = true;\n', '\tArmSharpnessInput();\n'),
    append('void PopDrawBlitImShader()\n{\n', '\t{ cfx::blit::PreserveError saved; sharpnessInput = {}; }\n'),
    before('\t\tdrawImVertices();\n', '\t\tconst auto sharpness = SampleSharpness(projectionSize);\n'),
    append('\t\tdrawImVertices();\n', '\t\tEmitSharpness(sharpness);\n'),
    before('static void TraceBlitSubmission()\n{\n', SAMPLE),
))


def require_source(data):
    if type(data) is not bytes or (len(data), hashlib.sha256(data).hexdigest()) != SOURCE_PIN:
        raise ValueError('Require the exact aligned projection DrawCommands overlay')


def apply(data):
    require_source(data)
    for before_bytes, after_bytes in CHANGES:
        if data.count(before_bytes) != 1:
            raise ValueError('Unexpected sharpness overlay anchor scope')
        data = data.replace(before_bytes, after_bytes, 1)
    return data


def strip(data):
    for before_bytes, after_bytes in reversed(CHANGES):
        if data.count(after_bytes) != 1:
            raise ValueError('Unexpected sharpness overlay scope')
        data = data.replace(after_bytes, before_bytes, 1)
    require_source(data)
    return data
