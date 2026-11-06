"""Admit only a validated high-resolution menu transition on its original window and swapchain."""
import hashlib


UNIT_PIN = (40473, '9ed055c9febcfe3c32b5ed975ab61103152ba955d9dbda310b5d61a8d10ae488')
HEADER = 'GraphicsBlitFullscreenY.h'

HELPERS = r'''
thread_local projection::FullscreenYReference fullscreenY;

bool ClientMonitorSpan(HWND window, unsigned width, unsigned height, bool& spanning)
{
	static const auto user = GetModuleHandleW(L"user32.dll");
	static const auto clientRect = user ? reinterpret_cast<decltype(&GetClientRect)>(GetProcAddress(user, "GetClientRect")) : nullptr;
	static const auto monitorFromWindow = user ? reinterpret_cast<decltype(&MonitorFromWindow)>(GetProcAddress(user, "MonitorFromWindow")) : nullptr;
	static const auto monitorInfo = user ? reinterpret_cast<decltype(&GetMonitorInfoW)>(GetProcAddress(user, "GetMonitorInfoW")) : nullptr;
	DWORD owner = 0;
	RECT client{};
	if (!window || !clientRect || !monitorFromWindow || !monitorInfo || !GetWindowThreadProcessId(window, &owner)
		|| owner != GetCurrentProcessId() || !clientRect(window, &client) || client.left || client.top
		|| client.right != static_cast<LONG>(width) || client.bottom != static_cast<LONG>(height))
		return false;
	POINT topLeft{client.left, client.top}, bottomRight{client.right, client.bottom};
	if (!ClientToScreen(window, &topLeft) || !ClientToScreen(window, &bottomRight)
		|| static_cast<int64_t>(bottomRight.x) - topLeft.x != width
		|| static_cast<int64_t>(bottomRight.y) - topLeft.y != height)
		return false;
	const auto monitor = monitorFromWindow(window, MONITOR_DEFAULTTONULL);
	MONITORINFO info{};
	info.cbSize = sizeof(info);
	if (!monitor || !monitorInfo(monitor, &info))
		return false;
	const auto& rect = info.rcMonitor;
	spanning = projection::SpansMonitor({topLeft.x, topLeft.y, bottomRight.x, bottomRight.y},
		{rect.left, rect.top, rect.right, rect.bottom});
	return true;
}

void EmitFullscreenY(unsigned phase, unsigned startupHeight, unsigned width, unsigned height)
{
	static thread_local unsigned lastHeight = 0, lastWidth = 0;
	static std::atomic<unsigned> remaining{8};
	if (width == lastWidth && height == lastHeight)
		return;
	lastWidth = width;
	lastHeight = height;
	auto budget = remaining.load(std::memory_order_relaxed);
	if (!budget || !remaining.compare_exchange_strong(budget, budget - 1, std::memory_order_relaxed))
		return;

	using namespace cfx::blit;
	char line[160], *out = line;
	static_assert(sizeof("[CFX_GRAPHICS_BLIT_FULLSCREEN_Y] pid= tid= phase= startup_h= target_w= target_h=\n") + 60 <= sizeof(line));
	Append(out, "[CFX_GRAPHICS_BLIT_FULLSCREEN_Y] pid="); AppendUnsigned(out, GetCurrentProcessId());
	Append(out, " tid="); AppendUnsigned(out, GetCurrentThreadId());
	Append(out, " phase="); AppendUnsigned(out, phase);
	Append(out, " startup_h="); AppendUnsigned(out, startupHeight);
	Append(out, " target_w="); AppendUnsigned(out, width);
	Append(out, " target_h="); AppendUnsigned(out, height);
	*out++ = '\n'; *out = '\0';
	OutputDebugStringA(line);
}

void ReplayFullscreenY(projection::Vertex (&vertices)[4])
{
	if (!(vertices[1].x >= ProjectionReferenceWidth && vertices[1].x <= projection::MaxExtent
		&& vertices[0].y >= ProjectionReferenceHeight && vertices[0].y <= projection::MaxExtent))
		return;
	const auto width = static_cast<unsigned>(vertices[1].x);
	const auto height = static_cast<unsigned>(vertices[0].y);
	if (fullscreenY.observed && (!fullscreenY.height || height <= fullscreenY.height))
		return;

	cfx::blit::PreserveError saved;
	bool spanning = false;
	if (fullscreenY.observed
		&& (!ClientMonitorSpan(static_cast<HWND>(const_cast<void*>(fullscreenY.window)), width, height, spanning) || !spanning))
		return;

	IDXGISwapChain* chain = nullptr;
	const auto geometry = ProjectionGeometry(&chain);
	if (!chain || !projection::Scale(vertices, geometry, ProjectionReferenceWidth, ProjectionReferenceHeight))
		return;
	DXGI_SWAP_CHAIN_DESC desc{};
	if (FAILED(chain->GetDesc(&desc)))
		return;
	if (!fullscreenY.observed)
	{
		if (ClientMonitorSpan(desc.OutputWindow, width, height, spanning)
			&& fullscreenY.Learn(chain, desc.OutputWindow, height, spanning))
			EmitFullscreenY(1, height, width, height);
		return;
	}
	if (fullscreenY.Apply(vertices, chain, desc.OutputWindow, height, spanning))
		EmitFullscreenY(2, fullscreenY.height, width, height);
}
'''


CHANGES = tuple((before.replace('\n', '\r\n').encode('ascii'), after.replace('\n', '\r\n').encode('ascii'))
                for before, after in (
    ('#include "GraphicsBlitProjection.h"\n', '#include "GraphicsBlitProjection.h"\n' + f'#include "{HEADER}"\n'),
    ('projection::Geometry ProjectionGeometry();\n',
     'projection::Geometry ProjectionGeometry(IDXGISwapChain** observed = nullptr);\n' + HELPERS),
    ('\tfor (unsigned i = 0; i < pending.count; ++i)\n',
     '\telse if (allowScaling && pending.active && pending.count == 4)\n'
     '\t\tReplayFullscreenY(pending.vertices);\n'
     '\tfor (unsigned i = 0; i < pending.count; ++i)\n'),
    ('projection::Geometry ProjectionGeometry()\n{\n',
     'projection::Geometry ProjectionGeometry(IDXGISwapChain** observed)\n{\n'),
    ('\tgeometry.menuOutputBound = true;\n',
     '\tgeometry.menuOutputBound = true;\n\tif (observed)\n\t\t*observed = swapChain;\n'),
))


def require(data):
    if type(data) is not bytes or (len(data), hashlib.sha256(data).hexdigest()) != UNIT_PIN:
        raise ValueError('Require exact fast native-extents input')


def replace(data, changes):
    for before, after in changes:
        if data.count(before) != 1:
            raise ValueError('Expected one exact fullscreen-Y anchor')
        data = data.replace(before, after, 1)
    return data


def apply(data):
    require(data)
    return replace(data, CHANGES)


def strip(data):
    original = replace(data, ((after, before) for before, after in reversed(CHANGES)))
    require(original)
    return original
