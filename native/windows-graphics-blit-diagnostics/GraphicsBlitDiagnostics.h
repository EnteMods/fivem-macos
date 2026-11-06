#pragma once

namespace cfx::blit
{
struct Quad
{
    bool armed = false;
    unsigned next = 5;
    unsigned width = 0, height = 0;

    void Push() noexcept { armed = true; next = 5; }
    void Pop() noexcept { armed = false; next = 5; }
    bool WantsBegin(int type, int count) const noexcept { return armed && type == 4 && count == 4; }

    void Begin(bool admitted) noexcept
    {
        next = armed && admitted ? 0 : 5;
        armed = false;
    }

    void Vertex(float x, float y, float z, float u, float v) noexcept
    {
        if (next >= 4)
        {
            next = 5;
            return;
        }
        const bool right = (next & 1) != 0, bottom = (next & 2) != 0;
        if (u != (right ? 1.0f : 0.0f) || v != (bottom ? 1.0f : 0.0f)
            || z != 0 || (!right && x != 0) || (!bottom && y != 0))
        {
            next = 5;
            return;
        }
        if (next == 1)
            width = Extent(x);
        if (next == 2)
            height = Extent(y);
        if ((right && (!width || x != static_cast<float>(width)))
            || (bottom && (!height || y != static_cast<float>(height))))
        {
            next = 5;
            return;
        }
        ++next;
    }

    bool End() noexcept
    {
        const bool complete = next == 4;
        Pop();
        return complete;
    }

private:
    static unsigned Extent(float value) noexcept
    {
        if (!(value >= 1 && value <= 65535))
            return 0;
        const auto integer = static_cast<unsigned>(value);
        return value == static_cast<float>(integer) ? integer : 0;
    }
};

inline int Subpixels(float value, bool& valid) noexcept
{
    if (!(value >= -65536 && value <= 65536))
    {
        valid = false;
        return 0;
    }
    const float scaled = value * 16;
    return static_cast<int>(scaled + (scaled >= 0 ? 0.5f : -0.5f));
}
}

#ifdef CFX_GRAPHICS_BLIT_DIAGNOSTICS
#include <windows.h>
#include <d3d11.h>
#include <intrin.h>
#include <cerrno>

namespace cfx::blit
{
struct PreserveError
{
    DWORD error = GetLastError();
    int crtError = errno;
    ~PreserveError() { errno = crtError; SetLastError(error); }
};

inline bool GlueCaller(const void* address) noexcept
{
    PreserveError saved;
    const HMODULE glue = GetModuleHandleW(L"glue.dll");
    HMODULE caller = nullptr;
    return glue && GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
        | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, static_cast<LPCWSTR>(address), &caller) && caller == glue;
}

inline void RenderTargetSize(ID3D11DeviceContext* context, UINT& width, UINT& height) noexcept
{
    ID3D11RenderTargetView* view = nullptr;
    context->OMGetRenderTargets(1, &view, nullptr);
    if (!view)
        return;
    D3D11_RENDER_TARGET_VIEW_DESC desc{};
    view->GetDesc(&desc);
    UINT mip = 0;
    switch (desc.ViewDimension)
    {
        case D3D11_RTV_DIMENSION_TEXTURE2D: mip = desc.Texture2D.MipSlice; break;
        case D3D11_RTV_DIMENSION_TEXTURE2DARRAY: mip = desc.Texture2DArray.MipSlice; break;
        case D3D11_RTV_DIMENSION_TEXTURE2DMS:
        case D3D11_RTV_DIMENSION_TEXTURE2DMSARRAY: break;
        default: view->Release(); return;
    }
    ID3D11Resource* resource = nullptr;
    view->GetResource(&resource);
    view->Release();
    if (!resource)
        return;
    ID3D11Texture2D* texture = nullptr;
    const HRESULT hr = resource->QueryInterface(IID_PPV_ARGS(&texture));
    resource->Release();
    if (FAILED(hr) || !texture)
        return;
    D3D11_TEXTURE2D_DESC surface{};
    texture->GetDesc(&surface);
    texture->Release();
    if (mip < surface.MipLevels && mip < 32 && surface.Width && surface.Height)
    {
        width = surface.Width >> mip;
        height = surface.Height >> mip;
        if (!width) width = 1;
        if (!height) height = 1;
    }
}

inline void Append(char*& p, const char* s) noexcept { while (*s) *p++ = *s++; }

inline void AppendUnsigned(char*& p, unsigned value) noexcept
{
    char digits[10];
    unsigned count = 0;
    do { digits[count++] = static_cast<char>('0' + value % 10); value /= 10; } while (value);
    while (count) *p++ = digits[--count];
}

inline void AppendSigned(char*& p, int value) noexcept
{
    if (value < 0) *p++ = '-';
    AppendUnsigned(p, value < 0 ? static_cast<unsigned>(-value) : static_cast<unsigned>(value));
}

inline volatile LONG sampleCount = 0;

inline bool HasBudget() noexcept { return InterlockedCompareExchange(&sampleCount, 0, 0) < 64; }

// One record per second for unchanged quad extents, at most 64 queries per process.
inline void Record(ID3D11DeviceContext* context, const Quad& quad) noexcept
{
    static thread_local ULONGLONG lastTime = 0;
    static thread_local unsigned lastWidth = 0, lastHeight = 0;
    if (!context || !HasBudget())
        return;
    PreserveError saved;
    const auto now = GetTickCount64();
    if (quad.width == lastWidth && quad.height == lastHeight && now - lastTime < 1000)
        return;
    if (InterlockedIncrement(&sampleCount) > 64)
        return;
    lastTime = now;
    lastWidth = quad.width;
    lastHeight = quad.height;

    D3D11_VIEWPORT viewports[D3D11_VIEWPORT_AND_SCISSORRECT_OBJECT_COUNT_PER_PIPELINE]{};
    UINT count = D3D11_VIEWPORT_AND_SCISSORRECT_OBJECT_COUNT_PER_PIPELINE;
    context->RSGetViewports(&count, viewports);
    bool viewportValid = count == 1;
    int x = 0, y = 0, w = 0, h = 0;
    if (viewportValid)
    {
        x = Subpixels(viewports[0].TopLeftX, viewportValid);
        y = Subpixels(viewports[0].TopLeftY, viewportValid);
        w = Subpixels(viewports[0].Width, viewportValid);
        h = Subpixels(viewports[0].Height, viewportValid);
    }
    UINT targetWidth = 0, targetHeight = 0;
    RenderTargetSize(context, targetWidth, targetHeight);

    char line[256];
    static_assert(sizeof("[CFX_GRAPHICS_BLIT] pid= tid= quad_w= quad_h= vp_count= vp_valid= vp_x16= vp_y16= vp_w16= vp_h16= rt_w= rt_h=\n")
        + 12 * 11 <= sizeof(line));
    char* p = line;
    Append(p, "[CFX_GRAPHICS_BLIT] pid="); AppendUnsigned(p, GetCurrentProcessId());
    Append(p, " tid="); AppendUnsigned(p, GetCurrentThreadId());
    Append(p, " quad_w="); AppendUnsigned(p, quad.width);
    Append(p, " quad_h="); AppendUnsigned(p, quad.height);
    Append(p, " vp_count="); AppendUnsigned(p, count);
    Append(p, " vp_valid="); AppendUnsigned(p, viewportValid);
    Append(p, " vp_x16="); AppendSigned(p, viewportValid ? x : 0);
    Append(p, " vp_y16="); AppendSigned(p, viewportValid ? y : 0);
    Append(p, " vp_w16="); AppendSigned(p, viewportValid ? w : 0);
    Append(p, " vp_h16="); AppendSigned(p, viewportValid ? h : 0);
    Append(p, " rt_w="); AppendUnsigned(p, targetWidth);
    Append(p, " rt_h="); AppendUnsigned(p, targetHeight);
    *p++ = '\n'; *p = '\0';
    OutputDebugStringA(line);
}
}
#endif
