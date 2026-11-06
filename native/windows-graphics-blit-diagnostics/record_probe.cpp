#define WIN32_LEAN_AND_MEAN
#define CFX_GRAPHICS_BLIT_DIAGNOSTICS
#include "GraphicsBlitDiagnostics.h"
#include <wrl/client.h>
#include <cstdio>
#include <cstring>

using Microsoft::WRL::ComPtr;

struct ContextState
{
    UINT viewportCount = 1, scissorCount = 1;
    D3D11_VIEWPORT viewport{};
    D3D11_RECT scissor{};
    ComPtr<ID3D11RenderTargetView> target;
};

static ContextState Snapshot(ID3D11DeviceContext* context)
{
    ContextState state;
    context->RSGetViewports(&state.viewportCount, &state.viewport);
    context->RSGetScissorRects(&state.scissorCount, &state.scissor);
    context->OMGetRenderTargets(1, state.target.GetAddressOf(), nullptr);
    return state;
}

static int CheckRecord(HWND window)
{
    DXGI_SWAP_CHAIN_DESC chainDesc{};
    chainDesc.BufferDesc.Width = 128;
    chainDesc.BufferDesc.Height = 64;
    chainDesc.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    chainDesc.SampleDesc.Count = 1;
    chainDesc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    chainDesc.BufferCount = 2;
    chainDesc.OutputWindow = window;
    chainDesc.Windowed = TRUE;
    chainDesc.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
    const D3D_FEATURE_LEVEL level = D3D_FEATURE_LEVEL_11_0;
    ComPtr<IDXGISwapChain> chain;
    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    if (FAILED(D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0,
            &level, 1, D3D11_SDK_VERSION, &chainDesc, chain.GetAddressOf(), device.GetAddressOf(),
            nullptr, context.GetAddressOf())) || !chain || !device || !context) return 11;

    D3D11_TEXTURE2D_DESC desc{};
    desc.Width = 512;
    desc.Height = 256;
    desc.MipLevels = 3;
    desc.ArraySize = 1;
    desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    desc.SampleDesc.Count = 1;
    desc.Usage = D3D11_USAGE_DEFAULT;
    desc.BindFlags = D3D11_BIND_RENDER_TARGET;
    ComPtr<ID3D11Texture2D> texture;
    if (FAILED(device->CreateTexture2D(&desc, nullptr, texture.GetAddressOf())) || !texture) return 12;
    D3D11_RENDER_TARGET_VIEW_DESC viewDesc{};
    viewDesc.Format = desc.Format;
    viewDesc.ViewDimension = D3D11_RTV_DIMENSION_TEXTURE2D;
    viewDesc.Texture2D.MipSlice = 2;
    ComPtr<ID3D11RenderTargetView> target;
    if (FAILED(device->CreateRenderTargetView(texture.Get(), &viewDesc, target.GetAddressOf())) || !target) return 13;

    auto* targetView = target.Get();
    const D3D11_VIEWPORT viewport{1.5f, 2.25f, 120.5f, 60.0f, 0.0f, 1.0f};
    const D3D11_RECT scissor{3, 4, 122, 62};
    context->OMSetRenderTargets(1, &targetView, nullptr);
    context->RSSetViewports(1, &viewport);
    context->RSSetScissorRects(1, &scissor);

    cfx::blit::Quad quad;
    quad.Push();
    quad.Begin(quad.WantsBegin(4, 4));
    quad.Vertex(0, 0, 0, 0, 0);
    quad.Vertex(1512, 0, 0, 1, 0);
    quad.Vertex(0, 982, 0, 0, 1);
    quad.Vertex(1512, 982, 0, 1, 1);
    if (!quad.End()) return 14;

    const auto before = Snapshot(context.Get());
    errno = 123;
    SetLastError(4321);
    cfx::blit::Record(context.Get(), quad);
    const bool lastErrorPreserved = GetLastError() == 4321;
    const bool errnoPreserved = errno == 123;
    const auto after = Snapshot(context.Get());
    const bool unchanged = before.viewportCount == 1 && after.viewportCount == 1
        && before.scissorCount == 1 && after.scissorCount == 1
        && before.target.Get() == targetView && after.target.Get() == targetView
        && !std::memcmp(&before.viewport, &viewport, sizeof(viewport))
        && !std::memcmp(&after.viewport, &viewport, sizeof(viewport))
        && !std::memcmp(&before.scissor, &scissor, sizeof(scissor))
        && !std::memcmp(&after.scissor, &scissor, sizeof(scissor));
    const bool hidden = !IsWindowVisible(window);
    context->OMSetRenderTargets(0, nullptr, nullptr);

    std::printf("{\"pid\":%lu,\"tid\":%lu,\"context_unchanged\":%s,\"last_error_preserved\":%s,"
        "\"errno_preserved\":%s,\"window_hidden\":%s}\n", GetCurrentProcessId(), GetCurrentThreadId(),
        unchanged ? "true" : "false", lastErrorPreserved ? "true" : "false",
        errnoPreserved ? "true" : "false", hidden ? "true" : "false");
    return unchanged && lastErrorPreserved && errnoPreserved && hidden ? 0 : 15;
}

int main()
{
    const WNDCLASSW cls{0, DefWindowProcW, 0, 0, GetModuleHandleW(nullptr), nullptr, nullptr, nullptr,
                        nullptr, L"OwnDxmtBlitRecord"};
    if (!RegisterClassW(&cls)) return 2;
    HWND window = CreateWindowExW(0, cls.lpszClassName, L"", WS_POPUP, 0, 0, 128, 64,
                                  nullptr, nullptr, cls.hInstance, nullptr);
    const int result = window && !IsWindowVisible(window) ? CheckRecord(window) : 3;
    const bool destroyed = !window || DestroyWindow(window);
    const bool unregistered = UnregisterClassW(cls.lpszClassName, cls.hInstance);
    return destroyed && unregistered ? result : 4;
}
