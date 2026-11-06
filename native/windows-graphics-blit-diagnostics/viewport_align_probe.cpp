#define WIN32_LEAN_AND_MEAN
#define CFX_GRAPHICS_BLIT_DIAGNOSTICS
#include "ViewportAlignProbe.h"
#include <d3dcompiler.h>
#include <wrl/client.h>
#include <algorithm>
#include <cstdio>
#include <cstring>

using Microsoft::WRL::ComPtr;
using cfx::blit::test::ViewportAlignScope;

static constexpr UINT Width = 1512, Height = 982;
static constexpr char Shader[] = R"(
float4 vertex(uint id : SV_VertexID) : SV_Position
{
    return float4(id == 2 ? 3 : -1, id == 1 ? 3 : -1, 0, 1);
}
float4 pixel() : SV_Target { return float4(1, 0, 0, 1); }
)";

struct Bounds
{
    UINT left = Width, top = Height, right = 0, bottom = 0, pixels = 0;
    bool Matches(UINT x, UINT y, UINT w, UINT h) const noexcept
    {
        return left == x && top == y && right == x + w && bottom == y + h && pixels == w * h;
    }
};

static void Draw(ID3D11DeviceContext* context, ID3D11RenderTargetView* view)
{
    const float black[4]{0, 0, 0, 1};
    context->ClearRenderTargetView(view, black);
    context->Draw(3, 0);
}

static bool Readback(ID3D11DeviceContext* context, ID3D11Texture2D* target,
                     ID3D11Texture2D* staging, Bounds& bounds)
{
    context->OMSetRenderTargets(0, nullptr, nullptr);
    context->CopyResource(staging, target);
    D3D11_MAPPED_SUBRESOURCE bytes{};
    if (FAILED(context->Map(staging, 0, D3D11_MAP_READ, 0, &bytes))) return false;
    if (!bytes.pData || bytes.RowPitch < Width * 4)
    {
        context->Unmap(staging, 0);
        return false;
    }
    for (UINT y = 0; y < Height; ++y)
    {
        const auto* row = static_cast<const unsigned char*>(bytes.pData) + y * bytes.RowPitch;
        for (UINT x = 0; x < Width; ++x)
        {
            const auto* pixel = row + x * 4;
            if (pixel[0] != 255 || pixel[1] || pixel[2] || pixel[3] != 255) continue;
            bounds.left = std::min(bounds.left, x);
            bounds.top = std::min(bounds.top, y);
            bounds.right = std::max(bounds.right, x + 1);
            bounds.bottom = std::max(bounds.bottom, y + 1);
            ++bounds.pixels;
        }
    }
    context->Unmap(staging, 0);
    return true;
}

static bool SameViewports(ID3D11DeviceContext* context, const D3D11_VIEWPORT* viewports, UINT expectedCount)
{
    D3D11_VIEWPORT actual[D3D11_VIEWPORT_AND_SCISSORRECT_OBJECT_COUNT_PER_PIPELINE]{};
    UINT count = D3D11_VIEWPORT_AND_SCISSORRECT_OBJECT_COUNT_PER_PIPELINE;
    context->RSGetViewports(&count, actual);
    return count == expectedCount && !std::memcmp(viewports, actual, count * sizeof(*actual));
}

static bool Declines(ID3D11DeviceContext* context, const D3D11_VIEWPORT* viewports, UINT count, UINT quadWidth = Width)
{
    context->RSSetViewports(count, viewports);
    bool declined;
    {
        ViewportAlignScope scope(context, quadWidth, Height);
        declined = !scope.Applied() && SameViewports(context, viewports, count);
    }
    return declined && SameViewports(context, viewports, count);
}

static void PrintBounds(const char* name, const Bounds& bounds)
{
    std::printf(",\"%s\":[%u,%u,%u,%u],\"%s_pixels\":%u", name,
                bounds.left, bounds.top, bounds.right, bounds.bottom, name, bounds.pixels);
}

static int Run(HWND window)
{
    DXGI_SWAP_CHAIN_DESC desc{};
    desc.BufferDesc.Width = Width;
    desc.BufferDesc.Height = Height;
    desc.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    desc.SampleDesc.Count = 1;
    desc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    desc.BufferCount = 2;
    desc.OutputWindow = window;
    desc.Windowed = TRUE;
    desc.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
    const D3D_FEATURE_LEVEL level = D3D_FEATURE_LEVEL_11_0;
    ComPtr<IDXGISwapChain> chain;
    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    if (FAILED(D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0,
            &level, 1, D3D11_SDK_VERSION, &desc, chain.GetAddressOf(), device.GetAddressOf(),
            nullptr, context.GetAddressOf())) || !chain || !device || !context) return 11;

    ComPtr<ID3D11Texture2D> target, staging;
    if (FAILED(chain->GetBuffer(0, IID_PPV_ARGS(target.GetAddressOf()))) || !target) return 12;
    D3D11_TEXTURE2D_DESC targetDesc{};
    target->GetDesc(&targetDesc);
    if (targetDesc.Width != Width || targetDesc.Height != Height || targetDesc.SampleDesc.Count != 1
            || targetDesc.Format != DXGI_FORMAT_R8G8B8A8_UNORM) return 13;
    auto stagingDesc = targetDesc;
    stagingDesc.BindFlags = 0;
    stagingDesc.MiscFlags = 0;
    stagingDesc.Usage = D3D11_USAGE_STAGING;
    stagingDesc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
    if (FAILED(device->CreateTexture2D(&stagingDesc, nullptr, staging.GetAddressOf())) || !staging) return 14;
    ComPtr<ID3D11RenderTargetView> targetView;
    if (FAILED(device->CreateRenderTargetView(target.Get(), nullptr, targetView.GetAddressOf())) || !targetView) return 15;

    ComPtr<ID3DBlob> vertexCode, pixelCode;
    if (FAILED(D3DCompile(Shader, sizeof(Shader) - 1, nullptr, nullptr, nullptr, "vertex", "vs_5_0", 0, 0,
            vertexCode.GetAddressOf(), nullptr)) || !vertexCode
        || FAILED(D3DCompile(Shader, sizeof(Shader) - 1, nullptr, nullptr, nullptr, "pixel", "ps_5_0", 0, 0,
            pixelCode.GetAddressOf(), nullptr)) || !pixelCode) return 16;
    ComPtr<ID3D11VertexShader> vertex;
    ComPtr<ID3D11PixelShader> pixel;
    if (FAILED(device->CreateVertexShader(vertexCode->GetBufferPointer(), vertexCode->GetBufferSize(), nullptr,
            vertex.GetAddressOf())) || !vertex
        || FAILED(device->CreatePixelShader(pixelCode->GetBufferPointer(), pixelCode->GetBufferSize(), nullptr,
            pixel.GetAddressOf())) || !pixel) return 17;
    D3D11_RASTERIZER_DESC raster{};
    raster.FillMode = D3D11_FILL_SOLID;
    raster.CullMode = D3D11_CULL_NONE;
    raster.DepthClipEnable = TRUE;
    ComPtr<ID3D11RasterizerState> plain, clipped;
    if (FAILED(device->CreateRasterizerState(&raster, plain.GetAddressOf())) || !plain) return 18;
    raster.ScissorEnable = TRUE;
    if (FAILED(device->CreateRasterizerState(&raster, clipped.GetAddressOf())) || !clipped) return 19;
    context->RSSetState(plain.Get());
    context->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
    context->VSSetShader(vertex.Get(), nullptr, 0);
    context->PSSetShader(pixel.Get(), nullptr, 0);

    const D3D11_VIEWPORT original{0, 89, 1191, 893, 0.125f, 0.875f};
    const D3D11_VIEWPORT full{0, 0, Width, Height, original.MinDepth, original.MaxDepth};
    auto* view = targetView.Get();
    Bounds before, within, after;
    context->RSSetViewports(1, &original);
    context->OMSetRenderTargets(1, &view, nullptr);
    Draw(context.Get(), view);
    if (!Readback(context.Get(), target.Get(), staging.Get(), before)) return 20;

    context->OMSetRenderTargets(1, &view, nullptr);
    bool applied;
    {
        ViewportAlignScope scope(context.Get(), Width, Height);
        applied = scope.Applied() && SameViewports(context.Get(), &full, 1);
        Draw(context.Get(), view);
    }
    const bool restored = SameViewports(context.Get(), &original, 1);
    if (!Readback(context.Get(), target.Get(), staging.Get(), within)) return 21;
    context->OMSetRenderTargets(1, &view, nullptr);
    Draw(context.Get(), view);
    if (!Readback(context.Get(), target.Get(), staging.Get(), after)) return 22;

    context->OMSetRenderTargets(1, &view, nullptr);
    const D3D11_VIEWPORT unrelated{1, 89, 1191, 893, original.MinDepth, original.MaxDepth};
    const D3D11_VIEWPORT multiple[]{original, full};
    const bool fullUntouched = Declines(context.Get(), &full, 1);
    const bool unrelatedUntouched = Declines(context.Get(), &unrelated, 1);
    const bool mismatchUntouched = Declines(context.Get(), &original, 1, Width - 1);
    const bool multipleUntouched = Declines(context.Get(), multiple, 2);
    context->RSSetState(clipped.Get());
    const D3D11_RECT scissor{0, 89, 1110, 982};
    context->RSSetScissorRects(1, &scissor);
    const bool clippedViewportUntouched = Declines(context.Get(), &original, 1);
    UINT scissorCount = 1;
    D3D11_RECT observedScissor{};
    ComPtr<ID3D11RasterizerState> observedRasterizer;
    context->RSGetScissorRects(&scissorCount, &observedScissor);
    context->RSGetState(observedRasterizer.GetAddressOf());
    const bool scissorDeclined = clippedViewportUntouched && scissorCount == 1
        && observedRasterizer.Get() == clipped.Get() && !std::memcmp(&observedScissor, &scissor, sizeof(scissor));
    const bool hidden = !IsWindowVisible(window);
    context->OMSetRenderTargets(0, nullptr, nullptr);

    std::printf("{\"phase\":\"complete\",\"pid\":%lu,\"tid\":%lu", GetCurrentProcessId(), GetCurrentThreadId());
    PrintBounds("before", before);
    PrintBounds("within", within);
    PrintBounds("after", after);
    std::printf(",\"scope_applied\":%s,\"restored\":%s,\"full_untouched\":%s,\"unrelated_untouched\":%s,"
        "\"mismatch_untouched\":%s,\"multiple_untouched\":%s,\"scissor_declined\":%s,\"window_hidden\":%s}\n",
        applied ? "true" : "false", restored ? "true" : "false", fullUntouched ? "true" : "false",
        unrelatedUntouched ? "true" : "false", mismatchUntouched ? "true" : "false", multipleUntouched ? "true" : "false",
        scissorDeclined ? "true" : "false", hidden ? "true" : "false");
    return applied && restored && fullUntouched && unrelatedUntouched && mismatchUntouched && multipleUntouched
        && scissorDeclined && hidden && before.Matches(0, 89, 1191, 893) && within.Matches(0, 0, Width, Height)
        && after.Matches(0, 89, 1191, 893) ? 0 : 23;
}

int main(int argc, char**)
{
    if (argc != 1) return 1;
    const WNDCLASSW cls{0, DefWindowProcW, 0, 0, GetModuleHandleW(nullptr), nullptr, nullptr, nullptr,
                        nullptr, L"OwnDxmtViewportAlignProbe"};
    if (!RegisterClassW(&cls)) return 2;
    HWND window = CreateWindowExW(0, cls.lpszClassName, L"", WS_POPUP, 0, 0, Width, Height,
                                  nullptr, nullptr, cls.hInstance, nullptr);
    const int result = window && !IsWindowVisible(window) ? Run(window) : 3;
    const bool destroyed = !window || DestroyWindow(window);
    const bool unregistered = UnregisterClassW(cls.lpszClassName, cls.hInstance);
    return destroyed && unregistered ? result : 4;
}
