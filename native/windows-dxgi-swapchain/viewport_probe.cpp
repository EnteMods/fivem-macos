#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <d3d11.h>
#include <d3dcompiler.h>
#include <wrl/client.h>
#include <algorithm>
#include <cstdio>
#include <cstring>

using Microsoft::WRL::ComPtr;

static constexpr UINT Width = 1512, Height = 982;
static constexpr char Shader[] = R"(
float4 vertex(uint id : SV_VertexID) : SV_Position
{
    return float4(id == 2 ? 3 : -1, id == 1 ? 3 : -1, 0, 1);
}
float4 pixel() : SV_Target { return float4(1, 0, 0, 1); }
)";

static bool sample(ID3D11Device* device, ID3D11DeviceContext* context,
                   ID3D11Texture2D* target, const D3D11_VIEWPORT& expected, unsigned phase)
{
    D3D11_TEXTURE2D_DESC desc = {};
    target->GetDesc(&desc);
    ComPtr<ID3D11RenderTargetView> view;
    if (FAILED(device->CreateRenderTargetView(target, nullptr, view.GetAddressOf()))) return false;
    auto* bound = view.Get();
    context->OMSetRenderTargets(1, &bound, nullptr);
    const float clear[4] = {0, 0, 0, 1};
    context->ClearRenderTargetView(view.Get(), clear);
    context->RSSetViewports(1, &expected);
    UINT count = 1;
    D3D11_VIEWPORT observed = {};
    context->RSGetViewports(&count, &observed);
    context->Draw(3, 0);
    context->OMSetRenderTargets(0, nullptr, nullptr);

    auto stagingDesc = desc;
    stagingDesc.BindFlags = 0;
    stagingDesc.MiscFlags = 0;
    stagingDesc.Usage = D3D11_USAGE_STAGING;
    stagingDesc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
    ComPtr<ID3D11Texture2D> staging;
    if (FAILED(device->CreateTexture2D(&stagingDesc, nullptr, staging.GetAddressOf()))) return false;
    context->CopyResource(staging.Get(), target);
    D3D11_MAPPED_SUBRESOURCE bytes = {};
    if (FAILED(context->Map(staging.Get(), 0, D3D11_MAP_READ, 0, &bytes))) return false;
    UINT left = desc.Width, top = desc.Height, right = 0, bottom = 0, red = 0;
    for (UINT y = 0; y < desc.Height; ++y)
    {
        const auto* row = static_cast<const unsigned char*>(bytes.pData) + y * bytes.RowPitch;
        for (UINT x = 0; x < desc.Width; ++x)
        {
            const auto* pixel = row + x * 4;
            if (pixel[0] != 255 || pixel[1] || pixel[2] || pixel[3] != 255) continue;
            left = std::min(left, x);
            top = std::min(top, y);
            right = std::max(right, x + 1);
            bottom = std::max(bottom, y + 1);
            ++red;
        }
    }
    context->Unmap(staging.Get(), 0);
    std::printf("{\"phase\":%u,\"target\":[%u,%u],\"viewport\":[%g,%g,%g,%g],"
                "\"red_bounds\":[%u,%u,%u,%u],\"red_pixels\":%u}\n",
                phase, desc.Width, desc.Height, observed.TopLeftX, observed.TopLeftY,
                observed.Width, observed.Height, left, top, right, bottom, red);
    return count == 1 && !std::memcmp(&expected, &observed, sizeof(expected)) &&
           left == expected.TopLeftX && top == expected.TopLeftY && right == left + expected.Width &&
           bottom == top + expected.Height && red == expected.Width * expected.Height;
}

static int run(HWND window)
{
    DXGI_SWAP_CHAIN_DESC desc = {};
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
        &level, 1, D3D11_SDK_VERSION, &desc, chain.GetAddressOf(), device.GetAddressOf(), nullptr, context.GetAddressOf()))) return 11;
    ComPtr<ID3D11Texture2D> backbuffer;
    if (FAILED(chain->GetBuffer(0, IID_PPV_ARGS(backbuffer.GetAddressOf())))) return 12;
    ComPtr<ID3DBlob> vertexCode, pixelCode;
    if (FAILED(D3DCompile(Shader, sizeof(Shader) - 1, nullptr, nullptr, nullptr, "vertex", "vs_5_0", 0, 0,
                         vertexCode.GetAddressOf(), nullptr)) ||
        FAILED(D3DCompile(Shader, sizeof(Shader) - 1, nullptr, nullptr, nullptr, "pixel", "ps_5_0", 0, 0,
                         pixelCode.GetAddressOf(), nullptr))) return 13;
    ComPtr<ID3D11VertexShader> vertex;
    ComPtr<ID3D11PixelShader> pixel;
    if (FAILED(device->CreateVertexShader(vertexCode->GetBufferPointer(), vertexCode->GetBufferSize(), nullptr, vertex.GetAddressOf())) ||
        FAILED(device->CreatePixelShader(pixelCode->GetBufferPointer(), pixelCode->GetBufferSize(), nullptr, pixel.GetAddressOf()))) return 14;
    D3D11_RASTERIZER_DESC raster = {};
    raster.FillMode = D3D11_FILL_SOLID;
    raster.CullMode = D3D11_CULL_NONE;
    raster.DepthClipEnable = TRUE;
    ComPtr<ID3D11RasterizerState> state;
    if (FAILED(device->CreateRasterizerState(&raster, state.GetAddressOf()))) return 15;
    context->RSSetState(state.Get());
    context->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
    context->VSSetShader(vertex.Get(), nullptr, 0);
    context->PSSetShader(pixel.Get(), nullptr, 0);

    D3D11_TEXTURE2D_DESC offscreenDesc = {};
    backbuffer->GetDesc(&offscreenDesc);
    offscreenDesc.Width = 1190;
    offscreenDesc.Height = 894;
    offscreenDesc.BindFlags = D3D11_BIND_RENDER_TARGET;
    offscreenDesc.MiscFlags = 0;
    ComPtr<ID3D11Texture2D> offscreen;
    if (FAILED(device->CreateTexture2D(&offscreenDesc, nullptr, offscreen.GetAddressOf()))) return 16;
    const D3D11_VIEWPORT full = {0, 0, Width, Height, 0, 1};
    const D3D11_VIEWPORT small = {0, 0, 1190, 894, 0, 1};
    const D3D11_VIEWPORT offset = {0, 88, 1190, 894, 0, 1};
    if (!sample(device.Get(), context.Get(), backbuffer.Get(), full, 1)) return 21;
    if (!sample(device.Get(), context.Get(), offscreen.Get(), small, 2)) return 22;
    if (!sample(device.Get(), context.Get(), backbuffer.Get(), offset, 3)) return 23;
    if (!sample(device.Get(), context.Get(), backbuffer.Get(), full, 4)) return 24;
    return 0;
}

int main()
{
    WNDCLASSW cls = {};
    cls.lpfnWndProc = DefWindowProcW;
    cls.hInstance = GetModuleHandleW(nullptr);
    cls.lpszClassName = L"OwnDxmtViewportProbe";
    if (!RegisterClassW(&cls)) return 2;
    HWND window = CreateWindowExW(0, cls.lpszClassName, L"", WS_POPUP, 0, 0, Width, Height,
                                  nullptr, nullptr, cls.hInstance, nullptr);
    const int result = window ? run(window) : 3;
    if (window) DestroyWindow(window);
    UnregisterClassW(cls.lpszClassName, cls.hInstance);
    return result;
}
