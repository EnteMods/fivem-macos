#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <d3d11.h>
#include <d3dcompiler.h>
#include <wrl/client.h>
#include <algorithm>
#include <charconv>
#include <cstdio>
#include <cstring>
#include <vector>

using Microsoft::WRL::ComPtr;

static constexpr char Shader[] = R"(
Texture2D<float4> stripes : register(t0);
SamplerState stripeSampler : register(s0);
struct Vertex { float4 position : SV_Position; float2 uv : TEXCOORD; };
Vertex vertex(uint id : SV_VertexID)
{
    Vertex output;
    output.uv = float2(id == 1 ? 2 : 0, id == 2 ? 2 : 0);
    output.position = float4(2 * output.uv.x - 1, 1 - 2 * output.uv.y, 0, 1);
    return output;
}
float4 pixel(Vertex input) : SV_Target { return stripes.SampleLevel(stripeSampler, input.uv, 0); }
)";

static unsigned expected(UINT x, UINT width, bool low, bool linear)
{
    if (!low) return (x & 1) ? 255 : 0;
    const bool white = (x & 2) != 0;
    if (!linear || x == 0 || x == width - 1) return white ? 255 : 0;
    return white ? 191 : 64;
}

static bool Sample(ID3D11DeviceContext* context, ID3D11Texture2D* target, ID3D11Texture2D* staging,
                   ID3D11RenderTargetView* view, ID3D11ShaderResourceView* source,
                   ID3D11SamplerState* sampler, UINT width, UINT height, bool low, bool linear)
{
    const float sentinel[]{1, 0, 1, 1};
    context->ClearRenderTargetView(view, sentinel);
    context->OMSetRenderTargets(1, &view, nullptr);
    context->PSSetShaderResources(0, 1, &source);
    context->PSSetSamplers(0, 1, &sampler);
    context->Draw(3, 0);
    context->OMSetRenderTargets(0, nullptr, nullptr);
    context->CopyResource(staging, target);
    D3D11_MAPPED_SUBRESOURCE map{};
    if (FAILED(context->Map(staging, 0, D3D11_MAP_READ, 0, &map))) return false;
    if (!map.pData || map.RowPitch < width * 4)
    {
        context->Unmap(staging, 0);
        return false;
    }

    const auto* bytes = static_cast<const unsigned char*>(map.pData);
    const auto* middle = bytes + (height / 2) * map.RowPitch;
    unsigned period = 1;
    for (; period <= 8; ++period)
    {
        bool repeating = true;
        for (UINT x = 4 + period; x < width - 4 && repeating; ++x)
            repeating = middle[x * 4] == middle[(x - period) * 4];
        if (repeating) break;
    }
    unsigned minimum = 255, maximum = 0;
    for (UINT x = 4; x < width - 4; ++x)
    {
        const unsigned level = middle[x * 4];
        minimum = std::min(minimum, level);
        maximum = std::max(maximum, level);
    }
    const unsigned stripe[]{middle[16], middle[20], middle[24], middle[28]};
    bool exact = true;
    for (UINT y = 0; y < height && exact; ++y)
    {
        const auto* row = bytes + y * map.RowPitch;
        for (UINT x = 0; x < width && exact; ++x)
        {
            const auto* rgba = row + 4 * x;
            const auto level = expected(x, width, low, linear);
            exact = rgba[0] == level && rgba[1] == level && rgba[2] == level && rgba[3] == 255;
        }
    }
    context->Unmap(staging, 0);
    const UINT factor = low ? 2 : 1;
    std::printf("{\"source\":[%u,%u],\"target\":[%u,%u],\"filter\":\"%s\",\"period\":%u,"
                "\"interior\":[%u,%u],\"contrast\":%u,\"stripe\":[%u,%u,%u,%u],\"whole_target_exact\":%s}\n",
                width / factor, height / factor, width, height, linear ? "linear" : "point", period,
                minimum, maximum, maximum - minimum, stripe[0], stripe[1], stripe[2], stripe[3],
                exact ? "true" : "false");
    return exact && period == (low ? 4u : 2u);
}

static int Run(HWND window, UINT logicalW, UINT logicalH)
{
    const UINT width = logicalW * 2, height = logicalH * 2;
    DXGI_SWAP_CHAIN_DESC chainDesc{};
    chainDesc.BufferDesc.Width = logicalW;
    chainDesc.BufferDesc.Height = logicalH;
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
    desc.Width = width;
    desc.Height = height;
    desc.MipLevels = desc.ArraySize = desc.SampleDesc.Count = 1;
    desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    desc.BindFlags = D3D11_BIND_RENDER_TARGET;
    ComPtr<ID3D11Texture2D> target, staging;
    ComPtr<ID3D11RenderTargetView> view;
    if (FAILED(device->CreateTexture2D(&desc, nullptr, target.GetAddressOf())) || !target
        || FAILED(device->CreateRenderTargetView(target.Get(), nullptr, view.GetAddressOf())) || !view) return 12;
    auto stagingDesc = desc;
    stagingDesc.BindFlags = 0;
    stagingDesc.Usage = D3D11_USAGE_STAGING;
    stagingDesc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
    if (FAILED(device->CreateTexture2D(&stagingDesc, nullptr, staging.GetAddressOf())) || !staging) return 13;

    ComPtr<ID3DBlob> vs, ps;
    if (FAILED(D3DCompile(Shader, sizeof(Shader) - 1, nullptr, nullptr, nullptr, "vertex", "vs_5_0", 0, 0,
                          vs.GetAddressOf(), nullptr)) || !vs
        || FAILED(D3DCompile(Shader, sizeof(Shader) - 1, nullptr, nullptr, nullptr, "pixel", "ps_5_0", 0, 0,
                             ps.GetAddressOf(), nullptr)) || !ps) return 14;
    ComPtr<ID3D11VertexShader> vertex;
    ComPtr<ID3D11PixelShader> pixel;
    if (FAILED(device->CreateVertexShader(vs->GetBufferPointer(), vs->GetBufferSize(), nullptr, vertex.GetAddressOf()))
        || FAILED(device->CreatePixelShader(ps->GetBufferPointer(), ps->GetBufferSize(), nullptr, pixel.GetAddressOf()))
        || !vertex || !pixel) return 15;
    D3D11_RASTERIZER_DESC raster{};
    raster.FillMode = D3D11_FILL_SOLID;
    raster.CullMode = D3D11_CULL_NONE;
    raster.DepthClipEnable = TRUE;
    ComPtr<ID3D11RasterizerState> rasterizer;
    if (FAILED(device->CreateRasterizerState(&raster, rasterizer.GetAddressOf())) || !rasterizer) return 16;
    const D3D11_VIEWPORT viewport{0, 0, float(width), float(height), 0, 1};
    context->RSSetViewports(1, &viewport);
    context->RSSetState(rasterizer.Get());
    context->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
    context->VSSetShader(vertex.Get(), nullptr, 0);
    context->PSSetShader(pixel.Get(), nullptr, 0);

    bool exact = true;
    for (bool low : {true, false})
    {
        auto sourceDesc = desc;
        sourceDesc.Width = low ? logicalW : width;
        sourceDesc.Height = low ? logicalH : height;
        sourceDesc.Usage = D3D11_USAGE_IMMUTABLE;
        sourceDesc.BindFlags = D3D11_BIND_SHADER_RESOURCE;
        std::vector<UINT> stripes(sourceDesc.Width * sourceDesc.Height);
        for (std::size_t i = 0; i < stripes.size(); ++i)
            stripes[i] = (i % sourceDesc.Width) & 1 ? 0xffffffff : 0xff000000;
        const D3D11_SUBRESOURCE_DATA initial{stripes.data(), sourceDesc.Width * 4, 0};
        ComPtr<ID3D11Texture2D> texture;
        ComPtr<ID3D11ShaderResourceView> resource;
        if (FAILED(device->CreateTexture2D(&sourceDesc, &initial, texture.GetAddressOf())) || !texture
            || FAILED(device->CreateShaderResourceView(texture.Get(), nullptr, resource.GetAddressOf()))
            || !resource) return 17;

        for (bool linear : {false, true})
        {
            D3D11_SAMPLER_DESC samplerDesc{};
            samplerDesc.Filter = linear ? D3D11_FILTER_MIN_MAG_LINEAR_MIP_POINT : D3D11_FILTER_MIN_MAG_MIP_POINT;
            samplerDesc.AddressU = samplerDesc.AddressV = samplerDesc.AddressW = D3D11_TEXTURE_ADDRESS_CLAMP;
            samplerDesc.ComparisonFunc = D3D11_COMPARISON_NEVER;
            ComPtr<ID3D11SamplerState> sampler;
            if (FAILED(device->CreateSamplerState(&samplerDesc, sampler.GetAddressOf())) || !sampler) return 18;
            exact = Sample(context.Get(), target.Get(), staging.Get(), view.Get(), resource.Get(), sampler.Get(),
                           width, height, low, linear) && exact;
        }
    }
    return exact && !IsWindowVisible(window) && GetForegroundWindow() != window ? 0 : 19;
}

static bool Dimension(const char* argument, UINT& value)
{
    const auto* end = argument + std::strlen(argument);
    const auto parsed = std::from_chars(argument, end, value);
    return parsed.ec == std::errc{} && parsed.ptr == end && value >= 16 && value <= 1024 && !(value & 1);
}

int main(int argc, char** argv)
{
    UINT width = 0, height = 0;
    if (argc != 3 || !Dimension(argv[1], width) || !Dimension(argv[2], height)) return 1;
    const WNDCLASSW cls{0, DefWindowProcW, 0, 0, GetModuleHandleW(nullptr), nullptr, nullptr, nullptr,
                        nullptr, L"OwnDxmtSharpnessProbe"};
    if (!RegisterClassW(&cls)) return 2;
    HWND window = CreateWindowExW(WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW, cls.lpszClassName, L"", WS_POPUP,
                                  0, 0, width, height, nullptr, nullptr, cls.hInstance, nullptr);
    const int result = window && !IsWindowVisible(window) && GetForegroundWindow() != window
        ? Run(window, width, height) : 3;
    const bool destroyed = !window || DestroyWindow(window);
    const bool unregistered = UnregisterClassW(cls.lpszClassName, cls.hInstance);
    return destroyed && unregistered ? result : 4;
}
