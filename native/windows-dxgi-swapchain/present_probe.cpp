#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <d3d11.h>
#include <d3dcompiler.h>
#include <wrl/client.h>
#include <algorithm>
#include <cstdio>
#include <cstring>

using Microsoft::WRL::ComPtr;

static constexpr UINT ClientWidth = 480, ClientHeight = 320;
static constexpr ULONGLONG RunBudgetMs = 12000, PresentIntervalMs = 125;
static bool stopRequested;

static constexpr char Shader[] = R"(
struct Vertex { float4 position : SV_Position; float2 uv : TEXCOORD0; };

Vertex vertex(uint id : SV_VertexID)
{
    Vertex output;
    output.uv = float2(id == 2 ? 2 : 0, id == 1 ? 2 : 0);
    output.position = float4(output.uv.x * 2 - 1, 1 - output.uv.y * 2, 0, 1);
    return output;
}

bool inside(float2 uv, float2 start, float2 end)
{
    return all(uv >= start) && all(uv < end);
}

float4 pixel(Vertex input) : SV_Target
{
    float2 uv = input.uv;
    if (inside(uv, float2(.125, .125), float2(.25, .25))) return float4(1, 0, 0, 1);
    if (inside(uv, float2(.625, .125), float2(.875, .25))) return float4(0, 1, 0, 1);
    if (inside(uv, float2(.125, .625), float2(.25, .875))) return float4(0, 0, 1, 1);
    if (inside(uv, float2(.75, .75), float2(.875, .875))) return float4(1, 1, 0, 1);
    return float4(0, 0, 0, 1);
}
)";

static LRESULT CALLBACK WindowProc(HWND window, UINT message, WPARAM wp, LPARAM lp)
{
    if (message == WM_CLOSE)
    {
        stopRequested = true;
        return 0;
    }
    return DefWindowProcW(window, message, wp, lp);
}

static int Calibrate(HWND window, bool explicitSize, const char* mode, ULONGLONG deadline, UINT& presented)
{
    DXGI_SWAP_CHAIN_DESC desc{};
    desc.BufferDesc.Width = explicitSize ? 640 : ClientWidth;
    desc.BufferDesc.Height = explicitSize ? 360 : ClientHeight;
    desc.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    desc.SampleDesc.Count = 1;
    desc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    desc.BufferCount = 2;
    desc.OutputWindow = window;
    desc.Windowed = TRUE;
    desc.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
    const D3D_FEATURE_LEVEL feature = D3D_FEATURE_LEVEL_11_0;
    ComPtr<IDXGISwapChain> chain;
    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    if (FAILED(D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0,
            &feature, 1, D3D11_SDK_VERSION, &desc, chain.GetAddressOf(), device.GetAddressOf(),
            nullptr, context.GetAddressOf())) || !chain || !device || !context) return 11;

    ComPtr<ID3D11Texture2D> buffer;
    if (FAILED(chain->GetBuffer(0, IID_PPV_ARGS(buffer.GetAddressOf()))) || !buffer) return 12;
    D3D11_TEXTURE2D_DESC surface{};
    buffer->GetDesc(&surface);
    ComPtr<ID3D11RenderTargetView> target;
    if (FAILED(device->CreateRenderTargetView(buffer.Get(), nullptr, target.GetAddressOf())) || !target) return 13;

    ComPtr<ID3DBlob> vertexCode, pixelCode;
    if (FAILED(D3DCompile(Shader, sizeof(Shader) - 1, nullptr, nullptr, nullptr, "vertex", "vs_5_0", 0, 0,
            vertexCode.GetAddressOf(), nullptr)) || !vertexCode
        || FAILED(D3DCompile(Shader, sizeof(Shader) - 1, nullptr, nullptr, nullptr, "pixel", "ps_5_0", 0, 0,
            pixelCode.GetAddressOf(), nullptr)) || !pixelCode) return 14;
    ComPtr<ID3D11VertexShader> vertex;
    ComPtr<ID3D11PixelShader> pixel;
    if (FAILED(device->CreateVertexShader(vertexCode->GetBufferPointer(), vertexCode->GetBufferSize(), nullptr,
            vertex.GetAddressOf())) || !vertex
        || FAILED(device->CreatePixelShader(pixelCode->GetBufferPointer(), pixelCode->GetBufferSize(), nullptr,
            pixel.GetAddressOf())) || !pixel) return 15;
    D3D11_RASTERIZER_DESC raster{};
    raster.FillMode = D3D11_FILL_SOLID;
    raster.CullMode = D3D11_CULL_NONE;
    raster.DepthClipEnable = TRUE;
    ComPtr<ID3D11RasterizerState> state;
    if (FAILED(device->CreateRasterizerState(&raster, state.GetAddressOf())) || !state) return 16;
    context->RSSetState(state.Get());
    const D3D11_VIEWPORT viewport{0, 0, static_cast<float>(surface.Width), static_cast<float>(surface.Height), 0, 1};
    context->RSSetViewports(1, &viewport);
    context->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
    context->VSSetShader(vertex.Get(), nullptr, 0);
    context->PSSetShader(pixel.Get(), nullptr, 0);

    if (GetTickCount64() >= deadline || !SetWindowPos(window, HWND_BOTTOM, 0, 0, 0, 0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW)) return 17;
    ULONGLONG nextPresent = GetTickCount64();
    while (!stopRequested)
    {
        MSG message{};
        for (unsigned count = 0; count != 64 && PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE); ++count)
        {
            if (message.message == WM_QUIT)
            {
                stopRequested = true;
                break;
            }
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
        const auto now = GetTickCount64();
        if (stopRequested || now >= deadline) break;
        if (GetForegroundWindow() == window) return 18;
        if (now < nextPresent)
        {
            const auto wait = static_cast<DWORD>(std::min(nextPresent, deadline) - now);
            if (MsgWaitForMultipleObjectsEx(0, nullptr, wait, QS_ALLINPUT, MWMO_INPUTAVAILABLE) == WAIT_FAILED) return 19;
            continue;
        }

        auto* view = target.Get();
        context->OMSetRenderTargets(1, &view, nullptr);
        const float black[4] = {0, 0, 0, 1};
        context->ClearRenderTargetView(view, black);
        context->Draw(3, 0);
        const HRESULT result = chain->Present(0, 0);
        if (FAILED(result)) return 20;
        nextPresent = GetTickCount64() + PresentIntervalMs;
        if (result != S_OK) continue;

        if (++presented == 1)
        {
            RECT client{};
            if (!GetClientRect(window, &client)) return 21;
            const bool visible = IsWindowVisible(window) != FALSE;
            const bool foreground = GetForegroundWindow() == window;
            const LONG width = client.right - client.left, height = client.bottom - client.top;
            std::printf("{\"event\":\"ready\",\"mode\":\"%s\",\"pid\":%lu,\"tid\":%lu,"
                "\"client_w\":%ld,\"client_h\":%ld,\"backbuffer_w\":%u,\"backbuffer_h\":%u,"
                "\"visible\":%s,\"foreground\":%s}\n", mode, GetCurrentProcessId(), GetCurrentThreadId(),
                width, height, surface.Width, surface.Height, visible ? "true" : "false", foreground ? "true" : "false");
            std::fflush(stdout);
            if (!visible || foreground || width != static_cast<LONG>(ClientWidth) || height != static_cast<LONG>(ClientHeight)
                    || surface.Width != desc.BufferDesc.Width || surface.Height != desc.BufferDesc.Height) return 22;
        }
    }
    context->OMSetRenderTargets(0, nullptr, nullptr);
    return presented ? 0 : 23;
}

int main(int argc, char** argv)
{
    if (argc != 2 || (std::strcmp(argv[1], "match") && std::strcmp(argv[1], "explicit"))) return 1;
    const bool explicitSize = std::strcmp(argv[1], "explicit") == 0;
    const char* mode = explicitSize ? "explicit" : "match";
    const auto start = GetTickCount64();
    WNDCLASSW cls{};
    cls.lpfnWndProc = WindowProc;
    cls.hInstance = GetModuleHandleW(nullptr);
    cls.lpszClassName = L"OwnDxmtPresentCalibration";
    if (!RegisterClassW(&cls)) return 2;
    HWND window = CreateWindowExW(WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW, cls.lpszClassName,
        L"Own DXMT Present Calibration", WS_POPUP, 32, 64, ClientWidth, ClientHeight,
        nullptr, nullptr, cls.hInstance, nullptr);
    UINT presented = 0;
    int result = window && !IsWindowVisible(window) ? Calibrate(window, explicitSize, mode, start + RunBudgetMs, presented) : 3;
    const bool destroyed = window && DestroyWindow(window);
    const bool unregistered = UnregisterClassW(cls.lpszClassName, cls.hInstance) != FALSE;
    if (!result && (!destroyed || !unregistered)) result = 4;
    std::printf("{\"event\":\"complete\",\"mode\":\"%s\",\"pid\":%lu,\"tid\":%lu,\"presented\":%u,"
        "\"stopped\":%s,\"elapsed_ms\":%llu,\"window_destroyed\":%s,\"class_unregistered\":%s,\"exit\":%d}\n",
        mode, GetCurrentProcessId(), GetCurrentThreadId(), presented, stopRequested ? "true" : "false",
        static_cast<unsigned long long>(GetTickCount64() - start), destroyed ? "true" : "false",
        unregistered ? "true" : "false", result);
    std::fflush(stdout);
    return result;
}
