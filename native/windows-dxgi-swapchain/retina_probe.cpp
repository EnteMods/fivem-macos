#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <d3d11.h>
#include <dxgi1_2.h>
#include <shellscalingapi.h>
#include <wrl/client.h>
#include <charconv>
#include <cstdio>
#include <cstring>

using Microsoft::WRL::ComPtr;

struct Size
{
    UINT w = 0, h = 0;
    bool operator==(const Size& other) const noexcept { return w == other.w && h == other.h; }
};

struct Evidence
{
    Size logical, hostScreen, monitor, displayMode, monitorDpi, client, backbuffer;
    UINT clientDpi = 0, scale = 0, expectedScale = 0, modules = 0;
    bool hidden = false, destroyed = false, unregistered = false;
};

static bool Dimension(const char* argument, UINT& value)
{
    const auto* end = argument + std::strlen(argument);
    const auto parsed = std::from_chars(argument, end, value);
    return parsed.ec == std::errc{} && parsed.ptr == end && value > 0 && value <= 16384;
}

static Size Extent(const RECT& rect)
{
    const auto w = static_cast<long long>(rect.right) - rect.left;
    const auto h = static_cast<long long>(rect.bottom) - rect.top;
    if (w <= 0 || h <= 0 || w > 32768 || h > 32768) return {};
    return {static_cast<UINT>(w), static_cast<UINT>(h)};
}

static UINT Modules()
{
    return (GetModuleHandleW(L"d3d11.dll") ? 1u : 0u)
        | (GetModuleHandleW(L"dxgi.dll") ? 2u : 0u)
        | (GetModuleHandleW(L"winemetal.dll") ? 4u : 0u);
}

static int Swapchain(HWND window, Evidence& evidence)
{
    const D3D_FEATURE_LEVEL level = D3D_FEATURE_LEVEL_11_0;
    ComPtr<ID3D11Device> device;
    if (FAILED(D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                               &level, 1, D3D11_SDK_VERSION, device.GetAddressOf(), nullptr, nullptr)) || !device)
        return 10;
    ComPtr<IDXGIDevice> dxgi;
    ComPtr<IDXGIAdapter> adapter;
    ComPtr<IDXGIFactory2> factory;
    if (FAILED(device.As(&dxgi)) || !dxgi || FAILED(dxgi->GetAdapter(adapter.GetAddressOf())) || !adapter
        || FAILED(adapter->GetParent(IID_PPV_ARGS(factory.GetAddressOf()))) || !factory) return 11;

    DXGI_SWAP_CHAIN_DESC1 desc{};
    // Leave both dimensions zero so the provider must infer them from the HWND.
    desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    desc.SampleDesc.Count = 1;
    desc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    desc.BufferCount = 2;
    desc.Scaling = DXGI_SCALING_STRETCH;
    desc.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
    ComPtr<IDXGISwapChain1> chain;
    if (FAILED(factory->CreateSwapChainForHwnd(device.Get(), window, &desc, nullptr, nullptr,
                                              chain.GetAddressOf())) || !chain) return 12;
    ComPtr<ID3D11Texture2D> texture;
    if (FAILED(chain->GetBuffer(0, IID_PPV_ARGS(texture.GetAddressOf()))) || !texture) return 13;
    D3D11_TEXTURE2D_DESC surface{};
    texture->GetDesc(&surface);
    evidence.backbuffer = {surface.Width, surface.Height};
    evidence.modules = Modules();
    return evidence.backbuffer == evidence.client && surface.Format == desc.Format && surface.SampleDesc.Count == 1
        ? 0 : 14;
}

static int Run(Evidence& evidence)
{
    const auto aware = DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2;
    SetProcessDpiAwarenessContext(aware);
    if (!AreDpiAwarenessContextsEqual(GetThreadDpiAwarenessContext(), aware)) return 2;

    const HMONITOR monitor = MonitorFromPoint({0, 0}, MONITOR_DEFAULTTOPRIMARY);
    MONITORINFOEXW info{};
    info.cbSize = sizeof(info);
    if (!monitor || !GetMonitorInfoW(monitor, &info) || !(info.dwFlags & MONITORINFOF_PRIMARY)) return 3;
    evidence.monitor = Extent(info.rcMonitor);

    DEVMODEW mode{};
    mode.dmSize = sizeof(mode);
    if (!EnumDisplaySettingsW(info.szDevice, ENUM_CURRENT_SETTINGS, &mode)
        || (mode.dmFields & (DM_PELSWIDTH | DM_PELSHEIGHT)) != (DM_PELSWIDTH | DM_PELSHEIGHT)) return 4;
    evidence.displayMode = {mode.dmPelsWidth, mode.dmPelsHeight};
    if (FAILED(GetDpiForMonitor(monitor, MDT_EFFECTIVE_DPI, &evidence.monitorDpi.w, &evidence.monitorDpi.h))
        || !evidence.monitorDpi.w || !evidence.monitorDpi.h) return 5;

    if (evidence.monitor == evidence.hostScreen)
        evidence.scale = 1;
    else if (evidence.monitor == Size{2 * evidence.hostScreen.w, 2 * evidence.hostScreen.h})
        evidence.scale = 2;
    const Size requested{evidence.logical.w * evidence.scale, evidence.logical.h * evidence.scale};
    if (!evidence.scale || !(evidence.displayMode == evidence.monitor) || requested.w > evidence.monitor.w
        || requested.h > evidence.monitor.h) return 6;

    const WNDCLASSW cls{0, DefWindowProcW, 0, 0, GetModuleHandleW(nullptr), nullptr, nullptr, nullptr,
                        nullptr, L"OwnDxmtRetinaFixture"};
    if (!RegisterClassW(&cls)) return 7;
    const HWND window = CreateWindowExW(WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW, cls.lpszClassName, L"", WS_POPUP,
                                       info.rcMonitor.left, info.rcMonitor.top, requested.w, requested.h,
                                       nullptr, nullptr, cls.hInstance, nullptr);
    int status = 8;
    if (window)
    {
        RECT client{};
        evidence.hidden = !IsWindowVisible(window) && GetForegroundWindow() != window;
        if (GetClientRect(window, &client)) evidence.client = Extent(client);
        evidence.clientDpi = GetDpiForWindow(window);
        status = 9;
        if (evidence.hidden && evidence.clientDpi && evidence.client == requested
            && MonitorFromWindow(window, MONITOR_DEFAULTTONULL) == monitor)
            status = Swapchain(window, evidence);
        evidence.hidden = evidence.hidden && !IsWindowVisible(window) && GetForegroundWindow() != window;
    }
    evidence.destroyed = window && DestroyWindow(window) != FALSE;
    evidence.unregistered = UnregisterClassW(cls.lpszClassName, cls.hInstance) != FALSE;
    if (!status && (!evidence.hidden || !evidence.destroyed || !evidence.unregistered)) return 15;
    if (!status && evidence.expectedScale && evidence.expectedScale != evidence.scale) return 16;
    return status;
}

int main(int argc, char** argv)
{
    Evidence evidence;
    if ((argc != 5 && argc != 6) || !Dimension(argv[1], evidence.logical.w) || !Dimension(argv[2], evidence.logical.h)
        || !Dimension(argv[3], evidence.hostScreen.w) || !Dimension(argv[4], evidence.hostScreen.h)
        || (argc == 6 && (!Dimension(argv[5], evidence.expectedScale) || evidence.expectedScale > 2))) return 1;
    const int status = Run(evidence);
    const auto& e = evidence;
    std::printf("{\"phase\":\"complete\",\"pid\":%lu,\"tid\":%lu,\"logical\":[%u,%u],\"host_screen\":[%u,%u],"
                "\"monitor\":[%u,%u],\"display_mode\":[%u,%u],\"monitor_dpi\":[%u,%u],\"client_dpi\":%u,"
                "\"scale\":%u,\"expected_scale\":%u,\"client\":[%u,%u],\"backbuffer\":[%u,%u],\"modules\":%u,"
                "\"hidden\":%s,\"destroyed\":%s,\"unregistered\":%s,\"status\":%d}\n",
                GetCurrentProcessId(), GetCurrentThreadId(), e.logical.w, e.logical.h, e.hostScreen.w, e.hostScreen.h,
                e.monitor.w, e.monitor.h, e.displayMode.w, e.displayMode.h, e.monitorDpi.w, e.monitorDpi.h, e.clientDpi,
                e.scale, e.expectedScale, e.client.w, e.client.h, e.backbuffer.w, e.backbuffer.h, e.modules,
                e.hidden ? "true" : "false", e.destroyed ? "true" : "false", e.unregistered ? "true" : "false", status);
    return status;
}
