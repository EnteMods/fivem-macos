#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <d3d11.h>
#include <dxgi1_6.h>
#include <wrl/client.h>
#include <cstdio>

using Microsoft::WRL::ComPtr;

static constexpr wchar_t ClassName[] = L"OwnDxgiSwapchainFixture";

static bool Api(unsigned stage, unsigned kind, unsigned status, bool success, bool object)
{
    std::printf("{\"event\":\"api\",\"stage\":%u,\"result_kind\":%u,\"status\":%u,"
                "\"succeeded\":%s,\"object_nonnull\":%s}\n", stage, kind, status,
                success ? "true" : "false", object ? "true" : "false");
    std::fflush(stdout);
    return success && object;
}

static bool ComApi(unsigned stage, HRESULT status, bool object)
{
    return Api(stage, 2, static_cast<unsigned>(status), SUCCEEDED(status), object);
}

int main(int argc, char**)
{
    if (argc != 1) return 2;
    std::printf("{\"event\":\"ready\",\"schema\":1,\"windows_pid\":%lu,\"width\":1280,"
                "\"height\":720,\"format\":28,\"buffer_count\":2,\"sample_count\":1,"
                "\"swap_effect\":0,\"swapchain_flags\":2,\"windowed\":true,"
                "\"cross_process\":false,\"present_called\":false}\n", GetCurrentProcessId());
    std::fflush(stdout);

    HINSTANCE instance = GetModuleHandleW(nullptr);
    ATOM atom = 0;
    HWND window = nullptr;
    unsigned lastStage = 0;
    bool attempted = false, queryAttempted = false, swapchainNonnull = false;
    ComPtr<IDXGIFactory1> initialFactory;
    ComPtr<IDXGIFactory6> factory6;
    ComPtr<IDXGIAdapter1> preferred;
    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    ComPtr<IDXGIDevice> dxgiDevice;
    ComPtr<IDXGIAdapter> adapter;
    ComPtr<IDXGIFactory2> factory2;
    ComPtr<IDXGISwapChain1> swapchain1;
    ComPtr<IDXGISwapChain> swapchain;
    D3D_FEATURE_LEVEL level = static_cast<D3D_FEATURE_LEVEL>(0);

    const bool functional = [&]() {
        WNDCLASSW wc = {};
        wc.lpfnWndProc = DefWindowProcW;
        wc.hInstance = instance;
        wc.lpszClassName = ClassName;
        SetLastError(0);
        atom = RegisterClassW(&wc);
        DWORD error = GetLastError();
        if (!Api(lastStage = 1, 1, error, atom != 0, atom != 0)) return false;
        SetLastError(0);
        window = CreateWindowExW(0, ClassName, L"Own DXGI swapchain fixture", WS_OVERLAPPEDWINDOW,
                                 CW_USEDEFAULT, CW_USEDEFAULT, 1280, 720, nullptr, nullptr, instance, nullptr);
        error = GetLastError();
        if (!Api(lastStage = 2, 1, error, window != nullptr, window != nullptr)) return false;
        ShowWindow(window, SW_SHOWNOACTIVATE);
        MSG message = {};
        for (unsigned count = 0; count != 64 && PeekMessageW(&message, window, 0, 0, PM_REMOVE); ++count)
        {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }

        HRESULT hr = CreateDXGIFactory1(__uuidof(IDXGIFactory1),
                                       reinterpret_cast<void**>(initialFactory.GetAddressOf()));
        if (!ComApi(lastStage = 3, hr, initialFactory != nullptr)) return false;
        hr = initialFactory.As(&factory6);
        if (!ComApi(lastStage = 4, hr, factory6 != nullptr)) return false;
        hr = factory6->EnumAdapterByGpuPreference(0, DXGI_GPU_PREFERENCE_HIGH_PERFORMANCE,
                   __uuidof(IDXGIAdapter1), reinterpret_cast<void**>(preferred.GetAddressOf()));
        if (!ComApi(lastStage = 5, hr, preferred != nullptr)) return false;
        const D3D_FEATURE_LEVEL levels[] = {D3D_FEATURE_LEVEL_11_0};
        hr = D3D11CreateDevice(preferred.Get(), D3D_DRIVER_TYPE_UNKNOWN, nullptr,
                              D3D11_CREATE_DEVICE_BGRA_SUPPORT, levels, 1, D3D11_SDK_VERSION,
                              device.GetAddressOf(), &level, context.GetAddressOf());
        if (!ComApi(lastStage = 6, hr, device != nullptr && context != nullptr)) return false;
        hr = device.As(&dxgiDevice);
        if (!ComApi(lastStage = 7, hr, dxgiDevice != nullptr)) return false;
        hr = dxgiDevice->GetAdapter(adapter.GetAddressOf());
        if (!ComApi(lastStage = 8, hr, adapter != nullptr)) return false;
        hr = adapter->GetParent(__uuidof(IDXGIFactory2), reinterpret_cast<void**>(factory2.GetAddressOf()));
        if (!ComApi(lastStage = 9, hr, factory2 != nullptr)) return false;

        DXGI_SWAP_CHAIN_DESC1 desc = {};
        desc.Width = 1280;
        desc.Height = 720;
        desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        desc.BufferCount = 2;
        desc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
        desc.SampleDesc.Count = 1;
        desc.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
        desc.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
        DXGI_SWAP_CHAIN_FULLSCREEN_DESC fullscreen = {};
        fullscreen.Windowed = TRUE;
        attempted = true;
        hr = factory2->CreateSwapChainForHwnd(device.Get(), window, &desc, &fullscreen,
                                             nullptr, swapchain1.GetAddressOf());
        swapchainNonnull = swapchain1 != nullptr;
        if (!ComApi(lastStage = 10, hr, swapchainNonnull)) return false;
        queryAttempted = true;
        hr = swapchain1.As(&swapchain);
        return ComApi(lastStage = 11, hr, swapchain != nullptr);
    }();

    swapchain.Reset();
    swapchain1.Reset();
    factory2.Reset();
    adapter.Reset();
    dxgiDevice.Reset();
    context.Reset();
    device.Reset();
    preferred.Reset();
    factory6.Reset();
    initialFactory.Reset();
    const bool destroyed = !window || DestroyWindow(window) != FALSE;
    const bool unregistered = !atom || UnregisterClassW(ClassName, instance) != FALSE;
    const bool complete = destroyed && unregistered;
    std::printf("{\"event\":\"completed\",\"last_stage\":%u,\"feature_level\":%u,"
                "\"create_swapchain_attempted\":%s,\"swapchain_nonnull\":%s,"
                "\"query_interface_attempted\":%s,\"functional_success\":%s,"
                "\"window_destroyed\":%s,\"class_unregistered\":%s,"
                "\"capture_complete\":%s,\"exit\":%u}\n", lastStage, static_cast<unsigned>(level),
                attempted ? "true" : "false", swapchainNonnull ? "true" : "false",
                queryAttempted ? "true" : "false", functional ? "true" : "false",
                destroyed ? "true" : "false", unregistered ? "true" : "false",
                complete ? "true" : "false", complete ? 0u : 1u);
    return complete ? 0 : 1;
}
