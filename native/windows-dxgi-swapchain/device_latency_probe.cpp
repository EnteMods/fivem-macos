#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <d3d11.h>
#include <wrl/client.h>
#include <cstdio>

using Microsoft::WRL::ComPtr;

struct Trial
{
    HRESULT create = E_FAIL;
    HRESULT query = E_FAIL;
    HRESULT getOriginal = E_FAIL;
    HRESULT setLow = E_FAIL;
    HRESULT getLow = E_FAIL;
    HRESULT setOriginal = E_FAIL;
    HRESULT getRestored = E_FAIL;
    UINT original = 0;
    UINT low = 0;
    UINT restored = 0;
    bool sameDevice = false;
};

static Trial Measure(HWND window)
{
    Trial trial;
    DXGI_SWAP_CHAIN_DESC desc{};
    desc.BufferDesc.Width = 480;
    desc.BufferDesc.Height = 320;
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
    trial.create = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0,
        &feature, 1, D3D11_SDK_VERSION, &desc, chain.GetAddressOf(), device.GetAddressOf(), nullptr, nullptr);
    if (FAILED(trial.create) || !chain || !device)
        return trial;

    ComPtr<IDXGIDevice1> dxgi;
    trial.query = chain->GetDevice(IID_PPV_ARGS(dxgi.GetAddressOf()));
    if (FAILED(trial.query) || !dxgi)
        return trial;

    ComPtr<IUnknown> chainDeviceIdentity, deviceIdentity;
    trial.sameDevice = SUCCEEDED(dxgi.As(&chainDeviceIdentity)) && SUCCEEDED(device.As(&deviceIdentity))
        && chainDeviceIdentity.Get() == deviceIdentity.Get();
    if (!trial.sameDevice)
        return trial;

    trial.getOriginal = dxgi->GetMaximumFrameLatency(&trial.original);
    if (trial.getOriginal != S_OK || trial.original != 3)
        return trial;

    trial.setLow = dxgi->SetMaximumFrameLatency(1);
    trial.getLow = dxgi->GetMaximumFrameLatency(&trial.low);
    trial.setOriginal = dxgi->SetMaximumFrameLatency(trial.original);
    trial.getRestored = dxgi->GetMaximumFrameLatency(&trial.restored);
    return trial;
}

int main()
{
    WNDCLASSW cls{};
    cls.lpfnWndProc = DefWindowProcW;
    cls.hInstance = GetModuleHandleW(nullptr);
    cls.lpszClassName = L"OwnDxmtDeviceLatencyCalibration";
    if (!RegisterClassW(&cls))
        return 1;

    const HWND window = CreateWindowExW(WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW, cls.lpszClassName,
        L"Own DXMT Device Latency Calibration", WS_POPUP, 0, 0, 480, 320, nullptr, nullptr, cls.hInstance, nullptr);
    const bool hidden = window && !IsWindowVisible(window) && GetForegroundWindow() != window;
    const Trial trial = hidden ? Measure(window) : Trial{};
    const bool stillHidden = window && !IsWindowVisible(window) && GetForegroundWindow() != window;
    const bool destroyed = window && DestroyWindow(window);
    const bool unregistered = UnregisterClassW(cls.lpszClassName, cls.hInstance);
    const bool passed = hidden && stillHidden && destroyed && unregistered && trial.sameDevice
        && trial.create == S_OK && trial.query == S_OK && trial.getOriginal == S_OK
        && trial.setLow == S_OK && trial.getLow == S_OK && trial.setOriginal == S_OK && trial.getRestored == S_OK
        && trial.original == 3 && trial.low == 1 && trial.restored == 3;

    std::printf("{\"pid\":%lu,\"create\":%ld,\"query\":%ld,\"get_original\":%ld,\"set_low\":%ld,\"get_low\":%ld,"
        "\"set_original\":%ld,\"get_restored\":%ld,\"original\":%u,\"low\":%u,\"restored\":%u,"
        "\"same_device\":%s,\"hidden\":%s,\"destroyed\":%s,\"unregistered\":%s}\n",
        GetCurrentProcessId(), trial.create, trial.query, trial.getOriginal, trial.setLow, trial.getLow,
        trial.setOriginal, trial.getRestored, trial.original, trial.low, trial.restored,
        trial.sameDevice ? "true" : "false", hidden && stillHidden ? "true" : "false",
        destroyed ? "true" : "false", unregistered ? "true" : "false");
    return passed ? 0 : 1;
}
