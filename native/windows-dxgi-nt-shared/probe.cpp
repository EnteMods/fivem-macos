#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <d3d11_1.h>
#include <dxgi1_2.h>
#include <wrl/client.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>

using Microsoft::WRL::ComPtr;
static constexpr UINT Extent = 8;

static bool Record(unsigned mode, unsigned stage, HRESULT hr, bool valid, unsigned value = 0)
{
    const bool passed = SUCCEEDED(hr) && valid;
    std::printf("{\"mode\":%u,\"pid\":%lu,\"stage\":%u,\"hr\":%lu,\"ok\":%s,\"value\":%u}\n",
        mode, GetCurrentProcessId(), stage, static_cast<unsigned long>(hr), passed ? "true" : "false", value);
    return passed;
}

static bool Device(unsigned mode, unsigned stage, ComPtr<ID3D11Device>& device,
                   ComPtr<ID3D11DeviceContext>& context)
{
    const D3D_FEATURE_LEVEL level = D3D_FEATURE_LEVEL_11_0;
    const HRESULT hr = D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr,
        D3D11_CREATE_DEVICE_BGRA_SUPPORT, &level, 1, D3D11_SDK_VERSION,
        device.GetAddressOf(), nullptr, context.GetAddressOf());
    return Record(mode, stage, hr, device && context);
}

static bool Pixels(unsigned mode, unsigned stage, ID3D11Device* device,
                   ID3D11DeviceContext* context, ID3D11Texture2D* texture)
{
    D3D11_TEXTURE2D_DESC desc{};
    texture->GetDesc(&desc);
    desc.Usage = D3D11_USAGE_STAGING;
    desc.BindFlags = desc.MiscFlags = 0;
    desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
    ComPtr<ID3D11Texture2D> staging;
    HRESULT hr = device->CreateTexture2D(&desc, nullptr, staging.GetAddressOf());
    if (!Record(mode, stage, hr, !!staging))
        return false;
    context->CopyResource(staging.Get(), texture);
    D3D11_MAPPED_SUBRESOURCE mapped{};
    hr = context->Map(staging.Get(), 0, D3D11_MAP_READ, 0, &mapped);
    if (!Record(mode, stage + 1, hr, mapped.pData && mapped.RowPitch >= Extent * 4))
    {
        if (SUCCEEDED(hr))
            context->Unmap(staging.Get(), 0);
        return false;
    }
    unsigned matching = 0;
    for (UINT y = 0; y < Extent; ++y)
    {
        const auto* row = static_cast<const unsigned char*>(mapped.pData) + y * mapped.RowPitch;
        for (UINT x = 0; x < Extent; ++x)
        {
            const auto* pixel = row + x * 4;
            matching += pixel[0] == 255 && pixel[1] == 0 && pixel[2] == 0 && pixel[3] == 255;
        }
    }
    context->Unmap(staging.Get(), 0);
    return Record(mode, stage + 2, S_OK, matching == Extent * Extent, matching);
}

static bool Import(unsigned mode, HANDLE handle, bool keyed)
{
    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    if (!Device(mode, 20, device, context))
        return false;
    ComPtr<ID3D11Device1> device1;
    HRESULT hr = device.As(&device1);
    if (!Record(mode, 21, hr, !!device1))
        return false;
    ComPtr<ID3D11Texture2D> texture;
    hr = device1->OpenSharedResource1(handle, IID_PPV_ARGS(texture.GetAddressOf()));
    if (!Record(mode, 22, hr, !!texture))
        return false;
    D3D11_TEXTURE2D_DESC desc{};
    texture->GetDesc(&desc);
    if (!Record(mode, 23, S_OK, desc.Width == Extent, desc.Width)
        || !Record(mode, 24, S_OK, desc.Height == Extent, desc.Height)
        || !Record(mode, 25, S_OK, desc.Format == DXGI_FORMAT_B8G8R8A8_UNORM, desc.Format))
        return false;
    ComPtr<IDXGIKeyedMutex> mutex;
    if (keyed)
    {
        hr = texture.As(&mutex);
        if (!Record(mode, 26, hr, !!mutex))
            return false;
        hr = mutex->AcquireSync(1, 5000);
        if (!Record(mode, 27, hr, hr == S_OK))
            return false;
    }
    bool passed = Pixels(mode, 30, device.Get(), context.Get(), texture.Get());
    if (mutex)
    {
        hr = mutex->ReleaseSync(2);
        passed = Record(mode, 28, hr, hr == S_OK) && passed;
    }
    return passed;
}

static bool Child(HANDLE shared)
{
    const BOOL inheritable = SetHandleInformation(shared, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    if (!Record(2, 38, inheritable ? S_OK : HRESULT_FROM_WIN32(GetLastError()), !!inheritable))
        return false;
    wchar_t executable[32768];
    const DWORD length = GetModuleFileNameW(nullptr, executable, ARRAYSIZE(executable));
    if (!Record(2, 39, length && length < ARRAYSIZE(executable) ? S_OK : E_FAIL,
                length && length < ARRAYSIZE(executable)))
        return false;
    wchar_t command[33024];
    const int written = std::swprintf(command, ARRAYSIZE(command), L"\"%ls\" --child %llu", executable,
        static_cast<unsigned long long>(reinterpret_cast<UINT_PTR>(shared)));
    if (written <= 0 || written >= static_cast<int>(ARRAYSIZE(command)))
        return Record(2, 40, E_FAIL, false);
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startup.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    PROCESS_INFORMATION child{};
    const BOOL created = CreateProcessW(executable, command, nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW, nullptr, nullptr, &startup, &child);
    const DWORD error = created ? 0 : GetLastError();
    if (!Record(2, 40, HRESULT_FROM_WIN32(error), !!created))
        return false;
    const DWORD wait = WaitForSingleObject(child.hProcess, 15000);
    bool passed = Record(2, 41, wait == WAIT_OBJECT_0 ? S_OK : E_FAIL, wait == WAIT_OBJECT_0);
    if (wait != WAIT_OBJECT_0)
    {
        TerminateProcess(child.hProcess, 98);
        WaitForSingleObject(child.hProcess, 5000);
    }
    DWORD exit = 0;
    const BOOL queried = GetExitCodeProcess(child.hProcess, &exit);
    passed = Record(2, 42, queried ? S_OK : HRESULT_FROM_WIN32(GetLastError()), queried && exit == 17, exit) && passed;
    passed = Record(2, 43, S_OK, !!CloseHandle(child.hThread)) && passed;
    passed = Record(2, 44, S_OK, !!CloseHandle(child.hProcess)) && passed;
    return passed;
}

static bool Produce(unsigned mode, bool keyed, HANDLE& shared)
{
    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    if (!Device(mode, 1, device, context))
        return false;
    D3D11_TEXTURE2D_DESC desc{};
    desc.Width = desc.Height = Extent;
    desc.MipLevels = desc.ArraySize = desc.SampleDesc.Count = 1;
    desc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    desc.Usage = D3D11_USAGE_DEFAULT;
    desc.BindFlags = D3D11_BIND_RENDER_TARGET | D3D11_BIND_SHADER_RESOURCE;
    desc.MiscFlags = D3D11_RESOURCE_MISC_SHARED_NTHANDLE
        | (keyed ? D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX : D3D11_RESOURCE_MISC_SHARED);
    ComPtr<ID3D11Texture2D> texture;
    HRESULT hr = device->CreateTexture2D(&desc, nullptr, texture.GetAddressOf());
    if (!Record(mode, 2, hr, !!texture, desc.MiscFlags))
        return false;
    ComPtr<IDXGIResource1> resource;
    hr = texture.As(&resource);
    if (!Record(mode, 3, hr, !!resource))
        return false;
    hr = resource->CreateSharedHandle(nullptr, DXGI_SHARED_RESOURCE_READ | DXGI_SHARED_RESOURCE_WRITE,
        nullptr, &shared);
    if (!Record(mode, 4, hr, shared != nullptr))
        return false;
    ComPtr<ID3D11RenderTargetView> view;
    hr = device->CreateRenderTargetView(texture.Get(), nullptr, view.GetAddressOf());
    if (!Record(mode, 5, hr, !!view))
        return false;
    ComPtr<IDXGIKeyedMutex> mutex;
    if (keyed)
    {
        hr = texture.As(&mutex);
        if (!Record(mode, 6, hr, !!mutex))
            return false;
        hr = mutex->AcquireSync(0, 5000);
        if (!Record(mode, 7, hr, hr == S_OK))
            return false;
    }
    const float blue[4] = {0, 0, 1, 1};
    context->ClearRenderTargetView(view.Get(), blue);
    context->Flush();
    bool passed = Pixels(mode, 10, device.Get(), context.Get(), texture.Get());
    if (mutex)
    {
        hr = mutex->ReleaseSync(1);
        passed = Record(mode, 8, hr, hr == S_OK) && passed;
    }
    if (!passed)
        return false;
    return mode == 2 ? Child(shared) : Import(mode, shared, keyed);
}

int main(int argc, char** argv)
{
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    if (argc == 3 && !std::strcmp(argv[1], "--child"))
    {
        char* end = nullptr;
        const auto value = std::strtoull(argv[2], &end, 10);
        if (!value || !end || *end)
            return 64;
        HANDLE shared = reinterpret_cast<HANDLE>(static_cast<UINT_PTR>(value));
        bool passed = Import(3, shared, false);
        passed = Record(3, 90, S_OK, !!CloseHandle(shared)) && passed;
        Record(3, 99, S_OK, passed, 17);
        return passed ? 17 : 1;
    }
    if (argc != 2)
        return 64;
    const bool keyed = !std::strcmp(argv[1], "--same-keyed");
    const unsigned mode = !std::strcmp(argv[1], "--child-roundtrip") ? 2 : 1;
    if (!keyed && mode != 2 && std::strcmp(argv[1], "--same"))
        return 64;
    HANDLE shared = nullptr;
    bool passed = Produce(mode, keyed, shared);
    const bool closed = !shared || CloseHandle(shared);
    passed = Record(mode, 90, S_OK, closed, shared ? 1 : 0) && passed;
    Record(mode, 99, S_OK, passed);
    return passed ? 0 : 1;
}
