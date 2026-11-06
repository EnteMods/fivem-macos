#include <d3d11_3.h>
#include <dxgi.h>
#include <initializer_list>

template<typename Desc> struct Resource {
  Desc desc{};
  constexpr HRESULT GetDXGIUsage(DXGI_USAGE* pUsage) {
#include "method-body.inc"
  }
};

template<typename Desc> constexpr bool Check() {
  Resource<Desc> resource;
  DXGI_USAGE usage = 0xdead;
  if (resource.GetDXGIUsage(nullptr) != E_INVALIDARG) return false;
  if (resource.GetDXGIUsage(&usage) != S_OK || usage != 0) return false;
  resource.desc.BindFlags = D3D11_BIND_SHADER_RESOURCE | D3D11_BIND_RENDER_TARGET;
  if (resource.GetDXGIUsage(&usage) != S_OK || usage != 0x30) return false;
  resource.desc.BindFlags = D3D11_BIND_CONSTANT_BUFFER;
  if (resource.GetDXGIUsage(&usage) != S_OK || usage != DXGI_USAGE_SHADER_INPUT) return false;
  resource.desc.BindFlags = D3D11_BIND_UNORDERED_ACCESS;
  if (resource.GetDXGIUsage(&usage) != S_OK || usage != DXGI_USAGE_UNORDERED_ACCESS) return false;
  resource.desc.BindFlags = D3D11_BIND_DEPTH_STENCIL;
  if (resource.GetDXGIUsage(&usage) != S_OK || usage != 0) return false;
  resource.desc.BindFlags = 0;
  for (UINT flag : {UINT(D3D11_RESOURCE_MISC_SHARED), UINT(D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX),
                    UINT(D3D11_RESOURCE_MISC_SHARED_NTHANDLE)}) {
    resource.desc.MiscFlags = flag;
    if (resource.GetDXGIUsage(&usage) != S_OK || usage != DXGI_USAGE_SHARED) return false;
  }
  resource.desc.MiscFlags = 0;
  resource.desc.Usage = D3D11_USAGE_IMMUTABLE;
  if (resource.GetDXGIUsage(&usage) != S_OK || usage != DXGI_CPU_ACCESS_NONE) return false;
  resource.desc.Usage = D3D11_USAGE_DYNAMIC;
  if (resource.GetDXGIUsage(&usage) != S_OK || usage != DXGI_CPU_ACCESS_DYNAMIC) return false;
  resource.desc.Usage = D3D11_USAGE_STAGING;
  if (resource.GetDXGIUsage(&usage) != S_OK || usage != DXGI_CPU_ACCESS_READ_WRITE) return false;
  resource.desc.Usage = D3D11_USAGE_DEFAULT;
  resource.desc.BindFlags = D3D11_BIND_SHADER_RESOURCE | D3D11_BIND_RENDER_TARGET | D3D11_BIND_UNORDERED_ACCESS;
  resource.desc.MiscFlags = D3D11_RESOURCE_MISC_SHARED_NTHANDLE;
  if (resource.GetDXGIUsage(&usage) != S_OK || usage != 0x4b0) return false;
  return resource.desc.Usage == D3D11_USAGE_DEFAULT && resource.desc.MiscFlags == D3D11_RESOURCE_MISC_SHARED_NTHANDLE;
}

static_assert(Check<D3D11_BUFFER_DESC>());
static_assert(Check<D3D11_TEXTURE1D_DESC>());
static_assert(Check<D3D11_TEXTURE2D_DESC1>());
static_assert(Check<D3D11_TEXTURE3D_DESC1>());
