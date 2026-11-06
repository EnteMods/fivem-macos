#include <windows.h>
#include <d3d11.h>
#include <dxgi.h>
#include <wrl/client.h>
#include <array>
#include <cstdio>
#include <cstdint>
using Microsoft::WRL::ComPtr;

static void emit(unsigned scenario,unsigned stage,HRESULT hr,unsigned value,bool ok) {
 std::printf("{\"scenario\":%u,\"stage\":%u,\"hr\":%u,\"value\":%u,\"ok\":%s}\n",scenario,stage,unsigned(hr),value,ok?"true":"false");
}
// Only this defensive invalid-argument check uses SEH; no COM pointer value is exposed.
static HRESULT null_usage(IDXGIResource* resource, bool* caught) {
 __try { return resource->GetUsage(nullptr); }
 __except(EXCEPTION_EXECUTE_HANDLER) { *caught=true; return E_UNEXPECTED; }
}
static bool exercise(ID3D11Device* device,ID3D11DeviceContext* context,unsigned scenario,UINT binds) {
 D3D11_TEXTURE2D_DESC request{}; request.Width=8; request.Height=8; request.MipLevels=1;
 request.ArraySize=1; request.Format=DXGI_FORMAT_B8G8R8A8_UNORM;request.SampleDesc.Count=1;
 request.Usage=D3D11_USAGE_DEFAULT;request.BindFlags=binds;
 ComPtr<ID3D11Texture2D> texture; HRESULT hr=device->CreateTexture2D(&request,nullptr,texture.GetAddressOf());
 bool ok=SUCCEEDED(hr)&&texture;emit(scenario,1,hr,0,ok);if(!ok)return false;
 D3D11_TEXTURE2D_DESC actual{};texture->GetDesc(&actual);
 ok=actual.Width==8&&actual.Height==8&&actual.MipLevels==1&&actual.ArraySize==1&&actual.Format==request.Format&&actual.SampleDesc.Count==1&&actual.SampleDesc.Quality==0&&actual.Usage==D3D11_USAGE_DEFAULT&&actual.CPUAccessFlags==0&&actual.BindFlags==binds&&actual.MiscFlags==0;
 emit(scenario,2,S_OK,actual.BindFlags,ok);if(!ok)return false;
 ComPtr<IDXGIResource> resource;hr=texture.As(&resource);ok=SUCCEEDED(hr)&&resource;
 emit(scenario,3,hr,0,ok);if(!ok)return false;
 DXGI_USAGE usage=0;hr=resource->GetUsage(&usage);
 const unsigned mask=DXGI_USAGE_SHADER_INPUT|DXGI_USAGE_RENDER_TARGET_OUTPUT;
 const unsigned expected=((binds&D3D11_BIND_SHADER_RESOURCE)?DXGI_USAGE_SHADER_INPUT:0)|((binds&D3D11_BIND_RENDER_TARGET)?DXGI_USAGE_RENDER_TARGET_OUTPUT:0);
 ok=SUCCEEDED(hr)&&(usage&mask)==expected;emit(scenario,4,hr,usage,ok);
 if(binds&D3D11_BIND_SHADER_RESOURCE) {
  ComPtr<ID3D11ShaderResourceView> srv;hr=device->CreateShaderResourceView(texture.Get(),nullptr,srv.GetAddressOf());bool viewok=SUCCEEDED(hr)&&srv;emit(scenario,5,hr,0,viewok);ok&=viewok;
 }
 if(binds&D3D11_BIND_RENDER_TARGET) {
  ComPtr<ID3D11RenderTargetView> rtv;hr=device->CreateRenderTargetView(texture.Get(),nullptr,rtv.GetAddressOf());bool viewok=SUCCEEDED(hr)&&rtv;emit(scenario,6,hr,0,viewok);ok&=viewok;
  if(viewok) {
   const float red[4]={1,0,0,1};context->ClearRenderTargetView(rtv.Get(),red);
   D3D11_TEXTURE2D_DESC desc=actual;desc.BindFlags=0;desc.Usage=D3D11_USAGE_STAGING;desc.CPUAccessFlags=D3D11_CPU_ACCESS_READ;desc.MiscFlags=0;
   ComPtr<ID3D11Texture2D> staging;hr=device->CreateTexture2D(&desc,nullptr,staging.GetAddressOf());bool stageok=SUCCEEDED(hr)&&staging;
   if(stageok) {
    context->CopyResource(staging.Get(),texture.Get());D3D11_MAPPED_SUBRESOURCE map{};hr=context->Map(staging.Get(),0,D3D11_MAP_READ,0,&map);
    bool mapped=SUCCEEDED(hr)&&map.pData&&map.RowPitch>=32;unsigned match=0;
    if(mapped)for(unsigned y=0;y<8;y++)for(unsigned x=0;x<8;x++){auto p=static_cast<const uint8_t*>(map.pData)+y*map.RowPitch+x*4;match+=p[0]==0&&p[1]==0&&p[2]==255&&p[3]==255;}
    if(SUCCEEDED(hr))context->Unmap(staging.Get(),0);stageok=mapped&&match==64;emit(scenario,7,hr,match,stageok);
   } else emit(scenario,7,hr,0,false);
   ok&=stageok;
  }
 }
 if(scenario==3) {
  bool caught=false;hr=null_usage(resource.Get(),&caught);
  // Documentation does not promise a particular HRESULT for this invalid call.
  const bool defensive=!caught&&FAILED(hr);emit(scenario,8,hr,unsigned(caught),defensive);ok&=defensive;
 }
 return ok;
}
int main() {
 std::setvbuf(stdout,nullptr,_IONBF,0);
 ComPtr<ID3D11Device> dev;ComPtr<ID3D11DeviceContext> context;D3D_FEATURE_LEVEL level{};
 const D3D_FEATURE_LEVEL requested=D3D_FEATURE_LEVEL_11_0;
 HRESULT hr=D3D11CreateDevice(nullptr,D3D_DRIVER_TYPE_HARDWARE,nullptr,D3D11_CREATE_DEVICE_BGRA_SUPPORT,&requested,1,D3D11_SDK_VERSION,dev.GetAddressOf(),&level,context.GetAddressOf());
 bool ok=SUCCEEDED(hr)&&dev&&context&&level==requested;emit(0,0,hr,unsigned(level),ok);
 if(ok)for(unsigned i=0;i<4;i++) {unsigned flags=(i&1?D3D11_BIND_SHADER_RESOURCE:0)|(i&2?D3D11_BIND_RENDER_TARGET:0);ok=exercise(dev.Get(),context.Get(),i,flags)&&ok;}
 emit(0,99,S_OK,ok?1:0,ok);return ok?0:1;
}
