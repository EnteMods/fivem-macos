#pragma once

#include "GraphicsBlitDiagnostics.h"
#include <cmath>

namespace cfx::blit::test
{
// Own fixture only. The caller supplies the dimensions of its full, origin-zero quad.
class ViewportAlignScope
{
public:
    ViewportAlignScope(ID3D11DeviceContext* context, UINT quadWidth, UINT quadHeight) noexcept
        : context_(context)
    {
        if (!context_ || !quadWidth || !quadHeight)
            return;

        D3D11_VIEWPORT viewports[D3D11_VIEWPORT_AND_SCISSORRECT_OBJECT_COUNT_PER_PIPELINE]{};
        UINT count = D3D11_VIEWPORT_AND_SCISSORRECT_OBJECT_COUNT_PER_PIPELINE;
        context_->RSGetViewports(&count, viewports);
        if (count != 1)
            return;

        UINT targetWidth = 0, targetHeight = 0;
        RenderTargetSize(context_, targetWidth, targetHeight);
        if (quadWidth != targetWidth || quadHeight != targetHeight)
            return;

        const auto& viewport = viewports[0];
        const auto width = static_cast<float>(targetWidth);
        const auto height = static_cast<float>(targetHeight);
        if (!(viewport.TopLeftX == 0 && viewport.TopLeftY > 0
                && viewport.Width > 0 && viewport.Width < width
                && viewport.Height > 0 && viewport.Height < height
                && viewport.TopLeftY + viewport.Height == height
                && std::fabs(3 * viewport.Width - 4 * viewport.Height) <= 3))
            return;

        // An enabled scissor has independent clipping intent. Leave it and the viewport alone.
        ID3D11RasterizerState* rasterizer = nullptr;
        context_->RSGetState(&rasterizer);
        if (rasterizer)
        {
            D3D11_RASTERIZER_DESC desc{};
            rasterizer->GetDesc(&desc);
            rasterizer->Release();
            if (desc.ScissorEnable)
                return;
        }

        original_ = viewport;
        const D3D11_VIEWPORT full{0, 0, width, height, original_.MinDepth, original_.MaxDepth};
        context_->RSSetViewports(1, &full);
        applied_ = true;
    }

    ~ViewportAlignScope()
    {
        if (applied_)
            context_->RSSetViewports(1, &original_);
    }

    ViewportAlignScope(const ViewportAlignScope&) = delete;
    ViewportAlignScope& operator=(const ViewportAlignScope&) = delete;
    bool Applied() const noexcept { return applied_; }

private:
    ID3D11DeviceContext* context_;
    D3D11_VIEWPORT original_{};
    bool applied_ = false;
};
}
