#pragma once

#include "GraphicsBlitProjection.h"

namespace cfx::blit::projection
{
struct Bounds { std::int32_t left, top, right, bottom; };

inline bool SpansMonitor(const Bounds& client, const Bounds& monitor) noexcept
{
    const auto topGap = static_cast<std::int64_t>(client.top) - monitor.top;
    return monitor.right > monitor.left && client.bottom > client.top
        && client.left == monitor.left && client.right == monitor.right && client.bottom == monitor.bottom
        && topGap >= 0 && topGap <= 128;
}

struct FullscreenYReference
{
    const void* chain = nullptr;
    const void* window = nullptr;
    unsigned height = 0;
    bool observed = false;

    bool Learn(const void* candidateChain, const void* candidateWindow, unsigned extent, bool spanning) noexcept
    {
        if (observed || !candidateChain || !candidateWindow || !extent || extent > MaxExtent)
            return false;
        observed = true;
        if (spanning)
            return false;
        chain = candidateChain;
        window = candidateWindow;
        height = extent;
        return true;
    }

    bool Apply(Vertex (&quad)[4], const void* candidateChain, const void* candidateWindow,
               unsigned currentHeight, bool spanning) const noexcept
    {
        // The caller has already admitted the exact native quad and the current raster state.
        if (!height || !spanning || candidateChain != chain || candidateWindow != window || currentHeight <= height)
            return false;
        quad[0].y = quad[1].y = static_cast<float>(height);
        return true;
    }
};
}
