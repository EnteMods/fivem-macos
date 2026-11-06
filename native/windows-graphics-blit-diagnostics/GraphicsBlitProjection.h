#pragma once

#include <cstdint>

namespace cfx::blit::projection
{
struct Vertex
{
    float x, y, z, nX, nY, nZ;
    std::uint32_t color;
    float u, v;
};

enum class ScissorMode { unavailable, disabled, enabled };

struct Geometry
{
    unsigned width = 0, height = 0, viewportCount = 0;
    float viewportX = 0, viewportY = 0, viewportWidth = 0, viewportHeight = 0;
    ScissorMode scissor = ScissorMode::unavailable;
    unsigned scissorCount = 0;
    std::int32_t scissorLeft = 0, scissorTop = 0, scissorRight = 0, scissorBottom = 0;
    // Require a verified menu draw and destination identity. Matching dimensions alone are insufficient.
    bool menuOutputBound = false;
};

constexpr unsigned MaxExtent = 16384;

// A prefix check uses only previous vertices. The complete check below also binds target size.
inline bool Expected(const Vertex (&vertices)[4], unsigned index, const Vertex& next) noexcept
{
    if (index >= 4)
        return false;
    const bool right = (index & 1) != 0, top = index < 2;
    if (next.u != (right ? 1.0f : 0.0f) || next.v != (top ? 0.0f : 1.0f)
            || next.z != 0 || next.nX != 0 || next.nY != 0 || next.nZ != -1)
        return false;

    if (index == 0)
        return next.x == 0 && next.y > 0 && next.y <= MaxExtent;
    if (index == 1)
        return next.x > 0 && next.x <= MaxExtent && next.y == vertices[0].y;
    if (index == 2)
        return next.x == 0 && next.y == 0;
    return next.x == vertices[1].x && next.y == 0;
}

inline bool Scale(Vertex (&vertices)[4], const Geometry& geometry,
                  unsigned referenceWidth, unsigned referenceHeight) noexcept
{
    const auto width = geometry.width, height = geometry.height;
    if (!geometry.menuOutputBound || !width || width > MaxExtent || !height || height > MaxExtent
            || !referenceWidth || referenceWidth > MaxExtent || !referenceHeight || referenceHeight > MaxExtent
            || (width == referenceWidth && height == referenceHeight))
        return false;

    if (geometry.viewportCount != 1 || geometry.viewportX != 0 || geometry.viewportY != 0
            || geometry.viewportWidth != static_cast<float>(width)
            || geometry.viewportHeight != static_cast<float>(height))
        return false;

    const bool fullScissor = geometry.scissor == ScissorMode::enabled && geometry.scissorCount == 1
        && geometry.scissorLeft == 0 && geometry.scissorTop == 0
        && geometry.scissorRight == static_cast<std::int32_t>(width)
        && geometry.scissorBottom == static_cast<std::int32_t>(height);
    if (geometry.scissor != ScissorMode::disabled && !fullScissor)
        return false;

    if (vertices[1].x != static_cast<float>(width) || vertices[0].y != static_cast<float>(height))
        return false;
    for (unsigned i = 0; i < 4; ++i)
        if (!Expected(vertices, i, vertices[i]))
            return false;

    // Each checked coordinate is either the origin or the full extent. Assigning the
    // reference extent is exactly the desired scaling and avoids floating-point ratio error.
    if (width != referenceWidth)
        vertices[1].x = vertices[3].x = static_cast<float>(referenceWidth);
    if (height != referenceHeight)
        vertices[0].y = vertices[1].y = static_cast<float>(referenceHeight);
    return true;
}
}
