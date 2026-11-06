#pragma once

#include "GraphicsBlitDiagnostics.h"
#include <atomic>

namespace cfx::blit::gate
{
enum class Stage : unsigned
{
    none = 0,
    push = 1,
    beginPrimitive = 2,
    beginBudget = 3,
    beginCaller = 4,
    beginAdmitted = 5,
    vertexRejected = 6,
    endIncomplete = 7,
    quadComplete = 8,
    deviceSlotMissing = 9,
    renderIndexNonpositive = 10,
    contextOffsetNonpositive = 11,
    gameTlsMissing = 12,
    renderThreadBitUnset = 13,
    contextNull = 14,
    contextReady = 15,
    popWhileArmed = 16,
};

inline bool First(std::atomic<unsigned>& seen, Stage stage) noexcept
{
    if (stage == Stage::none)
        return false;
    const unsigned bit = 1u << (static_cast<unsigned>(stage) - 1);
    return !(seen.load(std::memory_order_relaxed) & bit)
        && !(seen.fetch_or(bit, std::memory_order_relaxed) & bit);
}

template<typename Budget, typename Glue>
Stage Begin(Quad& quad, int type, int count, Budget hasBudget, Glue isGlue) noexcept
{
    Stage stage = Stage::none;
    if (quad.armed)
    {
        if (!quad.WantsBegin(type, count))
            stage = Stage::beginPrimitive;
        else if (!hasBudget())
            stage = Stage::beginBudget;
        else if (!isGlue())
            stage = Stage::beginCaller;
        else
            stage = Stage::beginAdmitted;
    }
    quad.Begin(stage == Stage::beginAdmitted);
    return stage;
}

inline Stage Vertex(Quad& quad, float x, float y, float z, float u, float v) noexcept
{
    const bool admitted = quad.next <= 4;
    quad.Vertex(x, y, z, u, v);
    return admitted && quad.next > 4 ? Stage::vertexRejected : Stage::none;
}

inline Stage End(Quad& quad) noexcept
{
    const bool incomplete = quad.next < 4;
    if (quad.End())
        return Stage::quadComplete;
    return incomplete ? Stage::endIncomplete : Stage::none;
}

constexpr Stage Offsets(bool deviceSlot, int renderIndex, int contextOffset) noexcept
{
    if (!deviceSlot) return Stage::deviceSlotMissing;
    if (renderIndex <= 0) return Stage::renderIndexNonpositive;
    if (contextOffset <= 0) return Stage::contextOffsetNonpositive;
    return Stage::none;
}

constexpr Stage Thread(bool gameTls, bool renderBit) noexcept
{
    if (!gameTls) return Stage::gameTlsMissing;
    if (!renderBit) return Stage::renderThreadBitUnset;
    return Stage::none;
}

constexpr Stage Context(bool available) noexcept
{
    return available ? Stage::contextReady : Stage::contextNull;
}

#if defined(CFX_GRAPHICS_BLIT_DIAGNOSTICS) && defined(CFX_GRAPHICS_BLIT_GATE_DIAGNOSTICS)
inline void Emit(Stage stage) noexcept
{
    static std::atomic<unsigned> seen{0};
    if (!First(seen, stage))
        return;

    PreserveError saved;
    char line[96];
    static_assert(sizeof("[CFX_GRAPHICS_BLIT_GATE] pid= tid= gate=\n") + 10 + 10 + 2 <= sizeof(line));
    char* out = line;
    Append(out, "[CFX_GRAPHICS_BLIT_GATE] pid=");
    AppendUnsigned(out, GetCurrentProcessId());
    Append(out, " tid=");
    AppendUnsigned(out, GetCurrentThreadId());
    Append(out, " gate=");
    AppendUnsigned(out, static_cast<unsigned>(stage));
    *out++ = '\n';
    *out = '\0';
    OutputDebugStringA(line);
}
#endif
}
