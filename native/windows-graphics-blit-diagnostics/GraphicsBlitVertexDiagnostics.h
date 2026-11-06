#pragma once

#include "GraphicsBlitGateDiagnostics.h"
#include <array>

namespace cfx::blit::vertices
{
using Pattern = std::array<int, 20>;
constexpr unsigned Extra = 5, Inactive = 6, Invalid = 7;

class Capture
{
public:
    void Begin(gate::Stage stage) noexcept { seen_ = stage == gate::Stage::beginAdmitted ? 0 : Inactive; }
    void Reset() noexcept { seen_ = Inactive; }
    bool Active() const noexcept { return seen_ != Inactive; }

    void Vertex(float x, float y, float z, float u, float v) noexcept
    {
        if (seen_ < 4)
            actual_[seen_++] = {x, y, z, u, v};
        else if (seen_ == 4)
            seen_ = Extra;
    }

    unsigned Finish(Pattern& pattern) noexcept
    {
        const auto seen = seen_;
        Reset();
        if (seen != 4)
            return seen;

        for (unsigned i = 0; i < 4; ++i)
        {
            for (unsigned j = 0; j < 5; ++j)
            {
                const float value = actual_[i][j];
                if (!(value >= -65536.0f && value <= 65536.0f))
                    return Invalid;
                const float scaled = value * (j < 2 ? 16.0f : 4096.0f);
                pattern[i * 5 + j] = static_cast<int>(scaled + (scaled >= 0 ? 0.5f : -0.5f));
            }
        }
        return seen;
    }

private:
    std::array<std::array<float, 5>, 4> actual_{};
    unsigned seen_ = Inactive;
};

class UniquePatterns
{
public:
    unsigned First(const Pattern& pattern) noexcept
    {
        // Diagnostics can miss contended samples. The render thread never waits for another sampler.
        if (busy_.test_and_set(std::memory_order_acquire))
            return 0;
        const auto id = Admit(pattern);
        busy_.clear(std::memory_order_release);
        return id;
    }

private:
    unsigned Admit(const Pattern& pattern) noexcept
    {
        if (used_ == patterns_.size())
            return 0;
        for (unsigned i = 0; i < used_; ++i)
            if (pattern == patterns_[i])
                return 0;

        int minX = pattern[0], maxX = pattern[0], minY = pattern[1], maxY = pattern[1];
        for (unsigned i = 5; i < pattern.size(); i += 5)
        {
            if (pattern[i] < minX) minX = pattern[i];
            if (pattern[i] > maxX) maxX = pattern[i];
            if (pattern[i + 1] < minY) minY = pattern[i + 1];
            if (pattern[i + 1] > maxY) maxY = pattern[i + 1];
        }
        if (maxX - minX < 256 * 16 || maxY - minY < 256 * 16)
        {
            if (small_ == 4)
                return 0;
            ++small_;
        }
        patterns_[used_++] = pattern;
        return used_;
    }

    std::array<Pattern, 8> patterns_{};
    std::atomic_flag busy_ = ATOMIC_FLAG_INIT;
    unsigned used_ = 0, small_ = 0;
};

#if defined(CFX_GRAPHICS_BLIT_DIAGNOSTICS) && defined(CFX_GRAPHICS_BLIT_GATE_DIAGNOSTICS) && defined(CFX_GRAPHICS_BLIT_VERTEX_DIAGNOSTICS)

inline void EmitCount(unsigned seen) noexcept
{
    if (seen >= 4 && seen != Extra)
        return;
    static std::atomic<unsigned> emitted{0};
    const unsigned bit = seen == Extra ? 2u : 1u;
    if ((emitted.load(std::memory_order_relaxed) & bit) || (emitted.fetch_or(bit, std::memory_order_relaxed) & bit))
        return;

    PreserveError saved;
    char line[96], *out = line;
    Append(out, "[CFX_GRAPHICS_BLIT_VERTEX_COUNT] pid="); AppendUnsigned(out, GetCurrentProcessId());
    Append(out, " tid="); AppendUnsigned(out, GetCurrentThreadId());
    Append(out, " seen="); AppendUnsigned(out, seen);
    *out++ = '\n'; *out = '\0';
    OutputDebugStringA(line);
}

struct ContextSnapshot
{
    UINT viewportCount = 0, width = 0, height = 0, scissorCount = 0;
    int viewport[4]{};
    bool viewportValid = false, scissorEnabled = false;
    D3D11_RECT scissor{};
};

inline ContextSnapshot Inspect(ID3D11DeviceContext* context) noexcept
{
    ContextSnapshot data;
    if (!context)
        return data;

    D3D11_VIEWPORT viewports[D3D11_VIEWPORT_AND_SCISSORRECT_OBJECT_COUNT_PER_PIPELINE]{};
    data.viewportCount = D3D11_VIEWPORT_AND_SCISSORRECT_OBJECT_COUNT_PER_PIPELINE;
    context->RSGetViewports(&data.viewportCount, viewports);
    if (data.viewportCount > D3D11_VIEWPORT_AND_SCISSORRECT_OBJECT_COUNT_PER_PIPELINE)
        data.viewportCount = 0;
    data.viewportValid = data.viewportCount == 1;
    if (data.viewportValid)
    {
        data.viewport[0] = Subpixels(viewports[0].TopLeftX, data.viewportValid);
        data.viewport[1] = Subpixels(viewports[0].TopLeftY, data.viewportValid);
        data.viewport[2] = Subpixels(viewports[0].Width, data.viewportValid);
        data.viewport[3] = Subpixels(viewports[0].Height, data.viewportValid);
    }
    RenderTargetSize(context, data.width, data.height);
    if (data.width > D3D11_REQ_TEXTURE2D_U_OR_V_DIMENSION || data.height > D3D11_REQ_TEXTURE2D_U_OR_V_DIMENSION)
        data.width = data.height = 0;

    ID3D11RasterizerState* rasterizer = nullptr;
    context->RSGetState(&rasterizer);
    if (rasterizer)
    {
        D3D11_RASTERIZER_DESC desc{};
        rasterizer->GetDesc(&desc);
        rasterizer->Release();
        data.scissorEnabled = desc.ScissorEnable != FALSE;
    }
    D3D11_RECT scissors[D3D11_VIEWPORT_AND_SCISSORRECT_OBJECT_COUNT_PER_PIPELINE]{};
    data.scissorCount = D3D11_VIEWPORT_AND_SCISSORRECT_OBJECT_COUNT_PER_PIPELINE;
    context->RSGetScissorRects(&data.scissorCount, scissors);
    if (data.scissorCount > D3D11_VIEWPORT_AND_SCISSORRECT_OBJECT_COUNT_PER_PIPELINE)
        data.scissorCount = 0;
    if (data.scissorCount == 1)
        data.scissor = scissors[0];
    return data;
}

inline void Field(char*& out, const char* label, LONG value) noexcept
{
    Append(out, label);
    if (value < 0) *out++ = '-';
    const auto bits = static_cast<unsigned>(value);
    AppendUnsigned(out, value < 0 ? 0u - bits : bits);
}

inline void Key(char*& out, unsigned pid, unsigned tid, unsigned id) noexcept
{
    Append(out, " pid="); AppendUnsigned(out, pid);
    Append(out, " tid="); AppendUnsigned(out, tid);
    Append(out, " id="); AppendUnsigned(out, id);
}

// Keep each row below Wine's debug-string escape buffer. Geometry and state share one sample ID.
// The caller must use the same TLS guards as the legacy viewport observation.
inline void Emit(const Pattern& pattern, unsigned id, bool legacy, gate::Stage status, ID3D11DeviceContext* context) noexcept
{
    PreserveError saved;
    const auto data = Inspect(context);
    const auto pid = GetCurrentProcessId(), tid = GetCurrentThreadId();
    char line[284], *out = line;
    static_assert(sizeof("[CFX_GRAPHICS_BLIT_VERTICES] pid= tid= id= legacy= v=\n")
                  + 22 + 19 + 4 * (2 * 8 + 3 * 10) <= sizeof(line));
    static_assert(sizeof("[CFX_GRAPHICS_BLIT_VERTEX_CONTEXT] pid= tid= id= ctx= vp_count= vp_valid="
                         " vp_x16= vp_y16= vp_w16= vp_h16= rt_w= rt_h= sc_enabled= sc_count="
                         " sc_l= sc_t= sc_r= sc_b=\n")
                  + 20 + 1 + 2 + 2 + 1 + 32 + 10 + 1 + 2 + 44 <= sizeof(line));
    Append(out, "[CFX_GRAPHICS_BLIT_VERTICES]");
    Key(out, pid, tid, id);
    Append(out, " legacy="); AppendUnsigned(out, legacy);
    for (unsigned i = 0; i < pattern.size(); ++i)
        Field(out, i ? "," : " v=", pattern[i]);
    *out++ = '\n'; *out = '\0';
    OutputDebugStringA(line);

    out = line;
    Append(out, "[CFX_GRAPHICS_BLIT_VERTEX_CONTEXT]");
    Key(out, pid, tid, id);
    Append(out, " ctx="); AppendUnsigned(out, static_cast<unsigned>(status));
    Append(out, " vp_count="); AppendUnsigned(out, data.viewportCount);
    Append(out, " vp_valid="); AppendUnsigned(out, data.viewportValid);
    Field(out, " vp_x16=", data.viewportValid ? data.viewport[0] : 0);
    Field(out, " vp_y16=", data.viewportValid ? data.viewport[1] : 0);
    Field(out, " vp_w16=", data.viewportValid ? data.viewport[2] : 0);
    Field(out, " vp_h16=", data.viewportValid ? data.viewport[3] : 0);
    Append(out, " rt_w="); AppendUnsigned(out, data.width);
    Append(out, " rt_h="); AppendUnsigned(out, data.height);
    Append(out, " sc_enabled="); AppendUnsigned(out, data.scissorEnabled);
    Append(out, " sc_count="); AppendUnsigned(out, data.scissorCount);
    Field(out, " sc_l=", data.scissor.left);
    Field(out, " sc_t=", data.scissor.top);
    Field(out, " sc_r=", data.scissor.right);
    Field(out, " sc_b=", data.scissor.bottom);
    *out++ = '\n'; *out = '\0';
    OutputDebugStringA(line);
}
#endif
}
