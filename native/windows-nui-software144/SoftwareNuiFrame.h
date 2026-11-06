#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <new>
#include <stdexcept>
#include <vector>

namespace cfx::software_nui
{
// The caller serializes CEF paint callbacks and the game render thread.
class Frame
{
public:
    bool Reset(int width, int height)
    {
        if (width <= 0 || height <= 0 || width > 16384 || height > 16384)
        {
            return false;
        }
        const size_t bytes = static_cast<size_t>(width) * height * 4;
        try
        {
            std::vector<uint8_t> next(bytes);
            pixels_.swap(next);
        }
        catch (const std::bad_alloc&)
        {
            return false;
        }
        catch (const std::length_error&)
        {
            return false;
        }
        width_ = width;
        height_ = height;
        pending_ = false;
        uploaded_ = false;
        return true;
    }

    void Clear()
    {
        pixels_.clear();
        width_ = height_ = 0;
        pending_ = uploaded_ = false;
    }

    bool Paint(const void* source, int width, int height)
    {
        if (!source || width != width_ || height != height_ || pixels_.empty())
        {
            return false;
        }
        // CEF supplies the complete BGRA image even for a small dirty rectangle.
        std::memcpy(pixels_.data(), source, pixels_.size());
        pending_ = true;
        return true;
    }

    bool Upload(void* destination, int width, int height, size_t pitch)
    {
        const size_t rowBytes = static_cast<size_t>(width_) * 4;
        if (!pending_ || !destination || width != width_ || height != height_ ||
            pitch < rowBytes || !height_ || pitch > std::numeric_limits<size_t>::max() / height_)
        {
            return false;
        }
        auto* target = static_cast<uint8_t*>(destination);
        for (int row = 0; row < height_; ++row)
        {
            std::memcpy(target + static_cast<size_t>(row) * pitch,
                pixels_.data() + static_cast<size_t>(row) * rowBytes, rowBytes);
        }
        pending_ = false;
        uploaded_ = true;
        return true;
    }

    bool Pending() const { return pending_; }
    bool Uploaded() const { return uploaded_; }
    void Reupload() { pending_ = pending_ || uploaded_; uploaded_ = false; }
    int Width() const { return width_; }
    int Height() const { return height_; }

private:
    std::vector<uint8_t> pixels_;
    int width_ = 0;
    int height_ = 0;
    bool pending_ = false;
    bool uploaded_ = false;
};
}
