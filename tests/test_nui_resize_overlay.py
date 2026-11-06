import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


OVERLAY = Path(__file__).resolve().parents[1] / "native/windows-nui/resize_overlay.py"
SPEC = importlib.util.spec_from_file_location("resize_overlay", OVERLAY)
resize_overlay = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(resize_overlay)

PIXEL_FIXTURE = r'''
#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstring>
#include <limits>
#include <vector>

struct CefRect { int x, y, width, height; };

@UPLOAD_RECT@

void CheckUpload(int width, int height)
{
    const size_t visibleBytes = width * 4;
    const size_t sourcePitch = visibleBytes + 16;
    const size_t targetPitch = visibleBytes + 32;
    const char untouched = 77;
    std::vector<char> source(sourcePitch * height, 12);
    std::vector<char> target(targetPitch * height, untouched);
    for (int row = 0; row < height; ++row)
    {
        auto* line = source.data() + row * sourcePitch;
        for (size_t byte = 0; byte < visibleBytes; ++byte)
            line[byte] = static_cast<char>((row * 31 + byte) % 73);
    }

    CopySoftwareTextureRect(target.data(), targetPitch, source.data(), sourcePitch,
        width, height, {0, 0, width, height});
    for (int row = 0; row < height; ++row)
    {
        auto* line = target.data() + row * targetPitch;
        const auto* expected = source.data() + (height - row - 1) * sourcePitch;
        assert(memcmp(line, expected, visibleBytes) == 0);
        assert(std::all_of(line + visibleBytes, line + targetPitch, [=](char b) { return b == untouched; }));
    }

    std::fill(target.begin(), target.end(), untouched);
    const CefRect invalid[] = {
        {-1, 0, 1, 1}, {0, -1, 1, 1}, {0, 0, 0, 1}, {0, height, 1, 1},
        {width - 1, 0, 2, 1}, {0, 0, std::numeric_limits<int>::max(), 1},
    };
    for (const auto& rect : invalid)
        CopySoftwareTextureRect(target.data(), targetPitch, source.data(), sourcePitch, width, height, rect);
    assert(std::all_of(target.begin(), target.end(), [=](char b) { return b == untouched; }));

    CopySoftwareTextureRect(target.data(), targetPitch, source.data(), sourcePitch,
        width, height, {width - 1, height - 1, 1, 1});
    const auto targetPixel = target.begin() + visibleBytes - 4;
    const auto sourcePixel = source.begin() + (height - 1) * sourcePitch + visibleBytes - 4;
    assert(std::equal(targetPixel, targetPixel + 4, sourcePixel));
    assert(std::all_of(target.begin(), targetPixel, [=](char b) { return b == untouched; }));
    assert(std::all_of(targetPixel + 4, target.end(), [=](char b) { return b == untouched; }));
}

int main()
{
    CheckUpload(1919, 1079);
    CheckUpload(3016, 1694);
    CheckUpload(1280, 720);
}
'''


class NuiResizeUploadTest(unittest.TestCase):
    @unittest.skipUnless(shutil.which("clang++"), "clang++ is required for the upload fixture")
    def test_padded_full_and_partial_uploads_at_resize_dimensions(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "upload.cpp"
            binary = Path(tmp) / "upload"
            source.write_text(PIXEL_FIXTURE.replace("@UPLOAD_RECT@", resize_overlay.UPLOAD_RECT))
            subprocess.run(
                ["clang++", "-std=c++17", "-Wall", "-Wextra", "-Werror", str(source), "-o", str(binary)],
                check=True,
                timeout=20,
            )
            subprocess.run([str(binary)], check=True, timeout=20)
