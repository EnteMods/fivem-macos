#include "SoftwareNuiFrame.h"
#include <array>
#include <cstdio>

static int failures;
#define CHECK(expr) do { if (!(expr)) { std::fprintf(stderr, "line %d: %s\n", __LINE__, #expr); ++failures; } } while (0)

int main()
{
    using cfx::software_nui::Frame;
    Frame view, popup;
    CHECK(!view.Reset(0, 2));
    CHECK(!view.Reset(-1, 2));
    CHECK(!view.Reset(16385, 2));
    CHECK(view.Reset(3, 2));
    std::array<unsigned char, 24> image{};
    for (size_t i = 0; i < image.size(); ++i) image[i] = static_cast<unsigned char>(i + 1);
    std::array<unsigned char, 48> output;
    output.fill(0xa5);
    CHECK(!view.Upload(output.data() + 8, 3, 2, 16));
    CHECK(!view.Paint(nullptr, 3, 2));
    CHECK(!view.Paint(image.data(), 2, 3));
    CHECK(view.Paint(image.data(), 3, 2));
    CHECK(view.Pending() && !view.Uploaded());
    CHECK(!view.Upload(nullptr, 3, 2, 16));
    CHECK(!view.Upload(output.data() + 8, 3, 2, 11));
    CHECK(!view.Upload(output.data() + 8, 2, 3, 16));
    CHECK(!view.Upload(output.data() + 8, 3, 2, static_cast<size_t>(-1)));
    CHECK(view.Pending());
    CHECK(view.Upload(output.data() + 8, 3, 2, 16));
    CHECK(!view.Pending() && view.Uploaded());
    view.Reupload();
    CHECK(view.Pending() && !view.Uploaded());
    CHECK(view.Upload(output.data() + 8, 3, 2, 16));
    for (size_t i = 0; i < 12; ++i) {
        CHECK(output[8 + i] == image[i]);
        CHECK(output[24 + i] == image[12 + i]);
    }
    for (size_t i : {0, 7, 20, 23, 36, 47}) CHECK(output[i] == 0xa5);
    CHECK(popup.Reset(1, 1));
    CHECK(popup.Paint(image.data() + 16, 1, 1));
    CHECK(popup.Upload(output.data(), 1, 1, 4));
    CHECK(view.Uploaded());
    popup.Clear();
    CHECK(!popup.Uploaded() && !popup.Pending());
    CHECK(!popup.Paint(image.data(), 1, 1));
    CHECK(view.Reset(2, 2));
    CHECK(!view.Uploaded());
    CHECK(!view.Paint(image.data(), 3, 2));
    CHECK(view.Paint(image.data(), 2, 2));
    CHECK(view.Upload(output.data() + 8, 2, 2, 12));
    CHECK(!view.Reset(0, 1));
    CHECK(view.Width() == 2 && view.Uploaded());
    std::printf("SOFTWARE_NUI_FRAME_FAILURES=%d\n", failures);
    return failures ? 1 : 0;
}
