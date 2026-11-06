#include <windows.h>

static LRESULT CALLBACK window_proc(HWND window, UINT message, WPARAM wp, LPARAM lp)
{
    return DefWindowProcW(window, message, wp, lp);
}

__declspec(dllexport) ATOM register_probe_class(HINSTANCE owner, const wchar_t *name, UINT style)
{
    const WNDCLASSEXW definition = {
        .cbSize = sizeof(definition),
        .style = style,
        .lpfnWndProc = window_proc,
        .hInstance = owner,
        .lpszClassName = name,
    };
    return RegisterClassExW(&definition);
}
