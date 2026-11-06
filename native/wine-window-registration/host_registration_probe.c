#include <stdio.h>
#include <string.h>
#include <windows.h>

static const WCHAR class_name[] = L"grcWindow";

static void report(const char *step, unsigned int value, DWORD error)
{
    printf("{\"step\":\"%s\",\"pid\":%lu,\"tid\":%lu,\"value\":%u,\"error\":%lu}\n",
           step, GetCurrentProcessId(), GetCurrentThreadId(), value, error);
    fflush(stdout);
}

int main(int argc, char **argv)
{
    if (argc != 2 || (strcmp(argv[1], "cold") && strcmp(argv[1], "icon")))
        return 2;
    BOOL with_icon = !strcmp(argv[1], "icon");
    HINSTANCE instance = GetModuleHandleW(NULL);
    HICON icon = NULL;
    report("ready", with_icon, 0);
    if (with_icon)
    {
        static const BYTE and_mask[128] = {0}, xor_mask[128] = {0};
        SetLastError(0);
        icon = CreateIcon(instance, 32, 32, 1, 1, and_mask, xor_mask);
        report("icon", icon != NULL, GetLastError());
        if (!icon) return 3;
    }

    const WNDCLASSW wc = {.lpfnWndProc = DefWindowProcW, .hInstance = instance,
                         .hIcon = icon, .lpszClassName = class_name};
    SetLastError(0);
    ATOM atom = RegisterClassW(&wc);
    report("register", atom, GetLastError());

    SetLastError(0);
    HWND window = CreateWindowExW(0, class_name, L"", WS_POPUP, 0, 0, 64, 64,
                                  NULL, NULL, NULL, NULL);
    report("create", window != NULL, GetLastError());
    BOOL passed = atom >= 0xc000 && window != NULL;
    if (window)
    {
        BOOL ok = DestroyWindow(window);
        report("destroy", ok != FALSE, ok ? 0 : GetLastError());
        passed &= ok;
    }
    if (atom >= 0xc000)
    {
        BOOL ok = UnregisterClassW(class_name, instance);
        report("unregister", ok != FALSE, ok ? 0 : GetLastError());
        passed &= ok;
    }
    if (icon)
    {
        BOOL ok = DestroyIcon(icon);
        report("destroy_icon", ok != FALSE, ok ? 0 : GetLastError());
        passed &= ok;
    }
    return passed ? 0 : 1;
}
