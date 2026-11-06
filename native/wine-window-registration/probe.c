#include <stdio.h>
#include <windows.h>

static void result(unsigned int step, ATOM atom, DWORD error)
{
    printf("{\"step\":%u,\"pid\":%lu,\"ok\":%u,\"error\":%lu}\n",
           step, GetCurrentProcessId(), atom != 0, error);
}

int main(void)
{
    ATOM atom;
    HINSTANCE instance = GetModuleHandleW(NULL);
    WNDCLASSW definition = {
        .lpfnWndProc = DefWindowProcW,
        .hInstance = instance,
        .lpszClassName = L"grcWindow",
    };
    WNDCLASSEXW extended = {
        .cbSize = sizeof(extended),
        .lpfnWndProc = DefWindowProcW,
        .hInstance = instance,
        .lpszClassName = L"GRCWINDOW",
    };

    if (!GetDesktopWindow()) return 1;
    SetLastError(1234);
    atom = RegisterClassW(&definition);
    result(1, atom, GetLastError());
    if (!atom || !UnregisterClassW(definition.lpszClassName, instance)) return 2;

    definition.cbClsExtra = -1;
    SetLastError(1234);
    atom = RegisterClassW(&definition);
    result(2, atom, GetLastError());
    if (atom) return 3;

    SetLastError(1234);
    atom = RegisterClassExW(&extended);
    result(3, atom, GetLastError());
    if (!atom || !UnregisterClassW(extended.lpszClassName, instance)) return 4;

    definition.lpszClassName = L"OwnUnselectedWindowClass";
    definition.cbClsExtra = 0;
    SetLastError(1234);
    atom = RegisterClassW(&definition);
    result(4, atom, GetLastError());
    if (!atom || !UnregisterClassW(definition.lpszClassName, instance)) return 5;
    return 0;
}
