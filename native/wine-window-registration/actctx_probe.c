#include <stdio.h>
#include <windows.h>

static const WCHAR class_name[] = L"grcWindow";
static const WCHAR versioned_name[] = L"4.3.2.1!grcWindow";

static LRESULT CALLBACK window_proc(HWND window, UINT message, WPARAM wp, LPARAM lp)
{
    return DefWindowProcW(window, message, wp, lp);
}

static DWORD report(const char *step, BOOL ok)
{
    DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    printf("{\"step\":\"%s\",\"pid\":%lu,\"ok\":%s,\"error\":%lu}\n",
           step, GetCurrentProcessId(), ok ? "true" : "false", error);
    return error;
}

static BOOL create(const char *step, const char *destroy_step, const WCHAR *name,
                   HINSTANCE instance, BOOL expected)
{
    HWND window = CreateWindowExW(0, name, L"", WS_POPUP, 0, 0, 64, 64,
                                  NULL, NULL, instance, NULL);
    DWORD error = report(step, window != NULL);
    if (!window)
        return !expected && error == ERROR_CLASS_DOES_NOT_EXIST;

    BOOL destroyed = DestroyWindow(window);
    report(destroy_step, destroyed);
    return expected && destroyed;
}

int main(void)
{
    WCHAR manifest_path[MAX_PATH];
    DWORD length = GetFullPathNameW(L"actctx.manifest", ARRAYSIZE(manifest_path), manifest_path, NULL);
    if (!length || length >= ARRAYSIZE(manifest_path))
        return 2;

    const ACTCTXW definition = {.cbSize = sizeof(definition), .lpSource = manifest_path};
    HANDLE context = CreateActCtxW(&definition);
    report("create_context", context != INVALID_HANDLE_VALUE);
    if (context == INVALID_HANDLE_VALUE)
        return 3;

    HINSTANCE instance = GetModuleHandleW(NULL);
    const WNDCLASSW window_class = {
        .lpfnWndProc = window_proc,
        .hInstance = instance,
        .lpszClassName = class_name,
    };
    ULONG_PTR cookie;
    ATOM atom = 0;
    BOOL passed = FALSE;
    BOOL active = ActivateActCtx(context, &cookie);
    report("activate", active);
    if (!active)
        goto cleanup;

    atom = RegisterClassW(&window_class);
    report("register", atom != 0);
    if (!atom)
        goto cleanup;

    passed = create("active_unqualified", "destroy_active", class_name, instance, TRUE);
    BOOL deactivated = DeactivateActCtx(0, cookie);
    report("deactivate", deactivated);
    if (!deactivated)
    {
        passed = FALSE;
        goto cleanup;
    }
    active = FALSE;

    passed &= create("inactive_unqualified", "destroy_unexpected", class_name, instance, FALSE);
    passed &= create("inactive_versioned", "destroy_versioned", versioned_name, instance, TRUE);

    active = ActivateActCtx(context, &cookie);
    report("reactivate", active);
    if (active)
        passed &= create("reactivated_unqualified", "destroy_reactivated", class_name, instance, TRUE);
    else
        passed = FALSE;

cleanup:
    if (atom)
    {
        BOOL removed = UnregisterClassW(active ? class_name : versioned_name, instance);
        report("unregister", removed);
        passed &= removed;
    }
    if (active)
    {
        BOOL removed = DeactivateActCtx(0, cookie);
        report("deactivate_final", removed);
        passed &= removed;
    }
    ReleaseActCtx(context);
    return passed ? 0 : 1;
}
