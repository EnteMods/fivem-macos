#include <stdio.h>
#include <windows.h>

__declspec(dllimport) ATOM register_probe_class(HINSTANCE, const wchar_t *, UINT);

static DWORD report(const char *step, BOOL ok)
{
    DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    printf("{\"step\":\"%s\",\"pid\":%lu,\"ok\":%s,\"error\":%lu}\n",
           step, GetCurrentProcessId(), ok ? "true" : "false", error);
    return error;
}

static BOOL create(const char *step, const wchar_t *name, HINSTANCE instance, BOOL expected)
{
    HWND window = CreateWindowExW(0, name, L"", WS_POPUP, 0, 0, 64, 64,
                                  NULL, NULL, instance, NULL);
    DWORD error = report(step, window != NULL);
    if (window && !DestroyWindow(window))
        return FALSE;
    return expected ? window != NULL : !window && error == ERROR_CLASS_DOES_NOT_EXIST;
}

int main(void)
{
    const wchar_t *local = L"FivemOwnProbeLocal";
    const wchar_t *global = L"FivemOwnProbeGlobal";
    HINSTANCE owner = GetModuleHandleW(L"window-class-owner.dll");
    HINSTANCE caller = GetModuleHandleW(NULL);
    if (!owner || !caller || owner == caller)
        return 2;

    ATOM atom = register_probe_class(owner, local, 0);
    report("register_local", atom != 0);
    if (!atom)
        return 3;

    BOOL passed = create("local_matching_module", local, owner, TRUE);
    passed &= create("local_different_module", local, caller, FALSE);

    // Record NULL lookup separately because it is not the cross-module control.
    HWND null_instance = CreateWindowExW(0, local, L"", WS_POPUP, 0, 0, 64, 64,
                                         NULL, NULL, NULL, NULL);
    report("local_null_instance", null_instance != NULL);
    if (null_instance)
        passed &= DestroyWindow(null_instance);

    BOOL removed = UnregisterClassW(local, owner);
    report("unregister_local", removed);
    passed &= removed;
    passed &= create("local_after_unregister", local, owner, FALSE);

    atom = register_probe_class(owner, global, CS_GLOBALCLASS);
    report("register_global", atom != 0);
    if (!atom)
        return 4;
    passed &= create("global_different_module", global, caller, TRUE);
    removed = UnregisterClassW(global, owner);
    report("unregister_global", removed);
    return passed && removed ? 0 : 1;
}
