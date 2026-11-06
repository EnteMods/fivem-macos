"""Pure numeric window overlay over the exact admitted graphics-SC overlay."""
import hashlib

INPUT_BYTES = 42200
INPUT_SHA256 = '39ab3f4966e9434894c004977914a39869782891b5d5ebd55c13f1be7d2d874e'
HEADER_NAME = 'GraphicsWindowDiagnostics.h'
_NORMAL = b'\t\tw = g_origCreateWindowExW(dwExStyle, lpClassName, wndName, dwStyle, X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);\r\n'
_REVERSE = b'\t\tw = g_origCreateWindowExW(dwExStyle, lpClassName, wndName, WS_POPUP | WS_CLIPSIBLINGS, 0, 0, rgd->width, rgd->height, NULL, hMenu, hInstance, lpParam);\r\n'
_CAPTURE = b'\t\tcfxWindowError = cfx::compat::CaptureGraphicsWindowError();\r\n'
_NORMAL_METADATA = b'\t\tcfxWindowStyle = dwStyle;\r\n\t\tcfxWindowParentNonnull = hWndParent != nullptr;\r\n'
_REVERSE_METADATA = b'\t\tcfxWindowStyle = WS_POPUP | WS_CLIPSIBLINGS;\r\n\t\tcfxWindowParentNonnull = false;\r\n'
_SC = b'\t\t\t\t\tcfx::compat::TraceGraphicsSwapChainBefore(cfxScMask);\r\n'
CHANGES = (
    (b'#include "GraphicsSwapChainDiagnostics.h"\r\n',
     b'#include "GraphicsSwapChainDiagnostics.h"\r\n#include "GraphicsWindowDiagnostics.h"\r\n'),
    (b'\tHWND w;\r\n', b'\tHWND w;\r\n\tDWORD cfxWindowError = 0;\r\n\tDWORD cfxWindowStyle = 0;\r\n\tbool cfxWindowParentNonnull = false;\r\n'),
    (_NORMAL, _NORMAL + _CAPTURE + _NORMAL_METADATA),
    (_REVERSE, _REVERSE + _CAPTURE + _REVERSE_METADATA),
    (b'\t\tCoreSetGameWindow(w);\r\n',
     b'\t\tcfx::compat::TraceGraphicsWindowResult(w != nullptr, cfxWindowError, cfxWindowStyle, dwExStyle, cfxWindowParentNonnull);\r\n\t\tCoreSetGameWindow(w);\r\n'),
    (_SC, b'\t\t\t\t\tcfx::compat::TraceGraphicsWindowAvailability(ppSwapChain != nullptr);\r\n' + _SC),
)


def _input(data):
    if (type(data) is not bytes or len(data) != INPUT_BYTES
            or hashlib.sha256(data).hexdigest() != INPUT_SHA256):
        raise ValueError('Require exact admitted graphics-SC RenderHooks bytes')


def apply(data):
    _input(data)
    patched = data
    for before, after in CHANGES:
        if patched.count(before) != 1 or after in patched:
            raise ValueError('Unexpected numeric window overlay scope')
        patched = patched.replace(before, after, 1)
    if strip(patched) != data:
        raise ValueError('Numeric window roundtrip failed')
    return patched, {
        'input_bytes': INPUT_BYTES, 'input_sha256': INPUT_SHA256,
        'patched_bytes': len(patched), 'patched_sha256': hashlib.sha256(patched).hexdigest(),
        'replacement_count': 6,
        'modified_regions': ['header_include', 'HookCreateWindowExW', 'swapchain_checkpoint'],
        'stripped_equals_exact_v11_bytes': True,
        'original_window_calls_arguments_and_returns_preserved': True,
        'last_error_captured_immediately_after_both_original_window_calls': True,
        'style_and_parent_metadata_match_actual_original_call_branch': True,
        'original_swapchain_request_presence_logged': True,
        'window_result_logging_only_in_existing_grcWindow_branch': True,
        'original_sc_call_and_diagnostics_preserved': True,
        'original_hresult_and_error_path_unchanged': True,
        'class_query_only_after_own_process_check': True,
        'core_get_game_window_find_window_or_fallback_selection_added': False,
        'raw_handles_titles_class_strings_or_candidate_pids_logged': False,
        'default_logging_enabled': False,
    }


def strip(data):
    if type(data) is not bytes:
        raise ValueError('Require bytes')
    result = data
    for before, after in reversed(CHANGES):
        if result.count(after) != 1:
            raise ValueError('Unexpected numeric window overlay bytes')
        result = result.replace(after, before, 1)
    _input(result)
    return result
