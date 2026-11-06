#pragma once
#include <windows.h>
#include <cerrno>

namespace cfx::compat
{
inline DWORD CaptureGraphicsWindowError() noexcept
{
#ifdef CFX_GRAPHICS_WINDOW_DIAGNOSTICS
    return GetLastError();
#else
    return 0;
#endif
}

#ifdef CFX_GRAPHICS_WINDOW_DIAGNOSTICS
inline void GraphicsWndText(char*& output, const char* text) noexcept
{
    while (*text) *output++ = *text++;
}

inline void GraphicsWndUnsigned(char*& output, unsigned int value) noexcept
{
    char digits[10];
    unsigned int count = 0;
    do { digits[count++] = static_cast<char>('0' + value % 10); value /= 10; } while (value);
    while (count) *output++ = digits[--count];
}

struct GraphicsWndQuery
{
    DWORD pid;
    unsigned int visited = 0, count = 0, failures = 0;
    bool capped = false;
};

inline BOOL CALLBACK GraphicsWndVisit(HWND window, LPARAM parameter) noexcept
{
    auto& query = *reinterpret_cast<GraphicsWndQuery*>(parameter);
    if (query.visited == 256)
    {
        query.capped = true;
        return FALSE;
    }
    ++query.visited;
    DWORD owner = 0;
    if (!GetWindowThreadProcessId(window, &owner)) { ++query.failures; return TRUE; }
    if (owner != query.pid) return TRUE;
    if (!IsWindow(window)) { ++query.failures; return TRUE; }
    wchar_t name[16] = {};
    const int length = GetClassNameW(window, name, 16);
    if (!length) { ++query.failures; return TRUE; }
    static constexpr wchar_t expected[] = L"grcWindow";
    if (length != 9) return TRUE;
    for (unsigned int index = 0; index < 9; ++index)
        if (name[index] != expected[index]) return TRUE;
    owner = 0;
    if (!GetWindowThreadProcessId(window, &owner) || owner != query.pid || !IsWindow(window))
    {
        ++query.failures;
        return TRUE;
    }
    ++query.count;
    return TRUE;
}

inline void GraphicsWndPrefix(char*& output, DWORD pid, DWORD tid, unsigned int phase) noexcept
{
    GraphicsWndText(output, "[CFX_GRAPHICS_WND] pid="); GraphicsWndUnsigned(output, pid);
    GraphicsWndText(output, " tid="); GraphicsWndUnsigned(output, tid);
    GraphicsWndText(output, " phase="); GraphicsWndUnsigned(output, phase);
}
#endif

inline void TraceGraphicsWindowResult(bool returned, DWORD error, DWORD style,
                                      DWORD exstyle, bool parentNonnull) noexcept
{
#ifdef CFX_GRAPHICS_WINDOW_DIAGNOSTICS
    static_assert(sizeof(DWORD) == 4 && sizeof(unsigned int) == 4);
    const DWORD savedError = GetLastError();
    const int savedErrno = errno;
    const DWORD pid = GetCurrentProcessId(), tid = GetCurrentThreadId();
    char line[256];
    static_assert(sizeof("[CFX_GRAPHICS_WND] pid= tid= phase=1 returned=1 error= style= exstyle= parent_nonnull=1\n") + 5 * 10 <= sizeof(line));
    char* output = line;
    GraphicsWndPrefix(output, pid, tid, 1);
    GraphicsWndText(output, " returned="); *output++ = returned ? '1' : '0';
    GraphicsWndText(output, " error="); GraphicsWndUnsigned(output, error);
    GraphicsWndText(output, " style="); GraphicsWndUnsigned(output, style);
    GraphicsWndText(output, " exstyle="); GraphicsWndUnsigned(output, exstyle);
    GraphicsWndText(output, " parent_nonnull="); *output++ = parentNonnull ? '1' : '0';
    *output++ = '\n'; *output = '\0';
    OutputDebugStringA(line);
    errno = savedErrno;
    SetLastError(savedError);
#else
    (void)returned; (void)error; (void)style; (void)exstyle; (void)parentNonnull;
#endif
}

inline void TraceGraphicsWindowAvailability(bool swapchainRequested) noexcept
{
#ifdef CFX_GRAPHICS_WINDOW_DIAGNOSTICS
    const DWORD savedError = GetLastError();
    const int savedErrno = errno;
    const DWORD pid = GetCurrentProcessId(), tid = GetCurrentThreadId();
    GraphicsWndQuery query{pid};
    const BOOL enumerated = EnumWindows(GraphicsWndVisit, reinterpret_cast<LPARAM>(&query));
    char line[256];
    static_assert(sizeof("[CFX_GRAPHICS_WND] pid= tid= phase=2 swapchain_requested=1 count= capped=1 enum_ok=1 query_failures=\n") + 4 * 10 <= sizeof(line));
    char* output = line;
    GraphicsWndPrefix(output, pid, tid, 2);
    GraphicsWndText(output, " swapchain_requested="); *output++ = swapchainRequested ? '1' : '0';
    GraphicsWndText(output, " count="); GraphicsWndUnsigned(output, query.count);
    GraphicsWndText(output, " capped="); *output++ = query.capped ? '1' : '0';
    GraphicsWndText(output, " enum_ok="); *output++ = enumerated ? '1' : '0';
    GraphicsWndText(output, " query_failures="); GraphicsWndUnsigned(output, query.failures);
    *output++ = '\n'; *output = '\0';
    OutputDebugStringA(line);
    errno = savedErrno;
    SetLastError(savedError);
#else
    (void)swapchainRequested;
#endif
}
}
