#pragma once
#include <windows.h>
#include <cerrno>

namespace cfx::compat
{
inline void CoreMHText(char*& output, const char* text) noexcept
{
    while (*text) *output++ = *text++;
}

inline void CoreMHUnsigned(char*& output, unsigned int value) noexcept
{
    char digits[10];
    unsigned int count = 0;
    do { digits[count++] = static_cast<char>('0' + value % 10); value /= 10; } while (value);
    while (count) *output++ = digits[--count];
}

inline void TraceCoreMH(unsigned int phase, bool statusValid, int status) noexcept
{
#ifdef CFX_CORE_LIFECYCLE_DIAGNOSTICS
    static_assert(sizeof(unsigned int) == 4);
    if (phase < 1 || phase > 4) return;
    const auto savedError = GetLastError();
    const int savedErrno = errno;
    const auto pid = static_cast<unsigned int>(GetCurrentProcessId());
    const auto tid = static_cast<unsigned int>(GetCurrentThreadId());
    const int boundedStatus = statusValid && status >= -1 && status <= 12 ? status : -1;
    char line[128];
    char* output = line;
    CoreMHText(output, "[CFX_CORE_MH] pid="); CoreMHUnsigned(output, pid);
    CoreMHText(output, " tid="); CoreMHUnsigned(output, tid);
    CoreMHText(output, " phase="); CoreMHUnsigned(output, phase);
    CoreMHText(output, " status_valid="); *output++ = statusValid ? '1' : '0';
    CoreMHText(output, " status=");
    if (boundedStatus < 0) CoreMHText(output, "-1");
    else CoreMHUnsigned(output, static_cast<unsigned int>(boundedStatus));
    *output++ = '\n'; *output = '\0';
    OutputDebugStringA(line);
    errno = savedErrno;
    SetLastError(savedError);
#else
    (void)phase; (void)statusValid; (void)status;
#endif
}
}
