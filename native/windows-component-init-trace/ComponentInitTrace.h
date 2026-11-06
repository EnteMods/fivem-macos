#pragma once
#include <windows.h>
#include <cstdio>
#include "ComponentInitTraceCore.h"

namespace cfx::component_init_trace {
struct Win32Platform {
  static DWORD GetError() { return GetLastError(); }
  static void SetError(DWORD value) { SetLastError(value); }
  static bool EnabledExact() {
    wchar_t option[2] = {};
    return GetEnvironmentVariableW(L"CFX_COMPONENT_INIT_TRACE", option, 2) == 1 && option[0] == L'1';
  }
  static void Write(unsigned sequence, unsigned event, unsigned component, unsigned ordinal, unsigned call, unsigned value) {
    char buffer[192];
    const int count = std::snprintf(buffer, sizeof(buffer),
        "[CFX_COMPONENT_INIT] seq=%u event=%u pid=%lu tid=%lu component=%u ordinal=%u call=%u value=%u\n",
        sequence, event, GetCurrentProcessId(), GetCurrentThreadId(), component, ordinal, call, value);
    if (count > 0 && static_cast<size_t>(count) < sizeof(buffer)) OutputDebugStringA(buffer);
  }
};
using Trace = Observer<Win32Platform>;
}
