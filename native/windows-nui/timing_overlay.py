"""Instrument the pinned CEF 103 resize build without changing NUI behavior."""

import hashlib


SOURCE_PINS = {
    "src/CefInput.cpp": (22073, "ec55744761a3652dc61ca36089602a49994ed5a0e0ad4e7d0ef4138af77383b6"),
    "src/NUIRenderHandler.cpp": (11168, "939fb6222f447a9d5b5a5e2d3f0fbd1604c8da367f17a6e2fa41a0fea377f3fa"),
    "src/NUIWindow.cpp": (28540, "14f8c6149eee9519838751b13a87b1705f3838b65418d25554e5ee39a8af87c4"),
}
HEADER_NAME = "include/NuiTimingDiagnostics.h"

HEADER = r'''#pragma once

#include <atomic>
#include <cstdio>
#include <windows.h>

namespace nuiTiming
{
enum Channel { Win32Move = 1, RageMove, Paint, Upload };
constexpr unsigned MaxRows = 256;

struct SavedError
{
	DWORD value = GetLastError();
	~SavedError() { SetLastError(value); }
};

inline long long Now()
{
	SavedError error;
	LARGE_INTEGER value{};
	return QueryPerformanceCounter(&value) ? value.QuadPart : 0;
}

inline long long Frequency()
{
	static const auto value = []
	{
		SavedError error;
		LARGE_INTEGER frequency{};
		return QueryPerformanceFrequency(&frequency) ? frequency.QuadPart : 0;
	}();
	return value;
}

struct Limit
{
	std::atomic<long long> lastRow{0};
	std::atomic<unsigned> rows{0};
};

inline Limit& GetLimit(Channel channel)
{
	static Limit limits[4];
	return limits[channel - 1];
}

inline bool Enabled(Channel channel)
{
	static const bool enabled = []
	{
		SavedError error;
		wchar_t value[2]{};
		return GetEnvironmentVariableW(L"CFX_NUI_TIMING_DIAGNOSTICS", value, 2) == 1 && value[0] == L'1';
	}();
	return enabled && GetLimit(channel).rows.load(std::memory_order_relaxed) < MaxRows;
}

inline long long Start(Channel channel)
{
	return Enabled(channel) ? Now() : 0;
}

struct Cadence
{
	long long first = 0;
	long long last = 0;
	long long maxGap = 0;
	long long maxDuration = 0;
	long long totalDuration = 0;
	unsigned count = 0;
};

inline bool Sample(Channel channel, long long when, long long duration, Cadence& summary)
{
	static thread_local Cadence windows[4];
	auto& window = windows[channel - 1];
	const auto period = Frequency() / 10;
	if (when <= 0 || period <= 0)
	{
		return false;
	}
	if (!window.first)
	{
		window.first = when;
	}
	if (window.last && when - window.last > window.maxGap)
	{
		window.maxGap = when - window.last;
	}
	window.last = when;
	window.totalDuration += duration;
	if (duration > window.maxDuration)
	{
		window.maxDuration = duration;
	}
	++window.count;
	if (when - window.first < period)
	{
		return false;
	}

	auto& limit = GetLimit(channel);
	auto lastRow = limit.lastRow.load(std::memory_order_relaxed);
	if (when - lastRow < period ||
		!limit.lastRow.compare_exchange_strong(lastRow, when, std::memory_order_relaxed) ||
		limit.rows.fetch_add(1, std::memory_order_relaxed) >= MaxRows)
	{
		return false;
	}

	summary = window;
	window = {};
	window.first = when;
	window.last = when;
	return true;
}

inline long long Elapsed(long long start, long long end)
{
	return start > 0 && end >= start ? end - start : 0;
}

struct PointerSample
{
	Cadence cadence{};
	Channel channel = Win32Move;
	long long sendStart = 0;
	POINT screen{};
	POINT client{};
	POINT origin{};
	RECT rect{};
	unsigned valid = 0;
	LONG messageTime = 0;
};

inline PointerSample PreparePointer(HWND messageWindow, HWND gameWindow, LONG messageTime)
{
	SavedError error;
	PointerSample sample;
	sample.channel = messageWindow ? Win32Move : RageMove;
	if (!Sample(sample.channel, Start(sample.channel), 0, sample.cadence))
	{
		return sample;
	}
	const HWND window = messageWindow ? messageWindow : gameWindow;
	if (messageWindow)
	{
		// GetMessagePos is the last dequeued message, including under a synthetic WndProc call.
		const DWORD position = GetMessagePos();
		sample.screen = {static_cast<short>(LOWORD(position)), static_cast<short>(HIWORD(position))};
		sample.messageTime = messageTime;
		sample.valid |= 4;
	}
	else if (GetCursorPos(&sample.screen))
	{
		sample.valid |= 4;
	}
	if (window && ClientToScreen(window, &sample.origin))
	{
		sample.valid |= 1;
	}
	if (window && GetClientRect(window, &sample.rect))
	{
		sample.valid |= 2;
	}
	POINT client = sample.screen;
	if ((sample.valid & 4) && window && ScreenToClient(window, &client))
	{
		sample.client = client;
		sample.valid |= 8;
	}
	sample.sendStart = Now();
	return sample;
}

inline void EmitPointer(const PointerSample& sample, int inputX, int inputY, int cefX, int cefY)
{
	if (!sample.sendStart)
	{
		return;
	}
	SavedError error;
	const auto duration = Elapsed(sample.sendStart, Now());
	char line[512];
	const auto& count = sample.cadence;
	const int size = std::snprintf(line, sizeof(line),
		"[CFX_NUI_TIMING] kind=%d pid=%lu tid=%lu qpc=%lld freq=%lld span=%lld n=%u gap=%lld "
		"send=%lld valid=%u msgtime=%ld sx=%ld sy=%ld cx=%ld cy=%ld ox=%ld oy=%ld cw=%ld ch=%ld "
		"ix=%d iy=%d ex=%d ey=%d\n",
		sample.channel, GetCurrentProcessId(), GetCurrentThreadId(), count.last, Frequency(),
		count.last - count.first, count.count, count.maxGap, duration, sample.valid, sample.messageTime,
		sample.screen.x, sample.screen.y, sample.client.x, sample.client.y, sample.origin.x, sample.origin.y,
		sample.rect.right - sample.rect.left, sample.rect.bottom - sample.rect.top, inputX, inputY, cefX, cefY);
	if (size > 0 && static_cast<size_t>(size) < sizeof(line))
	{
		OutputDebugStringA(line);
	}
}

template<typename Rectangles>
inline void ObservePaint(long long start, int width, int height, const Rectangles& dirtyRects)
{
	const auto end = Now();
	const auto duration = Elapsed(start, end);
	Cadence count;
	if (!Sample(Paint, end, duration, count))
	{
		return;
	}
	SavedError error;
	unsigned long long dirtyPixels = 0;
	unsigned scanned = 0;
	for (const auto& rect : dirtyRects)
	{
		if (scanned == 128)
		{
			break;
		}
		++scanned;
		if (width > 0 && width <= 16384 && height > 0 && height <= 16384 &&
			rect.x >= 0 && rect.y >= 0 && rect.width > 0 && rect.height > 0 &&
			rect.x <= width - rect.width && rect.y <= height - rect.height)
		{
			dirtyPixels += static_cast<unsigned long long>(rect.width) * rect.height;
		}
	}
	char line[512];
	const int size = std::snprintf(line, sizeof(line),
		"[CFX_NUI_TIMING] kind=3 pid=%lu tid=%lu qpc=%lld freq=%lld span=%lld n=%u gap=%lld "
		"paint=%lld max=%lld total=%lld w=%d h=%d rects=%zu scanned=%u dirty=%llu\n",
		GetCurrentProcessId(), GetCurrentThreadId(), count.last, Frequency(), count.last - count.first,
		count.count, count.maxGap, duration, count.maxDuration, count.totalDuration, width, height,
		dirtyRects.size(), scanned, dirtyPixels);
	if (size > 0 && static_cast<size_t>(size) < sizeof(line))
	{
		OutputDebugStringA(line);
	}
}

struct UploadTiming
{
	explicit UploadTiming(bool isMenu) : start(isMenu ? Start(Upload) : 0) {}

	void EndWrite(bool mapped)
	{
		if (start)
		{
			writeEnd = Now();
			choice = mapped ? 1 : 0;
		}
	}

	void EndDiscard(bool mapped)
	{
		if (start)
		{
			discardEnd = Now();
			choice = mapped ? 2 : 0;
		}
	}

	void BeginUnmap(bool copiedPixels, int textureWidth, int textureHeight, int rowPitch)
	{
		if (start)
		{
			unmapStart = Now();
			copied = copiedPixels;
			width = textureWidth;
			height = textureHeight;
			pitch = rowPitch;
		}
	}

	~UploadTiming()
	{
		if (!start)
		{
			return;
		}
		const auto end = Now();
		const auto duration = Elapsed(start, end);
		Cadence count;
		if (!Sample(Upload, end, duration, count))
		{
			return;
		}
		SavedError error;
		char line[512];
		const int size = std::snprintf(line, sizeof(line),
			"[CFX_NUI_TIMING] kind=4 pid=%lu tid=%lu qpc=%lld freq=%lld span=%lld n=%u gap=%lld "
			"write=%lld discard=%lld copy=%lld unmap=%lld method=%d copied=%d w=%d h=%d pitch=%d max=%lld total=%lld\n",
			GetCurrentProcessId(), GetCurrentThreadId(), count.last, Frequency(), count.last - count.first,
			count.count, count.maxGap, Elapsed(start, writeEnd), Elapsed(writeEnd, discardEnd),
			Elapsed(discardEnd ? discardEnd : writeEnd, unmapStart), Elapsed(unmapStart, end),
			choice, copied ? 1 : 0, width, height, pitch, count.maxDuration, count.totalDuration);
		if (size > 0 && static_cast<size_t>(size) < sizeof(line))
		{
			OutputDebugStringA(line);
		}
	}

private:
	long long start = 0;
	long long writeEnd = 0;
	long long discardEnd = 0;
	long long unmapStart = 0;
	int choice = 0;
	int width = 0;
	int height = 0;
	int pitch = 0;
	bool copied = false;
};
}
'''


def append(anchor, addition):
    return anchor, anchor + addition


COMMON = append('#include "StdInc.h"\n', '#include "NuiTimingDiagnostics.h"\n')

INPUT = (
    COMMON,
    (
        "\t\tvoid MouseEvent(int button, int x, int y, bool down)\n",
        "\t\tvoid MouseEvent(int button, int x, int y, bool down, HWND messageWindow = nullptr)\n",
    ),
    (
        "\t\t\tTranslateMouseEvent(GetFocusWindow(), &x, &y);\n\n\t\t\tlastX = x;",
        "\t\t\tconst int inputX = x, inputY = y;\n"
        "\t\t\tbool traceMenu = false;\n\t\t\t{\n\t\t\t\tconst auto window = GetFocusWindow();\n"
        "\t\t\t\tTranslateMouseEvent(window, &x, &y);\n"
        "\t\t\t\ttraceMenu = button == -1 && window.GetRef() && window->GetName() == \"nui_mpMenu\";\n"
        "\t\t\t}\n\n\t\t\tlastX = x;",
    ),
    (
        "\t\t\t\t\tbrowser->GetHost()->SendMouseMoveEvent(mouse_event, false);\n",
        "\t\t\t\t\tconst auto channel = messageWindow ? nuiTiming::Win32Move : nuiTiming::RageMove;\n"
        "\t\t\t\t\tconst auto timing = traceMenu && nuiTiming::Enabled(channel)\n"
        "\t\t\t\t\t\t? nuiTiming::PreparePointer(messageWindow, messageWindow ? nullptr : g_nuiGi->GetHWND(), currentTime)\n"
        "\t\t\t\t\t\t: nuiTiming::PointerSample{};\n"
        "\t\t\t\t\tbrowser->GetHost()->SendMouseMoveEvent(mouse_event, false);\n"
        "\t\t\t\t\tnuiTiming::EmitPointer(timing, inputX, inputY, mouse_event.x, mouse_event.y);\n",
    ),
    (
        "\t\t\t\tinputTarget.MouseEvent(-1, x, y, true);\n",
        "\t\t\t\tinputTarget.MouseEvent(-1, x, y, true, hWnd);\n",
    ),
)

RENDER_HANDLER = (
    COMMON,
    (
        "\tif (window)\n\t{\n\t\tauto renderLock = window->GetRenderBufferLock();",
        "\tif (window)\n\t{\n"
        "\t\tconst auto paintStart = type == PET_VIEW && window->GetName() == \"nui_mpMenu\"\n"
        "\t\t\t? nuiTiming::Start(nuiTiming::Paint) : 0;\n"
        "\t\tauto renderLock = window->GetRenderBufferLock();",
    ),
    (
        "\t\t\twindow->MarkRenderBufferDirty();\n\t\t}\n\t}\n}\n",
        "\t\t\twindow->MarkRenderBufferDirty();\n\t\t}\n"
        "\t\tif (paintStart)\n\t\t{\n"
        "\t\t\twindowLock.unlock();\n"
        "\t\t\tnuiTiming::ObservePaint(paintStart, width, height, dirtyRects);\n"
        "\t\t}\n\t}\n}\n",
    ),
)

WINDOW = (
    COMMON,
    (
        "\t\t\tnui::GILockedTexture locked{};\n\t\t\tbool discarded = false;\n"
        "\t\t\tif (!backing->Map(0, 0, &locked, nui::GILockFlags::Write))\n\t\t\t{\n"
        "\t\t\t\tif (!backing->Map(0, 0, &locked, nui::GILockFlags::WriteDiscard))\n",
        "\t\t\tnui::GILockedTexture locked{};\n\t\t\tbool discarded = false;\n"
        "\t\t\tnuiTiming::UploadTiming uploadTiming(m_name == \"nui_mpMenu\");\n"
        "\t\t\tconst bool writeMapped = backing->Map(0, 0, &locked, nui::GILockFlags::Write);\n"
        "\t\t\tuploadTiming.EndWrite(writeMapped);\n"
        "\t\t\tif (!writeMapped)\n\t\t\t{\n"
        "\t\t\t\tconst bool discardMapped = backing->Map(0, 0, &locked, nui::GILockFlags::WriteDiscard);\n"
        "\t\t\t\tuploadTiming.EndDiscard(discardMapped);\n\t\t\t\tif (!discardMapped)\n",
    ),
    (
        "\t\t\tif (locked.pBits && locked.width == m_width && locked.height == m_height &&\n"
        "\t\t\t\tlocked.pitch >= locked.width * 4)\n",
        "\t\t\tconst bool copyable = locked.pBits && locked.width == m_width && locked.height == m_height &&\n"
        "\t\t\t\tlocked.pitch >= locked.width * 4;\n\t\t\tif (copyable)\n",
    ),
    (
        "\t\t\tbacking->Unmap(&locked);\n",
        "\t\t\tuploadTiming.BeginUnmap(copyable, locked.width, locked.height, locked.pitch);\n"
        "\t\t\tbacking->Unmap(&locked);\n",
    ),
)

CHANGES = {
    "src/CefInput.cpp": INPUT,
    "src/NUIRenderHandler.cpp": RENDER_HANDLER,
    "src/NUIWindow.cpp": WINDOW,
}


def apply(sources):
    if sources.keys() != SOURCE_PINS.keys():
        raise ValueError("Require the three pinned NUI timing sources")
    result = {}
    for path, source in sources.items():
        if (len(source), hashlib.sha256(source).hexdigest()) != SOURCE_PINS[path]:
            raise ValueError(f"Unexpected NUI timing source bytes for {path}")
        for old, new in CHANGES[path]:
            before = old.replace("\n", "\r\n").encode("ascii")
            if source.count(before) != 1:
                raise ValueError(f"Ambiguous NUI timing anchor in {path}")
            source = source.replace(before, new.replace("\n", "\r\n").encode("ascii"), 1)
        result[path] = source
    result[HEADER_NAME] = HEADER.encode("ascii")
    return result
