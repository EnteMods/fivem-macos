"""Resize the Wine GTA V software NUI backing in the pinned CEF 103 component."""

import hashlib


SOURCE_PINS = {
    "src/NUIWindow.cpp": (24844, "98797e2e07c5731f331b3f35b3c566444eb8ac09f8b2d64bf0945fb08ef8e10a"),
    "src/NUIRenderHandler.cpp": (8370, "5e5eb1d719dece54509d480775631f0d93a2a98ce8a9ac7d5111483c03c677db"),
    "src/NUIRenderCallbacks.cpp": (4666, "b83742b10d2d8805dfd8943e7a4fdaa3f5879850fadc11586f56716222aae314"),
    "include/NUIWindow.h": (4717, "ea4dfaa1dfc896c27124107178205a7a83d3f033c6bb7f491c9e4a696ead879d"),
}

UPLOAD_RECT = r'''
static void CopySoftwareTextureRect(char* target, size_t targetPitch,
	const char* source, size_t sourcePitch, int width, int height, const CefRect& rect)
{
	if (rect.x < 0 || rect.y < 0 || rect.width <= 0 || rect.height <= 0 ||
		rect.x > width - rect.width || rect.y > height - rect.height)
	{
		return;
	}

	const size_t column = static_cast<size_t>(rect.x) * 4;
	const size_t bytes = static_cast<size_t>(rect.width) * 4;
	for (int y = rect.y; y < rect.y + rect.height; ++y)
	{
		const auto sourceRow = static_cast<size_t>(y) * sourcePitch;
		const auto targetRow = static_cast<size_t>(height - y - 1) * targetPitch;
		memcpy(target + targetRow + column, source + sourceRow + column, bytes);
	}
}
'''

WINDOW_SOFTWARE_HELPERS = "#if defined(GTA_FIVE)\n" + UPLOAD_RECT + r'''
bool HasPaintedSoftwareBacking(NUIWindow& window)
{
	auto lock = window.GetRenderBufferLock();
	return !window.m_needsFullSoftwarePaint;
}
#endif

'''

WINDOW_RESIZE_OLD = r'''			m_width = resX;
			m_height = resY;

			{
				auto _ = GetRenderBufferLock();
				m_roundedHeight = roundUp(m_height, 16);
				m_roundedWidth = roundUp(m_width, 16);

				if (m_renderBuffer)
				{
					delete[] m_renderBuffer;
					m_renderBuffer = new char[4 * m_roundedWidth * m_roundedHeight];
				}
			}
'''

WINDOW_RESIZE_SOFTWARE = r'''#if defined(GTA_FIVE)
			if (wineSoftware)
			{
				constexpr int maxExtent = D3D11_REQ_TEXTURE2D_U_OR_V_DIMENSION;
				if (resX <= 0 || resY <= 0 || resX > maxExtent || resY > maxExtent)
				{
					return;
				}

				const int roundedWidth = roundUp(resX, 16);
				const int roundedHeight = roundUp(resY, 16);
				const auto bytes = static_cast<size_t>(roundedWidth) * roundedHeight * 4;
				std::unique_ptr<char[]> buffer(new (std::nothrow) char[bytes]);
				if (!buffer)
				{
					return;
				}

				auto backing = g_nuiGi->CreateTextureBacking(resX, resY, nui::GITextureFormat::ARGB);
				if (!backing.GetRef())
				{
					return;
				}

				auto renderLock = GetRenderBufferLock();
				std::unique_lock textureLock(m_textureMutex);
				delete[] m_renderBuffer;
				m_renderBuffer = buffer.release();
				m_width = resX;
				m_height = resY;
				m_roundedWidth = roundedWidth;
				m_roundedHeight = roundedHeight;
				m_dirtyRects = {};
				m_needsFullSoftwarePaint = true;
				m_nuiTexture = backing;
			}
			else
#endif
'''

WINDOW_UPLOAD_SOFTWARE = r'''#if defined(GTA_FIVE)
		if (wineSoftware)
		{
			{
				auto renderLock = GetRenderBufferLock();
				if (m_dirtyRects.empty())
				{
					return;
				}
			}

			auto backing = GetTexture();
			// GTA materializes backing textures on the next render pass.
			if (!backing.GetRef() || !backing->GetNativeTexture())
			{
				return;
			}

			nui::GILockedTexture locked{};
			bool discarded = false;
			if (!backing->Map(0, 0, &locked, nui::GILockFlags::Write))
			{
				if (!backing->Map(0, 0, &locked, nui::GILockFlags::WriteDiscard))
				{
					return;
				}
				discarded = true;
			}

			if (locked.pBits && locked.width == m_width && locked.height == m_height &&
				locked.pitch >= locked.width * 4)
			{
				auto renderLock = GetRenderBufferLock();
				const auto sourcePitch = static_cast<size_t>(m_roundedWidth) * 4;
				auto* target = static_cast<char*>(locked.pBits);
				if (discarded)
				{
					CopySoftwareTextureRect(target, locked.pitch, m_renderBuffer, sourcePitch,
						locked.width, locked.height, CefRect(0, 0, locked.width, locked.height));
					m_dirtyRects = {};
				}
				else
				{
					while (!m_dirtyRects.empty())
					{
						CopySoftwareTextureRect(target, locked.pitch, m_renderBuffer, sourcePitch,
							locked.width, locked.height, m_dirtyRects.front());
						m_dirtyRects.pop();
					}
				}
				m_needsFullSoftwarePaint = false;
			}
			backing->Unmap(&locked);
			return;
		}
#endif

'''

RENDER_VIEW_SOFTWARE = r'''#if defined(GTA_FIVE)
	if (window->IsPrimary() && CfxIsWine())
	{
		if (!renderBuffer || !buffer || width != window->GetWidth() || height != wheight ||
			width <= 0 || height <= 0)
		{
			return;
		}

		const auto copyRect = [&](const CefRect& rect)
		{
			if (rect.x < 0 || rect.y < 0 || rect.width <= 0 || rect.height <= 0 ||
				rect.x > width - rect.width || rect.y > height - rect.height)
			{
				return;
			}

			for (int y = rect.y; y < rect.y + rect.height; ++y)
			{
				const auto sourceOffset = (static_cast<size_t>(y) * width + rect.x) * 4;
				const auto targetOffset = (static_cast<size_t>(y) * roundedWidth + rect.x) * 4;
				memcpy(static_cast<char*>(renderBuffer) + targetOffset,
					static_cast<const char*>(buffer) + sourceOffset, static_cast<size_t>(rect.width) * 4);
			}
			window->AddDirtyRect(rect);
		};

		// A new backing needs every pixel even if CEF only marks a small region dirty.
		if (window->m_needsFullSoftwarePaint && window->m_dirtyRects.empty())
		{
			copyRect(CefRect(0, 0, width, height));
		}
		else
		{
			for (const auto& rect : dirtyRects)
			{
				copyRect(rect);
			}
		}
		return;
	}
#endif

'''

RENDER_POPUP_SOFTWARE = r'''#if defined(GTA_FIVE)
	if (window->IsPrimary() && CfxIsWine())
	{
		auto lock = window->GetRenderBufferLock();
		auto* target = static_cast<char*>(window->GetRenderBuffer());
		if (!target || !buffer || width <= 0 || height <= 0 ||
			width != m_popupRect.width || height != m_popupRect.height ||
			(window->m_needsFullSoftwarePaint && window->m_dirtyRects.empty()))
		{
			return;
		}

		const int x = m_popupRect.x;
		const int y = m_popupRect.y;
		if (x < 0 || y < 0 || x >= window->GetWidth() || y >= window->GetHeight())
		{
			return;
		}

		const int copyWidth = (std::min)(width, window->GetWidth() - x);
		const int copyHeight = (std::min)(height, window->GetHeight() - y);
		const int roundedWidth = window->GetRoundedWidth();
		for (int row = 0; row < copyHeight; ++row)
		{
			const auto targetOffset = (static_cast<size_t>(y + row) * roundedWidth + x) * 4;
			const auto sourceOffset = static_cast<size_t>(row) * width * 4;
			memcpy(target + targetOffset, static_cast<const char*>(buffer) + sourceOffset,
				static_cast<size_t>(copyWidth) * 4);
		}
		window->AddDirtyRect(CefRect(x, y, copyWidth, copyHeight));
		return;
	}
#endif

'''


def insert_before(anchor, addition):
    return anchor, addition + anchor


def insert_after(anchor, addition):
    return anchor, anchor + addition


def indented_block(code, depth):
    return "\n".join("\t" * depth + line if line else "" for line in code.split("\n"))


WINDOW_CHANGES = (
    insert_after('#include <CefOverlay.h>\n', '#include <new>\n'),
    ("m_dereferencedNuiTexture(false)", "m_needsFullSoftwarePaint(false)"),
    (
        "\t\tnuiClient->SetWindowValid(false);\n\t\tnuiClient->ClearWindow();\n\n"
        "\t\tstd::unique_lock _(nuiClient->GetWindowLock());\n",
        "\t\tstd::unique_lock _(nuiClient->GetWindowLock());\n"
        "\t\tnuiClient->SetWindowValid(false);\n\t\tnuiClient->ClearWindow();\n",
    ),
    (
        "\tCefBrowserHost::CreateBrowser(info, m_client, url, settings, {}, rc);\n\n"
        "\tif (!info.shared_texture_enabled)\n\t{\n"
        "\t\tm_renderBuffer = new char[4 * m_roundedWidth * m_roundedHeight];\n\t}\n",
        "\tif (!info.shared_texture_enabled)\n\t{\n"
        "\t\tauto renderLock = GetRenderBufferLock();\n"
        "\t\tm_renderBuffer = new char[4 * m_roundedWidth * m_roundedHeight];\n"
        "#if defined(GTA_FIVE)\n\t\tm_needsFullSoftwarePaint = m_rawBlit && CfxIsWine();\n#endif\n\t}\n\n"
        "\tCefBrowserHost::CreateBrowser(info, m_client, url, settings, {}, rc);\n",
    ),
    insert_before("void NUIWindow::UpdateFrame()\n", WINDOW_SOFTWARE_HELPERS),
    insert_after(
        "void NUIWindow::UpdateFrame()\n{\n",
        "#if defined(GTA_FIVE)\n\tconst bool wineSoftware = m_rawBlit && CfxIsWine();\n#endif\n",
    ),
    (
        WINDOW_RESIZE_OLD,
        WINDOW_RESIZE_SOFTWARE + "\t\t\t{\n" + indented_block(WINDOW_RESIZE_OLD, 1) + "\t\t\t}\n",
    ),
    insert_after("\telse if (m_renderBuffer)\n\t{\n", WINDOW_UPLOAD_SOFTWARE),
)

HANDLER_CHANGES = (
    insert_after("#include <CrossBuildRuntime.h>\n", "#include <LaunchMode.h>\n"),
    insert_after(
        "void NUIRenderHandler::GetViewRect(CefRefPtr<CefBrowser> browser, CefRect& rect)\n{\n",
        "\tstd::unique_lock windowLock(m_owner->GetWindowLock());\n",
    ),
    (
        "\t\tNUIWindow* window = m_owner->GetWindow();\n\t\trect.Set(0, 0, window->GetWidth(), window->GetHeight());\n",
        "\t\tNUIWindow* window = m_owner->GetWindow();\n"
        "\t\tauto renderLock = window->GetRenderBufferLock();\n"
        "\t\trect.Set(0, 0, window->GetWidth(), window->GetHeight());\n",
    ),
    (
        "\tif (m_owner->GetWindowValid() && m_owner->GetWindow()->GetRenderBuffer())\n\t{\n"
        "\t\t// lock the window lock\n\t\tauto& lock = m_owner->GetWindowLock();\n\t\tlock.lock();\n",
        "\tstd::unique_lock windowLock(m_owner->GetWindowLock());\n"
        "\tauto* window = m_owner->GetWindowValid() ? m_owner->GetWindow() : nullptr;\n"
        "\tif (window)\n\t{\n\t\tauto renderLock = window->GetRenderBufferLock();\n"
        "\t\tif (!window->GetRenderBuffer())\n\t\t{\n\t\t\treturn;\n\t\t}\n"
        "\t\trenderLock.unlock();\n",
    ),
    (
        "\t\tif (auto w = m_owner->GetWindow())\n\t\t{\n\t\t\tw->MarkRenderBufferDirty();\n\t\t}\n"
        "\n\t\t// unlock the lock\n\t\tlock.unlock();\n",
        "#if defined(GTA_FIVE)\n\t\tif (!window->IsPrimary() || !CfxIsWine())\n#endif\n"
        "\t\t{\n\t\t\twindow->MarkRenderBufferDirty();\n\t\t}\n",
    ),
    (
        "\tNUIWindow* window = m_owner->GetWindow();\n\n\tm_popupRect = rect;\n",
        "\tstd::unique_lock windowLock(m_owner->GetWindowLock());\n"
        "\tauto* window = m_owner->GetWindowValid() ? m_owner->GetWindow() : nullptr;\n"
        "\tif (!window)\n\t{\n\t\treturn;\n\t}\n"
        "\tauto renderLock = window->GetRenderBufferLock();\n\n\tm_popupRect = rect;\n",
    ),
    insert_after("\tint wheight = window->GetHeight();\n\n", RENDER_VIEW_SOFTWARE),
    insert_after(
        "void NUIRenderHandler::PaintPopup(const void* buffer, int width, int height)\n{\n"
        "\tNUIWindow* window = m_owner->GetWindow();\n\n",
        RENDER_POPUP_SOFTWARE,
    ),
)

CALLBACK_CHANGES = (
    insert_after("#include <CL2LaunchMode.h>\n", "#include <LaunchMode.h>\n"),
    (
        "\t\t\tif (window->GetTexture().GetRef())\n\t\t\t{\n"
        "\t\t\t\tg_nuiGi->SetTexture(window->GetTexture(), true);\n",
        "\t\t\tauto texture = window->GetTexture();\n\t\t\tif (texture.GetRef()\n"
        "#if defined(GTA_FIVE)\n"
        "\t\t\t\t&& (!window->IsPrimary() || !CfxIsWine() ||\n"
        "\t\t\t\t\t(texture->GetNativeTexture() && HasPaintedSoftwareBacking(*window.GetRef())))\n"
        "#endif\n\t\t\t)\n\t\t\t{\n\t\t\t\tg_nuiGi->SetTexture(texture, true);\n",
    ),
)

HEADER_CHANGES = (
    (
        "\tbool m_dereferencedNuiTexture;",
        "\tfriend class NUIRenderHandler;\n\tfriend bool HasPaintedSoftwareBacking(NUIWindow& window);\n"
        "\tbool m_needsFullSoftwarePaint;",
    ),
)

CHANGES = {
    "src/NUIWindow.cpp": WINDOW_CHANGES,
    "src/NUIRenderHandler.cpp": HANDLER_CHANGES,
    "src/NUIRenderCallbacks.cpp": CALLBACK_CHANGES,
    "include/NUIWindow.h": HEADER_CHANGES,
}


def apply(sources):
    """Return all generated files after validating every upstream input."""
    if sources.keys() != SOURCE_PINS.keys():
        raise ValueError("Require the four pinned CEF 103 NUI files")
    for path, source in sources.items():
        if (len(source), hashlib.sha256(source).hexdigest()) != SOURCE_PINS[path]:
            raise ValueError(f"Unexpected CEF 103 source bytes for {path}")

    result = {}
    for path, source in sources.items():
        newline = "\r\n" if b"\r\n" in source else "\n"
        for old, new in CHANGES[path]:
            before = old.replace("\n", newline).encode("ascii")
            if source.count(before) != 1:
                raise ValueError(f"Ambiguous CEF 103 overlay anchor in {path}")
            source = source.replace(before, new.replace("\n", newline).encode("ascii"), 1)
        result[path] = source
    return result
