"""Generate a Wine-only CPU OSR adapter from the unchanged current NUI sources."""
from pathlib import Path


def replace_once(data, before, after):
    if data.count(before) != 1:
        raise ValueError("NUI source anchor is missing or ambiguous: " + before[:90])
    return data.replace(before, after, 1)


HELPERS = r'''
bool NUIWindow::ResizeSoftwareView(int width, int height)
{
    cfx::software_nui::Frame next;
    if (!next.Reset(width, height))
    {
        return false;
    }
    auto backing = g_nuiGi->CreateTextureBacking(width, height, nui::GITextureFormat::ARGB);
    if (!backing.GetRef())
    {
        return false;
    }
    std::lock_guard softwareLock(m_softwareMutex);
    std::unique_lock textureLock(m_textureMutex);
    auto& frame = m_softwareFrames[PET_VIEW];
    if (frame.Width() != width || frame.Height() != height)
    {
        frame = std::move(next);
    }
    else
    {
        frame.Reupload();
    }
    m_width = width;
    m_height = height;
    m_nuiTexture = backing;
    return true;
}

void NUIWindow::GetSoftwareViewRect(CefRect& rect)
{
    std::lock_guard lock(m_softwareMutex);
    rect.Set(0, 0, m_width, m_height);
}

void NUIWindow::PaintSoftware(CefRenderHandler::PaintElementType type,
    const void* pixels, int width, int height)
{
    if (!m_softwareRendering || (type != PET_VIEW && type != PET_POPUP))
    {
        return;
    }
    std::lock_guard lock(m_softwareMutex);
    if (m_softwareFrames[type].Paint(pixels, width, height) && !m_softwarePaintReported[type])
    {
        m_softwarePaintReported[type] = true;
        trace("NUI_SOFTWARE_144_PAINT type=%d width=%d height=%d\n", int(type), width, height);
    }
}

bool NUIWindow::HasSoftwareFrame(CefRenderHandler::PaintElementType type)
{
    if (!m_softwareRendering)
    {
        return true;
    }
    std::lock_guard lock(m_softwareMutex);
    return m_softwareFrames[type].Uploaded();
}

void NUIWindow::UploadSoftwareFrames()
{
    std::lock_guard softwareLock(m_softwareMutex);
    for (int i = 0; i < kMaxPaintElements; ++i)
    {
        auto& frame = m_softwareFrames[i];
        if (!frame.Pending())
        {
            continue;
        }
        fwRefContainer<nui::GITexture> backing;
        {
            std::shared_lock textureLock(m_textureMutex);
            backing = i == PET_VIEW ? m_nuiTexture : m_popupTexture;
        }
        // GTA creates the native backing on a later render-queue pass.
        if (!backing.GetRef() || !backing->GetNativeTexture())
        {
            continue;
        }
        nui::GILockedTexture mapped{};
        if (!backing->Map(0, 0, &mapped, nui::GILockFlags::WriteDiscard) &&
            !backing->Map(0, 0, &mapped, nui::GILockFlags::Write))
        {
            continue;
        }
        if (mapped.pitch > 0)
        {
            if (frame.Upload(mapped.pBits, mapped.width, mapped.height, static_cast<size_t>(mapped.pitch)) &&
                !m_softwareUploadReported[i])
            {
                m_softwareUploadReported[i] = true;
                trace("NUI_SOFTWARE_144_UPLOAD type=%d width=%d height=%d\n", i, mapped.width, mapped.height);
            }
        }
        backing->Unmap(&mapped);
    }
}
'''


def apply(files):
    out = {name: value.decode("utf-8").replace("\r\n", "\n") for name, value in files.items()}
    header = out["include/NUIWindow.h"]
    header = replace_once(header, "#include <queue>", '#include <queue>\n#include <mutex>\n#include "SoftwareNuiFrame.h"')
    # Append fields: exported original inline accessors retain every old member offset.
    header = replace_once(header, "\tbool IsFixedSizeWindow() const;\n};", '''\tbool IsFixedSizeWindow() const;

    bool IsSoftwareRendered() const { return m_softwareRendering; }
    void GetSoftwareViewRect(CefRect& rect);
    void PaintSoftware(CefRenderHandler::PaintElementType type, const void* pixels, int width, int height);
    bool HasSoftwareFrame(CefRenderHandler::PaintElementType type);

private:
    bool ResizeSoftwareView(int width, int height);
    void UploadSoftwareFrames();
    bool m_softwareRendering = false;
    std::mutex m_softwareMutex;
    cfx::software_nui::Frame m_softwareFrames[kMaxPaintElements];
    bool m_softwarePaintReported[kMaxPaintElements] = {};
    bool m_softwareUploadReported[kMaxPaintElements] = {};
};''')
    out["include/NUIWindow.h"] = header
    cpp = out["src/NUIWindow.cpp"]
    cpp = replace_once(cpp, '#include <LaunchMode.h>', '#include <LaunchMode.h>\n#include <CrossBuildRuntime.h>')
    cpp = replace_once(cpp, '''\t\tnuiClient->SetWindowValid(false);
\t\tnuiClient->ClearWindow();

\t\tCefRefPtr<CefBrowser> browser;
\t\t{
\t\t\tstd::unique_lock _(nuiClient->GetWindowLock());''', '''\t\tCefRefPtr<CefBrowser> browser;
\t\t{
\t\t\tstd::unique_lock _(nuiClient->GetWindowLock());
\t\t\tnuiClient->SetWindowValid(false);
\t\t\tnuiClient->ClearWindow();''')
    cpp = replace_once(cpp, '\tmemset(&m_sharedResourceTexturesCreated, 0, sizeof(m_sharedResourceTexturesCreated));', '''#ifdef GTA_FIVE
    wchar_t softwareOption[2] = {};
    m_softwareRendering = CfxIsWine() &&
        GetEnvironmentVariableW(L"CFX_NUI_SOFTWARE_144", softwareOption, 2) == 1 && softwareOption[0] == L'1';
    trace("NUI_SOFTWARE_144_TRANSPORT cpu=%d\\n", m_softwareRendering ? 1 : 0);
#endif
\tmemset(&m_sharedResourceTexturesCreated, 0, sizeof(m_sharedResourceTexturesCreated));''')
    cpp = replace_once(cpp, 'void NUIWindow::Initialize(CefString url)\n{\n\tInitializeRenderBacking();', '''void NUIWindow::Initialize(CefString url)
{
    if (m_softwareRendering)
    {
        std::lock_guard lock(m_softwareMutex);
        if (!m_softwareFrames[PET_VIEW].Reset(m_width, m_height))
        {
            throw std::runtime_error("Invalid software NUI view size");
        }
    }
\tInitializeRenderBacking();''')
    cpp = replace_once(cpp, 'info.shared_texture_enabled = true;', 'info.shared_texture_enabled = !m_softwareRendering;')
    cpp = replace_once(cpp, '\t// create the backing texture', '''    if (m_softwareRendering)
    {
        ResizeSoftwareView(m_width, m_height);
        return;
    }

\t// create the backing texture''')
    cpp = replace_once(cpp, '\t\t\tm_width = resX;\n\t\t\tm_height = resY;', '''            if (m_softwareRendering)
            {
                if (!ResizeSoftwareView(resX, resY))
                {
                    return;
                }
            }
            else
            {
\t\t\tm_width = resX;
\t\t\tm_height = resY;
            }''')
    cpp = replace_once(cpp, '\tm_pollQueue.clear();', '''    if (m_softwareRendering)
    {
        UploadSoftwareFrames();
        m_pollQueue.clear();
        return;
    }

\tm_pollQueue.clear();''')
    cpp = replace_once(cpp, 'void NUIWindow::HandlePopupShow(bool show)\n{', '''void NUIWindow::HandlePopupShow(bool show)
{
    if (m_softwareRendering && !show)
    {
        std::lock_guard softwareLock(m_softwareMutex);
        std::unique_lock textureLock(m_textureMutex);
        m_softwareFrames[PET_POPUP].Clear();
        m_popupTexture = nullptr;
        m_popupRect = {};
        return;
    }''')
    cpp = replace_once(cpp, 'CefRect NUIWindow::GetPopupRect()\n{', '''CefRect NUIWindow::GetPopupRect()
{
    std::unique_lock softwareLock(m_softwareMutex, std::defer_lock);
    if (m_softwareRendering)
    {
        softwareLock.lock();
    }''')
    cpp = replace_once(cpp, 'void NUIWindow::SetPopupRect(const CefRect& rect)\n{', '''void NUIWindow::SetPopupRect(const CefRect& rect)
{
    if (m_softwareRendering)
    {
        cfx::software_nui::Frame next;
        if (!next.Reset(rect.width, rect.height))
        {
            return;
        }
        auto backing = g_nuiGi->CreateTextureBacking(rect.width, rect.height, nui::GITextureFormat::ARGB);
        if (!backing.GetRef())
        {
            return;
        }
        std::lock_guard softwareLock(m_softwareMutex);
        std::unique_lock textureLock(m_textureMutex);
        m_softwareFrames[PET_POPUP] = std::move(next);
        m_popupTexture = backing;
        m_popupRect = rect;
        return;
    }''')
    cpp = replace_once(cpp, 'void NUIWindow::UpdateSharedResource(CefRenderHandler::PaintElementType type)\n{', '''void NUIWindow::UpdateSharedResource(CefRenderHandler::PaintElementType type)
{
    if (m_softwareRendering)
    {
        return;
    }''')
    out["src/NUIWindow.cpp"] = cpp + "\n" + HELPERS
    handler = out["src/NUIRenderHandler.cpp"]
    handler = replace_once(handler, 'void NUIRenderHandler::GetViewRect(CefRefPtr<CefBrowser> browser, CefRect& rect)\n{', '''void NUIRenderHandler::GetViewRect(CefRefPtr<CefBrowser> browser, CefRect& rect)
{
    std::unique_lock windowLock(m_owner->GetWindowLock());
    if (m_owner->GetWindowValid() && m_owner->GetWindow()->IsSoftwareRendered())
    {
        m_owner->GetWindow()->GetSoftwareViewRect(rect);
        return;
    }''')
    handler = replace_once(handler, 'void NUIRenderHandler::OnPaint(CefRefPtr<CefBrowser> browser, PaintElementType type, const RectList& dirtyRects, const void* buffer, int width, int height)\n{', '''void NUIRenderHandler::OnPaint(CefRefPtr<CefBrowser> browser, PaintElementType type, const RectList& dirtyRects, const void* buffer, int width, int height)
{
    std::unique_lock windowLock(m_owner->GetWindowLock());
    if (m_owner->GetWindowValid() && m_owner->GetWindow()->IsSoftwareRendered())
    {
        m_owner->GetWindow()->PaintSoftware(type, buffer, width, height);
        return;
    }''')
    out["src/NUIRenderHandler.cpp"] = handler
    handler = replace_once(handler, 'void NUIRenderHandler::OnPopupShow(CefRefPtr<CefBrowser> browser, bool show)\n{', '''void NUIRenderHandler::OnPopupShow(CefRefPtr<CefBrowser> browser, bool show)
{
    std::unique_lock windowLock(m_owner->GetWindowLock());''')
    handler = replace_once(handler, 'void NUIRenderHandler::OnPopupSize(CefRefPtr<CefBrowser> browser, const CefRect& rect)\n{', '''void NUIRenderHandler::OnPopupSize(CefRefPtr<CefBrowser> browser, const CefRect& rect)
{
    std::unique_lock windowLock(m_owner->GetWindowLock());
    if (!m_owner->GetWindowValid())
    {
        return;
    }''')
    out["src/NUIRenderHandler.cpp"] = handler
    callbacks = out["src/NUIRenderCallbacks.cpp"]
    callbacks = replace_once(callbacks, 'if (window->GetTexture().GetRef())', 'if (window->GetTexture().GetRef() && window->HasSoftwareFrame(PET_VIEW))')
    callbacks = replace_once(callbacks, 'if (window->GetPopupTexture().GetRef())', 'auto popupTexture = window->GetPopupTexture();\n\t\t\tif (popupTexture.GetRef() && window->HasSoftwareFrame(PET_POPUP))')
    callbacks = replace_once(callbacks, 'g_nuiGi->SetTexture(window->GetPopupTexture(), true);', 'g_nuiGi->SetTexture(popupTexture, true);')
    out["src/NUIRenderCallbacks.cpp"] = callbacks
    return {name: value.encode("utf-8") for name, value in out.items()}


def stage(component, target):
    paths = ("include/NUIWindow.h", "src/NUIWindow.cpp", "src/NUIRenderHandler.cpp", "src/NUIRenderCallbacks.cpp")
    files = {path: (component / path).read_bytes() for path in paths}
    adapted = apply(files)
    for relative, data in adapted.items():
        (target / relative).write_bytes(data)
    (target / "include/SoftwareNuiFrame.h").write_bytes(Path(__file__).with_name("SoftwareNuiFrame.h").read_bytes())
    return files, adapted
