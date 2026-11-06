import AppKit
import Darwin
import Foundation
import ScreenCaptureKit

@main
@MainActor
struct CaptureOwnedWindow {
    static func main() async {
        let deadline = Task.detached {
            do {
                try await Task.sleep(nanoseconds: 10_000_000_000)
            } catch {
                return
            }
            FileHandle.standardError.write(Data("Window capture timed out after 10 seconds.\n".utf8))
            exit(2)
        }
        defer { deadline.cancel() }
        do {
            try await capture()
        } catch {
            let message = "Window capture failed: \(error.localizedDescription)\n"
            FileHandle.standardError.write(Data(message.utf8))
            exit(1)
        }
    }

    static func capture() async throws {
        let arguments = CommandLine.arguments
        guard arguments.count == 2 || arguments.count == 4,
              let processID = Int32(arguments[1]), processID > 0 else {
            throw NSError(domain: "CfxWindowCapture", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "Usage: capture-owned-window PID [WINDOW_ID OUTPUT.png]"])
        }
        let application = NSApplication.shared
        application.setActivationPolicy(.prohibited)
        let content = try await SCShareableContent.excludingDesktopWindows(true, onScreenWindowsOnly: false)
        let windows = content.windows.filter { $0.owningApplication?.processID == processID }
        if arguments.count == 2 {
            let records: [[String: Any]] = windows.map {
                ["window_id": $0.windowID, "pid": processID, "title": $0.title ?? "",
                 "owner": $0.owningApplication?.applicationName ?? "",
                 "width": $0.frame.width, "height": $0.frame.height]
            }
            let data = try JSONSerialization.data(withJSONObject: records, options: [.prettyPrinted, .sortedKeys])
            print(String(decoding: data, as: UTF8.self))
            return
        }
        guard let windowID = UInt32(arguments[2]),
              let window = windows.first(where: { $0.windowID == windowID }) else {
            throw NSError(domain: "CfxWindowCapture", code: 2,
                userInfo: [NSLocalizedDescriptionKey: "Requested window does not belong to the selected process"])
        }
        let filter = SCContentFilter(desktopIndependentWindow: window)
        let configuration = SCStreamConfiguration()
        configuration.width = max(1, Int(ceil(window.frame.width * 2)))
        configuration.height = max(1, Int(ceil(window.frame.height * 2)))
        configuration.showsCursor = false
        let screenshot = try await SCScreenshotManager.captureImage(contentFilter: filter, configuration: configuration)
        guard let png = NSBitmapImageRep(cgImage: screenshot).representation(using: .png, properties: [:]) else {
            throw NSError(domain: "CfxWindowCapture", code: 3)
        }
        try png.write(to: URL(fileURLWithPath: arguments[3]), options: .atomic)
        print("Captured window \(windowID) from PID \(processID): \(arguments[3])")
    }
}
