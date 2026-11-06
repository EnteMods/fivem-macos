import AppKit
import CoreGraphics
import Darwin
import Foundation
import ScreenCaptureKit

@main
@MainActor
struct CaptureOwnedWindowV2 {
    enum Phase: String {
        case argumentsValidated = "arguments_validated"
        case appKitInitialized = "appkit_initialized"
        case preflightBegin = "preflight_begin"
        case preflightAllowed = "preflight_allowed"
        case preflightDenied = "preflight_denied"
        case preflightOnlyComplete = "preflight_only_complete"
        case shareableBegin = "shareable_begin"
        case shareableEnd = "shareable_end"
        case ownerSelected = "owner_selected"
        case screenshotBegin = "screenshot_begin"
        case screenshotEnd = "screenshot_end"
        case pngBegin = "png_begin"
        case pngEnd = "png_end"
        case complete = "complete"
        case failed = "failed"
    }

    static func phase(_ value: Phase) {
        FileHandle.standardError.write(Data(("CAPTURE_V2 phase=" + value.rawValue + "\n").utf8))
    }

    static func reject(_ code: Int) throws -> Never {
        throw NSError(domain: "CfxWindowCaptureV2", code: code)
    }

    static func main() async {
        let deadline = Task.detached {
            do {
                try await Task.sleep(nanoseconds: 10_000_000_000)
            } catch {
                return
            }
            FileHandle.standardError.write(Data("CAPTURE_V2 phase=timeout budget_ms=10000\n".utf8))
            exit(2)
        }
        defer { deadline.cancel() }
        do {
            try await capture()
        } catch {
            phase(.failed)
            let code = (error as NSError).code
            FileHandle.standardError.write(Data("CAPTURE_V2 error_code=\(code)\n".utf8))
            exit(1)
        }
    }

    static func capture() async throws {
        let arguments = CommandLine.arguments
        let preflightOnly = arguments.count == 2 && arguments[1] == "--preflight-only"
        var processID: Int32?
        if !preflightOnly {
            guard arguments.count == 2 || arguments.count == 4,
                  let selectedPID = Int32(arguments[1]), selectedPID > 1 else {
                try reject(1)
            }
            processID = selectedPID
        }
        phase(.argumentsValidated)
        let application = NSApplication.shared
        application.setActivationPolicy(.prohibited)
        phase(.appKitInitialized)
        phase(.preflightBegin)
        let allowed = CGPreflightScreenCaptureAccess()
        phase(allowed ? .preflightAllowed : .preflightDenied)
        if preflightOnly {
            print("{\"operation\":\"screen_capture_preflight\",\"authorized\":\(allowed),\"request_called\":false,\"shareable_content_called\":false,\"screenshot_called\":false}")
            phase(.preflightOnlyComplete)
            if !allowed { exit(3) }
            return
        }
        guard allowed else { exit(3) }
        guard let processID else { try reject(1) }
        phase(.shareableBegin)
        let content = try await SCShareableContent.excludingDesktopWindows(true, onScreenWindowsOnly: false)
        phase(.shareableEnd)
        let windows = content.windows.filter { $0.owningApplication?.processID == processID }
        if arguments.count == 2 {
            let records: [[String: Any]] = windows.map {
                ["window_id": $0.windowID, "pid": processID, "title": $0.title ?? "",
                 "owner": $0.owningApplication?.applicationName ?? "",
                 "width": $0.frame.width, "height": $0.frame.height]
            }
            let data = try JSONSerialization.data(withJSONObject: records, options: [.prettyPrinted, .sortedKeys])
            print(String(decoding: data, as: UTF8.self))
            phase(.complete)
            return
        }
        guard let windowID = UInt32(arguments[2]), windowID != 0,
              let window = windows.first(where: { $0.windowID == windowID }),
              window.owningApplication?.processID == processID else { try reject(3) }
        phase(.ownerSelected)
        let filter = SCContentFilter(desktopIndependentWindow: window)
        let configuration = SCStreamConfiguration()
        configuration.width = max(1, Int(ceil(window.frame.width * 2)))
        configuration.height = max(1, Int(ceil(window.frame.height * 2)))
        configuration.showsCursor = false
        phase(.screenshotBegin)
        let screenshot = try await SCScreenshotManager.captureImage(contentFilter: filter, configuration: configuration)
        phase(.screenshotEnd)
        guard window.owningApplication?.processID == processID else { try reject(2) }
        phase(.pngBegin)
        guard let png = NSBitmapImageRep(cgImage: screenshot).representation(using: .png, properties: [:]) else {
            try reject(4)
        }
        try png.write(to: URL(fileURLWithPath: arguments[3]), options: .atomic)
        phase(.pngEnd)
        print("Captured window \(windowID) from PID \(processID): \(arguments[3])")
        phase(.complete)
    }
}
