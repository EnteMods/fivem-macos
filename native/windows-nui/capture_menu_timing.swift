import AppKit
import CoreMedia
import CoreVideo
import Foundation
import ScreenCaptureKit

final class FrameSink: NSObject, SCStreamOutput, @unchecked Sendable {
    private let clientOffset: Int
    private var previous: String?

    init(clientOffset: Int) {
        self.clientOffset = clientOffset
    }

    func stream(_ stream: SCStream, didOutputSampleBuffer sample: CMSampleBuffer,
                of outputType: SCStreamOutputType) {
        guard outputType == .screen, let pixel = sample.imageBuffer,
              CVPixelBufferGetPixelFormatType(pixel) == kCVPixelFormatType_32BGRA,
              CVPixelBufferGetWidth(pixel) > 32, CVPixelBufferGetHeight(pixel) > clientOffset + 48,
              CVPixelBufferLockBaseAddress(pixel, .readOnly) == kCVReturnSuccess else { return }
        defer { CVPixelBufferUnlockBaseAddress(pixel, .readOnly) }
        guard let base = CVPixelBufferGetBaseAddress(pixel) else { return }
        let stride = CVPixelBufferGetBytesPerRow(pixel)
        var blue = 0
        var magenta = 0
        for y in (clientOffset + 8)..<(clientOffset + 48) {
            for x in 16..<32 {
                let color = base.advanced(by: y * stride + x * 4).assumingMemoryBound(to: UInt8.self)
                if color[0] > 175 && color[1] < 105 {
                    if color[2] < 100 { blue += 1 }
                    if color[2] > 160 { magenta += 1 }
                }
            }
        }
        guard max(blue, magenta) > 40 else { return }
        let marker = blue > magenta ? "blue" : "magenta"
        guard marker != previous else { return }
        previous = marker
        let now = Date().timeIntervalSince1970 * 1000
        let age = CMTimeGetSeconds(CMTimeSubtract(CMClockGetTime(CMClockGetHostTimeClock()),
                                                  sample.presentationTimeStamp)) * 1000
        let frameTime = age.isFinite && age >= 0 && age < 1000 ? String(now - age) : "null"
        print("{\"at\":\(now),\"frameAt\":\(frameTime),\"color\":\"\(marker)\"}")
    }
}

@main
struct Capture {
    @MainActor
    static func main() async throws {
        let arguments = CommandLine.arguments
        guard arguments.count == 6, let pid = Int32(arguments[1]), pid > 1,
              let id = UInt32(arguments[2]), let scale = Int(arguments[3]), (1...2).contains(scale),
              let title = Int(arguments[4]), (0...80).contains(title),
              let seconds = UInt64(arguments[5]), (2...15).contains(seconds) else { exit(2) }
        NSApplication.shared.setActivationPolicy(.prohibited)
        let content = try await SCShareableContent.excludingDesktopWindows(true, onScreenWindowsOnly: true)
        let matches = content.windows.filter {
            $0.windowID == id && $0.owningApplication?.processID == pid && $0.title == "FiveM® by Cfx.re"
        }
        guard matches.count == 1, let window = matches.first else { exit(3) }
        let settings = SCStreamConfiguration()
        settings.width = Int(window.frame.width) * scale
        settings.height = Int(window.frame.height) * scale
        settings.pixelFormat = kCVPixelFormatType_32BGRA
        settings.minimumFrameInterval = CMTime(value: 1, timescale: 120)
        settings.queueDepth = 3
        settings.showsCursor = false
        settings.ignoreShadowsSingleWindow = true
        let stream = SCStream(filter: SCContentFilter(desktopIndependentWindow: window),
                              configuration: settings, delegate: nil)
        let sink = FrameSink(clientOffset: title)
        try stream.addStreamOutput(sink, type: .screen, sampleHandlerQueue: DispatchQueue(label: "nui-capture"))
        try await stream.startCapture()
        try await Task.sleep(nanoseconds: seconds * 1_000_000_000)
        try await stream.stopCapture()
    }
}
