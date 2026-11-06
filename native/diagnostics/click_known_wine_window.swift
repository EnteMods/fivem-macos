import AppKit
import CoreGraphics
import Foundation

// Coordinates must come from a current captured window and its logical screen frame.
let args = CommandLine.arguments
guard args.count == 4, let pid = Int32(args[1]), pid > 1,
      let x = Double(args[2]), let y = Double(args[3]), x.isFinite, y.isFinite,
      let target = NSRunningApplication(processIdentifier: pid) else {
    fputs("Usage: click-known-wine-window PID SCREEN_X SCREEN_Y\n", stderr)
    exit(2)
}
let application = NSApplication.shared
application.setActivationPolicy(.prohibited)
let point = CGPoint(x: x, y: y)
let windows = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID) as? [[String: Any]] ?? []
guard windows.contains(where: { window in
    guard (window[kCGWindowOwnerPID as String] as? Int32) == pid,
          let owner = window[kCGWindowOwnerName as String] as? String,
          ["wine", "wine64", "wine-preloader", "wine64-preloader"].contains(owner.lowercased()),
          let values = window[kCGWindowBounds as String] as? [String: CGFloat],
          let wx = values["X"], let wy = values["Y"], let width = values["Width"], let height = values["Height"] else { return false }
    return CGRect(x: wx, y: wy, width: width, height: height).contains(point)
}) else {
    fputs("Point is outside this PID's currently visible Wine windows; no click sent.\n", stderr)
    exit(5)
}
guard target.activate(options: [.activateAllWindows]) else { exit(3) }
RunLoop.current.run(until: Date().addingTimeInterval(0.7))
guard target.isActive, NSWorkspace.shared.frontmostApplication?.processIdentifier == pid else {
    fputs("Known target did not become active; no click sent.\n", stderr)
    exit(4)
}
CGEvent(mouseEventSource: nil, mouseType: .mouseMoved, mouseCursorPosition: point, mouseButton: .left)?.post(tap: .cghidEventTap)
RunLoop.current.run(until: Date().addingTimeInterval(0.15))
CGEvent(mouseEventSource: nil, mouseType: .leftMouseDown, mouseCursorPosition: point, mouseButton: .left)?.post(tap: .cghidEventTap)
RunLoop.current.run(until: Date().addingTimeInterval(0.12))
CGEvent(mouseEventSource: nil, mouseType: .leftMouseUp, mouseCursorPosition: point, mouseButton: .left)?.post(tap: .cghidEventTap)
RunLoop.current.run(until: Date().addingTimeInterval(0.5))
