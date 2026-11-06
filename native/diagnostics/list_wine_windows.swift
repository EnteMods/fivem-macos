import AppKit
import CoreGraphics
import Foundation

let application = NSApplication.shared
application.setActivationPolicy(.prohibited)
let entries = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID) as? [[String: Any]] ?? []
let selected = entries.filter { entry in
    let owner = (entry[kCGWindowOwnerName as String] as? String ?? "").lowercased()
    return ["wine", "wine64", "wine-preloader", "wine64-preloader"].contains(owner)
}.map { entry -> [String: Any] in
    ["native_pid": entry[kCGWindowOwnerPID as String] ?? 0,
     "window_id": entry[kCGWindowNumber as String] ?? 0,
     "owner": entry[kCGWindowOwnerName as String] ?? "",
     "title": entry[kCGWindowName as String] ?? "",
     "bounds": entry[kCGWindowBounds as String] ?? [:]]
}
let data = try JSONSerialization.data(withJSONObject: selected, options: [.prettyPrinted, .sortedKeys])
print(String(decoding: data, as: UTF8.self))
