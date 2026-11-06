import AppKit
import CoreGraphics
import Darwin
import Foundation

// Native SDK: NSRunningApplication.h; activation is asynchronous and can be refused.
// https://developer.apple.com/documentation/appkit/nsrunningapplication/activate(options:)
// https://developer.apple.com/documentation/appkit/nsapplication/activationoptions/activateallwindows
// The caller separately verifies this current PID's exact authorized code CWD before and after invocation.
@main
@MainActor
struct ActivateKnownWineError {
    static func windowMatches(pid: pid_t, windowID: CGWindowID) -> Bool {
        let options: CGWindowListOption = [.optionIncludingWindow, .optionOnScreenOnly, .excludeDesktopElements]
        guard let entries = CGWindowListCopyWindowInfo(options, windowID) as? [[String: Any]] else { return false }
        return entries.contains { item in
            guard (item[kCGWindowNumber as String] as? NSNumber)?.uint32Value == windowID,
                  (item[kCGWindowOwnerPID as String] as? NSNumber)?.int32Value == pid,
                  (item[kCGWindowName as String] as? String) == "Error",
                  let owner = item[kCGWindowOwnerName as String] as? String,
                  ["wine", "wine64", "wine-preloader", "wine64-preloader"].contains(owner.lowercased()),
                  (item[kCGWindowIsOnscreen as String] as? NSNumber)?.boolValue == true else { return false }
            return true
        }
    }

    static func sameApplication(_ original: NSRunningApplication, launch: Date, pid: pid_t) -> NSRunningApplication? {
        guard !original.isTerminated,
              let current = NSRunningApplication(processIdentifier: pid), !current.isTerminated,
              original.isEqual(current), current.processIdentifier == pid,
              let currentLaunch = current.launchDate, currentLaunch == launch else { return nil }
        return current
    }

    static func main() {
        var report: [String: Any] = [
            "schema_version": 1, "operation": "activate-known-wine-error",
            "preflight_window_matches": false, "preflight_application_identity_matches": false,
            "launch_date_available": false, "activation_attempted": false, "activation_returned": false,
            "postflight_application_identity_matches": false, "postflight_window_matches": false,
            "target_is_active": false, "frontmost_is_target": false,
            "runloop_budget_ms": 700, "activate_all_windows": false,
            "click_or_keyboard_event_sent": false, "activation_policy_changed": false,
            "pixel_or_error_text_success_claim": false,
            "caller_must_verify_exact_code_cwd_before_and_after": true
        ]
        func finish(_ status: String, _ code: Int32) -> Never {
            report["status"] = status
            report["exit"] = code
            if let data = try? JSONSerialization.data(withJSONObject: report, options: [.sortedKeys]) {
                FileHandle.standardOutput.write(data)
                FileHandle.standardOutput.write(Data([10]))
            }
            exit(code)
        }
        let args = CommandLine.arguments
        guard args.count == 3, args[1].utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }),
              args[2].utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }),
              let pid = Int32(args[1]), pid > 1,
              let windowID = UInt32(args[2]), windowID != 0 else { finish("invalid_arguments", 2) }
        report["native_pid"] = pid
        report["window_id"] = windowID
        _ = NSApplication.shared
        guard let target = NSRunningApplication(processIdentifier: pid), !target.isTerminated,
              target.processIdentifier == pid, let launch = target.launchDate,
              launch.timeIntervalSince1970.isFinite else { finish("application_identity_unavailable", 2) }
        report["launch_date_available"] = true
        report["preflight_window_matches"] = windowMatches(pid: pid, windowID: windowID)
        guard report["preflight_window_matches"] as? Bool == true else { finish("window_scope_rejected", 2) }
        guard sameApplication(target, launch: launch, pid: pid) != nil,
              windowMatches(pid: pid, windowID: windowID) else { finish("preflight_identity_changed", 2) }
        report["preflight_application_identity_matches"] = true
        report["activation_attempted"] = true
        let requested = target.activate(options: [])
        report["activation_returned"] = requested
        RunLoop.current.run(until: Date().addingTimeInterval(0.7))
        let current = sameApplication(target, launch: launch, pid: pid)
        report["postflight_application_identity_matches"] = current != nil
        let matchingWindow = windowMatches(pid: pid, windowID: windowID)
        report["postflight_window_matches"] = matchingWindow
        report["target_is_active"] = current?.isActive ?? false
        report["frontmost_is_target"] = NSWorkspace.shared.frontmostApplication?.processIdentifier == pid
        guard current != nil, matchingWindow else { finish("postflight_identity_changed", 4) }
        guard requested else { finish("activation_request_refused", 3) }
        guard current?.isActive == true, NSWorkspace.shared.frontmostApplication?.processIdentifier == pid else {
            finish("foreground_not_observed", 5)
        }
        finish("activation_observed_metadata_only", 0)
    }
}
