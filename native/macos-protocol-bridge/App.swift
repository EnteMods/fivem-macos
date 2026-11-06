import AppKit
import CryptoKit
import Darwin
import Foundation

enum Handoff {
    static func dispatch(_ data: Data) -> HandoffOutcome {
        let helper = URL(fileURLWithPath: BuildConfiguration.helper)
        guard helper.resolvingSymlinksInPath().path == helper.path,
              let values = try? helper.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey]),
              values.isRegularFile == true, values.isSymbolicLink != true,
              let helperData = try? Data(contentsOf: helper), helperData.count <= 65_536,
              SHA256.hash(data: helperData).map({ String(format: "%02x", $0) }).joined()
                == BuildConfiguration.helperSHA256 else { return .failed }
        let child = Process()
        child.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        child.arguments = [helper.path]
        var environment = ProcessInfo.processInfo.environment.filter {
            !$0.key.hasPrefix("PYTHON") && !$0.key.hasPrefix("DYLD_")
        }
        environment["PYTHONNOUSERSITE"] = "1"
        child.environment = environment
        let input = Pipe()
        child.standardInput = input
        child.standardOutput = FileHandle.nullDevice
        child.standardError = FileHandle.nullDevice
        do {
            try child.run()
            try input.fileHandleForWriting.write(contentsOf: data)
            try input.fileHandleForWriting.close()
            child.waitUntilExit()
            return HandoffOutcome.from(exitStatus: child.terminationStatus,
                                       normalExit: child.terminationReason == .exit)
        } catch {
            try? input.fileHandleForWriting.close()
            if child.isRunning { child.waitUntilExit() }
            return .failed
        }
    }
}

final class BridgeDelegate: NSObject, NSApplicationDelegate {
    private var window: NSWindow?
    private let label = NSTextField(wrappingLabelWithString: "Bereit für die FiveM-Anmeldung.")
    private var busy = false

    func applicationDidFinishLaunching(_ notification: Notification) {
        showWindow()
    }

    func application(_ application: NSApplication, open urls: [URL]) {
        showWindow()
        guard !busy else {
            label.stringValue = "Eine Anmeldung wird bereits weitergegeben."
            return
        }
        guard urls.count == 1 else {
            label.stringValue = "Dieser Anmeldeaufruf wurde nicht angenommen."
            return
        }
        let text = urls[0].absoluteString
        guard AuthRoute.accepts(text) else {
            label.stringValue = "Dieser Anmeldeaufruf wurde nicht angenommen."
            return
        }
        busy = true
        label.stringValue = "Anmeldung wird an FiveM weitergegeben …"
        let data = Data(text.utf8)
        DispatchQueue.global(qos: .userInitiated).async {
            let outcome = Handoff.dispatch(data)
            DispatchQueue.main.async {
                self.busy = false
                self.label.stringValue = outcome.message
                if outcome.shouldClose { NSApp.terminate(nil) }
            }
        }
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        showWindow()
        return true
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }

    private func showWindow() {
        if window == nil {
            let view = NSView(frame: NSRect(x: 0, y: 0, width: 460, height: 150))
            label.frame = NSRect(x: 28, y: 42, width: 404, height: 66)
            label.font = .systemFont(ofSize: 15)
            view.addSubview(label)
            let created = NSWindow(contentRect: view.frame, styleMask: [.titled, .closable, .miniaturizable],
                                   backing: .buffered, defer: false)
            created.title = "FiveM Anmeldung"
            created.contentView = view
            created.center()
            created.isReleasedWhenClosed = false
            window = created
        }
        window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }
}

@main
struct FiveMAuthBridge {
    static func main() {
        signal(SIGPIPE, SIG_IGN)
        let application = NSApplication.shared
        application.setActivationPolicy(.regular)
        let delegate = BridgeDelegate()
        application.delegate = delegate
        let menu = NSMenu()
        let applicationItem = NSMenuItem()
        let applicationMenu = NSMenu()
        applicationMenu.addItem(withTitle: "Beenden", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        applicationItem.submenu = applicationMenu
        menu.addItem(applicationItem)
        application.mainMenu = menu
        withExtendedLifetime(delegate) { application.run() }
    }
}
