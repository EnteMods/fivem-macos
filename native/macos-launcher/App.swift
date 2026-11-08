import AppKit
import Foundation

struct Configuration: Decodable {
    let projectRoot: String
    let python: String
    let launcherRelativePath: String?
}

enum LauncherError: LocalizedError {
    case configuration(String)
    var errorDescription: String? {
        switch self { case .configuration(let message): return message }
    }
}

let defaultRunner = "native/client-profile/run_current.py"

func runnerURL(_ config: Configuration) throws -> URL {
    let relative = config.launcherRelativePath ?? defaultRunner
    let parts = relative.components(separatedBy: "/")
    guard config.projectRoot.hasPrefix("/"), !relative.hasPrefix("/"),
          !parts.contains(where: { $0.isEmpty || $0 == "." || $0 == ".." }),
          config.python.hasPrefix("/"), FileManager.default.isExecutableFile(atPath: config.python) else {
        throw LauncherError.configuration("Die Launcher-Konfiguration enthält einen ungültigen Pfad.")
    }
    let root = URL(fileURLWithPath: config.projectRoot, isDirectory: true).standardizedFileURL.resolvingSymlinksInPath()
    let runner = root.appendingPathComponent(relative).standardizedFileURL.resolvingSymlinksInPath()
    var isDirectory: ObjCBool = false
    guard runner.path.hasPrefix(root.path.hasSuffix("/") ? root.path : root.path + "/"),
          FileManager.default.fileExists(atPath: runner.path, isDirectory: &isDirectory), !isDirectory.boolValue else {
        throw LauncherError.configuration("Der konfigurierte Runner fehlt oder liegt außerhalb des Projektordners.")
    }
    return runner
}

func configuration() throws -> Configuration {
    let url = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Application Support/FiveM macOS/launcher.json")
    guard let data = try? Data(contentsOf: url),
          let config = try? JSONDecoder().decode(Configuration.self, from: data) else {
        throw LauncherError.configuration("Die lokale Launcher-Konfiguration fehlt oder ist ungültig.")
    }
    _ = try runnerURL(config)
    return config
}

func makeProcess(_ config: Configuration, check: Bool) throws -> Process {
    let runner = try runnerURL(config)
    let process = Process()
    process.executableURL = URL(fileURLWithPath: config.python)
    process.arguments = ["-B", runner.path] + (check ? ["--check"] : [])
    process.currentDirectoryURL = URL(fileURLWithPath: config.projectRoot, isDirectory: true)
    var environment = ProcessInfo.processInfo.environment
    environment["HOME"] = FileManager.default.homeDirectoryForCurrentUser.path
    environment["PATH"] = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
    environment["PYTHONUNBUFFERED"] = "1"
    process.environment = environment
    return process
}

func selfTest() throws {
    let fm = FileManager.default
    let root = fm.temporaryDirectory.appendingPathComponent("fivem-launcher-selftest-" + UUID().uuidString)
    defer { try? fm.removeItem(at: root) }
    let folder = root.appendingPathComponent("native/client-profile")
    try fm.createDirectory(at: folder, withIntermediateDirectories: true)
    let file = folder.appendingPathComponent("run_current.py")
    try Data("print('fixture')".utf8).write(to: file)
    let fixture = Configuration(projectRoot: root.path, python: "/usr/bin/python3", launcherRelativePath: nil)
    guard try runnerURL(fixture).path == file.resolvingSymlinksInPath().path else { throw LauncherError.configuration("Default runner test failed") }
    let old = "{\"projectRoot\":\"/tmp\",\"python\":\"/usr/bin/python3\"}".data(using: .utf8)!
    guard try JSONDecoder().decode(Configuration.self, from: old).launcherRelativePath == nil else { throw LauncherError.configuration("Legacy config test failed") }
    for path in ["../escape", "/absolute", "native/../escape", "./escape", "native//escape", ""] {
        let invalid = Configuration(projectRoot: root.path, python: "/usr/bin/python3", launcherRelativePath: path)
        if (try? runnerURL(invalid)) != nil { throw LauncherError.configuration("Unsafe path accepted") }
    }
    try fm.createSymbolicLink(at: root.appendingPathComponent("outside"), withDestinationURL: URL(fileURLWithPath: "/etc/hosts"))
    let escape = Configuration(projectRoot: root.path, python: "/usr/bin/python3", launcherRelativePath: "outside")
    if (try? runnerURL(escape)) != nil { throw LauncherError.configuration("Symlink escape accepted") }
    let alternate = folder.appendingPathComponent("alternate.py")
    try Data("import sys\nsys.exit(0 if sys.argv[1:] == ['--check'] else 9)\n".utf8).write(to: alternate)
    let custom = Configuration(projectRoot: root.path, python: "/usr/bin/python3", launcherRelativePath: "native/client-profile/alternate.py")
    let check = try makeProcess(custom, check: true)
    guard check.arguments?.last == "--check", check.arguments?[1] == alternate.path,
          check.currentDirectoryURL?.path == root.path else { throw LauncherError.configuration("Check runner test failed") }
    try check.run()
    check.waitUntilExit()
    guard check.terminationReason == .exit, check.terminationStatus == 0 else { throw LauncherError.configuration("Fixture check execution failed") }
    print("Self-test OK: legacy config, default/custom runner, unsafe paths, symlink escape and check arguments")
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    var window: NSWindow!
    var status: NSTextField!
    var process: Process?
    var logHandle: FileHandle?
    var restart: NSButton!

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        let menu = NSMenu()
        let appItem = NSMenuItem()
        menu.addItem(appItem)
        let appMenu = NSMenu()
        appMenu.addItem(withTitle: "FiveM Launcher beenden", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        appItem.submenu = appMenu
        NSApp.mainMenu = menu
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 460, height: 180),
                          styleMask: [.titled, .closable, .miniaturizable], backing: .buffered, defer: false)
        window.title = "FiveM"
        let title = NSTextField(labelWithString: "FiveM")
        title.font = .systemFont(ofSize: 23, weight: .semibold)
        title.frame = NSRect(x: 24, y: 118, width: 410, height: 32)
        status = NSTextField(wrappingLabelWithString: "FiveM wird gestartet …")
        status.frame = NSRect(x: 24, y: 62, width: 410, height: 52)
        restart = NSButton(title: "Erneut starten", target: self, action: #selector(startClient))
        restart.frame = NSRect(x: 20, y: 17, width: 140, height: 32)
        window.contentView?.addSubview(restart)
        window.contentView?.addSubview(title)
        window.contentView?.addSubview(status)
        window.center()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        startClient()
    }

    @objc func startClient() {
        guard process == nil else { return }
        restart.isEnabled = false
        status.stringValue = "FiveM wird gestartet …"
        do {
            let config = try configuration()
            let directory = FileManager.default.homeDirectoryForCurrentUser
                .appendingPathComponent("Library/Logs/FiveM macOS", isDirectory: true)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                     attributes: [.posixPermissions: 0o700])
            let log = directory.appendingPathComponent("launcher-\(UUID().uuidString).log")
            guard FileManager.default.createFile(atPath: log.path, contents: nil,
                                                  attributes: [.posixPermissions: 0o600]) else {
                throw LauncherError.configuration("Das Startprotokoll konnte nicht angelegt werden.")
            }
            let handle = try FileHandle(forWritingTo: log)
            logHandle = handle
            let task = try makeProcess(config, check: false)
            task.standardOutput = handle
            task.standardError = handle
            task.terminationHandler = { [weak self] completed in
                DispatchQueue.main.async {
                    self?.logHandle?.closeFile()
                    self?.logHandle = nil
                    self?.process = nil
                    self?.restart.isEnabled = true
                    if completed.terminationReason == .exit && completed.terminationStatus == 0 {
                        self?.status.stringValue = "FiveM wurde beendet. Dieses Fenster kann geschlossen werden."
                    } else {
                        self?.status.stringValue = "FiveM konnte nicht erfolgreich gestartet oder beendet werden. Das lokale Startprotokoll liegt unter ~/Library/Logs/FiveM macOS/."
                    }
                }
            }
            try task.run()
            process = task
            status.stringValue = "FiveM wird ausgeführt. Das Startprotokoll wird lokal gespeichert."
        } catch {
            logHandle?.closeFile()
            logHandle = nil
            restart.isEnabled = true
            status.stringValue = "Start fehlgeschlagen: \(error.localizedDescription)"
        }
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows: Bool) -> Bool {
        if !hasVisibleWindows { window.makeKeyAndOrderFront(nil) }
        if process == nil { startClient() }
        return true
    }
}

if CommandLine.arguments.dropFirst() == ["--self-test"] {
    do { try selfTest() } catch {
        fputs("Self-test failed: \(error.localizedDescription)\n", stderr)
        exit(1)
    }
} else if CommandLine.arguments.dropFirst() == ["--check"] {
    do {
        let task = try makeProcess(configuration(), check: true)
        try task.run()
        task.waitUntilExit()
        exit(task.terminationReason == .exit ? task.terminationStatus : 1)
    } catch {
        fputs("FiveM launcher: \(error.localizedDescription)\n", stderr)
        exit(1)
    }
} else if CommandLine.arguments.count > 1 {
    fputs("Usage: FiveMLauncher [--check|--self-test]\n", stderr)
    exit(2)
} else {
    let app = NSApplication.shared
    let delegate = AppDelegate()
    app.delegate = delegate
    app.run()
}
