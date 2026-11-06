import Foundation

enum AuthRoute {
    static let maximumBytes = 65_536
    private static let prefix = "fivem://accept-auth?payload="

    static func accepts(_ text: String) -> Bool {
        guard text.utf8.count <= maximumBytes,
              text.hasPrefix(prefix), text.utf8.count > prefix.utf8.count,
              !text.unicodeScalars.contains(where: { $0.value <= 0x20 || $0.value == 0x7f }),
              let parts = URLComponents(string: text),
              parts.scheme == "fivem", parts.host == "accept-auth",
              parts.user == nil, parts.password == nil, parts.port == nil,
              parts.path.isEmpty, parts.fragment == nil,
              let query = parts.percentEncodedQuery,
              query.hasPrefix("payload="), query.utf8.count > 8,
              !query.contains("&"),
              String(text.dropFirst(prefix.count - 8)) == query else {
            return false
        }
        let bytes = Array(query.utf8)
        var index = 0
        while index < bytes.count {
            if bytes[index] == 0x25 {
                guard index + 2 < bytes.count,
                      isHex(bytes[index + 1]), isHex(bytes[index + 2]) else { return false }
                index += 3
            } else {
                index += 1
            }
        }
        return true
    }

    private static func isHex(_ value: UInt8) -> Bool {
        (value >= 0x30 && value <= 0x39) ||
        (value >= 0x41 && value <= 0x46) ||
        (value >= 0x61 && value <= 0x66)
    }
}

// The secondary process exiting normally is the available handoff confirmation.
enum HandoffOutcome: Equatable {
    case delivered, pending, failed

    static func from(exitStatus: Int32?, normalExit: Bool) -> HandoffOutcome {
        guard normalExit, let status = exitStatus else { return .failed }
        switch status {
        case 0: return .delivered
        case 6: return .pending
        default: return .failed
        }
    }

    var shouldClose: Bool { self == .delivered }
    var message: String {
        switch self {
        case .delivered: return "Anmeldung an FiveM weitergegeben. Bitte dort fortfahren."
        case .pending: return "Die Weitergabe läuft möglicherweise noch. Bitte FiveM prüfen."
        case .failed: return "Die Weitergabe ist fehlgeschlagen. Bitte FiveM prüfen."
        }
    }
}
