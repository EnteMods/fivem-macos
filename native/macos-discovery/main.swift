import Foundation
import Darwin

struct Finding: Codable {
    let code: String
    let message: String
}
struct Asset: Codable {
    let path: String
    let valid: Bool
    let bytes: UInt64?
    let diagnostic: String?
}
struct PEMetadata: Codable {
    let architecture: String
    let format: String
    let imageBase: UInt64
    let imageBytes: UInt32
    let entryRVA: UInt32
    let sectionCount: Int
    let fileBytes: UInt64
    let fileVersion: String?
    let productVersion: String?
    let versionDiagnostic: String?
}
struct Candidate: Codable {
    let gamePath: String
    let prefixPath: String?
    let edition: String
    let executablePath: String?
    let architecture: String?
    let validInstallation: Bool
    let supportedByThisComponent: Bool
    let pe: PEMetadata?
    let assets: [Asset]
    let diagnostics: [Finding]
}
struct Report: Codable {
    let schema: Int
    let component: String
    let hostArchitecture: String
    let readOnly: Bool
    let inputMode: String
    let prefixPath: String?
    let requestedGameDirectory: String?
    let status: String
    let foundLegacy: Bool
    let candidates: [Candidate]
    let diagnostics: [Finding]
    let limitations: [String]
}
struct DiscoveryFailure: Error {
    let code: String
    let message: String
}

func fail(_ code: String, _ message: String) -> DiscoveryFailure {
    DiscoveryFailure(code: code, message: message)
}
func openNoSymlinks(_ url: URL, directory: Bool) throws -> Int32 {
    var descriptor = Darwin.open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
    guard descriptor >= 0 else { throw fail("read_failed", "Dateisystemwurzel kann nicht lesend geöffnet werden.") }
    let parts = Array(url.pathComponents.dropFirst())
    do {
        for (index, part) in parts.enumerated() {
            let wantDirectory = index < parts.count - 1 || directory
            var before = stat()
            guard part.withCString({ fstatat(descriptor, $0, &before, AT_SYMLINK_NOFOLLOW) }) == 0 else {
                throw fail("missing_or_unreadable_path", "Pfad fehlt oder ist nicht lesbar: \(url.path)")
            }
            let kind = before.st_mode & S_IFMT
            if kind == S_IFLNK { throw fail("symlink_not_followed", "Symbolischer Link wird nicht verfolgt: \(url.path)") }
            guard kind == (wantDirectory ? S_IFDIR : S_IFREG) else {
                throw fail("unexpected_file_type", "Unerwarteter Dateityp im angegebenen Pfad: \(url.path)")
            }
            let flags = O_RDONLY | O_NOFOLLOW | O_CLOEXEC | (wantDirectory ? O_DIRECTORY : O_NONBLOCK)
            let next = part.withCString { Darwin.openat(descriptor, $0, flags) }
            guard next >= 0 else {
                throw fail(errno == ELOOP ? "symlink_not_followed" : "read_failed", "Pfad kann nicht ohne Linkverfolgung geöffnet werden: \(url.path)")
            }
            Darwin.close(descriptor)
            descriptor = next
            var opened = stat()
            guard fstat(descriptor, &opened) == 0,
                  opened.st_mode & S_IFMT == (wantDirectory ? S_IFDIR : S_IFREG) else {
                throw fail("unexpected_file_type", "Geöffneter Pfad besitzt nicht den erwarteten Dateityp.")
            }
        }
        return descriptor
    } catch {
        Darwin.close(descriptor)
        throw error
    }
}
func safePath(_ url: URL, directory: Bool) throws {
    let descriptor = try openNoSymlinks(url, directory: directory)
    Darwin.close(descriptor)
}
func namedEntryPresent(_ url: URL) -> Bool {
    do {
        let descriptor = try openNoSymlinks(url, directory: false)
        Darwin.close(descriptor)
        return true
    } catch let error as DiscoveryFailure {
        return error.code == "symlink_not_followed" || error.code == "unexpected_file_type"
    } catch { return false }
}
func pathURL(_ input: String) -> URL {
    let expanded = (input as NSString).expandingTildeInPath
    let absolute = expanded.hasPrefix("/") ? expanded : FileManager.default.currentDirectoryPath + "/" + expanded
    var components: [String] = []
    for component in absolute.split(separator: "/") {
        if component == "." { continue }
        if component == ".." { if !components.isEmpty { components.removeLast() }; continue }
        components.append(String(component))
    }
    return URL(fileURLWithPath: "/" + components.joined(separator: "/"), isDirectory: true)
}
func u16(_ data: Data, _ offset: Int) -> UInt16 {
    UInt16(data[offset]) | UInt16(data[offset + 1]) << 8
}
func u32(_ data: Data, _ offset: Int) -> UInt32 {
    UInt32(data[offset]) | UInt32(data[offset + 1]) << 8 | UInt32(data[offset + 2]) << 16 | UInt32(data[offset + 3]) << 24
}
func u64(_ data: Data, _ offset: Int) -> UInt64 {
    UInt64(u32(data, offset)) | UInt64(u32(data, offset + 4)) << 32
}
final class Reader {
    let handle: FileHandle
    let size: UInt64
    init(_ path: URL) throws {
        let descriptor = try openNoSymlinks(path, directory: false)
        var info = stat()
        guard fstat(descriptor, &info) == 0, info.st_size >= 0 else {
            Darwin.close(descriptor)
            throw fail("read_failed", "Geöffnete Dateigröße kann nicht bestimmt werden.")
        }
        size = UInt64(info.st_size)
        handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
    }
    func read(_ offset: UInt64, _ count: Int) throws -> Data {
        guard count >= 0, offset <= size, UInt64(count) <= size - offset else {
            throw fail("truncated_pe", "Angeforderter PE-Bereich liegt außerhalb der Datei.")
        }
        do {
            try handle.seek(toOffset: offset)
            let value = try handle.read(upToCount: count) ?? Data()
            guard value.count == count else { throw fail("short_read", "Datei wurde nicht vollständig gelesen.") }
            return value
        } catch let error as DiscoveryFailure { throw error }
        catch { throw fail("read_failed", "Datei konnte nicht gelesen werden.") }
    }
}
struct Section {
    let rva: UInt32
    let virtualBytes: UInt32
    let rawBytes: UInt32
    let rawOffset: UInt32
    let characteristics: UInt32
}
struct PE {
    let reader: Reader
    let imageBase: UInt64
    let imageBytes: UInt32
    let entry: UInt32
    let sections: [Section]
    let resourceRVA: UInt32
    let resourceBytes: UInt32
    init(_ path: URL) throws {
        reader = try Reader(path)
        let dos = try reader.read(0, 64)
        guard Array(dos.prefix(2)) == [0x4d, 0x5a] else { throw fail("missing_mz", "Keine DOS/MZ-Signatur.") }
        let ntOffset = UInt64(u32(dos, 60))
        guard ntOffset >= 64, ntOffset <= 16 * 1024 * 1024 else { throw fail("invalid_pe_offset", "Ungültiger PE-Headeroffset.") }
        let coff = try reader.read(ntOffset, 24)
        guard Array(coff.prefix(4)) == [0x50, 0x45, 0, 0] else { throw fail("missing_pe_signature", "Keine PE-Signatur.") }
        guard u16(coff, 4) == 0x8664 else { throw fail("not_amd64", "Das Spielprogramm ist kein Windows-AMD64-PE.") }
        let characteristics = u16(coff, 22)
        guard characteristics & 0x0002 != 0, characteristics & 0x2000 == 0 else {
            throw fail("not_executable_image", "Erwartet wird ein PE-Spielprogramm, keine DLL oder Objektdatei.")
        }
        let count = Int(u16(coff, 6)), optionalBytes = Int(u16(coff, 20))
        guard count > 0, count <= 96, optionalBytes >= 136, optionalBytes <= 4096 else {
            throw fail("invalid_pe_headers", "Ungültige Anzahl oder Größe der PE-Header.")
        }
        let optional = try reader.read(ntOffset + 24, optionalBytes)
        guard u16(optional, 0) == 0x20b else { throw fail("not_pe32_plus", "AMD64 benötigt das PE32+-Format.") }
        entry = u32(optional, 16)
        imageBase = u64(optional, 24)
        imageBytes = u32(optional, 56)
        guard imageBytes > 0, entry > 0, entry < imageBytes else { throw fail("invalid_entry", "EntryPoint liegt nicht im PE-Image.") }
        let headersBytes = u32(optional, 60)
        guard ntOffset + 24 + UInt64(optionalBytes) + UInt64(count * 40) <= UInt64(headersBytes),
              UInt64(headersBytes) <= reader.size, headersBytes <= imageBytes else {
            throw fail("invalid_pe_headers", "PE-Sectionheader überschreiten die deklarierten Headergrenzen.")
        }
        let directories = u32(optional, 108)
        guard directories <= 16, 112 + UInt64(directories) * 8 <= UInt64(optionalBytes) else {
            throw fail("invalid_pe_headers", "PE-Datenverzeichnisse überschreiten den optionalen Header.")
        }
        if directories >= 3 {
            resourceRVA = u32(optional, 128); resourceBytes = u32(optional, 132)
        } else { resourceRVA = 0; resourceBytes = 0 }
        let rawSections = try reader.read(ntOffset + 24 + UInt64(optionalBytes), count * 40)
        var result: [Section] = []
        for index in 0..<count {
            let start = index * 40
            let section = Section(rva: u32(rawSections, start + 12), virtualBytes: u32(rawSections, start + 8),
                                  rawBytes: u32(rawSections, start + 16), rawOffset: u32(rawSections, start + 20),
                                  characteristics: u32(rawSections, start + 36))
            guard UInt64(section.rva) + UInt64(section.virtualBytes) <= UInt64(imageBytes),
                  UInt64(section.rawOffset) + UInt64(section.rawBytes) <= reader.size,
                  section.rawBytes == 0 || section.rawOffset >= headersBytes else {
                throw fail("section_outside_image", "Eine PE-Section liegt außerhalb von Datei oder Image.")
            }
            result.append(section)
        }
        sections = result
        guard result.contains(where: { $0.characteristics & 0x20000000 != 0 && $0.rva <= entry && UInt64(entry) < UInt64($0.rva) + UInt64($0.virtualBytes) }) else {
            throw fail("entry_not_executable", "EntryPoint liegt nicht in einer ausführbaren Section.")
        }
        guard result.contains(where: { $0.characteristics & 0x20000000 != 0 && $0.rva <= entry &&
            UInt64(entry) < UInt64($0.rva) + UInt64($0.virtualBytes) &&
            UInt64(entry) - UInt64($0.rva) < UInt64($0.rawBytes) }) else {
            throw fail("entry_not_file_backed", "EntryPoint besitzt keine ausführbare Dateiabbildung.")
        }
    }
    func fileOffset(_ rva: UInt32, _ count: Int) throws -> UInt64 {
        for section in sections where rva >= section.rva {
            let delta = UInt64(rva - section.rva)
            if delta + UInt64(count) <= UInt64(section.rawBytes) {
                return UInt64(section.rawOffset) + delta
            }
        }
        throw fail("unmapped_resource", "PE-Ressource besitzt keinen vollständigen Dateibereich.")
    }
    func versions() throws -> (String?, String?) {
        guard resourceRVA != 0, resourceBytes >= 16 else { return (nil, nil) }
        func resource(_ offset: UInt32, _ count: Int) throws -> Data {
            guard UInt64(offset) + UInt64(count) <= UInt64(resourceBytes), UInt64(resourceRVA) + UInt64(offset) <= UInt64(UInt32.max) else {
                throw fail("invalid_version_resource", "Versionsressource überschreitet den Ressourcenbereich.")
            }
            return try reader.read(fileOffset(resourceRVA + offset, count), count)
        }
        func child(_ directory: UInt32, id: UInt32?) throws -> UInt32? {
            let head = try resource(directory, 16)
            let count = Int(u16(head, 12)) + Int(u16(head, 14))
            guard count <= 512 else { throw fail("invalid_version_resource", "Zu viele Ressourceneinträge.") }
            guard UInt64(directory) + 16 + UInt64(count * 8) <= UInt64(UInt32.max) else { return nil }
            let entries = try resource(directory + 16, count * 8)
            for index in 0..<count {
                let name = u32(entries, index * 8), target = u32(entries, index * 8 + 4)
                if id == nil || name == id { return target }
            }
            return nil
        }
        guard let type = try child(0, id: 16), type & 0x80000000 != 0,
              let name = try child(type & 0x7fffffff, id: nil), name & 0x80000000 != 0,
              let language = try child(name & 0x7fffffff, id: nil), language & 0x80000000 == 0 else { return (nil, nil) }
        let descriptor = try resource(language, 16)
        let size = Int(u32(descriptor, 4))
        guard size >= 6, size <= 1024 * 1024 else { throw fail("invalid_version_resource", "Ungültige Versionsressourcengröße.") }
        let blob = try reader.read(fileOffset(u32(descriptor, 0), size), size)
        let length = Int(u16(blob, 0)), valueLength = Int(u16(blob, 2))
        guard length <= blob.count, length >= 6 else { throw fail("invalid_version_resource", "Abgeschnittene Versionsstruktur.") }
        var cursor = 6, words: [UInt16] = []
        while cursor + 2 <= length && words.count <= 64 {
            let word = u16(blob, cursor); cursor += 2
            if word == 0 { break }; words.append(word)
        }
        guard String(decoding: words, as: UTF16.self) == "VS_VERSION_INFO" else { return (nil, nil) }
        cursor = (cursor + 3) & ~3
        guard u16(blob, 4) == 0, cursor + valueLength <= length else {
            throw fail("invalid_version_resource", "Die deklarierte binäre Versionsstruktur ist unvollständig.")
        }
        guard valueLength >= 52, cursor + 52 <= length, u32(blob, cursor) == 0xfeef04bd else { return (nil, nil) }
        func version(_ offset: Int) -> String {
            let ms = u32(blob, cursor + offset), ls = u32(blob, cursor + offset + 4)
            return "\(ms >> 16).\(ms & 0xffff).\(ls >> 16).\(ls & 0xffff)"
        }
        return (version(8), version(16))
    }
    func metadata() -> PEMetadata {
        var file: String?, product: String?, diagnostic: String?
        do { (file, product) = try versions() }
        catch let error as DiscoveryFailure { diagnostic = error.code }
        catch { diagnostic = "version_read_failed" }
        return PEMetadata(architecture: "x86_64", format: "PE32+", imageBase: imageBase, imageBytes: imageBytes,
                          entryRVA: entry, sectionCount: sections.count, fileBytes: reader.size,
                          fileVersion: file, productVersion: product, versionDiagnostic: diagnostic)
    }
}

// Same characteristic filenames as the pinned upstream GameSelect.cpp; no registry use.
let characteristicAssets = ["x64a.rpf", "x64b.rpf", "x64g.rpf", "common.rpf", "bink2w64.dll",
                            "x64/audio/audio_rel.rpf", "update/x64/dlcpacks/mpheist3/dlc.rpf",
                            "update/x64/dlcpacks/mptuner/dlc.rpf", "update/x64/dlcpacks/mpsum2/dlc.rpf"]
let knownGamePaths = [
    "drive_c/Program Files/Rockstar Games/Grand Theft Auto V Legacy",
    "drive_c/Program Files/Rockstar Games/Grand Theft Auto V",
    "drive_c/Program Files/Rockstar Games/Grand Theft Auto V Enhanced",
    "drive_c/Program Files (x86)/Steam/steamapps/common/Grand Theft Auto V Legacy",
    "drive_c/Program Files (x86)/Steam/steamapps/common/Grand Theft Auto V",
    "drive_c/Program Files (x86)/Steam/steamapps/common/Grand Theft Auto V Enhanced",
    "drive_c/Program Files/Epic Games/GTAV",
    "drive_c/Program Files/Epic Games/GTAVEnhanced"
]
func inspectGame(_ game: URL, prefix: URL?) -> Candidate {
    var diagnostics: [Finding] = []
    do { try safePath(game, directory: true) }
    catch let error as DiscoveryFailure {
        return Candidate(gamePath: game.path, prefixPath: prefix?.path, edition: "unknown", executablePath: nil,
                         architecture: nil, validInstallation: false, supportedByThisComponent: false,
                         pe: nil, assets: [], diagnostics: [Finding(code: error.code, message: error.message)])
    } catch {
        return Candidate(gamePath: game.path, prefixPath: prefix?.path, edition: "unknown", executablePath: nil,
                         architecture: nil, validInstallation: false, supportedByThisComponent: false,
                         pe: nil, assets: [], diagnostics: [Finding(code: "path_read_failed", message: "Spielpfad kann nicht geprüft werden.")])
    }
    let legacy = game.appendingPathComponent("GTA5.exe"), enhanced = game.appendingPathComponent("GTA5_Enhanced.exe")
    let legacyExists = namedEntryPresent(legacy)
    let enhancedExists = namedEntryPresent(enhanced)
    let edition = legacyExists && enhancedExists ? "ambiguous" : legacyExists ? "legacy" : enhancedExists ? "enhanced" : "unknown"
    let executable: URL? = edition == "legacy" ? legacy : edition == "enhanced" ? enhanced : nil
    var metadata: PEMetadata?
    if let executable {
        do { metadata = try PE(executable).metadata() }
        catch let error as DiscoveryFailure { diagnostics.append(Finding(code: error.code, message: error.message)) }
        catch { diagnostics.append(Finding(code: "pe_read_failed", message: "Spielprogramm kann nicht geprüft werden.")) }
    } else {
        diagnostics.append(Finding(code: edition == "ambiguous" ? "mixed_editions" : "game_executable_missing",
                                   message: edition == "ambiguous" ? "Legacy- und Enhanced-Programme liegen gemeinsam vor; eindeutiger Spielordner erforderlich." : "GTA5.exe beziehungsweise GTA5_Enhanced.exe fehlt."))
    }
    var assets: [Asset] = []
    if executable != nil {
        for relative in characteristicAssets {
            let path = game.appendingPathComponent(relative)
            do {
                let reader = try Reader(path)
                guard reader.size > 0 else { throw fail("empty_asset", "Leere Spieldatei.") }
                if relative.hasSuffix(".rpf") {
                    guard Array(try reader.read(0, 4)) == [0x37, 0x46, 0x50, 0x52] else {
                        throw fail("invalid_rpf7_header", "RPF7-Archivsignatur fehlt.")
                    }
                } else {
                    guard Array(try reader.read(0, 2)) == [0x4d, 0x5a] else { throw fail("invalid_binary_asset", "Binäre Spieldatei besitzt keine MZ-Signatur.") }
                }
                assets.append(Asset(path: relative, valid: true, bytes: reader.size, diagnostic: nil))
            } catch let error as DiscoveryFailure { assets.append(Asset(path: relative, valid: false, bytes: nil, diagnostic: error.code)) }
            catch { assets.append(Asset(path: relative, valid: false, bytes: nil, diagnostic: "asset_read_failed")) }
        }
    }
    let valid = metadata != nil && !assets.isEmpty && assets.allSatisfy(\.valid)
    if !assets.isEmpty && !assets.allSatisfy(\.valid) { diagnostics.append(Finding(code: "legacy_assets_incomplete", message: "Die charakteristischen Spieldateien fehlen oder besitzen ungültige Header.")) }
    if edition == "enhanced" { diagnostics.append(Finding(code: "enhanced_unsupported", message: "Enhanced wird getrennt erkannt, ist in diesem Projekt ungetestet und aktuell nicht unterstützt.")) }
    return Candidate(gamePath: game.path, prefixPath: prefix?.path, edition: edition, executablePath: executable?.path,
                     architecture: metadata?.architecture, validInstallation: valid,
                     supportedByThisComponent: valid && edition == "legacy", pe: metadata, assets: assets, diagnostics: diagnostics)
}

let limitations = ["Erkennung prüft PE- und charakteristische Asset-Header, keine vollständigen Dateihashes oder DRM-/Lizenzberechtigung.",
                   "Kein Spiel, Launcher oder Unterprozess wird gestartet; Profile, Registryhives und Cookies werden nicht gelesen.",
                   "Kein Nachweis für Spielstart, Performance, FiveM-, Anti-Cheat- oder DMG-Kompatibilität.",
                   "Benutzerdefinierte Bibliotheken außerhalb der festen Program-Files-Pfade benötigen --game-dir."]
func emit(_ report: Report, exitCode: Int32) -> Never {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
    encoder.keyEncodingStrategy = .convertToSnakeCase
    do { var data = try encoder.encode(report); data.append(0x0a); FileHandle.standardOutput.write(data) }
    catch { FileHandle.standardError.write(Data("JSON encoding failed\n".utf8)); Darwin.exit(70) }
    Darwin.exit(exitCode)
}
#if arch(arm64)
let hostArchitecture = "arm64"
#else
let hostArchitecture = "unsupported_build_architecture"
#endif
let arguments = Array(CommandLine.arguments.dropFirst())
if arguments == ["--help"] {
    print("Usage: gta-discovery (--prefix /explicit/wine-prefix | --game-dir /explicit/game-directory)\nRead-only JSON output; no profile/registry reads, downloads or game execution.")
    Darwin.exit(0)
}
guard arguments.count == 2, ["--prefix", "--game-dir"].contains(arguments[0]),
      !arguments[1].isEmpty, !arguments[1].hasPrefix("--") else {
    emit(Report(schema: 1, component: "gta-installation-discovery", hostArchitecture: hostArchitecture, readOnly: true,
                inputMode: "invalid", prefixPath: nil, requestedGameDirectory: nil, status: "input_error", foundLegacy: false,
                candidates: [], diagnostics: [Finding(code: "explicit_input_required", message: "Genau --prefix PFAD oder --game-dir PFAD angeben.")], limitations: limitations), exitCode: 64)
}
let mode = arguments[0] == "--prefix" ? "prefix" : "game_directory"
let input = pathURL(arguments[1])
var candidates: [Candidate] = []
if mode == "prefix" {
    do { try safePath(input, directory: true) }
    catch let error as DiscoveryFailure {
        emit(Report(schema: 1, component: "gta-installation-discovery", hostArchitecture: hostArchitecture, readOnly: true,
                    inputMode: mode, prefixPath: input.path, requestedGameDirectory: nil, status: "input_error", foundLegacy: false,
                    candidates: [], diagnostics: [Finding(code: error.code, message: error.message)], limitations: limitations), exitCode: 2)
    } catch { Darwin.exit(70) }
    candidates = knownGamePaths.map { inspectGame(input.appendingPathComponent($0), prefix: input) }
} else { candidates = [inspectGame(input, prefix: nil)] }
let legacyFound = candidates.contains { $0.validInstallation && $0.edition == "legacy" }
let enhancedFound = candidates.contains { $0.validInstallation && $0.edition == "enhanced" }
let status = legacyFound ? "legacy_detected" : enhancedFound ? "enhanced_detected_unsupported" : "not_found_or_invalid"
emit(Report(schema: 1, component: "gta-installation-discovery", hostArchitecture: hostArchitecture, readOnly: true,
            inputMode: mode, prefixPath: mode == "prefix" ? input.path : nil,
            requestedGameDirectory: mode == "game_directory" ? input.path : nil, status: status, foundLegacy: legacyFound,
            candidates: candidates, diagnostics: [], limitations: limitations), exitCode: legacyFound ? 0 : 2)
