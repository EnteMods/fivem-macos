#!/usr/bin/env python3
"""Fetch the exact source-pinned official CEF package and extract build inputs only."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import urllib.parse
import zipfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "port/fivem"
REVISION = "9f0e34e1cbdfc34fd05079416791f01938279097"


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def ensure_plain_path(path):
    current = ROOT
    for part in path.relative_to(ROOT).parts:
        current /= part
        if current.is_symlink():
            raise SystemExit("Refusing a symlink in the isolated CEF path: " + str(current))


def extract_build_inputs(archive, destination, build_name, cached_hashes):
    inventory, selected, seen = [], [], set()
    with zipfile.ZipFile(archive) as package:
        for entry in package.infolist():
            name = entry.filename
            path = PurePosixPath(name)
            mode = entry.external_attr >> 16
            if ("\\" in name or ":" in name or path.is_absolute() or ".." in path.parts
                    or str(path) != name.rstrip("/")
                    or not path.parts or path.parts[0] != build_name or stat.S_ISLNK(mode)):
                raise SystemExit("Refusing unsafe CEF archive entry: " + name)
            key = name.rstrip("/").casefold()
            if key in seen:
                raise SystemExit("Refusing duplicate CEF archive entry: " + name)
            seen.add(key)
            relative = PurePosixPath(*path.parts[1:])
            inventory.append({"name": str(relative), "bytes": entry.file_size,
                              "compressed_bytes": entry.compress_size, "directory": entry.is_dir()})
            if entry.is_dir() or not relative.parts:
                continue
            allowed = (relative.parts[0] in ("include", "libcef_dll", "cmake")
                       or (relative.parts[0] in ("Release", "Debug") and relative.suffix.lower() == ".lib")
                       or (len(relative.parts) == 1 and (relative.suffix.lower() in (".txt", ".md")
                                                        or relative.name == "CMakeLists.txt")))
            if not allowed:
                continue
            target = destination.joinpath(*relative.parts)
            ensure_plain_path(target)
            if not target.resolve().is_relative_to(destination.resolve()):
                raise SystemExit("Refusing redirected extraction target")
            target.parent.mkdir(parents=True, exist_ok=True)
            if not (target.is_file() and sha(target) == cached_hashes.get(str(relative))):
                with package.open(entry) as source, target.open("wb") as output:
                    shutil.copyfileobj(source, output)
            selected.append({"name": str(relative), "bytes": target.stat().st_size, "sha256": sha(target)})
    return inventory, selected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true", help="Require the previously downloaded package")
    options = parser.parse_args()
    head = subprocess.run(["git", "-C", str(SOURCE), "rev-parse", "HEAD"],
                          capture_output=True, text=True, check=True).stdout.strip()
    if head != REVISION:
        raise SystemExit("Source HEAD changed; review the CEF package pin before writing files")
    pin_hashes = {}
    for relative in ("vendor/cef/cef_build_name.txt", "code/tools/ci/psm1/cfxSetupCEF.psm1"):
        expected = subprocess.run(["git", "-C", str(SOURCE), "show", REVISION + ":" + relative],
                                  capture_output=True, check=True).stdout
        if (SOURCE / relative).read_bytes() != expected:
            raise SystemExit("CEF acquisition source differs from the pinned revision: " + relative)
        pin_hashes[relative] = hashlib.sha256(expected).hexdigest()
    build_name = (SOURCE / "vendor/cef/cef_build_name.txt").read_text().strip()
    if not re.fullmatch(r"cef_binary_[A-Za-z0-9_.+-]+_windows64_minimal", build_name):
        raise SystemExit("Unexpected CEF package name in source pin")
    expected_source = 'https://content.cfx.re/mirrors/vendor/cef/v144/$CefBuildName.zip'
    setup_script = SOURCE / "code/tools/ci/psm1/cfxSetupCEF.psm1"
    if expected_source not in setup_script.read_text():
        raise SystemExit("Official package URL layout changed; review upstream setup script")
    url = "https://content.cfx.re/mirrors/vendor/cef/v144/" + urllib.parse.quote(build_name, safe="") + ".zip"
    lock = json.loads((ROOT / "config/cef-package.json").read_text())
    if (lock["source_revision"] != REVISION or lock["build_name"] != build_name
            or lock["requested_url"] != url or lock["verified_source_pin_sha256"] != pin_hashes):
        raise SystemExit("CEF source/package selection differs from reviewed config/cef-package.json")

    def verify_archive(path):
        digest = sha(path)
        if path.stat().st_size != lock["archive_bytes"] or digest != lock["archive_sha256"]:
            raise SystemExit("CEF archive bytes differ from reviewed config/cef-package.json; refusing extraction and evidence replacement")
        return digest

    downloads = ROOT / "downloads/cef"
    ensure_plain_path(downloads)
    downloads.mkdir(parents=True, exist_ok=True)
    archive = downloads / (build_name + ".zip")
    metadata = downloads / "transport.json"
    ensure_plain_path(archive)
    ensure_plain_path(metadata)
    if not archive.is_file():
        if options.offline:
            raise SystemExit("CEF archive is not cached")
        temporary = archive.with_suffix(".zip.part")
        ensure_plain_path(temporary)
        ensure_plain_path(downloads / "headers.txt")
        command = ["curl", "--proto", "=https", "--proto-redir", "=https", "--tlsv1.2", "--fail",
                   "--location", "--silent", "--show-error", "--dump-header", str(downloads / "headers.txt"),
                   "--output", str(temporary), "--write-out", "%{url_effective}\n%{http_code}\n", url]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        effective_url, status = result.stdout.strip().splitlines()[-2:]
        if urllib.parse.urlparse(effective_url).scheme != "https" or status != "200":
            raise SystemExit("Unexpected CEF download transport result")
        verify_archive(temporary)
        temporary.replace(archive)
        metadata.write_text(json.dumps({"requested_url": url, "effective_url": effective_url,
                                       "http_status": int(status), "command": command}, indent=2) + "\n")

    archive_hash = verify_archive(archive)
    destination = ROOT / "toolchains/cef" / build_name
    ensure_plain_path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    previous_path = ROOT / "research/cef-package.json"
    previous = json.loads(previous_path.read_text()) if previous_path.is_file() else {}
    cached_hashes = {item["name"]: item["sha256"] for item in previous.get("selected_files", [])}
    cache_matches = previous.get("archive_sha256") == archive_hash
    inventory, selected = extract_build_inputs(archive, destination, build_name, cached_hashes if cache_matches else {})
    (downloads / "inventory.json").write_text(json.dumps(inventory, indent=2) + "\n")
    version_header = (destination / "include/cef_version.h").read_text()
    declared_version = re.search(r'^#define CEF_VERSION "([^"]+)"', version_header, re.MULTILINE).group(1)
    declared_commit = re.search(r'^#define CEF_COMMIT_HASH "([^"]+)"', version_header, re.MULTILINE).group(1)
    api_versions = (destination / "include/cef_api_versions.h").read_text()
    windows_experimental_hash = re.search(r'#define CEF_API_VERSION_999999 999999\s+#if defined\(OS_WIN\)\s+#define CEF_API_HASH_999999 "([^"]+)"', api_versions).group(1)
    record = {
        "at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "source_revision": REVISION,
        "verified_source_head": head, "verified_source_pin_sha256": pin_hashes,
        "build_name": build_name, "official_setup_script": str(setup_script.relative_to(ROOT)),
        "requested_url": url, "transport": json.loads(metadata.read_text()) if metadata.is_file() else None,
        "archive": str(archive.relative_to(ROOT)), "archive_bytes": archive.stat().st_size,
        "archive_sha256": archive_hash, "archive_entries": len(inventory),
        "extracted_directory": str(destination.relative_to(ROOT)), "selected_files": selected,
        "selected_bytes": sum(item["bytes"] for item in selected),
        "extraction_scope": "CEF headers, wrapper source, CMake files, original import libraries, root documentation/licenses only",
        "runtime_dlls_extracted": False, "executed": False,
        "header_cef_version": declared_version, "header_cef_commit": declared_commit,
        "header_default_api_version": 999999, "header_windows_experimental_api_hash": windows_experimental_hash,
        "package_name_matches_header_version": build_name == "cef_binary_" + declared_version + "_windows64_minimal",
        "integrity_limit": "SHA256 records acquired bytes; upstream setup script provides no independently signed SHA256 pin",
    }
    output = ROOT / "research/cef-package.json"
    output.write_text(json.dumps(record, indent=2) + "\n")
    print("CEF archive:", record["archive_bytes"], "bytes; SHA256", record["archive_sha256"])
    print("Selected", len(selected), "build input files;", record["selected_bytes"], "bytes; no runtime DLL extraction or execution")
    print("Evidence:", output)


if __name__ == "__main__":
    main()
