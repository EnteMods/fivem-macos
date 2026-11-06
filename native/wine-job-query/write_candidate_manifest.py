#!/usr/bin/env python3
"""Bind completed isolated build/code data; never execute Wine or create a prefix."""
import datetime
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

from common import PROJECT, WORK, PINS, owned_path
BUILD = WORK / "full-x86_64"


def sha(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def identity(path):
    return {"path": str(path.relative_to(PROJECT)), "bytes": path.stat().st_size,
            "sha256": sha(path)}


def main():
    owned_path(BUILD)
    owned_path(WORK / "candidate-manifest.json")
    records = {}
    for key, name in [("source_preparation_record", "source-preparation.json"),
                      ("configure_record", "wine-moltenvk-configure-results.json"),
                      ("build_record", "wine-moltenvk-all-results.json"),
                      ("dependency_record", "moltenvk-build-dependency.json")]:
        path = WORK / name
        records[key] = identity(path)
    built = json.loads((PROJECT / records["build_record"]["path"]).read_text())
    configured = json.loads((PROJECT / records["configure_record"]["path"]).read_text())
    if not built["passed"] or not configured["passed"] or built["timeout"]:
        raise RuntimeError("A complete successful configure/build is mandatory")
    for artifact in built["artifacts"]:
        if sha(PROJECT / artifact["path"]) != artifact["sha256"]:
            raise RuntimeError("Completed build artifact identity changed")
    preparation = json.loads((WORK / "source-preparation.json").read_text())
    for name, expected in preparation["generated_after_sha256"].items():
        if sha(WORK / "source" / name) != expected:
            raise RuntimeError("Generated source protocol changed after build")
    proposal = {"files": PINS["query_patch"]["source_files"]}
    query_sources = []
    for item in proposal["files"]:
        path = WORK / "source" / item["path"]
        if sha(path) != item["proposed_sha256"]:
            raise RuntimeError("Reviewed query source changed after build")
        query_sources.append(identity(path))
    config = (BUILD / "include/config.h").read_text()
    if '#define SONAME_LIBVULKAN "libMoltenVK.dylib"' not in config:
        raise RuntimeError("Real Vulkan dependency configure result missing")
    dependency = json.loads((WORK / "moltenvk-build-dependency.json").read_text())
    original = WORK / dependency["path"]
    if sha(original) != dependency["sha256"]:
        raise RuntimeError("Pinned code dependency identity changed")
    # Original macOS pre_exec searches this own build directory automatically.
    placed = BUILD / "dlls/win32u/libMoltenVK.dylib"
    owned_path(placed)
    if placed.exists() and sha(placed) != dependency["sha256"]:
        raise RuntimeError("Refusing to replace different candidate dependency")
    if not placed.exists():
        shutil.copyfile(original, placed)
        placed.chmod(0o755)
    if sha(placed) != dependency["sha256"]:
        raise RuntimeError("Candidate dependency copy identity mismatch")
    roots = [BUILD / name for name in ["dlls", "programs", "loader", "server", "nls"]]
    paths = [p for root in roots if root.exists() for p in root.rglob("*")]
    paths += [BUILD / "tools/wine/wine", BUILD / "wine"]
    runtime = []
    magic = [b"MZ", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe"]
    for path in sorted(set(paths)):
        if path.suffix in [".o", ".a", ".res"]:
            continue
        if not path.is_file():
            continue
        resolved = path.resolve()
        if WORK not in resolved.parents:
            raise RuntimeError("Unexpected external runtime file target: " + str(path))
        with path.open("rb") as stream:
            header = stream.read(4)
        code = any(header.startswith(value) for value in magic)
        data = path.suffix == ".nls" or path == BUILD / "loader/wine.inf"
        if not code and not data:
            continue
        item = identity(path)
        item["kind"] = "code" if code else "data"
        if path.is_symlink():
            item["symlink_target"] = str(path.readlink())
            item["resolved_path"] = str(resolved.relative_to(PROJECT))
        runtime.append(item)
    named = {}
    for key, name in [("loader", "loader/wine"), ("server", "server/wineserver"),
                      ("ntdll_unix", "dlls/ntdll/ntdll.so")]:
        path = BUILD / name
        named[key] = identity(path)
        description = subprocess.run(["/usr/bin/file", "-b", str(path)],
                                     capture_output=True, text=True, check=True).stdout.strip()
        if "Mach-O" not in description or "x86_64" not in description:
            raise RuntimeError("Unexpected core runtime architecture")
        named[key]["file_description"] = description
    manifest = {
        "schema_version": 1,
        "at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "build_passed": True, "runtime_tested": False,
        "build_dir": str(BUILD.relative_to(PROJECT)), "protocol_version": 1810,
        **named, **records,
        "runtime_files": runtime, "runtime_file_count": len(runtime),
        "reviewed_query_sources": query_sources,
        "external_code_dependencies": [{**identity(placed),
            "original_snapshot": identity(original),
            "original_archive_sha256": dependency["archive_sha256"],
            "reason": "Real configure dependency; own win32u path is included by original macOS pre_exec",
            "renderer_tested": False}],
        "feature_limits": ["No GnuTLS/TLS support", "No FreeType support", "No GStreamer/SDL support",
                           "No OpenGL support", "No DXMT/D3DMetal integration or graphics parity claim",
                           "No runtime behavior, client, account, game or anti-cheat success established"],
        "intended_prefix": "prefixes/wine-job-query-regression-rebuild",
        "active_runtime_modified": False, "prefixes_accessed": False,
        "runtime_environment": {
            "WINEPREFIX": "absolute independently guarded fresh prefixes/wine-job-query-regression-rebuild",
            "WINESERVER": "absolute " + named["server"]["path"],
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "caller_DYLD_LIBRARY_PATH": "unset; original pre_exec adds own ntdll/win32u paths including the pinned dependency copy",
            "WINEDLLPATH": "unset", "WINEDLLPATH_PREPEND": "unset",
            "old_loader_socket_overrides_and_renderer_paths": "absent",
            "HOME_and_USER": "leave unchanged"},
    }
    target = WORK / "candidate-manifest.json"
    if target.exists():
        raise RuntimeError("Refusing to overwrite an issued candidate manifest")
    target.write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"manifest": str(target.relative_to(PROJECT)),
                      "sha256": sha(target), "runtime_file_count": len(runtime),
                      "build_passed": True, "runtime_tested": False}, indent=2))


if __name__ == "__main__":
    main()
