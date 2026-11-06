#!/usr/bin/env python3
"""Execute the original Cfx OpenSSL Lua source selector and compare exact pinned file sets."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
import urllib.request

import run as abi

ROOT = abi.ROOT
SOURCE = ROOT / "port/fivem"
BUILD = abi.BUILD / "openssl-selection"
DOWNLOADS = ROOT / "toolchains/downloads"
LUA_PACKAGE = DOWNLOADS / "lua-5.4.9.tar.gz"
LUA_ROOT = ROOT / "toolchains/lua-audit-5.4.9/lua-5.4.9"
LUA_SHA = "2335b6c582a52654f94612bf10d2f4672805d05329aa6568b1d8cd9e5c6fb8e6"
PREMAKE = DOWNLOADS / "premake-audit-beta1"
PREMAKE_COMMIT = "58780d67091b72929ccdf8d5fc79d425c7f6eb23"
PREMAKE_FILES = {
    "src/base/path.lua": "2e83e8f73cf65ce27b5e05872abdcf2dd69d3cfc4f256667947205b42152aac8",
    "src/base/os.lua": "6e639f52743794c49445d38165723b3ed4a6ec27e4fdb3d953a77a5cb26a83c6",
}
RESULT = ROOT / "research/main-openssl-selection-review.json"


def acquire(url, target, expected, size=None):
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.is_file():
        with urllib.request.urlopen(url) as response, target.open("xb") as output:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                output.write(chunk)
    if abi.sha256(target) != expected or (size is not None and target.stat().st_size != size):
        raise SystemExit("Original audit-tool download differs from pinned digest: " + str(target))


def original_lua():
    acquire("https://www.lua.org/ftp/lua-5.4.9.tar.gz", LUA_PACKAGE, LUA_SHA, 373429)
    parent = LUA_ROOT.parent
    with tarfile.open(LUA_PACKAGE) as archive:
        for member in archive.getmembers():
            path = Path(member.name)
            if not path.parts or path.parts[0] != "lua-5.4.9" or path.is_absolute() or ".." in path.parts or not (member.isdir() or member.isfile()):
                raise SystemExit("Unsafe original Lua archive member")
        if not LUA_ROOT.exists():
            parent.mkdir(parents=True, exist_ok=True)
            archive.extractall(parent)
        original_count = 0
        for member in archive.getmembers():
            if member.isfile():
                if (parent / member.name).read_bytes() != archive.extractfile(member).read():
                    raise SystemExit("Local Lua audit source differs from original archive: " + member.name)
                original_count += 1
    executable = LUA_ROOT / "src/lua"
    build_command = ["make", "-C", str(LUA_ROOT / "src"), "-j4", "generic", "CC=/usr/bin/clang"]
    result = subprocess.run(build_command, capture_output=True, text=True, check=True)
    (BUILD / "lua-build.log").write_text(result.stdout + result.stderr)
    identity = abi.command_output(["file", executable]).strip()
    if "Mach-O 64-bit executable arm64" not in identity:
        raise SystemExit("Expected native ARM64 local audit interpreter")
    return {"version": abi.command_output([executable, "-v"]).strip(), "archive_url": "https://www.lua.org/ftp/lua-5.4.9.tar.gz",
            "official_checksum_page": "https://www.lua.org/ftp/", "archive_sha256": LUA_SHA, "archive_bytes": 373429,
            "verified_original_file_count": original_count, "executable": abi.relative(executable),
            "executable_sha256": abi.sha256(executable), "native_identity": identity,
            "build_command": build_command, "build_log": abi.relative(BUILD / "lua-build.log"),
            "license": "MIT; original Lua archive doc/readme.html", "global_installation": False}


def git_tree(repository, revision, paths=()):
    output = abi.command_output(["git", "-C", repository, "ls-tree", "-r", "--full-tree", revision, "--", *paths])
    return {name: info.split()[2] for info, name in (line.split("\t", 1) for line in output.splitlines()) if info.split()[1] == "blob"}


def blob_identity(path, expected):
    data = path.read_bytes()
    actual = hashlib.sha1(("blob %d\0" % len(data)).encode() + data).hexdigest()
    return {"path": str(path.relative_to(SOURCE)), "sha256": hashlib.sha256(data).hexdigest(),
            "expected_git_blob": expected, "actual_git_blob": actual, "matches_pinned_blob": actual == expected}


def main():
    BUILD.mkdir(parents=True, exist_ok=True)
    tools = original_lua()
    for name, digest in PREMAKE_FILES.items():
        acquire("https://raw.githubusercontent.com/premake/premake-core/" + PREMAKE_COMMIT + "/" + name,
                PREMAKE / name, digest)
    lock = json.loads((ROOT / "config/native-port.json").read_text())
    base = lock["base_revision"]
    pin = lock["submodule_pins"]["vendor/openssl"]
    root_blobs = git_tree(SOURCE, base, ("code/vendor", "code/tools/ci/docker-builder/proot_prepare.sh"))
    vendor_blobs = git_tree(SOURCE / "vendor/openssl", pin)
    recipe_names = ("openssl_ext.lua", "openssl_cfg.lua", "openssl_crypto.lua", "openssl_ssl.lua")
    recipe_checks = [blob_identity(SOURCE / "code/vendor" / name, root_blobs["code/vendor/" + name]) for name in recipe_names]
    ci_path = SOURCE / "code/tools/ci/docker-builder/proot_prepare.sh"
    ci_check = blob_identity(ci_path, root_blobs[str(ci_path.relative_to(SOURCE))])
    if "v5.0.0-beta1/premake-5.0.0-beta1-src.zip" not in ci_path.read_text():
        raise SystemExit("Review changed original CI Premake version")
    head = abi.command_output(["git", "-C", SOURCE / "vendor/openssl", "rev-parse", "HEAD"]).strip()
    status = abi.command_output(["git", "-C", SOURCE / "vendor/openssl", "status", "--porcelain", "--untracked-files=no"])
    if head != pin or status or not all(check["matches_pinned_blob"] for check in recipe_checks + [ci_check]):
        raise SystemExit("Original selection inputs are not the pinned unmodified sources")
    crypto = SOURCE / "vendor/openssl/crypto"
    inventory = [{"name": "../vendor/openssl/" + str(path.relative_to(SOURCE / "vendor/openssl")), "file": path.is_file()}
                 for path in sorted(crypto.rglob("*")) if path.is_dir() or path.name == "build.info"]
    inventory += [{"name": "../vendor/openssl/crypto", "file": False},
                  {"name": "../vendor/openssl/build.info", "file": True},
                  {"name": "../vendor/openssl/ssl/build.info", "file": True}]
    manifest = BUILD / "filesystem.lua"
    manifest.write_text("return {\n" + ",\n".join('{name=%s,file=%s}' % (json.dumps(entry["name"]), str(entry["file"]).lower())
                                                                 for entry in inventory) + "\n}\n")
    output = BUILD / "original-lua.tsv"
    command = [str(LUA_ROOT / "src/lua"), str(ROOT / "native/windows-client-tests/audit_selection.lua"), str(manifest), str(PREMAKE), str(output)]
    result = subprocess.run(command, cwd=SOURCE / "code", capture_output=True, text=True)
    (BUILD / "original-lua.log").write_text(result.stdout + result.stderr)
    if result.returncode:
        print(result.stdout + result.stderr)
        raise SystemExit(result.returncode)
    lua_sources = {"crypto": [], "ssl": []}
    descriptors, glob_matches = set(), set()
    for line in output.read_text().splitlines():
        parts = line.split("\t")
        if parts[0] == "source":
            lua_sources[parts[1]].append(str((SOURCE / "code" / parts[2]).resolve().relative_to(SOURCE)))
        elif parts[0] == "descriptor":
            descriptors.add(str((SOURCE / "code" / parts[1]).resolve().relative_to(SOURCE)))
        elif parts[0] == "glob":
            glob_matches.add(str((SOURCE / "code" / parts[2]).resolve().relative_to(SOURCE)))
    python_output = BUILD / "python-selection.cmake"
    python_result = subprocess.run(["python3", str(ROOT / "native/windows-client/openssl_sources.py"), "--source", str(SOURCE),
                                    "--output", str(python_output)], capture_output=True, text=True, check=True)
    (BUILD / "python-selection.log").write_text(python_result.stdout + python_result.stderr)
    translated = json.loads(python_output.with_suffix(".json").read_text())
    comparisons = {}
    selected = set()
    for group in ("crypto", "ssl"):
        native, current = set(lua_sources[group]), set(translated[group + "_sources"])
        comparisons[group] = {"original_lua_count": len(lua_sources[group]), "original_lua_unique_count": len(native),
                              "python_count": len(translated[group + "_sources"]), "exact_set_match": native == current,
                              "missing_from_python": sorted(native - current), "extra_in_python": sorted(current - native),
                              "original_lua_duplicates": len(lua_sources[group]) - len(native),
                              "sorted_set_sha256": hashlib.sha256(("\n".join(sorted(native)) + "\n").encode()).hexdigest(),
                              "sources": sorted(native)}
        selected.update(native | current)
    input_paths = descriptors | selected
    inputs = []
    for relative in sorted(input_paths):
        expected = (vendor_blobs[relative[len("vendor/openssl/"):]] if relative.startswith("vendor/openssl/") else root_blobs[relative])
        inputs.append(blob_identity(SOURCE / relative, expected))
    python_descriptors = {entry["path"] for entry in translated["build_info_inputs"]}
    premake_scope = {"tag": "v5.0.0-beta1", "tag_object": "cf1874552176bb554945ff34f1e8bc55893b64be", "commit": PREMAKE_COMMIT,
                     "selection_reason": "Original source-pinned CI proot_prepare.sh downloads this version; bundled Windows Premake executable was not run",
                     "original_files_sha256": PREMAKE_FILES, "source_url": "https://github.com/premake/premake-core/tree/" + PREMAKE_COMMIT,
                     "original_os_match_and_matchfiles_executed": True, "original_path_getdirectory_executed": True,
                     "glob_root_crypto_build_info_matched": "vendor/openssl/crypto/build.info" in glob_matches,
                     "root_crypto_build_info_separately_read": "vendor/openssl/crypto/build.info" in descriptors,
                     "recursive_glob_match_count": len(glob_matches), "glob_matches": sorted(glob_matches),
                     "bounded_facades": {"os.matchstart_next_name_isfile_done": "Read-only snapshot of actual crypto directories and build.info files; single-component * implemented with Lua pattern; original Premake os.match performs recursive traversal",
                                         "os.isfile_isdir": "Exact membership in actual filesystem snapshot; no source descriptor/parser emulation",
                                         "path.normalize_join": "Forward slash path joining for actual current relative inputs; no general Premake path API claim",
                                         "string.findlast_table.join": "Standard helper behavior used by original path.getdirectory/os.match",
                                         "includedirs_defines_filter": "No-op collectors: source emission is unconditional in original Windows/five calls"}}
    passed = all(value["exact_set_match"] and not value["original_lua_duplicates"] for value in comparisons.values()) and all(
        item["matches_pinned_blob"] for item in inputs) and descriptors == python_descriptors and not (
        premake_scope["glob_root_crypto_build_info_matched"]) and premake_scope["root_crypto_build_info_separately_read"]
    record = {"at": datetime.now(timezone.utc).isoformat(), "passed": passed,
              "scope": "Exact pinned Windows/five OpenSSL file selection; original Lua generator execution versus Python translator, no build/client/Wine execution",
              "base_revision": base, "openssl_gitlink": pin, "openssl_head": head, "openssl_tracked_tree_unmodified": not bool(status),
              "lua_tool": tools, "premake_glob": premake_scope, "original_recipes": recipe_checks, "original_ci_recipe": ci_check,
              "python_translator_sha256": abi.sha256(ROOT / "native/windows-client/openssl_sources.py"),
              "audit_sources_sha256": {abi.relative(path): abi.sha256(path) for path in
                                       (Path(__file__).resolve(), ROOT / "native/windows-client-tests/audit_selection.lua")},
              "comparisons": comparisons, "original_descriptor_count": len(descriptors), "descriptor_sets_match": descriptors == python_descriptors,
              "descriptor_missing_from_python": sorted(descriptors - python_descriptors), "descriptor_extra_in_python": sorted(python_descriptors - descriptors),
              "crypto_asm_count": sum(path.endswith(".asm") for path in lua_sources["crypto"]), "pinned_input_blobs": inputs,
              "commands": {"original_lua": command, "original_lua_cwd": abi.relative(SOURCE / "code")},
              "artifacts": {"original_lua_output": abi.relative(output), "original_lua_log": abi.relative(BUILD / "original-lua.log"),
                            "python_output": abi.relative(python_output), "filesystem_snapshot_sha256": abi.sha256(manifest)},
              "wine_executed": False, "client_or_auth_executed": False, "global_lua_installation": False}
    RESULT.write_text(json.dumps(record, indent=2) + "\n")
    print(result.stdout.strip())
    print("Exact file-set comparison:", passed, "ASM:", record["crypto_asm_count"], "descriptors:", len(descriptors))
    if not passed:
        print(json.dumps({key: {field: value for field, value in comparison.items() if field != "sources"}
                          for key, comparison in comparisons.items()}, indent=2))
        raise SystemExit(1)


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
    main()
