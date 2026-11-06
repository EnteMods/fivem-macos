#!/usr/bin/env python3
"""Stage only explicitly named original/rebuilt PE DLLs, never account/profile data."""
import datetime
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[2]
STAGE = ROOT / "build/windows-nui-runtime"
REVISION = "9f0e34e1cbdfc34fd05079416791f01938279097"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def plain(path):
    current = ROOT
    for part in path.relative_to(ROOT).parts:
        current /= part
        if current.is_symlink():
            raise SystemExit("Refusing redirected runtime code path: " + str(current))


def machine(path):
    with path.open("rb") as binary:
        header = binary.read(64)
        if len(header) != 64 or header[:2] != b"MZ":
            raise SystemExit("Expected original PE binary: " + str(path))
        binary.seek(struct.unpack_from("<I", header, 60)[0])
        signature = binary.read(6)
        if signature[:4] != b"PE\0\0" or signature[4:] != b"\x64\x86":
            raise SystemExit("Expected Windows AMD64 PE binary: " + str(path))


def main():
    plain(STAGE)
    STAGE.mkdir(parents=True, exist_ok=True)
    artifacts = json.loads((ROOT / "build/windows-nui/nui-artifacts.json").read_text())
    build_record = json.loads((ROOT / "research/nui-build-results.json").read_text())
    if not build_record.get("passed") or build_record.get("stage") != "full-public-nui-dll-link":
        raise SystemExit("Require a successful actual full NUI build")
    selections = []
    for key, name in (("nui", "nui-core.dll"), ("net", "net-base.dll"), ("vfs", "vfs-core.dll"),
                      ("botan", "botan.dll"), ("core", "CoreRT.dll"), ("tbb", "tbb12.dll")):
        source = Path(artifacts[key])
        if sha(source) != build_record["sha256"][key]:
            raise SystemExit("Rebuilt DLL changed since full-link evidence: " + str(source))
        selections.append((source, name, "actual-public-source-build"))
    legitimacy = ROOT / "port/fivem/code/components/legitimacy/release/legitimacy.dll"
    expected_blob = subprocess.run(["git", "-C", str(ROOT / "port/fivem"), "rev-parse",
                                    REVISION + ":code/components/legitimacy/release/legitimacy.dll"],
                                   capture_output=True, text=True, check=True).stdout.strip()
    actual_blob = subprocess.run(["git", "hash-object", str(legitimacy)], capture_output=True, text=True, check=True).stdout.strip()
    if actual_blob != expected_blob:
        raise SystemExit("Original pinned legitimacy DLL bytes differ from source revision")
    selections.append((legitimacy, "legitimacy.dll", "original-source-tracked-vendor-dll"))
    official_code = ROOT / "prefixes/fivem-legacy/drive_c/FiveM/FiveM.app"
    for name in ("libuv.dll", "cfx_curl_x86_64.dll", "net-http-server.dll", "net-tcp-server.dll", "mojo.dll", "steam_api64.dll"):
        selections.append((official_code / name, name, "unchanged-official-updater-code-from-historical-prefix"))
    cef = ROOT / "build/cef-api-probe/bin"
    cef_record = json.loads((ROOT / "build/cef-api-probe/runtime-files.json").read_text())
    # The separate CEF API test owns original-archive acquisition verification.
    # Copy direct PE DLLs only; no profile, resource cache or session directory.
    for item in cef_record:
        source = ROOT / item["path"]
        if source.parent != cef or source.suffix.lower() != ".dll" or sha(source) != item["sha256"]:
            raise SystemExit("CEF API runtime bytes changed since original-archive evidence")
        selections.append((source, "bin/" + source.name, "original-official-cef-api-probe-runtime"))
    records = []
    for source, destination_name, origin in selections:
        plain(source)
        machine(source)
        destination = STAGE / destination_name
        plain(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        source_hash = sha(source)
        shutil.copy2(source, destination)
        if sha(destination) != source_hash:
            raise SystemExit("Runtime code copy verification failed")
        records.append({"name": destination_name, "source": str(source.relative_to(ROOT)),
                        "origin": origin, "bytes": destination.stat().st_size, "sha256": source_hash})
    inventory = subprocess.run(["/opt/homebrew/opt/llvm/bin/llvm-readobj", "--coff-imports", "--coff-exports",
                                *[str(STAGE / item["name"]) for item in records]], capture_output=True, text=True, check=True)
    (STAGE / "runtime-pe-inventory.txt").write_text(inventory.stdout)
    record = {"at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "source_revision": REVISION, "stage": str(STAGE.relative_to(ROOT)), "files": records,
              "copied_account_profile_cookies_sessions_tokens": False, "executed": False,
              "historical_prefix_used_for_execution": False,
              "official_cached_code_origin_evidence": "research/official-installer.json; docs/phase2-experiments.md",
              "cef_runtime_source_evidence": "build/cef-api-probe/runtime-files.json",
              "cef_runtime_source_metadata": cef_record,
              "limit": "PE symbol coverage and recorded file hashes do not establish complete runtime or anti-cheat compatibility"}
    (ROOT / "research/nui-runtime-stage.json").write_text(json.dumps(record, indent=2) + "\n")
    print("Staged", len(records), "AMD64 DLL code files; no account/profile data copied and no DLL executed")


if __name__ == "__main__":
    main()
