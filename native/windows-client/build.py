#!/usr/bin/env python3
"""Build actual public GameProcess and MAIN entrypoints; never launch a client or game."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from inspect_game import PE

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "port/fivem"
BUILD = ROOT / "build/windows-client"
REVISION = "9f0e34e1cbdfc34fd05079416791f01938279097"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def record_main():
    binary = BUILD / "FiveM.exe"
    pe = PE(binary)
    certificate_offset, certificate_bytes = pe.directory(4)
    inventory = subprocess.run(["/opt/homebrew/opt/llvm/bin/llvm-readobj", "--file-headers", "--coff-imports", "--coff-exports", str(binary)],
                               capture_output=True, text=True, check=True)
    (BUILD / "main-pe-inventory.txt").write_text(inventory.stdout)
    record = {
        "at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "source_revision": REVISION,
        "source_diff_sha256": hashlib.sha256(subprocess.run(["git", "-C", str(SOURCE), "diff", "HEAD"], capture_output=True, check=True).stdout).hexdigest(),
        "full_main_compile_and_link_passed": True, "updater_auth_tls_hash_logic_disabled": False,
        "entrypoint": "actual upstream MAIN WinMain, complete30C++ units plus original resource",
        "crt": "/MT", "language": "MAIN C++20 for actual SDK C++/WinRT; vendor C/C++17",
        "path": str(binary.relative_to(ROOT)), "sha256": sha(binary), "file_bytes": len(pe.data),
        "image_bytes": pe.image_size, "entry_rva": pe.entry, "stack_bytes": pe.stack,
        "certificate_directory_bytes": certificate_bytes,
        "private_publisher_signing_applied": False, "formaldev_updater_skip_marker_created": False,
        "executed": False, "gui_auth_game_or_anticheat_proven": False,
        "source_scope": "build/windows-client/main-source-scope.txt", "build_log": "logs/client-main-build.log",
        "limit": "A complete unsigned source build is not an official publisher identity or proof that integrity/update policy will accept modified components",
    }
    (ROOT / "research/client-main-build-results.json").write_text(json.dumps(record, indent=2) + "\n")
    print("Actual full MAIN executable built and recorded; no execution")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("game", "main", "all", "inspect"))
    action = parser.parse_args().action
    head = subprocess.run(["git", "-C", str(SOURCE), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    if head != REVISION:
        raise SystemExit("Review public entrypoint source selections after changing source revision")
    if action != "inspect":
        configure = ["cmake", "-S", str(ROOT / "native/windows-client"), "-B", str(BUILD), "-G", "Ninja",
                     "-DCMAKE_TOOLCHAIN_FILE=" + str(ROOT / "native/windows-core/toolchain.cmake"),
                     "-DCMAKE_POLICY_VERSION_MINIMUM=3.5", "-DCMAKE_BUILD_TYPE=RelWithDebInfo",
                     "-DCFX_BUILD_MAIN_UPDATER=" + ("ON" if action in ("main", "all") else "OFF")]
        with (ROOT / "logs/client-configure.log").open("w") as output:
            subprocess.run(configure, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT, check=True)
        targets = []
        if action in ("game", "all"): targets += ["CitiLaunch_game_3889", "CitiLaunch_TLSDummy", "retarget_pe"]
        if action in ("main", "all"): targets += ["CitiLaunch_main"]
        log = ROOT / "logs" / ("client-main-build.log" if action == "main" else "client-" + action + "-build.log")
        with log.open("w") as output:
            subprocess.run(["cmake", "--build", str(BUILD), "--target", *targets, "--parallel", "6"],
                           cwd=ROOT, stdout=output, stderr=subprocess.STDOUT, check=True)
    if action in ("game", "all", "inspect"):
        subprocess.run([sys.executable, str(ROOT / "native/windows-client/inspect_game.py")], check=True)
    if action in ("main", "all", "inspect"):
        record_main()


if __name__ == "__main__":
    main()
