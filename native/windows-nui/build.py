#!/usr/bin/env python3
"""Build the full public NUI graph without loading any runtime DLL or account."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "port/fivem"
BUILD = ROOT / "build/windows-nui"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--objects-only", action="store_true", help="Compile every full component source/resource without claiming a DLL link")
    options = parser.parse_args()
    subprocess.run([sys.executable, str(ROOT / "native/windows-nui/prepare_cef.py"), "--offline"], cwd=ROOT, check=True)
    configure = ["cmake", "-S", str(ROOT / "native/windows-nui"), "-B", str(BUILD), "-G", "Ninja",
                 "-DCMAKE_TOOLCHAIN_FILE=" + str(ROOT / "native/windows-core/toolchain.cmake"),
                 "-DCMAKE_POLICY_VERSION_MINIMUM=3.5", "-DCMAKE_BUILD_TYPE=RelWithDebInfo"]
    with (ROOT / "logs/nui-configure.log").open("w") as output:
        subprocess.run(configure, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT, check=True)
    object_targets = []
    if options.objects_only:
        inventory = subprocess.run(["ninja", "-C", str(BUILD), "-t", "targets", "all"], capture_output=True, text=True, check=True)
        for line in inventory.stdout.splitlines():
            target, kind = line.rsplit(": ", 1)
            if target.startswith(("CMakeFiles/NuiCore.dir/", "CMakeFiles/NuiNetBase.dir/", "CMakeFiles/NuiVfsCore.dir/")) and target.endswith((".obj", ".res")):
                object_targets.append(target)
        if len(object_targets) != 52:
            raise SystemExit("Full component source selection changed; review expected source/resource count")
        (BUILD / "full-component-object-targets.json").write_text(json.dumps(object_targets, indent=2) + "\n")
        command = ["ninja", "-C", str(BUILD), "-j6", "-k0", *object_targets]
        log = ROOT / "logs/nui-components-objects.log"
    else:
        command = ["cmake", "--build", str(BUILD), "--target", "NuiCore", "--parallel", "6"]
        log = ROOT / "logs/nui-build.log"
    with log.open("w") as output:
        result = subprocess.run(command, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT)
    record = {
        "at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source_revision": subprocess.run(["git", "-C", str(SOURCE), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip(),
        "worktree_diff_sha256": hashlib.sha256(subprocess.run(["git", "-C", str(SOURCE), "diff", "HEAD"], capture_output=True, check=True).stdout).hexdigest(),
        "stage": "full-component-object-compile" if options.objects_only else "full-public-nui-dll-link",
        "objects": len(object_targets) if options.objects_only else None,
        "exit": result.returncode, "passed": result.returncode == 0,
        "runtime_dlls_loaded": False, "client_gui_auth_game_anticheat_tested": False,
        "log": str(log.relative_to(ROOT)), "command": command,
    }
    if not options.objects_only and result.returncode == 0:
        artifacts = {name: Path(path) for name, path in json.loads((BUILD / "nui-artifacts.json").read_text()).items()}
        record["sha256"] = {name: sha(path) for name, path in artifacts.items()}
        inventory = subprocess.run(["/opt/homebrew/opt/llvm/bin/llvm-readobj", "--file-headers", "--coff-imports", "--coff-exports",
                                    *[str(artifacts[name]) for name in ("nui", "net", "vfs", "botan")]], capture_output=True, text=True, check=True)
        (BUILD / "nui-pe-inventory.txt").write_text(inventory.stdout)
    suffix = "objects" if options.objects_only else "build"
    (ROOT / "research" / ("nui-" + suffix + "-results.json")).write_text(json.dumps(record, indent=2) + "\n")
    print(record["stage"], "PASS" if record["passed"] else "FAIL", "exit", result.returncode)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
