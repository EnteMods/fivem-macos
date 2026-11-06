#!/usr/bin/env python3
"""Read-only regression checks for the isolated FiveM investigation."""

import argparse
import datetime
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT.parent / "GTA-V-macOS"


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def isolated_prefix(path, base=BASE, root=ROOT):
    resolved = path.resolve()
    return (resolved.parent == (root / "prefixes").resolve()
            and not path.is_symlink()
            and resolved != (base / "prefixes/rockstar-legacy").resolve())


def verify():
    inventory = json.loads((ROOT / "research/runtime-inventory.json").read_text())
    baseline = json.loads((ROOT / "research/gta-baseline.json").read_text())
    checks = []

    def record(name, passed, detail):
        checks.append({"name": name, "passed": passed, "detail": detail})

    for relative, item in inventory["runtime_verified"].items():
        p = BASE / relative
        record("runtime: " + relative, p.is_file() and digest(p) == item["sha256"],
               "Compared to the runtime measured before the FiveM tests.")

    for relative, item in baseline["files"].items():
        if relative.endswith(("user.reg", "system.reg")):
            continue
        p = BASE / relative
        record("original: " + relative, p.is_file() and digest(p) == item["sha256"],
               "Original GTA executables, command line and runner must remain unchanged.")

    original_game = BASE / "prefixes/rockstar-legacy/drive_c/Program Files/Rockstar Games/Grand Theft Auto V Legacy/GTA5.exe"
    for name in ("fivem-legacy", "fivem-enhanced-probe"):
        prefix = ROOT / "prefixes" / name
        record("separate-prefix: " + name, isolated_prefix(prefix) and prefix.is_dir(),
               "Must be a separate directory inside this investigation.")
        copied_game = prefix / "drive_c/Program Files/Rockstar Games/Grand Theft Auto V Legacy/GTA5.exe"
        record("no-game-hardlink: " + name,
               copied_game.is_file() and not copied_game.samefile(original_game),
               "APFS clones have independent file identities; hardlinks would share writes.")

    for manifest in ("official-installer.json", "official-enhanced-installer.json"):
        item = json.loads((ROOT / "research" / manifest).read_text())
        name = "FiveM.exe" if manifest == "official-installer.json" else "FiveM_Enhanced_Installer.exe"
        p = ROOT / "downloads" / name
        record("download: " + name, p.is_file() and digest(p) == item["sha256"],
               "Local download matches the bytes measured from the official download link; not independent signature validation.")

    source = ROOT / "upstream/fivem"
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
    dirty = subprocess.check_output(["git", "status", "--porcelain"], cwd=source, text=True)
    record("source-revision", revision == inventory["source_revision"], revision)
    record("source-unmodified", not dirty, "No tracked or untracked changes in the upstream checkout.")
    return {"at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "checks": checks, "passed": all(c["passed"] for c in checks),
            "coverage": "File identity, provenance and experiment isolation only.",
            "fivem_end_to_end_verified": False,
            "anti_cheat_compatibility_verified": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = verify()
    if args.output:
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Environment checks: {sum(c['passed'] for c in report['checks'])}/{len(report['checks'])}")
    for check in report["checks"]:
        if not check["passed"]:
            print("FAILED:", check["name"])
    print("FiveM end-to-end and anti-cheat compatibility: NOT VERIFIED.")
    raise SystemExit(0 if report["passed"] else 1)
