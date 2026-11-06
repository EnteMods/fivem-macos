#!/usr/bin/env python3
"""Build and run account-free Win64/Wine CoreRT regression probes."""

import argparse
import datetime
import getpass
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
from probe_environment import PERSONAL_FOLDERS, assert_account_free_prefix, probe_prefix

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "port/fivem"
BUILD = ROOT / "build/windows-regression"
PREFIX = ROOT / "prefixes/corert-regression"


def run(args, **kwargs):
    subprocess.run(list(map(str, args)), check=True, **kwargs)


def build():
    for tool in ("clang", "x86_64-w64-mingw32-gcc", "x86_64-w64-mingw32-g++"):
        if not shutil.which(tool):
            raise SystemExit("Missing required developer tool: " + tool)
    BUILD.mkdir(parents=True, exist_ok=True)
    hook = SOURCE / "vendor/minhook"
    objects = []
    for source in ("buffer.c", "hook.c", "trampoline.c", "hde/hde64.c"):
        target = BUILD / (Path(source).stem + ".o")
        run(["x86_64-w64-mingw32-gcc", "-O2", "-I" + str(hook / "include"),
             "-c", hook / "src" / source, "-o", target])
        objects.append(target)
    sysroot = subprocess.check_output(["x86_64-w64-mingw32-gcc", "-print-sysroot"], text=True).strip()
    seh_object = BUILD / "handled_seh.o"
    run(["clang", "--target=x86_64-w64-windows-gnu", "-fms-extensions", "-O1", "-g",
         "-isystem", Path(sysroot) / "x86_64-w64-mingw32/include", "-c",
         ROOT / "native/windows-tests/handled_seh.c", "-o", seh_object])
    run(["x86_64-w64-mingw32-g++", "-std=c++17", "-O2", "-g", "-static",
         "-I" + str(hook / "include"), "-I" + str(SOURCE / "code/client/citicore"),
         ROOT / "native/windows-tests/corert_regression.cpp", *objects, seh_object,
         "-o", BUILD / "corert-regression.exe"])


def test():
    if not (BUILD / "corert-regression.exe").is_file():
        raise SystemExit("Build the regression probe first.")
    with probe_prefix(PREFIX, root=ROOT, create=True):
        _test_locked()


def _test_locked():
    for directory in PERSONAL_FOLDERS:
        folder = PREFIX / "drive_c/users" / getpass.getuser() / directory
        folder.mkdir(parents=True, exist_ok=True)
    assert_account_free_prefix(PREFIX, root=ROOT)
    original = ROOT.parent / "GTA-V-macOS"
    spec = importlib.util.spec_from_file_location("existing_gta_environment", original / "scripts/gta-macos.py")
    runtime = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runtime)
    if PREFIX.resolve() == runtime.PREFIX.resolve():
        raise SystemExit("Refusing the productive GTA prefix.")
    env = runtime.environment()
    env["WINEPREFIX"] = str(PREFIX)
    logs = ROOT / "logs"
    logs.mkdir(exist_ok=True)
    results = []

    def wine(label, args, expected=0, markers=()):
        assert_account_free_prefix(PREFIX, root=ROOT)
        log = logs / ("corert-probe-" + label + ".log")
        print("Running", label, flush=True)
        with log.open("w") as output:
            p = subprocess.run([str(runtime.WINE), *map(str, args)], cwd=ROOT, env=env,
                               stdout=output, stderr=subprocess.STDOUT, timeout=120)
        assert_account_free_prefix(PREFIX, root=ROOT)
        output = log.read_text(errors="replace")
        passed = p.returncode == expected and all(marker in output for marker in markers)
        results.append({"case": label, "exit": p.returncode, "expected": expected,
                        "passed": passed, "log": str(log.relative_to(ROOT))})
        print(label, "PASS" if passed else "FAIL", "exit", p.returncode, flush=True)
        if not passed:
            raise RuntimeError(output[-5000:])

    try:
        if not (PREFIX / "system.reg").exists():
            wine("initialize", ["wineboot.exe", "-i"])
        wine("configure-win10", ["winecfg.exe", "-v", "win10"])
        executable = BUILD / "corert-regression.exe"
        wine("before-final", [executable, "--before"], 86,
             ("BEFORE_FAULT code=0xc0000005 access=1",))
        wine("after-final", [executable], 0,
             ("PASS: real captured frame unwinds identically", "PASS: handled SEH",
              "PASS: mapped-image lookup, outside delegation, exclusive boundary and cleanup"))
        wine("unhandled-final", [executable, "--unhandled"], 92,
             ("PASS: handled SEH", "UNHANDLED_REPORT code=0xe0425678"))
    finally:
        subprocess.run([str(runtime.ENGINE / "bin/wineserver"), "-k"], env=env)
        (ROOT / "research/corert-regression-results.json").write_text(json.dumps({
            "at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "cases": results,
            "account_free": True,
            "probe_sha256": hashlib.sha256((BUILD / "corert-regression.exe").read_bytes()).hexdigest(),
            "full_corert_dll_rebuilt": False, "official_fivem_started": False,
        }, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "test", "all"))
    args = parser.parse_args()
    if args.action in ("build", "all"):
        build()
    if args.action in ("test", "all"):
        test()
