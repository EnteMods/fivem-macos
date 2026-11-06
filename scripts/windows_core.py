#!/usr/bin/env python3
"""Cross-build public Windows CoreRT and exercise it without any FiveM account."""

import argparse
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
from probe_environment import assert_account_free_prefix, probe_prefix

ROOT = Path(__file__).resolve().parents[1]
PREFIX = ROOT / "prefixes/corert-regression"


def build():
    for name, tests in (("windows-core", False), ("windows-core-probe", True)):
        folder = ROOT / "build" / name
        subprocess.run(["cmake", "-S", str(ROOT / "native/windows-core"), "-B", str(folder),
                        "-G", "Ninja", "-DCMAKE_TOOLCHAIN_FILE=" + str(ROOT / "native/windows-core/toolchain.cmake"),
                        "-DCMAKE_POLICY_VERSION_MINIMUM=3.5", "-DCMAKE_BUILD_TYPE=RelWithDebInfo",
                        "-DCFX_CORE_ACCOUNT_FREE_TESTS=" + ("ON" if tests else "OFF")], check=True)
        subprocess.run(["cmake", "--build", str(folder), "--parallel", "6"], check=True)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test():
    with probe_prefix(PREFIX, root=ROOT):
        _test_locked()


def _test_locked():
    original = ROOT.parent / "GTA-V-macOS"
    spec = importlib.util.spec_from_file_location("existing_gta_environment", original / "scripts/gta-macos.py")
    runtime = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runtime)
    if PREFIX.resolve() == runtime.PREFIX.resolve() or PREFIX.is_symlink():
        raise SystemExit("Refusing the productive or a redirected prefix.")
    env = runtime.environment()
    env["WINEPREFIX"] = str(PREFIX)
    env["WINEDEBUG"] = "+loaddll"
    stages = {}
    for mode, source_name in (("plain", "windows-core"), ("instrumented", "windows-core-probe")):
        source = ROOT / "build" / source_name
        stage = ROOT / "build/windows-core-test" / mode
        stage.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / "build/windows-core-probe/corert_full_probe.exe", stage)
        shutil.copy2(source / "CoreRT.dll", stage)
        tbb = list(source.glob("*/tbb12.dll"))
        if len(tbb) != 1:
            raise SystemExit("Expected one actual built TBB DLL, found " + str(tbb))
        shutil.copy2(tbb[0], stage)
        if mode == "instrumented":
            shutil.copy2(source / "windows-fixture.dll", stage)
        stages[mode] = stage

    results = []
    try:
        for label, mode, arguments, expected, markers in (
            ("plain-unwind", "plain", [], 0, ("PASS: full DLL exported setup restores a real captured frame", "PASS: full DLL preserves handled SEH")),
            ("plain-unhandled", "plain", ["--unhandled"], 92, ("FULL_DLL_UNHANDLED code=0xe0425678",)),
            ("bounded-game-and-launcher-tail", "plain", ["--bounded"], 0,
             ("PASS: original launcher tail outside mapped range unwinds identically",)),
            ("launcher-policy-before", "plain", ["--launcher-before"], 93, ("BASELINE_UNHANDLED expected-exit=93",)),
            ("launcher-policy-after", "plain", ["--launcher-after"], 92, ("FULL_DLL_UNHANDLED code=0xe0425678",)),
            ("foreign-filter-chain", "plain", ["--foreign-chain"], 93,
             ("PASS: foreign chaining filter called once", "PASS: CoreRT reporter delegates CONTINUE_SEARCH", "BASELINE_UNHANDLED expected-exit=93")),
            ("instrumented-component", "instrumented", ["--component"], 0,
             ("PASS: real CoreRT component manifest, HardErrorScope, CreateComponent and C++ lifecycle",)),
        ):
            log = ROOT / "logs" / ("windows-core-" + label + ".log")
            print("Running", label, flush=True)
            assert_account_free_prefix(PREFIX, root=ROOT)
            with log.open("w") as output:
                run = subprocess.run([str(runtime.WINE), str(stages[mode] / "corert_full_probe.exe"), *arguments],
                                     cwd=stages[mode], env=env, stdout=output, stderr=subprocess.STDOUT, timeout=60)
            assert_account_free_prefix(PREFIX, root=ROOT)
            output = log.read_text(errors="replace")
            passed = run.returncode == expected and all(marker in output for marker in markers)
            results.append({"case": label, "exit": run.returncode, "expected_exit": expected,
                            "passed": passed, "dll_sha256": sha(stages[mode] / "CoreRT.dll"),
                            "instrumented": mode == "instrumented", "log": str(log.relative_to(ROOT))})
            print(label, "PASS" if passed else "FAIL", "exit", run.returncode, flush=True)
            if not passed:
                raise RuntimeError(output[-6000:])
    finally:
        subprocess.run([str(runtime.ENGINE / "bin/wineserver"), "-k"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        (ROOT / "research/windows-core-results.json").write_text(json.dumps({
            "at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "source_revision": "9f0e34e1cbdfc34fd05079416791f01938279097",
            "account_free": True, "official_fivem_started": False,
            "full_public_windows_corert_rebuilt": True,
            "native_mac_client": False, "cases": results,
        }, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "test", "all"))
    args = parser.parse_args()
    if args.action in ("build", "all"):
        build()
    if args.action in ("test", "all"):
        test()
