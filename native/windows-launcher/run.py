#!/usr/bin/env python3
"""Build upstream CitiCon and test only a local ToolComponent fixture."""
import argparse
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build/windows-launcher"
PREFIX = ROOT / "prefixes/corert-regression"
sys.path.insert(0, str(ROOT / "scripts"))
from probe_environment import assert_account_free_prefix, probe_prefix


def build(chrome=False):
    configure = [
            "cmake", "-S", str(ROOT / "native/windows-launcher"), "-B", str(BUILD), "-G", "Ninja",
            "-DCMAKE_TOOLCHAIN_FILE=" + str(ROOT / "native/windows-core/toolchain.cmake"),
            "-DCMAKE_POLICY_VERSION_MINIMUM=3.5", "-DCMAKE_BUILD_TYPE=RelWithDebInfo",
            "-DCFX_BUILD_CHROME_SUBPROCESS=" + ("ON" if chrome else "OFF")]
    targets = ["CitiLaunch_chrome", "CitiGame"] if chrome else ["CitiCon", "CitiConFixture"]
    label = "chrome" if chrome else "citicon"
    for arguments, name in ((configure, "configure"),
            (["cmake", "--build", str(BUILD), "--target", *targets, "--parallel", "6"], "build")):
        with (ROOT / "logs" / (label + "-" + name + ".log")).open("w") as log:
            subprocess.run(arguments, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, check=True)
    if chrome:
        artifacts = {name: Path(path) for name, path in json.loads((BUILD / "chrome-artifacts.json").read_text()).items()}
        inventory = subprocess.run(["/opt/homebrew/opt/llvm/bin/llvm-readobj", "--file-headers", "--coff-imports", "--coff-exports",
                                    str(artifacts["chrome"]), str(artifacts["citigame"])], capture_output=True, text=True, check=True)
        (BUILD / "chrome-pe-inventory.txt").write_text(inventory.stdout)
        (ROOT / "research/chrome-build-results.json").write_text(json.dumps({
            "at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "source_revision": "9f0e34e1cbdfc34fd05079416791f01938279097",
            "built": ["actual upstream CitiLaunch_chrome WinMain", "actual full public CitiGame DLL"],
            "platform": "Windows x64 /MD PE, cross-built on macOS ARM64",
            "launched": False, "gui_rendering_tested": False,
            "account_auth_anticheat_game_tested": False,
            "sha256": {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in artifacts.items()},
            "openssl_scope": "Original pinned SHA256 C implementation and cleansing routine only, not full libcrypto",
            "logs": ["logs/chrome-configure.log", "logs/chrome-build.log", "build/windows-launcher/chrome-pe-inventory.txt"],
        }, indent=2) + "\n")
        print("Actual Chrome WinMain executable and CitiGame DLL built; not launched.")


def test():
    with probe_prefix(PREFIX, root=ROOT):
        return test_locked()


def test_locked():
    spec = importlib.util.spec_from_file_location("existing_gta_environment", ROOT.parent / "GTA-V-macOS/scripts/gta-macos.py")
    runtime = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runtime)
    if PREFIX.resolve() == runtime.PREFIX.resolve():
        raise SystemExit("Refusing productive GTA prefix")
    env = runtime.environment()
    env["WINEPREFIX"] = str(PREFIX)
    env["WINEDEBUG"] = "-all,+loaddll"
    artifacts = {name: Path(value) for name, value in json.loads((BUILD / "launch-artifacts.json").read_text()).items()}
    stage = ROOT / "build/windows-launcher-test"
    missing = stage / "missing-core"
    fixture = stage / "tool-fixture"
    for directory in (missing, fixture):
        directory.mkdir(parents=True, exist_ok=True)
        shutil.copy2(artifacts["console"], directory / "FiveM.com")
    for name, destination in (("core", "CoreRT.dll"), ("tbb", "tbb12.dll"), ("fixture", "probe-tool.dll")):
        shutil.copy2(artifacts[name], fixture / destination)
    (fixture / "components.json").write_text('["probe:tool"]\n')
    (fixture / "bin").mkdir(exist_ok=True)
    cases = (
        ("missing-core", missing, [], 1, ("Couldn't load CoreRT.dll.",)),
        ("list-commands", fixture, [], 0, ("No command passed. Valid commands include: probe:dispatch",)),
        ("dispatch", fixture, ["probe:dispatch", "--value", "42"], 0,
         ("CITICON_FIXTURE_INITIALIZED", "CITICON_UPSTREAM_TOOL_DISPATCH_OK value=42")),
        ("reject-input", fixture, ["probe:dispatch", "--value", "41"], 93,
         ("CITICON_FIXTURE_INITIALIZED", "CITICON_FIXTURE_BAD_INPUT")),
        ("unknown-command", fixture, ["probe:unknown"], 0, ("Command [probe:unknown] is unknown to this tool.",)),
    )
    results = []
    try:
        for label, directory, arguments, expected_exit, markers in cases:
            assert_account_free_prefix(PREFIX, root=ROOT)
            log = ROOT / "logs" / ("citicon-" + label + ".log")
            with log.open("w") as output:
                result = subprocess.run([str(runtime.WINE), str(directory / "FiveM.com"), *arguments],
                                        cwd=directory, env=env, stdout=output, stderr=subprocess.STDOUT, timeout=60)
            assert_account_free_prefix(PREFIX, root=ROOT)
            output = log.read_text(errors="replace")
            passed = result.returncode == expected_exit and all(marker in output for marker in markers)
            results.append({"case": label, "exit": result.returncode, "expected_exit": expected_exit,
                            "passed": passed, "log": str(log.relative_to(ROOT))})
            print(label, "PASS" if passed else "FAIL", "exit", result.returncode, flush=True)
            if not passed:
                raise RuntimeError(output[-7000:])
    finally:
        subprocess.run([str(runtime.ENGINE / "bin/wineserver"), "-k"], env=env,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        record = {
            "at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "source_revision": "9f0e34e1cbdfc34fd05079416791f01938279097",
            "actual_upstream_console_entrypoint": True,
            "account_free": True, "own_fixture_only": True,
            "client_gui_game_auth_anticheat_tested": False,
            "instrumented_corert": False,
            "runtime": "Existing pinned Wine compatibility runtime; Wine builtin VC/UCRT DLLs, no copied runtime DLLs",
            "sha256": {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in artifacts.items()},
            "cases": results,
        }
        (ROOT / "research/citicon-results.json").write_text(json.dumps(record, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "build-chrome", "test", "all"))
    action = parser.parse_args().action
    if action in ("build", "all"):
        build()
    if action == "build-chrome":
        build(chrome=True)
    if action in ("test", "all"):
        raise SystemExit(test())
