#!/usr/bin/env python3
"""Load the actual NUI DLL graph only; no component creation, browser or account."""
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build/windows-nui"
STAGE = ROOT / "build/windows-nui-runtime"
PREFIX = ROOT / "prefixes/corert-regression"
sys.path.insert(0, str(ROOT / "scripts"))
from probe_environment import assert_account_free_prefix, probe_prefix


def main():
    subprocess.run([sys.executable, str(ROOT / "native/windows-nui/prepare_runtime.py")], cwd=ROOT, check=True)
    subprocess.run(["cmake", "-S", str(ROOT / "native/windows-nui"), "-B", str(BUILD), "-G", "Ninja",
                    "-DCMAKE_TOOLCHAIN_FILE=" + str(ROOT / "native/windows-core/toolchain.cmake"),
                    "-DCMAKE_POLICY_VERSION_MINIMUM=3.5", "-DCMAKE_BUILD_TYPE=RelWithDebInfo"], cwd=ROOT, check=True)
    subprocess.run(["cmake", "--build", str(BUILD), "--target", "nui_load_probe", "--parallel", "4"], cwd=ROOT, check=True)
    executable = STAGE / "nui-load-probe.exe"
    if executable.is_symlink():
        raise SystemExit("Refusing redirected probe executable")
    shutil.copy2(BUILD / "nui-load-probe.exe", executable)
    with probe_prefix(PREFIX, root=ROOT):
        return run_locked(executable)


def run_locked(executable):
    spec = importlib.util.spec_from_file_location("existing_gta_environment", ROOT.parent / "GTA-V-macOS/scripts/gta-macos.py")
    runtime = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runtime)
    env = runtime.environment()
    env["WINEPREFIX"] = str(PREFIX)
    env["WINEDEBUG"] = "+loaddll,+module"
    log = ROOT / "logs/nui-load-probe.log"
    result = None
    try:
        assert_account_free_prefix(PREFIX, root=ROOT)
        with log.open("w") as output:
            result = subprocess.run([str(runtime.WINE), str(executable)], cwd=STAGE, env=env,
                                    stdout=output, stderr=subprocess.STDOUT, timeout=60)
        assert_account_free_prefix(PREFIX, root=ROOT)
    finally:
        subprocess.run([str(runtime.ENGINE / "bin/wineserver"), "-k"], env=env,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    text = log.read_text(errors="replace")
    passed = result.returncode == 0 and "NUI_LOAD_PROBE_OK" in text and "NUI_CEF_API_MATCH" in text
    record = {"at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "exit": result.returncode, "passed": passed, "account_free": True,
              "component_created": False, "preinit_called": False, "browser_initialized": False,
              "auth_or_game_started": False, "historical_prefix_executed": False,
              "runtime_stage": "research/nui-runtime-stage.json",
              "probe_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
              "log": str(log.relative_to(ROOT)),
              "module_failures": [line for line in text.splitlines() if "NUI_LOAD_FAILED" in line or "err:module:" in line]}
    (ROOT / "research/nui-load-results.json").write_text(json.dumps(record, indent=2) + "\n")
    for line in text.splitlines():
        if "NUI_" in line or "err:module:" in line:
            print(line[:500])
    print("Actual NUI DLL LoadLibrary", "PASS" if passed else "FAIL", "exit", result.returncode)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
