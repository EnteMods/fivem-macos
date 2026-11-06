#!/usr/bin/env python3
"""Run the genuine Chrome entrypoint in a dedicated fresh source-only Wine prefix."""
import argparse
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
STAGE = ROOT / "build/windows-chrome-preinit"
PREFIX = ROOT / "prefixes/fivem-source-preinit"
sys.path.insert(0, str(ROOT / "scripts"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "run"))
    action = parser.parse_args().action
    if action == "prepare":
        subprocess.run([sys.executable, str(ROOT / "native/windows-nui/prepare_preinit.py")], cwd=ROOT, check=True)
        return 0
    from source_preinit_environment import source_preinit_prefix, assert_source_preinit_prefix
    from probe_environment import ProbePrefixError
    from prepare_runtime import plain
    stage_record = json.loads((ROOT / "research/chrome-preinit-stage.json").read_text())
    if stage_record["stage"] != str(STAGE.relative_to(ROOT)) or stage_record["arguments"] != ["-b3889"]:
        raise SystemExit("Unexpected source-only Chrome stage configuration")
    for item in stage_record["files"]:
        path = STAGE / item["name"]
        plain(path)
        if hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]:
            raise SystemExit("Source-only Chrome runtime file changed: " + item["name"])
    spec = importlib.util.spec_from_file_location("existing_gta_environment", ROOT.parent / "GTA-V-macOS/scripts/gta-macos.py")
    runtime = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runtime)
    env = runtime.environment()
    if PREFIX.resolve() == runtime.PREFIX.resolve():
        raise SystemExit("Refusing productive GTA prefix")
    if any(key.lower().startswith("citizenfx_") and value for key, value in env.items()):
        raise SystemExit("Refusing inherited CitizenFX mode variables for a normal source-only Chrome start")
    env["WINEPREFIX"] = str(PREFIX)
    env["WINEDEBUG"] = "+loaddll,+module,+seh"
    cases = []
    isolation_failure = None
    runner_failure = None
    with source_preinit_prefix(PREFIX, root=ROOT, create=True):
        def run(label, arguments, timeout):
            assert_source_preinit_prefix(PREFIX, root=ROOT)
            log = ROOT / "logs" / ("chrome-preinit-" + label + ".log")
            print("Running original source Chrome stage:", label, flush=True)
            try:
                with log.open("w") as output:
                    result = subprocess.run([str(runtime.WINE), *arguments], cwd=STAGE, env=env,
                                            stdout=output, stderr=subprocess.STDOUT, timeout=timeout)
                code, timed_out = result.returncode, False
            except subprocess.TimeoutExpired:
                code, timed_out = None, True
            cases.append({"case": label, "exit": code, "timed_out": timed_out,
                          "log": str(log.relative_to(ROOT))})
            assert_source_preinit_prefix(PREFIX, root=ROOT)
            return code, timed_out

        try:
            if not (PREFIX / "system.reg").exists():
                code, timed_out = run("wineboot", ["wineboot.exe", "-i"], 60)
                if code != 0 or timed_out:
                    raise RuntimeError("Fresh source-only Wine initialization did not finish successfully")
            code, timed_out = run("actual-entrypoint", [str(STAGE / "FiveM_ChromeBrowser"), "-b3889"], 60)
        except BaseException as error:
            detail = {"type": type(error).__name__, "message": str(error)}
            if isinstance(error, ProbePrefixError):
                isolation_failure = detail
            else:
                runner_failure = detail
            raise
        finally:
            subprocess.run([str(runtime.ENGINE / "bin/wineserver"), "-k"], env=env,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            record = {
                "at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "prefix": str(PREFIX.relative_to(ROOT)), "dedicated_fresh_source_only_prefix": True,
                "copied_account_or_profile_inputs": False, "api_probe_prefix_used": False,
                "stage_evidence": "research/chrome-preinit-stage.json",
                "entrypoint": "actual upstream Chrome WinMain and original CitiGame implementation",
                "arguments": ["-b3889"], "tool_sdk_or_invented_browser_role": False,
                "cases": cases, "isolation_guard_failure": isolation_failure,
                "runner_failure": runner_failure,
                "browser_gui_auth_game_anticheat_proven": False,
                "limit": "A normal exit alone does not prove PreInit reached; inspect actual module/CEF/launcher logs",
                "stage_launcher_logs": [str(p.relative_to(ROOT)) for p in (STAGE / "logs").glob("*.log")],
            }
            child_log = ROOT / "logs/chrome-preinit-actual-entrypoint.log"
            child_text = child_log.read_text(errors="replace") if child_log.is_file() else ""
            sequence = ("bluetoothapis.dll", "libEGL.dll", "libGLESv2.dll", "libcef.dll")
            loaded = [line for line in child_text.splitlines() if "Loaded L" in line]
            positions = [next((index for index, line in enumerate(loaded) if name.casefold() in line.casefold()), -1)
                         for name in sequence]
            record["preinit_entry_proven"] = all(index >= 0 for index in positions) and positions == sorted(positions)
            record["preinit_entry_evidence"] = {
                "original_source": "code/components/nui-core/src/NUIInitialize.cpp:1319-1344",
                "distinct_original_load_sequence": list(sequence),
                "lines": [line for line in loaded if any(name.casefold() in line.casefold() for name in sequence)],
            }
            record["cef_execute_process_return_directly_observed"] = False
            record["source_based_expected_no_type_return"] = -1
            record["standalone_crashserver_registration_failed"] = "Could not register with breakpad server" in child_text
            (ROOT / "research/chrome-preinit-results.json").write_text(json.dumps(record, indent=2) + "\n")
    print("Original Chrome entrypoint exit", code, "timeout", timed_out, flush=True)
    return 0 if code == 0 and not timed_out else 1


if __name__ == "__main__":
    raise SystemExit(main())
