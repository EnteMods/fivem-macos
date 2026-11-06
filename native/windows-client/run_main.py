#!/usr/bin/env python3
"""Stage and observe the genuine MAIN bootstrap in its own fresh Wine prefix."""
import argparse
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
STAGE = ROOT / "build/windows-main-first-start"
CHECKPOINT = ROOT / "build/checkpoints/main-first-start-before-update"
PREFIX = ROOT / "prefixes/fivem-source-main"
RECORD = ROOT / "research/client-main-first-stage.json"
REVISION = "9f0e34e1cbdfc34fd05079416791f01938279097"
sys.path.insert(0, str(ROOT / "scripts"))


def plain(path):
    current = ROOT
    for part in path.relative_to(ROOT).parts:
        current /= part
        if current.is_symlink():
            raise RuntimeError("Refusing redirected source MAIN path: " + str(current))


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def prepare():
    build = json.loads((ROOT / "research/client-main-build-results.json").read_text())
    if (not build.get("full_main_compile_and_link_passed")
            or build["source_revision"] != REVISION
            or build["path"] != "build/windows-client/FiveM.exe"):
        raise RuntimeError("Require the pinned full genuine MAIN source-build evidence")
    source = ROOT / build["path"]
    plain(source)
    if sha(source) != build["sha256"] or source.stat().st_size != build["file_bytes"]:
        raise RuntimeError("MAIN artifact differs from the full-link evidence")
    for directory in (STAGE, CHECKPOINT):
        plain(directory)
        directory.mkdir(parents=True, exist_ok=True)
        if set(item.name for item in directory.iterdir()) - {"FiveM.exe"}:
            raise RuntimeError("Refusing populated bootstrap stage/checkpoint: " + str(directory))
        target = directory / "FiveM.exe"
        plain(target)
        if target.exists():
            if sha(target) != build["sha256"]:
                raise RuntimeError("Refusing to replace a changed bootstrap stage/checkpoint")
        else:
            subprocess.run(["/bin/cp", "-c", str(source), str(target)], check=True)
        if sha(target) != build["sha256"]:
            raise RuntimeError("MAIN CoW copy verification failed")
    record = {
        "at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source_revision": REVISION, "stage": str(STAGE.relative_to(ROOT)),
        "checkpoint": str(CHECKPOINT.relative_to(ROOT)),
        "files": [{"name": "FiveM.exe", "source": build["path"],
                   "bytes": source.stat().st_size, "sha256": build["sha256"]}],
        "entrypoint": "actual public MAIN WinMain and normal full bootstrap/updater",
        "arguments": [], "prefix": str(PREFIX.relative_to(ROOT)),
        "mode_or_updater_skip_flags": [], "embedded_original_resources": True,
        "official_self_update_allowed": True, "account_or_profile_inputs_copied": False,
        "executed": False,
    }
    RECORD.write_text(json.dumps(record, indent=2) + "\n")
    print("Minimal genuine MAIN stage ready:", STAGE, flush=True)
    print("Immutable pre-update CoW checkpoint:", CHECKPOINT, flush=True)


def file_inventory(directory):
    result = []
    for path in sorted(directory.rglob("*")):
        plain(path)
        if path.is_file():
            result.append({"path": str(path.relative_to(ROOT)), "bytes": path.stat().st_size,
                           "sha256": sha(path)})
    return result


def inventory_evidence(directory):
    try:
        return {"files": file_inventory(directory), "error": None}
    except (OSError, RuntimeError) as error:
        return {"files": [], "error": {"type": type(error).__name__, "message": str(error)}}


def diagnostics(log):
    text = log.read_text(errors="replace") if log.is_file() else ""
    wanted = ("Windows.UI.Xaml.Hosting.WindowsXamlManager", "RoOriginateLanguageException",
              "Unhandled exception code", "EXCEPTION_WINE_CXX_EXCEPTION")
    return {
        "entrypoint_log_sha256": sha(log) if log.is_file() else None,
        "xaml_activation_class_not_registered":
            "Failed to find library for L\"Windows.UI.Xaml.Hosting.WindowsXamlManager\"" in text
            and "RoOriginateLanguageException 0x80040154" in text,
        "unhandled_c0000409": "Unhandled exception code c0000409" in text,
        "relevant_original_wine_lines": [line for line in text.splitlines()
                                         if any(token in line for token in wanted)],
    }


def run(observe_seconds, classic_ui=False, installed=False):
    from source_main_environment import source_main_prefix, assert_source_main_prefix
    from probe_environment import ProbePrefixError
    for path in (STAGE, CHECKPOINT, RECORD):
        plain(path)
    record = json.loads(RECORD.read_text())
    if (record["stage"] != str(STAGE.relative_to(ROOT)) or record["arguments"]
            or record["prefix"] != str(PREFIX.relative_to(ROOT))):
        raise RuntimeError("Unexpected MAIN first-start configuration")
    if not installed and set(path.name for path in STAGE.iterdir()) != {"FiveM.exe"}:
        raise RuntimeError("First MAIN stage must contain only the verified genuine executable")
    input_evidence = RECORD
    verified_installed_code = []
    if installed:
        classic_ui = True
        input_evidence = ROOT / "research/client-main-classic-results.json"
        original_update = json.loads(input_evidence.read_text())
        if (original_update.get("isolation_guard_failure") or original_update.get("runner_failure")
                or original_update["stage_inventory_after"].get("error")
                or not original_update.get("upstream_classic_ui_selected")):
            raise RuntimeError("Require the actual successful isolated normal official-update inventory")
        for item in original_update["stage_inventory_after"]["files"]:
            path = ROOT / item["path"]
            path.relative_to(STAGE)
            plain(path)
            if sha(path) != item["sha256"]:
                raise RuntimeError("Installed stage differs from actual normal updater evidence: " + item["path"])
            with path.open("rb") as source:
                is_pe = source.read(2) == b"MZ"
            if is_pe:
                verified_installed_code.append(item)
        if not any(item["path"] == str((STAGE / "FiveM.exe").relative_to(ROOT))
                   for item in verified_installed_code):
            raise RuntimeError("Official updated MAIN executable is absent from the verified PE inventory")
        for directory in (STAGE, STAGE / "FiveM.app"):
            for name in (".formaldev", "nobootstrap.txt"):
                if (directory / name).exists() or (directory / name).is_symlink():
                    raise RuntimeError("Refusing developer/updater skip marker in ordinary installed stage")
    for item in record["files"]:
        path = STAGE / item["name"]
        plain(path)
        if not installed and sha(path) != item["sha256"]:
            raise RuntimeError("MAIN stage bytes changed before the first ordinary start")
        if sha(CHECKPOINT / item["name"]) != item["sha256"]:
            raise RuntimeError("Pre-update MAIN checkpoint changed")
    spec = importlib.util.spec_from_file_location("existing_gta_environment", ROOT.parent / "GTA-V-macOS/scripts/gta-macos.py")
    runtime = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runtime)
    env = runtime.environment()
    if PREFIX.resolve() == runtime.PREFIX.resolve():
        raise RuntimeError("Refusing productive GTA prefix")
    if any(key.lower().startswith("citizenfx_") for key in env):
        raise RuntimeError("Refusing inherited CitizenFX mode variables for the normal MAIN start")
    if classic_ui:
        baseline = json.loads((ROOT / "research/client-main-first-results.json").read_text())
        if (not baseline.get("diagnostic", {}).get("xaml_activation_class_not_registered")
                or baseline.get("isolation_guard_failure") or baseline.get("runner_failure")):
            raise RuntimeError("Classic UI retry requires the actual isolated XAML-failure baseline")
        # This existing upstream switch only selects the ordinary classic updater UI.
        env["CitizenFX_NoTenUI"] = "1"
    env["WINEPREFIX"] = str(PREFIX)
    env["WINEDEBUG"] = "+loaddll,+seh"
    label = "client-main-classic" if classic_ui else "client-main-first"
    if installed:
        label = "client-main-installed-" + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    cases = []
    isolation_failure = None
    runner_failure = None
    parent = None
    with source_main_prefix(PREFIX, root=ROOT, create=not classic_ui):
        try:
            if not (PREFIX / "system.reg").exists():
                if classic_ui:
                    raise RuntimeError("Classic UI retry must use the already initialized baseline prefix")
                assert_source_main_prefix(PREFIX, root=ROOT)
                log = ROOT / "logs" / (label + "-wineboot.log")
                print("Initializing dedicated fresh MAIN prefix", flush=True)
                with log.open("w") as output:
                    boot = subprocess.run([str(runtime.WINE), "wineboot.exe", "-i"], cwd=STAGE, env=env,
                                          stdout=output, stderr=subprocess.STDOUT, timeout=60)
                cases.append({"case": "wineboot", "exit": boot.returncode, "log": str(log.relative_to(ROOT))})
                assert_source_main_prefix(PREFIX, root=ROOT)
                if boot.returncode:
                    raise RuntimeError("Fresh MAIN Wineboot failed")
            assert_source_main_prefix(PREFIX, root=ROOT)
            log = ROOT / "logs" / (label + "-entrypoint.log")
            print("Starting genuine MAIN without arguments:", STAGE / "FiveM.exe", flush=True)
            print("Observation window:", observe_seconds, "seconds; no UI consent or login automation", flush=True)
            print("Result record:", "research/" + label + "-results.json", flush=True)
            with log.open("w") as output:
                started = time.monotonic()
                parent = subprocess.Popen([str(runtime.WINE), str(STAGE / "FiveM.exe")], cwd=STAGE, env=env,
                                          stdout=output, stderr=subprocess.STDOUT)
                print("MAIN native Wine PID:", parent.pid, flush=True)
                next_guard = started
                while time.monotonic() - started < observe_seconds:
                    if time.monotonic() >= next_guard:
                        assert_source_main_prefix(PREFIX, root=ROOT)
                        next_guard = time.monotonic() + 2
                    # Self-update may hand off to a child after the first process exits.
                    # Keep the bounded observation window open for the original child/UI.
                    time.sleep(0.2)
                cases.append({"case": "actual-main-entrypoint", "parent_exit_before_cleanup": parent.poll(),
                              "observed_seconds": round(time.monotonic() - started, 2),
                              "log": str(log.relative_to(ROOT))})
            assert_source_main_prefix(PREFIX, root=ROOT)
        except BaseException as error:
            detail = {"type": type(error).__name__, "message": str(error)}
            if isinstance(error, ProbePrefixError):
                isolation_failure = detail
            else:
                runner_failure = detail
            raise
        finally:
            # The prefix-scoped lock remains held until all its Wine children stop.
            cleanup = subprocess.run([str(runtime.ENGINE / "bin/wineserver"), "-k"], env=env,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                stopped = subprocess.run([str(runtime.ENGINE / "bin/wineserver"), "-w"], env=env,
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
                cleanup_result = {"kill_exit": cleanup.returncode, "wait_exit": stopped.returncode,
                                  "wait_timed_out": False}
            except subprocess.TimeoutExpired:
                cleanup_result = {"kill_exit": cleanup.returncode, "wait_exit": None, "wait_timed_out": True}
            if parent is not None:
                try:
                    parent.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    parent.terminate()
                    parent.wait(timeout=5)
            result = {
                "at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "stage_evidence": str(RECORD.relative_to(ROOT)), "prefix": str(PREFIX.relative_to(ROOT)),
                "runtime_input_evidence": str(input_evidence.relative_to(ROOT)),
                "runtime_input_evidence_sha256": sha(input_evidence),
                "installed_official_resume": installed,
                "installed_official_pe_code_verified_before_start": verified_installed_code,
                "dedicated_fresh_prefix": True, "copied_account_or_profile_inputs": False,
                "prefix_reused_only_from_source_main_baseline": classic_ui,
                "upstream_classic_ui_selected": classic_ui,
                "self_set_mode_environment": {"CitizenFX_NoTenUI": "1"} if classic_ui else {},
                "arguments": [], "cases": cases, "isolation_guard_failure": isolation_failure,
                "runner_failure": runner_failure, "prefix_cleanup": cleanup_result,
                "stage_inventory_after": inventory_evidence(STAGE),
                "new_prefix_user_inventory_after": inventory_evidence(PREFIX / "drive_c/users")
                    if isolation_failure is None else {"files": [], "error": "Skipped after prefix isolation failure"},
                "ui_or_full_client_success_claim": False,
                "limit": "Observe first normal bootstrap window or rejection; no login, game or anti-cheat claim",
                "diagnostic": diagnostics(ROOT / "logs" / (label + "-entrypoint.log")),
            }
            (ROOT / "research" / (label + "-results.json")).write_text(json.dumps(result, indent=2) + "\n")
            if installed:
                (ROOT / "research/client-main-installed-latest.json").write_text(json.dumps({
                    "result": "research/" + label + "-results.json", "at": result["at"]}, indent=2) + "\n")
    print("MAIN bounded observation finished; prefix cleanup:", cleanup_result, flush=True)
    return 1 if cleanup_result["wait_timed_out"] else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "run", "resume"))
    parser.add_argument("--observe-seconds", type=int, default=None)
    parser.add_argument("--classic-ui", action="store_true",
                        help="Select only the original upstream CitizenFX_NoTenUI UI fallback after the baseline")
    args = parser.parse_args()
    duration = args.observe_seconds if args.observe_seconds is not None else (900 if args.action == "resume" else 60)
    maximum = 900 if args.action == "resume" else 60
    if not 1 <= duration <= maximum:
        parser.error("Observation must be between 1 and " + str(maximum) + " seconds")
    if args.action == "prepare":
        if args.classic_ui:
            parser.error("--classic-ui applies only to the coordinated runtime attempt")
        prepare()
        return 0
    return run(duration, args.classic_ui, installed=args.action == "resume")


if __name__ == "__main__":
    raise SystemExit(main())
