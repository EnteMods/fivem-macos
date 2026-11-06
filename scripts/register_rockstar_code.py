#!/usr/bin/env python3
"""Register only the two real installed code-folder paths in the isolated prefix."""
import datetime
import importlib.util
import json
from pathlib import Path
import subprocess

from source_main_environment import source_main_prefix, assert_source_main_prefix

ROOT = Path(__file__).resolve().parents[1]
PREFIX = ROOT / "prefixes/fivem-source-main"
VALUES = (
    (r"HKLM\SOFTWARE\WOW6432Node\Rockstar Games\Launcher",
     r"C:\Program Files\Rockstar Games\Launcher", "Launcher.exe"),
    (r"HKLM\SOFTWARE\WOW6432Node\Rockstar Games\Rockstar Games Social Club",
     r"C:\Program Files\Rockstar Games\Social Club", "socialclub.dll"),
)


def main():
    install_path = ROOT / "research/rockstar-code-only-install.json"
    installed = json.loads(install_path.read_text())
    if (installed["prefix"] != str(PREFIX.relative_to(ROOT))
            or not installed["all_program_file_hashes_verified"]
            or installed["copied_profile_registry_hives_tickets_sessions"]):
        raise RuntimeError("Require the verified real code-only installation in the reviewed prefix")
    spec = importlib.util.spec_from_file_location("existing_gta_environment", ROOT.parent / "GTA-V-macOS/scripts/gta-macos.py")
    runtime = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runtime)
    env = runtime.environment()
    if PREFIX.resolve() == runtime.PREFIX.resolve():
        raise RuntimeError("Refusing productive GTA prefix")
    if any(name.casefold().startswith("citizenfx_") for name in env):
        raise RuntimeError("Refusing inherited CitizenFX role variables")
    env["WINEPREFIX"] = str(PREFIX)
    env["WINEDEBUG"] = "-all,err+all"
    cases = []
    success = False
    with source_main_prefix(PREFIX, root=ROOT):
        def command(label, arguments, optional=False):
            assert_source_main_prefix(PREFIX, root=ROOT)
            result = subprocess.run([str(runtime.WINE), "reg.exe", *arguments], cwd=ROOT, env=env,
                                    capture_output=True, text=True, timeout=30)
            cases.append({"case": label, "arguments": arguments, "exit": result.returncode,
                          "stdout": result.stdout, "stderr": result.stderr})
            assert_source_main_prefix(PREFIX, root=ROOT)
            if result.returncode and not (optional and result.returncode == 1):
                raise RuntimeError("Original reg.exe operation failed: " + label)
            return result

        try:
            for number, (key, folder, executable) in enumerate(VALUES, 1):
                native_folder = PREFIX / "drive_c" / Path(folder[3:].replace("\\", "/"))
                if not (native_folder / executable).is_file():
                    raise RuntimeError("The actual official code dependency is missing: " + folder)
                command(f"{number}-before", ["query", key, "/v", "InstallFolder"], optional=True)
                command(f"{number}-register-real-folder", ["add", key, "/v", "InstallFolder", "/t", "REG_SZ", "/d", folder, "/f"])
                result = command(f"{number}-verify", ["query", key, "/v", "InstallFolder"])
                rows = [line.strip().split(None, 2) for line in result.stdout.splitlines()]
                if not any(len(row) == 3 and row[0].casefold() == "installfolder"
                           and row[1] == "REG_SZ" and row[2].casefold() == folder.casefold() for row in rows):
                    raise RuntimeError("Query did not return the exact actual installed code path")
            success = True
        finally:
            killed = subprocess.run([str(runtime.ENGINE / "bin/wineserver"), "-k"], env=env,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                stopped = subprocess.run([str(runtime.ENGINE / "bin/wineserver"), "-w"], env=env,
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
                cleanup = {"kill_exit": killed.returncode, "wait_exit": stopped.returncode, "wait_timed_out": False}
            except subprocess.TimeoutExpired:
                cleanup = {"kill_exit": killed.returncode, "wait_exit": None, "wait_timed_out": True}
            record = {"at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                      "prefix": str(PREFIX.relative_to(ROOT)), "code_install_evidence": str(install_path.relative_to(ROOT)),
                      "passed": success and not cleanup["wait_timed_out"], "cases": cases,
                      "prefix_cleanup": cleanup, "only_two_actual_installfolder_values_written": True,
                      "version_uninstall_auth_or_service_values_written": False,
                      "registry_hives_or_accounts_copied": False, "launcher_or_main_started": False}
            (ROOT / "research/rockstar-code-registration.json").write_text(json.dumps(record, indent=2) + "\n")
    assert_source_main_prefix(PREFIX, root=ROOT)
    print("Two real Rockstar InstallFolder values registered and queried successfully; no launcher start")
    print("Cleanup:", cleanup)


if __name__ == "__main__":
    main()
