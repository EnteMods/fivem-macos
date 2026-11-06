#!/usr/bin/env python3
"""List native windows of Wine processes whose working directory is a known code root."""
import concurrent.futures
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
CAPTURE = ROOT / "build/window-capture/capture-owned-window"
CODE_ROOTS = {
    ROOT / "build/windows-source-integration": "source-client",
    ROOT / "build/windows-source-integration/data/game-storage/launcher": "source-cached-rockstar-launcher",
    ROOT / "prefixes/fivem-source-main/drive_c/Program Files/Rockstar Games/Launcher": "source-rockstar-launcher",
    ROOT / "prefixes/fivem-source-main/drive_c/Program Files/Rockstar Games/Social Club": "source-social-club",
}


def plain_ancestors(path):
    path.relative_to(ROOT)
    current = path
    while current != ROOT.parent:
        if current.is_symlink():
            raise ValueError("A diagnostic code/helper path is redirected.")
        current = current.parent


def wine_pids():
    # `comm` reports executable names, without command-line arguments or environments.
    output = subprocess.check_output(["/bin/ps", "-axo", "pid=,comm="], text=True)
    result = set()
    for line in output.splitlines():
        fields = line.strip().split(None, 1)
        if len(fields) != 2 or not fields[0].isdigit():
            continue
        executable = fields[1].replace("\\", "/").rsplit("/", 1)[-1].lower()
        if executable in {"wine", "wine64", "wine64-preloader", "wine-preloader",
                           "fivem_roslauncher"} or executable.endswith(".exe"):
            result.add(int(fields[0]))
    return result


def owned_processes(pids):
    if not pids:
        return []
    result = subprocess.run(["/usr/sbin/lsof", "-a", "-p", ",".join(map(str, sorted(pids))),
                             "-d", "cwd", "-Fpnc"], text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=10)
    owners = []
    pid = None
    for line in result.stdout.splitlines():
        if line.startswith("p") and line[1:].isdigit():
            pid = int(line[1:])
        elif line.startswith("n") and pid in pids:
            code_root = CODE_ROOTS.get(Path(line[1:]))
            if code_root:
                owners.append({"native_pid": pid, "verified_working_directory": code_root})
    return owners


def windows(owner):
    try:
        if owner not in owned_processes({owner["native_pid"]}):
            return dict(owner, windows=[], inspection_status="working-directory-scope-changed")
        result = subprocess.run([str(CAPTURE), str(owner["native_pid"])], text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=12)
        if result.returncode:
            return dict(owner, windows=[], inspection_status="unavailable-or-process-ended")
        records = json.loads(result.stdout)
        if (not isinstance(records, list) or not all(isinstance(item, dict) for item in records)
                or any(item.get("pid") != owner["native_pid"] for item in records)):
            raise ValueError("Unexpected window owner")
        if owner not in owned_processes({owner["native_pid"]}):
            return dict(owner, windows=[], inspection_status="working-directory-scope-changed")
        return dict(owner, windows=records, inspection_status="observed")
    except (subprocess.TimeoutExpired, ValueError, OSError):
        return dict(owner, windows=[], inspection_status="unavailable-or-process-ended")


def main():
    if len(sys.argv) != 1:
        raise SystemExit("This inspection accepts no arbitrary process IDs or paths.")
    if not CAPTURE.is_file() or CAPTURE.is_symlink():
        raise SystemExit("Build the reviewed native capture helper first.")
    for path in [CAPTURE, *CODE_ROOTS]:
        plain_ancestors(path)
    owners = owned_processes(wine_pids())
    # Bound one metadata query even if a client creates many renderer processes.
    ordered = sorted(owners, key=lambda item: item["native_pid"])
    selected = ordered if len(ordered) <= 8 else ordered[:4] + ordered[-4:]
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        observed = list(pool.map(windows, selected))
    print(json.dumps({"processes": observed, "matching_process_count": len(owners),
                      "omitted_matching_process_count": max(0, len(owners) - len(selected)),
                      "command_arguments_or_environments_read": False,
                      "screenshots_taken": False, "profile_or_browser_store_read": False,
                      "limit": "Working-directory/executable-name scope only, not Wine-prefix identity. Directory scope is rechecked around SCK; process end, PID reuse and directory changes remain possible."},
                     indent=2))


if __name__ == "__main__":
    main()
