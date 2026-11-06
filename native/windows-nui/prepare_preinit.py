#!/usr/bin/env python3
"""Prepare a separate genuine Chrome-personality stage from verified code/runtime inputs."""
import datetime
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import zipfile

from prepare_runtime import plain, sha

ROOT = Path(__file__).resolve().parents[2]
STAGE = ROOT / "build/windows-chrome-preinit"
REVISION = "9f0e34e1cbdfc34fd05079416791f01938279097"


def main():
    plain(STAGE)
    STAGE.mkdir(parents=True, exist_ok=True)
    records = []

    def copy(source, relative, origin, expected):
        plain(source)
        if sha(source) != expected:
            raise SystemExit("PreInit code/runtime source changed: " + str(source))
        target = STAGE / relative
        plain(target)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        if sha(target) != expected:
            raise SystemExit("PreInit stage copy verification failed")
        records.append({"name": relative, "source": str(source.relative_to(ROOT)), "origin": origin,
                        "bytes": target.stat().st_size, "sha256": expected})

    previous = json.loads((ROOT / "research/nui-runtime-stage.json").read_text())
    load_result = json.loads((ROOT / "research/nui-load-results.json").read_text())
    if not load_result.get("passed"):
        raise SystemExit("Require the successful real NUI DLL-load checkpoint")
    for item in previous["files"]:
        copy(ROOT / previous["stage"] / item["name"], item["name"], item["origin"], item["sha256"])
    chrome = json.loads((ROOT / "research/chrome-build-results.json").read_text())
    copy(ROOT / "build/windows-launcher/CitizenFX_SubProcess_chrome.bin", "FiveM_ChromeBrowser",
         "actual-public-source-Chrome-personality", chrome["sha256"]["chrome"])
    copy(ROOT / "build/windows-launcher/CitizenGame.dll", "CitizenGame.dll",
         "actual-full-public-CitiGame-source-build", chrome["sha256"]["citigame"])
    relative = "data/client/components.json"
    source = ROOT / "port/fivem" / relative
    expected_json = subprocess.run(["git", "-C", str(ROOT / "port/fivem"), "show", REVISION + ":" + relative],
                                   capture_output=True, check=True).stdout
    if source.read_bytes() != expected_json:
        raise SystemExit("Full original client component list differs from the source pin")
    copy(source, "components.json", "complete-original-public-client-component-list-including-security-component",
         hashlib.sha256(expected_json).hexdigest())
    package = json.loads((ROOT / "research/cef-package.json").read_text())
    lock = json.loads((ROOT / "config/cef-package.json").read_text())
    archive = ROOT / package["archive"]
    if archive.stat().st_size != lock["archive_bytes"] or sha(archive) != lock["archive_sha256"]:
        raise SystemExit("CEF archive differs from the reviewed package lock")
    with zipfile.ZipFile(archive) as source_zip:
        selected_names = set()
        for entry in source_zip.infolist():
            path = PurePosixPath(entry.filename)
            if not path.parts or path.parts[0] != lock["build_name"]:
                raise SystemExit("Unexpected CEF archive root")
            tail = PurePosixPath(*path.parts[1:])
            destination = None
            if len(tail.parts) == 2 and tail.parts[0] == "Release" and tail.suffix == ".bin":
                destination = "bin/" + tail.name
            elif str(tail) == "Resources/icudtl.dat":
                destination = "bin/icudtl.dat"
            elif ((len(tail.parts) == 2 and tail.parts[0] == "Resources" and tail.suffix == ".pak")
                  or str(tail) == "Resources/locales/en-US.pak"):
                destination = "bin/cef/" + tail.name
            if destination is None:
                continue
            if (path.is_absolute() or ".." in path.parts or "\\" in entry.filename or ":" in entry.filename
                    or stat.S_ISLNK(entry.external_attr >> 16) or destination.casefold() in selected_names):
                raise SystemExit("Unsafe or duplicate CEF runtime resource entry")
            selected_names.add(destination.casefold())
            target = STAGE / destination
            plain(target)
            target.parent.mkdir(parents=True, exist_ok=True)
            with source_zip.open(entry) as input_file, target.open("wb") as output:
                shutil.copyfileobj(input_file, output)
            records.append({"name": destination, "source": str(archive.relative_to(ROOT)) + ":" + entry.filename,
                            "origin": "original-official-CEF-pack-layout", "bytes": target.stat().st_size,
                            "sha256": sha(target)})
    required = {"bin/icudtl.dat", "bin/cef/en-US.pak", "bin/cef/resources.pak"}
    if not required.issubset({item["name"] for item in records}):
        raise SystemExit("Required original CEF pack-layout resources are missing")
    record = {"at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "source_revision": REVISION,
              "stage": str(STAGE.relative_to(ROOT)), "files": records,
              "entrypoint": "FiveM_ChromeBrowser", "arguments": ["-b3889"],
              "full_original_component_list": True, "filter": "unchanged stock ChromeBrowser process-name filter",
              "account_profile_or_cache_inputs_copied": False, "executed": False,
              "browser_or_full_game_claim": False}
    (ROOT / "research/chrome-preinit-stage.json").write_text(json.dumps(record, indent=2) + "\n")
    print("Separate original Chrome PreInit stage prepared:", STAGE)
    print("Code/runtime files:", len(records), "; no profile/cache/session inputs and no execution")


if __name__ == "__main__":
    main()
