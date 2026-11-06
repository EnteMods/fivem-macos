#!/usr/bin/env python3
"""Prepare an explicitly labeled public-source developer output, without executing it."""
import configparser
import datetime
import json
from pathlib import Path, PurePosixPath
import subprocess

from run_main import ROOT, REVISION, plain, sha

STAGE = ROOT / "build/windows-source-integration"
PACKAGE = ROOT / "build/checkpoints/main-classic-after-official-update"
EVIDENCE = ROOT / "research/client-source-integration-stage.json"


def main():
    plain(STAGE)
    if STAGE.exists():
        raise SystemExit("Refusing to replace an existing source-integration stage")
    package_record = ROOT / "research/client-main-classic-results.json"
    package = json.loads(package_record.read_text())
    main_record = ROOT / "research/client-main-build-results.json"
    built_main = json.loads(main_record.read_text())
    core_record = ROOT / "research/windows-core-results.json"
    built_core = json.loads(core_record.read_text())
    if (package.get("isolation_guard_failure") or package.get("runner_failure")
            or package["stage_inventory_after"].get("error")
            or built_main["source_revision"] != REVISION
            or not built_main["full_main_compile_and_link_passed"]
            or built_core["source_revision"] != REVISION):
        raise SystemExit("Require the real isolated official-update and pinned source-build evidence")
    ordinary_core = [case for case in built_core["cases"] if not case["instrumented"]]
    if not ordinary_core or not all(case["passed"] for case in ordinary_core):
        raise SystemExit("Require the successful real non-instrumented CoreRT runtime checks")
    core_hashes = {case["dll_sha256"] for case in ordinary_core}
    if len(core_hashes) != 1:
        raise SystemExit("CoreRT runtime checks do not identify one ordinary artifact")
    records, omitted = [], []
    selections = []
    for item in package["stage_inventory_after"]["files"]:
        relative = PurePosixPath(item["path"]).relative_to("build/windows-main-first-start")
        if relative.is_absolute() or ".." in relative.parts:
            raise SystemExit("Unsafe package path")
        source = PACKAGE / str(relative)
        plain(source)
        if sha(source) != item["sha256"]:
            raise SystemExit("Original official-package checkpoint differs: " + str(relative))
        reason = None
        if not relative.parts or relative.parts[0] != "FiveM.app":
            reason = "original bootstrap/shell artifact is not part of the flat developer DLL/assets directory"
        else:
            destination = PurePosixPath(*relative.parts[1:])
            if destination.parts[:2] == ("data", "cache") or destination.parts[0] in ("logs", "crashes"):
                reason = "runtime-generated cache/session/log is not copied into the new source output"
            elif str(destination) in ("content_index.xml", "caches.xml", "desktop.ini"):
                reason = "production-updater index or shell metadata is not a developer identity/manifest"
            elif str(destination) == "CoreRT.dll":
                reason = "the independent developer output uses the real tested public-source CoreRT build"
        if reason:
            omitted.append({"input": str(relative), "reason": reason})
        else:
            selections.append((source, str(destination), item["sha256"],
                               "unchanged-original-official-package-code-or-asset"))
    selections.append((ROOT / built_main["path"], "FiveM.exe", built_main["sha256"],
                       "actual-pinned-public-source-MAIN-build"))
    selections.append((ROOT / "build/windows-core/CoreRT.dll", "CoreRT.dll", next(iter(core_hashes)),
                       "actual-pinned-public-source-uninstrumented-CoreRT-runtime-tested-build"))
    tbb = ROOT / "build/windows-core-test/plain/tbb12.dll"
    plain(tbb)
    corresponding_tbb = list((ROOT / "build/windows-core").glob("*/tbb12.dll"))
    if len(corresponding_tbb) != 1 or sha(tbb) != sha(corresponding_tbb[0]):
        raise SystemExit("TBB must match the real ordinary full-CoreRT runtime-test dependency")
    selections.append((tbb, "tbb12.dll", sha(tbb), "actual-pinned-public-TBB-build-used-by-CoreRT-runtime-tests"))
    selection_record = ROOT / "research/client-main-installed-20261101T172840115268Z-results.json"
    selected = json.loads(selection_record.read_text())["game_selection"]
    ini = ROOT / selected["ini"]
    plain(ini)
    if sha(ini) != selected["sha256"] or ini.stat().st_size != 19:
        raise SystemExit("Require the exact user-selected game-only INI")
    configuration = configparser.ConfigParser()
    configuration.read(ini, encoding="utf-8-sig")
    if configuration.sections() != ["Game"] or dict(configuration["Game"]) != {"ivpath": "G:"}:
        raise SystemExit("Refusing any INI data beyond the actual user's game path")
    selections.append((ini, "CitizenFX.ini", selected["sha256"], "user-selected-game-path-only-no-account-data"))
    names = set()
    for source, name, expected, origin in selections:
        if name.casefold() in names:
            raise SystemExit("Duplicate developer-output path")
        names.add(name.casefold())
        plain(source)
        if sha(source) != expected:
            raise SystemExit("Source integration input changed: " + str(source))
    STAGE.mkdir(parents=True)
    for source, name, expected, origin in selections:
        target = STAGE / name
        plain(target)
        target.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["/bin/cp", "-c", str(source), str(target)], check=True)
        if sha(target) != expected:
            raise SystemExit("Source-integration CoW copy changed")
        records.append({"name": name, "source": str(source.relative_to(ROOT)),
                        "origin": origin, "bytes": target.stat().st_size, "sha256": expected})
    marker = STAGE / "FiveM.exe.formaldev"
    marker.write_bytes(b"\r\n")
    records.append({"name": marker.name, "source": "generated-original-premake-postbuild-label",
                    "origin": "upstream-code/client/launcher/premake5.lua:191-194",
                    "bytes": marker.stat().st_size, "sha256": sha(marker)})
    components = json.loads((STAGE / "components.json").read_text())
    if "adhesive" not in components:
        raise SystemExit("Require the complete original component list including the security component")
    record = {
        "at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "source_revision": REVISION,
        "stage": str(STAGE.relative_to(ROOT)), "role": "explicit public-source developer output; not production identity",
        "entrypoint": "FiveM.exe", "arguments": [], "files": records,
        "input_evidence": [{"path": str(path.relative_to(ROOT)), "sha256": sha(path)}
                           for path in (package_record, main_record, core_record, selection_record)],
        "omitted_original_package_artifacts": omitted,
        "original_official_stage_modified": False, "copied_account_or_session_inputs": False,
        "original_component_list_unchanged": True, "security_modules_replaced": False,
        "sdk_tool_or_false_version_identity_selected": False, "nobootstrap_marker_created": False,
        "upstream_developer_postbuild_label_created": True,
        "production_updater_and_its_distribution_hash_pass_skipped_by_original_developer_role": True,
        "runtime_auth_game_cache_wine_security_policy_preserved": True,
        "original_verify_viability_preflight_required_before_run": True,
        "executed": False, "launcher_ui_goal_proven": False,
        "limit": "Own Main/Core/TBB with unchanged official dependency/assets; mixed public/vendor ABI and runtime acceptance untested; no production hash/signature or full anti-cheat claim",
    }
    EVIDENCE.write_text(json.dumps(record, indent=2) + "\n")
    print("Prepared separate explicit developer output:", STAGE)
    print("Files:", len(records), "; original official stage untouched; no execution")
    print("Evidence:", EVIDENCE)


if __name__ == "__main__":
    main()
