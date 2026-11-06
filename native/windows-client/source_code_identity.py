"""Versioned code/asset identity; user profiles, tickets and runtime caches stay opaque."""
import datetime
import json
import os
import re
from pathlib import Path
import subprocess

from run_main import ROOT, REVISION, plain, sha

STAGE = ROOT / "build/windows-source-integration"
PREFIX = ROOT / "prefixes/fivem-source-main"
INITIAL = ROOT / "research/client-source-integration-stage.json"
PRIOR = ROOT / "research/client-source-integration-resume.json"
MANIFEST = ROOT / "research/client-source-code-inputs-v2.json"
TRANSACTION = ROOT / "research/client-source-core-update-v2.json"
BACKUP = ROOT / "build/checkpoints/source-code-updates/core-v2/CoreRT.dll.previous"
AUTH_CONFIRMATION = ROOT / "research/client-source-ui-resume-20261101T182158822131Z-results.json"
OPAQUE = ("CitizenFX.ini", "data/cache/session", "logs", "crashes", "browser profiles and authentication/session storage")


def _inputs():
    initial = json.loads(INITIAL.read_text())
    prior = json.loads(PRIOR.read_text())
    if initial["source_revision"] != REVISION or prior["source_revision"] != REVISION:
        raise RuntimeError("Unexpected source-code pin")
    # The game-path INI is mutable user configuration, not a code identity.
    files = [dict(item) for item in initial["files"] if item["name"] != "CitizenFX.ini"]
    for proof in prior["added_pe_code_proofs"]:
        files.append({"name": proof["name"], "bytes": proof["bytes"], "sha256": proof["sha256"],
                      "origin": "previously-proven-original-GameCache-or-derived-subprocess-code"})
    known = {item["name"] for item in files}
    original = {item["name"]: item for item in initial["files"]}
    generated = {
        "data/cache/subprocess/FiveM_DumpServer": "FiveM.exe",
        "data/cache/subprocess/FiveM_ROSLauncher": "CitizenFX_SubProcess_game_mtl.bin",
        "data/cache/subprocess/FiveM_ROSService": "CitizenFX_SubProcess_game_mtl.bin",
        "data/cache/subprocess/FiveM_ChromeBrowser": "CitizenFX_SubProcess_chrome.bin",
    }
    for name in original:
        build = re.fullmatch(r"CitizenFX_SubProcess_game_(\d+)_aslr\.bin", name)
        if build:
            generated[f"data/cache/subprocess/FiveM_b{build.group(1)}_GameProcess.exe"] = name
    allowed_generated = []
    for name, origin in generated.items():
        expected = original[origin]
        allowed_generated.append({"name": name, "source_artifact": origin, "sha256": expected["sha256"],
                                  "bytes": expected["bytes"]})
        path = STAGE / name
        plain(path)
        if name not in known and path.is_file():
            if sha(path) != expected["sha256"]:
                raise RuntimeError("A generated subprocess differs from its original code artifact: " + name)
            files.append({"name": name, "bytes": path.stat().st_size, "sha256": expected["sha256"],
                          "origin": "byte-identical-original-subprocess-artifact", "source_artifact": origin})
    return files, allowed_generated


def prepare_core_update():
    from source_main_environment import source_main_prefix
    if MANIFEST.exists() or TRANSACTION.exists() or BACKUP.exists():
        raise RuntimeError("Refusing to replace an existing versioned code update")
    tests_path = ROOT / "research/windows-core-results.json"
    fixture_path = ROOT / "research/reserved-unwind-after-results.json"
    tests = json.loads(tests_path.read_text())
    fixture = json.loads(fixture_path.read_text())
    ordinary = [case for case in tests["cases"] if not case["instrumented"]]
    source = ROOT / "build/windows-core/CoreRT.dll"
    new_sha = sha(source)
    if (len(tests["cases"]) != 7 or not all(case["passed"] for case in tests["cases"])
            or not ordinary or any(case["dll_sha256"] != new_sha for case in ordinary)
            or not fixture["passed"]
            or fixture["probe"]["header_sha256"] != sha(ROOT / "port/fivem/code/client/citicore/WineFunctionTable.h")):
        raise RuntimeError("Require the exact rebuilt Core DLL regressions and header fixture evidence")
    confirmation = json.loads(AUTH_CONFIRMATION.read_text())
    if confirmation.get("user_authorized_manual_login_occurred") is not True:
        raise RuntimeError("Require the user's explicit manual-login context; do not inspect authentication data")
    with source_main_prefix(PREFIX, root=ROOT):
        files, generated = _inputs()
        previous_core = dict(next(item for item in files if item["name"] == "CoreRT.dll"))
        for item in files:
            path = STAGE / item["name"]
            plain(path)
            if sha(path) != item["sha256"]:
                raise RuntimeError("Existing code/asset input changed before explicit Core transaction: " + item["name"])
        plain(BACKUP)
        BACKUP.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["/bin/cp", "-c", str(STAGE / "CoreRT.dll"), str(BACKUP)], check=True)
        if sha(BACKUP) != previous_core["sha256"]:
            raise RuntimeError("Old Core code-only backup differs")
        pending = STAGE / ".CoreRT-v2.pending"
        plain(pending)
        if pending.exists():
            raise RuntimeError("Unexpected pending Core code file")
        subprocess.run(["/bin/cp", "-c", str(source), str(pending)], check=True)
        if sha(pending) != new_sha:
            raise RuntimeError("New tested Core DLL copy differs")
        os.replace(pending, STAGE / "CoreRT.dll")
        record = {"at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "source_revision": REVISION,
                  "developer_code_version": 2, "prefix": str(PREFIX.relative_to(ROOT)),
                  "target": "build/windows-source-integration/CoreRT.dll", "previous_sha256": previous_core["sha256"],
                  "new_sha256": new_sha, "source": str(source.relative_to(ROOT)),
                  "previous_code_backup": str(BACKUP.relative_to(ROOT)), "only_this_code_file_replaced": True,
                  "source_evidence": [{"path": str(path.relative_to(ROOT)), "sha256": sha(path)} for path in (
                      tests_path, fixture_path, ROOT / "port/fivem/code/client/citicore/WineFunctionTable.h",
                      ROOT / "port/fivem/code/client/citicore/SEHTableHandler.Win32.cpp")],
                  "profiles_sessions_tickets_read_copied_or_reset": False,
                  "production_manifest_version_or_signature_modified": False,
                  "native_windows_auth_anti_cheat_branches_changed": False}
        for item in files:
            if item["name"] == "CoreRT.dll":
                item.update(sha256=new_sha, bytes=(STAGE / "CoreRT.dll").stat().st_size,
                            origin="explicit-source-Core-v2-with-tested-inert-reserve-unwind-fix")
        TRANSACTION.write_text(json.dumps(record, indent=2) + "\n")
        manifest = {"at": record["at"], "source_revision": REVISION, "developer_code_version": 2,
                    "stage": str(STAGE.relative_to(ROOT)), "files": files,
                    "allowed_generated_subprocess_code": generated,
                    "initial_manifest": str(INITIAL.relative_to(ROOT)), "initial_manifest_sha256": sha(INITIAL),
                    "prior_code_provenance": str(PRIOR.relative_to(ROOT)), "prior_code_provenance_sha256": sha(PRIOR),
                    "core_update_transaction": str(TRANSACTION.relative_to(ROOT)), "core_update_transaction_sha256": sha(TRANSACTION),
                    "manual_login_user_confirmed": True, "auth_confirmation_evidence": str(AUTH_CONFIRMATION.relative_to(ROOT)),
                    "auth_confirmation_evidence_sha256": sha(AUTH_CONFIRMATION), "prefix_is_account_free": False,
                    "opaque_mutable_user_data_not_read_or_hashed": list(OPAQUE),
                    "role": "explicit upstream source-developer client, existing user-authorized session"}
        MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n")
    print("Versioned Core code-only transaction complete:", previous_core["sha256"], "->", new_sha)
    print("Known immutable code/assets:", len(files), "; profile/session/browser data untouched")


def validate_code_inputs(manifest_path=MANIFEST):
    plain(manifest_path)
    record = json.loads(manifest_path.read_text())
    if (record["source_revision"] != REVISION or record["stage"] != str(STAGE.relative_to(ROOT))
            or record["developer_code_version"] not in (2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12) or record["manual_login_user_confirmed"] is not True
            or record["prefix_is_account_free"] is not False):
        raise RuntimeError("Unexpected source code/session role")
    if record["developer_code_version"] == 5:
        # Admit the exact v4 metadata and Core-only delta before any dynamic evidence/code read.
        validate_mapping_version(record)
    elif record["developer_code_version"] == 6:
        import hook_diagnostic_identity
        hook_diagnostic_identity.validate_version(record)
    elif record["developer_code_version"] == 7:
        import file_policy_diagnostic_identity
        file_policy_diagnostic_identity.validate_version(record)
    elif record["developer_code_version"] == 8:
        import toolmode_diagnostic_identity
        toolmode_diagnostic_identity.validate_version(record)
    elif record["developer_code_version"] == 9:
        import lifecycle_diagnostic_identity
        lifecycle_diagnostic_identity.validate_version(record)
    elif record["developer_code_version"] == 10:
        import null_target_fix_identity
        null_target_fix_identity.validate_version(record)
    elif record["developer_code_version"] == 11:
        import graphics_diagnostic_identity
        graphics_diagnostic_identity.validate_version(record)
    elif record["developer_code_version"] == 12:
        import graphics_window_identity
        graphics_window_identity.validate_version(record)
    for path_key, hash_key in (("initial_manifest", "initial_manifest_sha256"),
                               ("prior_code_provenance", "prior_code_provenance_sha256"),
                               ("core_update_transaction", "core_update_transaction_sha256"),
                               ("auth_confirmation_evidence", "auth_confirmation_evidence_sha256")):
        path = ROOT / record[path_key]
        plain(path)
        if sha(path) != record[hash_key]:
            raise RuntimeError("Bound code-only evidence changed: " + record[path_key])
    for item in record["files"]:
        path = STAGE / item["name"]
        plain(path)
        if sha(path) != item["sha256"] or path.stat().st_size != item["bytes"]:
            raise RuntimeError("Known source code/asset bytes changed: " + item["name"])
    if record["developer_code_version"] in (3, 4, 5, 6, 7, 8, 9, 10, 11, 12):
        for key in ("phase_update_transaction", "previous_code_manifest"):
            path = ROOT / record[key]
            plain(path)
            if sha(path) != record[key + "_sha256"]:
                raise RuntimeError("Bound phase-diagnostics transaction changed")
    # This directory is exclusively generated executable copies, not browser/user storage.
    subprocess_root = STAGE / "data/cache/subprocess"
    allowed = {item["name"]: item for item in record["allowed_generated_subprocess_code"]}
    for path in subprocess_root.iterdir():
        plain(path)
        name = str(path.relative_to(STAGE))
        if path.is_file():
            if name not in allowed:
                raise RuntimeError("Unexpected code in the dedicated subprocess directory: " + path.name)
            accepted = [allowed[name]["sha256"], *allowed[name].get("previous_source_code_sha256", [])]
            if sha(path) not in accepted:
                raise RuntimeError("Generated executable bytes differ: " + path.name)
    if (STAGE / "FiveM.exe.formaldev").read_bytes() != b"\r\n" or (STAGE / "nobootstrap.txt").exists():
        raise RuntimeError("Unexpected source-developer role marker")
    if "adhesive" not in json.loads((STAGE / "components.json").read_text()):
        raise RuntimeError("Normal complete security-component list is required")
    return record


def validate_mapping_version(record):
    import mapping_diagnostic_identity as mapping
    for key, expected in (("mapping_previous_manifest", mapping.PREVIOUS_MANIFEST),
                          ("mapping_update_transaction", mapping.TRANSACTION)):
        if record[key] != expected:
            raise RuntimeError("Unexpected v5 mapping evidence reference")
        path = ROOT / expected
        plain(path)
        if sha(path) != record[key + "_sha256"]:
            raise RuntimeError("Bound v5 mapping evidence changed")
    previous = json.loads((ROOT / mapping.PREVIOUS_MANIFEST).read_text())
    transaction = json.loads((ROOT / mapping.TRANSACTION).read_text())
    if (previous["developer_code_version"] != 4 or transaction["developer_code_version"] != 5
            or transaction["source_revision"] != REVISION
            or transaction["mapping_previous_manifest"] != mapping.PREVIOUS_MANIFEST
            or transaction["mapping_previous_manifest_sha256"] != record["mapping_previous_manifest_sha256"]
            or transaction["previous_sha256"] != mapping.PREVIOUS_CORE_SHA256
            or transaction["new_sha256"] != mapping.CORE_SHA256
            or transaction["target"] != str((STAGE / "CoreRT.dll").relative_to(ROOT))
            or transaction["source"] != mapping.SOURCE or transaction["previous_code_backup"] != mapping.BACKUP
            or transaction["header_checks"].get("exit") != 0 or transaction["header_checks"].get("passed") != 2):
        raise RuntimeError("Unexpected mapping-only Core transaction")
    for key, value in previous.items():
        if key not in ("at", "developer_code_version", "files") and record.get(key) != value:
            raise RuntimeError("v5 must preserve existing v4 role and phase provenance: " + key)
    old = {item["name"]: item for item in previous["files"]}
    new = {item["name"]: item for item in record["files"]}
    if (len(old) != len(previous["files"]) or len(new) != len(record["files"]) or old.keys() != new.keys()
            or old["CoreRT.dll"]["sha256"] != mapping.PREVIOUS_CORE_SHA256
            or new["CoreRT.dll"]["sha256"] != mapping.CORE_SHA256
            or any(new[name] != old[name] for name in old if name != "CoreRT.dll")):
        raise RuntimeError("v5 may update only the declared own CoreRT input")
    backup = ROOT / mapping.BACKUP
    plain(backup)
    if sha(backup) != mapping.PREVIOUS_CORE_SHA256:
        raise RuntimeError("Previous source Core backup changed")
    if transaction["diagnostic_evidence"] != mapping.validate_evidence(ROOT):
        raise RuntimeError("The exact tested diagnostic Core/header/fixture inputs changed")


def code_only_snapshot(record):
    result = []
    names = {item["name"] for item in record["files"]}
    candidates = list(record["files"]) + [item for item in record["allowed_generated_subprocess_code"] if item["name"] not in names]
    for item in candidates:
        path = STAGE / item["name"]
        plain(path)
        if path.is_file():
            result.append({"name": item["name"], "bytes": path.stat().st_size, "sha256": sha(path)})
    return {"files": result, "profile_session_browser_cache_and_log_data_inspected": False}


if __name__ == "__main__":
    prepare_core_update()
