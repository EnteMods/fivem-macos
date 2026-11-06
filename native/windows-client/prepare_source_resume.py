#!/usr/bin/env python3
"""Bind the real source-run output/checkpoint and prove newly cached PE-code origins."""
import datetime
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from run_main import ROOT, REVISION, plain, sha

STAGE = ROOT / "build/windows-source-integration"
INITIAL = ROOT / "research/client-source-integration-stage.json"
CHECKPOINT_RECORD = ROOT / "research/client-source-rgl-checkpoint.json"
CHECKPOINT = ROOT / "build/checkpoints/source-main-rgl-missing"
OUTPUT = ROOT / "research/client-source-integration-resume.json"
ADVANCED_OUTPUT = ROOT / "research/client-source-integration-resume-487.json"
DIAGNOSTIC_RUN = ROOT / "research/client-source-ui-resume-20261101T181137265605Z-results.json"
DIAGNOSTIC_CHECKPOINT = ROOT / "build/checkpoints/source-main-service-diagnostics"
DIAGNOSTIC_CHECKPOINT_RECORD = ROOT / "research/client-source-service-diagnostics-checkpoint.json"
GAMECACHE_PATH = "code/client/launcher/GameCache.cpp"
DERIVED_CODE = {
    "data/cache/subprocess/FiveM_DumpServer": "FiveM.exe",
    "data/cache/subprocess/FiveM_ROSLauncher": "CitizenFX_SubProcess_game_mtl.bin",
}


def digest(path, algorithm):
    result = hashlib.new(algorithm)
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def create_record():
    initial = json.loads(INITIAL.read_text())
    checkpoint = json.loads(CHECKPOINT_RECORD.read_text())
    if (initial["source_revision"] != REVISION or initial["stage"] != str(STAGE.relative_to(ROOT))
            or checkpoint["checkpoint"] != str(CHECKPOINT.relative_to(ROOT))
            or not checkpoint["all_hashes_match_record"] or checkpoint["files_verified"] != 485):
        raise RuntimeError("Require the exact reviewed source-output and 485-file checkpoint")
    previous_path = ROOT / checkpoint["source_record"]
    plain(previous_path)
    if sha(previous_path) != checkpoint["source_record_sha256"]:
        raise RuntimeError("The bound source-run evidence changed after the verified checkpoint")
    previous = json.loads(previous_path.read_text())
    if (previous["source_revision"] != REVISION or previous["stage"] != str(STAGE.relative_to(ROOT))
            or previous["input_manifest"] != str(INITIAL.relative_to(ROOT))
            or previous["input_manifest_sha256"] != sha(INITIAL)
            or previous.get("isolation_guard_failure") or previous.get("runner_failure")
            or previous["source_stage_inventory_after"].get("error")
            or previous["prefix_cleanup"]["wait_timed_out"] or previous["prefix_cleanup"]["wait_exit"] != 0):
        raise RuntimeError("Require the actual safely completed source-client run")
    pinned = subprocess.run(["git", "-C", str(ROOT / "upstream/fivem"), "show", REVISION + ":" + GAMECACHE_PATH],
                            capture_output=True, check=True).stdout
    source = ROOT / "upstream/fivem" / GAMECACHE_PATH
    if source.read_bytes() != pinned:
        raise RuntimeError("Cache-package source differs from the pinned upstream revision")
    source_lines = pinned.decode().splitlines()
    by_initial = {item["name"]: item for item in initial["files"]}
    files, added_code, added_data = [], [], []
    for item in previous["source_stage_inventory_after"]["files"]:
        path = ROOT / item["path"]
        relative = str(path.relative_to(STAGE))
        plain(path)
        saved = CHECKPOINT / relative
        plain(saved)
        if (sha(path) != item["sha256"] or sha(saved) != item["sha256"]
                or path.stat().st_size != item["bytes"]):
            raise RuntimeError("Source output/checkpoint differs from the actual completed run: " + relative)
        if relative in by_initial:
            if item["sha256"] != by_initial[relative]["sha256"]:
                raise RuntimeError("An original source/code/security/asset input changed: " + relative)
        else:
            with path.open("rb") as binary:
                is_pe = binary.read(2) == b"MZ"
            if is_pe:
                proof = {"name": relative, "bytes": item["bytes"], "sha256": item["sha256"]}
                if relative in DERIVED_CODE:
                    origin = DERIVED_CODE[relative]
                    if item["sha256"] != by_initial[origin]["sha256"]:
                        raise RuntimeError("Generated subprocess bytes differ from the actual original source artifact")
                    proof.update(kind="byte-identical-copy-of-initial-code", initial_artifact=origin,
                                 implementation="code/client/shared/CfxSubProcess.h:13-145")
                elif relative.startswith("data/game-storage/"):
                    fingerprint = digest(path, "sha1")
                    logical_name = relative.removeprefix("data/game-storage/")
                    suffix = "_" + fingerprint
                    if logical_name.endswith(suffix):
                        logical_name = logical_name[:-len(suffix)].replace("+", "/")
                    matches = [{"line": number, "original_initializer": line.strip()}
                               for number, line in enumerate(source_lines, 1)
                               if fingerprint in line.casefold() and ('"' + logical_name + '"') in line]
                    if not matches:
                        raise RuntimeError("New cached PE lacks an exact filename/SHA1 source initializer: " + relative)
                    proof.update(kind="unchanged-normal-GameCache-source-package", sha1=fingerprint,
                                 source_file=GAMECACHE_PATH, source_matches=matches)
                else:
                    raise RuntimeError("Refusing an unproven newly generated PE-code file: " + relative)
                added_code.append(proof)
            else:
                added_data.append({"name": relative, "bytes": item["bytes"], "sha256": item["sha256"],
                                   "origin": "exact non-PE runtime output bound to the real completed source run and checkpoint"})
        files.append({"name": relative, "bytes": item["bytes"], "sha256": item["sha256"]})
    if {item["name"] for item in files}.intersection(by_initial) != set(by_initial):
        raise RuntimeError("Source-run inventory lost an original input")
    actual = set()
    for path in STAGE.rglob("*"):
        plain(path)
        if path.is_file():
            actual.add(str(path.relative_to(STAGE)))
    if actual != {item["name"] for item in files}:
        raise RuntimeError("Refusing source-stage extras outside the reviewed post-run inventory")
    record = {
        "at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "source_revision": REVISION,
        "stage": str(STAGE.relative_to(ROOT)), "files": files,
        "initial_manifest": str(INITIAL.relative_to(ROOT)), "initial_manifest_sha256": sha(INITIAL),
        "checkpoint_record": str(CHECKPOINT_RECORD.relative_to(ROOT)), "checkpoint_record_sha256": sha(CHECKPOINT_RECORD),
        "checkpoint": str(CHECKPOINT.relative_to(ROOT)),
        "source_run_record": str(previous_path.relative_to(ROOT)), "source_run_record_sha256": sha(previous_path),
        "gamecache_source": GAMECACHE_PATH, "gamecache_source_sha256": hashlib.sha256(pinned).hexdigest(),
        "added_pe_code_proofs": added_code, "added_non_pe_runtime_data": added_data,
        "all_original_source_and_security_inputs_unchanged": True, "new_pe_with_unknown_origin": [],
        "files_copied_or_replaced": False, "production_manifest_or_hashes_modified": False,
        "executed": False,
        "limit": "Independent source-developer continuation inventory, not a production identity or authentication/anti-cheat acceptance proof",
    }
    OUTPUT.write_text(json.dumps(record, indent=2) + "\n")
    print("Prepared verified in-place source continuation:", len(files), "files")
    print("New PE origins proven:", len(added_code), "; new non-PE runtime outputs:", len(added_data))
    print("No stage/code files copied, replaced or executed")
    return record


def validate_record(manifest=OUTPUT):
    if manifest not in (OUTPUT, ADVANCED_OUTPUT):
        raise RuntimeError("Unexpected developer continuation record")
    plain(manifest)
    record = json.loads(manifest.read_text())
    if (record["source_revision"] != REVISION or record["stage"] != str(STAGE.relative_to(ROOT))
            or not record["all_original_source_and_security_inputs_unchanged"]
            or record["new_pe_with_unknown_origin"] or record["files_copied_or_replaced"]
            or record["production_manifest_or_hashes_modified"]):
        raise RuntimeError("Unexpected developer continuation policy")
    for name, checksum in (("initial_manifest", "initial_manifest_sha256"),
                           ("checkpoint_record", "checkpoint_record_sha256"),
                           ("source_run_record", "source_run_record_sha256")):
        path = ROOT / record[name]
        plain(path)
        if sha(path) != record[checksum]:
            raise RuntimeError("Bound developer continuation evidence changed: " + record[name])
    if "previous_resume_manifest" in record:
        previous = ROOT / record["previous_resume_manifest"]
        plain(previous)
        if previous != OUTPUT or sha(previous) != record["previous_resume_manifest_sha256"]:
            raise RuntimeError("The previous 485-file continuation proof changed")
    checkpoint = ROOT / record["checkpoint"]
    if checkpoint not in (CHECKPOINT, DIAGNOSTIC_CHECKPOINT):
        raise RuntimeError("Unexpected developer checkpoint root")
    if sha(ROOT / "upstream/fivem" / GAMECACHE_PATH) != record["gamecache_source_sha256"]:
        raise RuntimeError("Pinned GameCache package evidence changed")
    for item in record["files"]:
        path = STAGE / item["name"]
        plain(path)
        saved = checkpoint / item["name"]
        plain(saved)
        if (sha(path) != item["sha256"] or path.stat().st_size != item["bytes"]
                or sha(saved) != item["sha256"]):
            raise RuntimeError("Developer continuation bytes changed: " + item["name"])
    return record


def advance_service_diagnostics():
    previous = validate_record()
    after = json.loads(DIAGNOSTIC_RUN.read_text())
    expected_failure = {"type": "ProbePrefixError", "message": "Refusing a client installation in the fresh source-MAIN prefix."}
    if (after["input_manifest"] != str(OUTPUT.relative_to(ROOT))
            or after["input_manifest_sha256"] != sha(OUTPUT)
            or after["source_revision"] != REVISION or after["stage"] != str(STAGE.relative_to(ROOT))
            or after["isolation_guard_failure"] != expected_failure or after["runner_failure"] is not None
            or after["parent_exit_before_cleanup"] is not None
            or after["prefix_cleanup"]["wait_exit"] != 0 or after["prefix_cleanup"]["wait_timed_out"]
            or after["source_stage_inventory_after"]["error"] is not None):
        raise RuntimeError("Require the exact acknowledged service-diagnostics guard interruption")
    old = {item["name"]: item for item in previous["files"]}
    files = []
    for item in after["source_stage_inventory_after"]["files"]:
        path = ROOT / item["path"]
        name = str(path.relative_to(STAGE))
        plain(path)
        if sha(path) != item["sha256"]:
            raise RuntimeError("Post-interruption source output changed: " + name)
        files.append({"name": name, "bytes": item["bytes"], "sha256": item["sha256"]})
    new = {item["name"]: item for item in files}
    added = set(new) - set(old)
    expected_added = {"data/cache/session", "logs/CitizenFX_log_2026-11-01T181142.log"}
    if len(new) != 487 or set(old) - set(new) or added != expected_added:
        raise RuntimeError("Require exactly the known two new non-PE runtime diagnostics")
    if any(old[name]["sha256"] != new[name]["sha256"] for name in old):
        raise RuntimeError("A prior source/code/security/runtime input changed")
    for name in added:
        with (STAGE / name).open("rb") as source:
            if source.read(2) == b"MZ":
                raise RuntimeError("A supposed runtime diagnostic is executable PE code")
    actual = set()
    for path in STAGE.rglob("*"):
        plain(path)
        if path.is_file():
            actual.add(str(path.relative_to(STAGE)))
    if actual != set(new):
        raise RuntimeError("Source stage has extras outside the bound 487-file output")
    plain(DIAGNOSTIC_CHECKPOINT)
    if DIAGNOSTIC_CHECKPOINT.exists():
        raise RuntimeError("Refusing to replace an existing diagnostics checkpoint")
    subprocess.run(["/bin/cp", "-cR", str(STAGE), str(DIAGNOSTIC_CHECKPOINT)], check=True)
    for item in files:
        path = DIAGNOSTIC_CHECKPOINT / item["name"]
        plain(path)
        if sha(path) != item["sha256"]:
            raise RuntimeError("Service-diagnostics checkpoint differs")
    snapshot = {"at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "checkpoint": str(DIAGNOSTIC_CHECKPOINT.relative_to(ROOT)),
                "source_record": str(DIAGNOSTIC_RUN.relative_to(ROOT)), "source_record_sha256": sha(DIAGNOSTIC_RUN),
                "source_stage": str(STAGE.relative_to(ROOT)), "files_verified": len(files),
                "file_bytes": sum(item["bytes"] for item in files), "all_hashes_match_record": True,
                "copy": "APFS clone /bin/cp -cR", "no_code_changed": True,
                "known_guard_conflict": "fresh ProgramData/Rockstar Games/Launcher service diagnostics",
                "launcher_ui_success_claim": False, "executed_from_checkpoint": False}
    DIAGNOSTIC_CHECKPOINT_RECORD.write_text(json.dumps(snapshot, indent=2) + "\n")
    record = dict(previous)
    record.update(at=snapshot["at"], files=files,
                  previous_resume_manifest=str(OUTPUT.relative_to(ROOT)), previous_resume_manifest_sha256=sha(OUTPUT),
                  checkpoint_record=str(DIAGNOSTIC_CHECKPOINT_RECORD.relative_to(ROOT)),
                  checkpoint_record_sha256=sha(DIAGNOSTIC_CHECKPOINT_RECORD),
                  checkpoint=str(DIAGNOSTIC_CHECKPOINT.relative_to(ROOT)),
                  source_run_record=str(DIAGNOSTIC_RUN.relative_to(ROOT)), source_run_record_sha256=sha(DIAGNOSTIC_RUN),
                  acknowledged_guard_interruption=expected_failure,
                  prefix_diagnostics_migration_required_before_run=True,
                  added_non_pe_runtime_data=previous["added_non_pe_runtime_data"] + [dict(new[name], origin="exact two reviewed non-PE outputs from the acknowledged service-diagnostics guard interruption") for name in sorted(added)])
    ADVANCED_OUTPUT.write_text(json.dumps(record, indent=2) + "\n")
    print("Prepared exact 487-file continuation; prior 485 and original 424 inputs unchanged")
    print("Only added data/cache/session and the recorded CitizenFX log; no new PE code")
    print("A validated prefix diagnostics migration remains mandatory before any new run")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "advance-service-diagnostics"), nargs="?", default="prepare")
    if parser.parse_args().action == "advance-service-diagnostics":
        advance_service_diagnostics()
    else:
        create_record()
