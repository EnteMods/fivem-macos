#!/usr/bin/env python3
"""Stage explicit public Main/CitiGame phase diagnostics, never runtime user data."""
import datetime
import json
from pathlib import Path
import os
import subprocess
import sys

from source_code_identity import validate_code_inputs, ROOT, STAGE
from run_main import plain, sha, REVISION

PREVIOUS = ROOT / "research/client-source-code-inputs-v2.json"
MANIFEST = ROOT / "research/client-source-code-inputs-v3.json"
TRANSACTION = ROOT / "research/client-source-phase-update-v3.json"
sys.path.insert(0, str(ROOT / "scripts"))


def main():
    from source_main_environment import source_main_prefix
    if MANIFEST.exists() or TRANSACTION.exists():
        raise RuntimeError("Refusing to replace an existing phase-code transaction")
    replacements = {
        "FiveM.exe": ROOT / "build/windows-client/FiveM.exe",
        "CitizenGame.dll": ROOT / "build/windows-client/dependencies/launcher/CitizenGame.dll",
    }
    with source_main_prefix(ROOT / "prefixes/fivem-source-main", root=ROOT):
        previous = validate_code_inputs(PREVIOUS)
        files = [dict(item) for item in previous["files"]]
        updates = []
        for name, source in replacements.items():
            plain(source)
            target = STAGE / name
            old = next(item for item in files if item["name"] == name)
            backup = ROOT / "build/checkpoints/source-code-updates/phase-v3" / (name + ".previous")
            plain(backup)
            backup.parent.mkdir(parents=True, exist_ok=True)
            if backup.exists():
                raise RuntimeError("Refusing phase-code backup overwrite")
            subprocess.run(["/bin/cp", "-c", str(target), str(backup)], check=True)
            if sha(backup) != old["sha256"]:
                raise RuntimeError("Original code-only backup differs")
            pending = STAGE / ("." + name + ".phase-v3.pending")
            plain(pending)
            if pending.exists():
                raise RuntimeError("Unexpected pending phase code")
            new_sha = sha(source)
            subprocess.run(["/bin/cp", "-c", str(source), str(pending)], check=True)
            if sha(pending) != new_sha:
                raise RuntimeError("Source-built phase code copy differs")
            os.replace(pending, target)
            updates.append({"name": name, "previous_sha256": old["sha256"], "new_sha256": new_sha,
                            "source": str(source.relative_to(ROOT)), "backup": str(backup.relative_to(ROOT))})
            old.update(sha256=new_sha, bytes=target.stat().st_size, origin="public-source-phase-diagnostics-build")
        generated = [dict(item) for item in previous["allowed_generated_subprocess_code"]]
        for item in generated:
            if item["source_artifact"] in replacements:
                update = next(value for value in updates if value["name"] == item["source_artifact"])
                item.update(sha256=update["new_sha256"], previous_source_code_sha256=[update["previous_sha256"]])
        aliases = {item["name"] for item in generated}
        files = [item for item in files if item["name"] not in aliases]
        record = {"at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "source_revision": REVISION,
                  "developer_code_version": 3, "updates": updates,
                  "only_public_main_and_citigame_code_updated": True,
                  "sticky_legitimacy_or_security_module_modified": False,
                  "original_conditions_returns_and_authentication_decisions_preserved": True,
                  "diagnostic_payload": "fixed code-phase names, PID/TID and numeric values only; LastError preserved",
                  "source_evidence": [{"path": str(path.relative_to(ROOT)), "sha256": sha(path)} for path in (
                      ROOT / "port/fivem/code/client/shared/StartupPhaseTrace.h",
                      ROOT / "port/fivem/code/client/launcher/Main.cpp",
                      ROOT / "port/fivem/code/client/citigame/Launcher.cpp",
                      ROOT / "native/windows-client/CMakeLists.txt")],
                  "profiles_sessions_tickets_read_copied_or_reset": False}
        TRANSACTION.write_text(json.dumps(record, indent=2) + "\n")
        manifest = dict(previous)
        manifest.update(at=record["at"], developer_code_version=3, files=files,
                        allowed_generated_subprocess_code=generated,
                        previous_code_manifest=str(PREVIOUS.relative_to(ROOT)), previous_code_manifest_sha256=sha(PREVIOUS),
                        phase_update_transaction=str(TRANSACTION.relative_to(ROOT)), phase_update_transaction_sha256=sha(TRANSACTION))
        MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n")
    print("Public Main/CitiGame phase-code transaction complete; immutable code/assets:", len(files))
    print("Core/Sticky/legitimacy/security and all user runtime data unchanged")


if __name__ == "__main__":
    main()
