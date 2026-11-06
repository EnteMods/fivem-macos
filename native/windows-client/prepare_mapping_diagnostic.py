#!/usr/bin/env python3
"""Apply an explicit v4-to-v5 own-Core diagnostic update with code-only rollback."""
import datetime
import json
import os
import subprocess
import sys

import mapping_diagnostic_identity as mapping
from run_main import ROOT, REVISION, plain, sha
from source_code_identity import STAGE, validate_code_inputs

sys.path.insert(0, str(ROOT / "scripts"))


def write_pending(path, record):
    plain(path)
    with path.open("x") as output:
        json.dump(record, output, indent=2)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())


def main():
    from source_main_environment import source_main_prefix
    previous_path = ROOT / mapping.PREVIOUS_MANIFEST
    manifest_path = ROOT / mapping.MANIFEST
    transaction_path = ROOT / mapping.TRANSACTION
    backup = ROOT / mapping.BACKUP
    source = ROOT / mapping.SOURCE
    target = STAGE / "CoreRT.dll"
    pending = STAGE / ".CoreRT.dll.mapping-v5.pending"
    manifest_pending = manifest_path.with_suffix(".json.pending")
    transaction_pending = transaction_path.with_suffix(".json.pending")
    def require_absent_outputs():
        for path in (manifest_path, transaction_path, backup, pending, manifest_pending, transaction_pending):
            plain(path)
            if path.exists():
                raise RuntimeError("Refusing to replace an existing v5 update or pending code file: " + str(path))

    require_absent_outputs()
    with source_main_prefix(ROOT / "prefixes/fivem-source-main", root=ROOT):
        require_absent_outputs()
        previous = validate_code_inputs(previous_path)
        if previous["developer_code_version"] != 4:
            raise RuntimeError("Mapping diagnostics require the exact existing v4 source role")
        evidence = mapping.validate_evidence(ROOT)
        header_command = [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_mapping_diagnostics.py", "-v"]
        header_checks = subprocess.run(header_command, cwd=ROOT, capture_output=True, text=True)
        if header_checks.returncode != 0 or "Ran 2 tests" not in header_checks.stderr or "\nOK\n" not in header_checks.stderr:
            raise RuntimeError("The two actual mapping header checks must pass before changing code")
        files = [dict(item) for item in previous["files"]]
        old = next(item for item in files if item["name"] == "CoreRT.dll")
        if old["sha256"] != mapping.PREVIOUS_CORE_SHA256:
            raise RuntimeError("Unexpected previous source Core")
        backup.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["/bin/cp", "-c", str(target), str(backup)], check=True)
        if sha(backup) != old["sha256"]:
            raise RuntimeError("Previous Core code-only backup differs")
        changed = False
        created = []
        try:
            subprocess.run(["/bin/cp", "-c", str(source), str(pending)], check=True)
            if sha(pending) != mapping.CORE_SHA256:
                raise RuntimeError("Diagnostic Core pending copy differs")
            record = {"at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "source_revision": REVISION,
                      "developer_code_version": 5, "target": str(target.relative_to(ROOT)),
                      "previous_sha256": old["sha256"], "new_sha256": mapping.CORE_SHA256,
                      "source": mapping.SOURCE, "previous_code_backup": mapping.BACKUP,
                      "mapping_previous_manifest": mapping.PREVIOUS_MANIFEST,
                      "mapping_previous_manifest_sha256": sha(previous_path), "diagnostic_evidence": evidence,
                      "header_checks": {"command": header_command, "exit": 0, "passed": 2},
                      "only_own_core_file_updated": True, "main_citigame_and_original_modules_unchanged": True,
                      "original_conditions_returns_mapping_authentication_and_security_decisions_preserved": True,
                      "diagnostics": "compile-time opt-in; fixed mapping phases, PID and three booleans only",
                      "profiles_sessions_tickets_read_copied_or_reset": False}
            old.update(sha256=mapping.CORE_SHA256, bytes=pending.stat().st_size,
                       origin="public-source-Core-v5-fixed-field-mapping-diagnostics")
            write_pending(transaction_pending, record)
            manifest = dict(previous)
            manifest.update(at=record["at"], developer_code_version=5, files=files,
                            mapping_previous_manifest=mapping.PREVIOUS_MANIFEST,
                            mapping_previous_manifest_sha256=sha(previous_path),
                            mapping_update_transaction=mapping.TRANSACTION,
                            mapping_update_transaction_sha256=sha(transaction_pending))
            write_pending(manifest_pending, manifest)
            os.replace(pending, target)
            changed = True
            os.replace(transaction_pending, transaction_path)
            created.append(transaction_path)
            os.replace(manifest_pending, manifest_path)
            created.append(manifest_path)
            validate_code_inputs(manifest_path)
        except BaseException:
            if changed:
                subprocess.run(["/bin/cp", "-c", str(backup), str(pending)], check=True)
                if sha(pending) != mapping.PREVIOUS_CORE_SHA256:
                    raise RuntimeError("Core rollback bytes differ; preserve backup and all evidence")
                os.replace(pending, target)
            for path in created + [pending, transaction_pending, manifest_pending]:
                if path.exists():
                    path.unlink()
            raise
    print("Explicit v5 mapping-diagnostic Core transaction complete; all other code and user data unchanged")


if __name__ == "__main__":
    main()
