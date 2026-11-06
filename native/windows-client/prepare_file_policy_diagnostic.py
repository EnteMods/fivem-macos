#!/usr/bin/env python3
"""Explicit v6-to-v7 own-Core file-policy diagnostic transaction and rollback."""
import datetime
import os
import subprocess
import sys

import file_policy_diagnostic_identity as policy
from prepare_hook_diagnostic import write_pending
from run_main import ROOT, REVISION, plain, sha
from source_code_identity import STAGE, validate_code_inputs

sys.path.insert(0, str(ROOT / "scripts"))


def main():
    from source_main_environment import source_main_prefix
    previous_path = ROOT / policy.PREVIOUS_MANIFEST
    manifest_path = ROOT / policy.MANIFEST
    transaction_path = ROOT / policy.TRANSACTION
    backup = ROOT / policy.BACKUP
    source = ROOT / policy.SOURCE
    target = STAGE / "CoreRT.dll"
    pending = STAGE / ".CoreRT.dll.file-policy-v7.pending"
    manifest_pending = manifest_path.with_suffix(".json.pending")
    transaction_pending = transaction_path.with_suffix(".json.pending")

    def require_absent_outputs():
        for path in (manifest_path, transaction_path, backup, pending, manifest_pending, transaction_pending):
            plain(path)
            if path.exists():
                raise RuntimeError("Refusing an existing v7 update or pending code file: " + str(path))

    require_absent_outputs()
    with source_main_prefix(ROOT / "prefixes/fivem-source-main", root=ROOT):
        require_absent_outputs()
        previous = validate_code_inputs(previous_path)
        if previous["developer_code_version"] != 6:
            raise RuntimeError("File-policy diagnostics require the exact existing v6 source role")
        evidence = policy.validate_evidence(ROOT)
        header_command = [sys.executable, "-m", "unittest", "discover", "-s", "native/windows-core-file-policy-diagnostic",
                          "-p", "test_file_policy_diagnostics.py", "-v"]
        checks = subprocess.run(header_command, cwd=ROOT, capture_output=True, text=True)
        if checks.returncode != 0 or "Ran 6 tests" not in checks.stderr or "\nOK\n" not in checks.stderr:
            raise RuntimeError("The six real file-policy header/overlay tests must pass before changing code")
        if validate_code_inputs(previous_path) != previous or policy.validate_evidence(ROOT) != evidence:
            raise RuntimeError("Code or file-policy evidence changed while checking the update")
        files = [dict(item) for item in previous["files"]]
        old = next(item for item in files if item["name"] == "CoreRT.dll")
        if old["sha256"] != policy.PREVIOUS_CORE_SHA256:
            raise RuntimeError("Unexpected previous v6 own Core")
        backup.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["/bin/cp", "-c", str(target), str(backup)], check=True)
        if sha(backup) != old["sha256"]:
            raise RuntimeError("Previous v6 own-Core backup differs")
        changed = False
        created = []
        try:
            subprocess.run(["/bin/cp", "-c", str(source), str(pending)], check=True)
            if sha(pending) != policy.CORE_SHA256:
                raise RuntimeError("File-policy Core pending copy differs")
            record = {"at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "source_revision": REVISION,
                      "developer_code_version": 7, "target": str(target.relative_to(ROOT)),
                      "previous_sha256": old["sha256"], "new_sha256": policy.CORE_SHA256,
                      "source": policy.SOURCE, "previous_code_backup": policy.BACKUP,
                      "file_policy_previous_manifest": policy.PREVIOUS_MANIFEST,
                      "file_policy_previous_manifest_sha256": sha(previous_path), "diagnostic_evidence": evidence,
                      "header_checks": {"command": header_command, "exit": 0, "passed": policy.HEADER_TEST_COUNT},
                      "only_own_core_file_updated": True, "main_citigame_and_original_modules_unchanged": True,
                      "original_conditions_returns_mapping_authentication_and_security_decisions_preserved": True,
                      "diagnostics": "compile-time opt-in; exact SC basename; fixed operation and four observation bits only",
                      "profiles_sessions_tickets_read_copied_or_reset": False}
            old.update(sha256=policy.CORE_SHA256, bytes=pending.stat().st_size, origin=policy.ORIGIN)
            write_pending(transaction_pending, record)
            manifest = dict(previous)
            manifest.update(at=record["at"], developer_code_version=7, files=files,
                            file_policy_previous_manifest=policy.PREVIOUS_MANIFEST,
                            file_policy_previous_manifest_sha256=sha(previous_path),
                            file_policy_update_transaction=policy.TRANSACTION,
                            file_policy_update_transaction_sha256=sha(transaction_pending))
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
                if sha(pending) != policy.PREVIOUS_CORE_SHA256:
                    raise RuntimeError("Core rollback differs; retain backup and evidence")
                os.replace(pending, target)
            for path in created + [pending, transaction_pending, manifest_pending]:
                if path.exists():
                    path.unlink()
            raise
    print("Explicit v7 file-policy diagnostic Core transaction complete; other code and user data unchanged")


if __name__ == "__main__":
    main()
