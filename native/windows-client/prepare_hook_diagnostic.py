#!/usr/bin/env python3
"""Explicit v5-to-v6 own-Core diagnostic transaction with code-only rollback."""
import datetime
import json
import os
import subprocess
import sys

import hook_diagnostic_identity as hook
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
    previous_path = ROOT / hook.PREVIOUS_MANIFEST
    manifest_path = ROOT / hook.MANIFEST
    transaction_path = ROOT / hook.TRANSACTION
    backup = ROOT / hook.BACKUP
    source = ROOT / hook.SOURCE
    target = STAGE / "CoreRT.dll"
    pending = STAGE / ".CoreRT.dll.hook-v6.pending"
    manifest_pending = manifest_path.with_suffix(".json.pending")
    transaction_pending = transaction_path.with_suffix(".json.pending")

    def require_absent_outputs():
        for path in (manifest_path, transaction_path, backup, pending, manifest_pending, transaction_pending):
            plain(path)
            if path.exists():
                raise RuntimeError("Refusing an existing v6 update or pending code file: " + str(path))

    require_absent_outputs()
    with source_main_prefix(ROOT / "prefixes/fivem-source-main", root=ROOT):
        require_absent_outputs()
        previous = validate_code_inputs(previous_path)
        if previous["developer_code_version"] != 5:
            raise RuntimeError("Hook diagnostics require the exact existing v5 source role")
        evidence = hook.validate_evidence(ROOT)
        header_command = [sys.executable, "-m", "unittest", "discover", "-s", "native/windows-core-hook-diagnostic",
                          "-p", "test_hook_diagnostics.py", "-v"]
        checks = subprocess.run(header_command, cwd=ROOT, capture_output=True, text=True)
        if (checks.returncode != 0 or "Ran 5 tests" not in checks.stderr
                or "\nOK\n" not in checks.stderr):
            raise RuntimeError("The five actual hook header/overlay checks must pass before changing code")
        # Recheck code/evidence after the tests and while holding the same MAIN lock.
        if validate_code_inputs(previous_path) != previous or hook.validate_evidence(ROOT) != evidence:
            raise RuntimeError("Code or hook evidence changed while checking the update")
        files = [dict(item) for item in previous["files"]]
        old = next(item for item in files if item["name"] == "CoreRT.dll")
        if old["sha256"] != hook.PREVIOUS_CORE_SHA256:
            raise RuntimeError("Unexpected previous v5 own Core")
        backup.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["/bin/cp", "-c", str(target), str(backup)], check=True)
        if sha(backup) != old["sha256"]:
            raise RuntimeError("Previous v5 Core code-only backup differs")
        changed = False
        created = []
        try:
            subprocess.run(["/bin/cp", "-c", str(source), str(pending)], check=True)
            if sha(pending) != hook.CORE_SHA256:
                raise RuntimeError("Hook diagnostic Core pending copy differs")
            record = {"at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "source_revision": REVISION,
                      "developer_code_version": 6, "target": str(target.relative_to(ROOT)),
                      "previous_sha256": old["sha256"], "new_sha256": hook.CORE_SHA256,
                      "source": hook.SOURCE, "previous_code_backup": hook.BACKUP,
                      "hook_previous_manifest": hook.PREVIOUS_MANIFEST,
                      "hook_previous_manifest_sha256": sha(previous_path), "diagnostic_evidence": evidence,
                      "header_checks": {"command": header_command, "exit": 0, "passed": hook.HEADER_TEST_COUNT},
                      "only_own_core_file_updated": True, "main_citigame_and_original_modules_unchanged": True,
                      "original_conditions_returns_mapping_authentication_and_security_decisions_preserved": True,
                      "diagnostics": "compile-time opt-in; fixed enum hook phases, PID and bounded MinHook status only",
                      "profiles_sessions_tickets_read_copied_or_reset": False}
            old.update(sha256=hook.CORE_SHA256, bytes=pending.stat().st_size, origin=hook.ORIGIN)
            write_pending(transaction_pending, record)
            manifest = dict(previous)
            manifest.update(at=record["at"], developer_code_version=6, files=files,
                            hook_previous_manifest=hook.PREVIOUS_MANIFEST,
                            hook_previous_manifest_sha256=sha(previous_path),
                            hook_update_transaction=hook.TRANSACTION,
                            hook_update_transaction_sha256=sha(transaction_pending))
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
                if sha(pending) != hook.PREVIOUS_CORE_SHA256:
                    raise RuntimeError("Core rollback differs; preserve the backup and all evidence")
                os.replace(pending, target)
            for path in created + [pending, transaction_pending, manifest_pending]:
                if path.exists():
                    path.unlink()
            raise
    print("Explicit v6 hook-diagnostic Core transaction complete; other code and user data unchanged")


if __name__ == "__main__":
    main()
