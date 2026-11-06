#!/usr/bin/env python3
"""Explicit v9-to-v10 own-Core transaction with a preserved CoW backup."""
import datetime
import os
import subprocess
import sys

import null_target_fix_identity as diagnostic
from prepare_hook_diagnostic import write_pending
from run_main import ROOT, REVISION, plain, sha
from source_code_identity import STAGE, validate_code_inputs

sys.path.insert(0, str(ROOT / 'scripts'))


def main():
    from source_main_environment import source_main_prefix
    diagnostic._pins()
    previous_path, manifest_path, transaction_path, backup, source = [ROOT / name for name in (
        diagnostic.PREVIOUS_MANIFEST, diagnostic.MANIFEST, diagnostic.TRANSACTION, diagnostic.BACKUP, diagnostic.SOURCE)]
    target = STAGE / 'CoreRT.dll'
    pending = STAGE / '.CoreRT.dll.null-target-v10.pending'
    manifest_pending, transaction_pending = [path.with_suffix('.json.pending') for path in (manifest_path, transaction_path)]

    def require_absent_outputs():
        for path in (manifest_path, transaction_path, backup, pending, manifest_pending, transaction_pending):
            plain(path)
            if path.exists():
                raise RuntimeError('Refusing an existing v10 update or pending code file: ' + str(path))

    def clone(before, after, digest):
        plain(before)
        plain(after)
        if after.exists():
            raise RuntimeError('A NULL-target clone destination already exists')
        subprocess.run(['/bin/cp', '-c', '-n', str(before), str(after)], check=True)
        value, original = after.lstat(), before.lstat()
        if (value.st_nlink != 1 or (value.st_dev, value.st_ino) == (original.st_dev, original.st_ino)
                or sha(after) != digest):
            raise RuntimeError('A NULL-target CoW code copy differs or aliases its source')

    require_absent_outputs()
    with source_main_prefix(ROOT / 'prefixes/fivem-source-main', root=ROOT):
        require_absent_outputs()
        previous = validate_code_inputs(previous_path)
        if previous.get('developer_code_version') != 9:
            raise RuntimeError('NULL-target fix requires the exact existing v9 source role')
        evidence = diagnostic.validate_evidence(ROOT)
        command = [sys.executable, '-m', 'unittest', 'discover', '-s', 'native/windows-core-null-target-fix',
                   '-p', 'test_null_target_fix.py', '-v']
        checks = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
        if (checks.returncode != 0 or f'Ran {diagnostic.HEADER_TEST_COUNT} tests' not in checks.stderr
                or '\nOK\n' not in checks.stderr):
            raise RuntimeError('All native NULL-target header/overlay checks must pass before changing code')
        if validate_code_inputs(previous_path) != previous or diagnostic.validate_evidence(ROOT) != evidence:
            raise RuntimeError('Code or NULL-target evidence changed during the update checks')
        files = [dict(item) for item in previous['files']]
        old = next(item for item in files if item['name'] == 'CoreRT.dll')
        if old['sha256'] != diagnostic.PREVIOUS_CORE_SHA256:
            raise RuntimeError('Unexpected previous v9 own Core')
        backup.parent.mkdir(parents=True, exist_ok=True)
        clone(target, backup, old['sha256'])
        changed, created = False, []
        try:
            clone(source, pending, diagnostic.CORE_SHA256)
            record = {'at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'source_revision': REVISION,
                'developer_code_version': 10, 'target': str(target.relative_to(ROOT)),
                'previous_sha256': old['sha256'], 'new_sha256': diagnostic.CORE_SHA256,
                'source': diagnostic.SOURCE, 'previous_code_backup': diagnostic.BACKUP,
                'null_target_previous_manifest': diagnostic.PREVIOUS_MANIFEST,
                'null_target_previous_manifest_sha256': sha(previous_path), 'diagnostic_evidence': evidence,
                'header_checks': {'exit': 0, 'passed': diagnostic.HEADER_TEST_COUNT},
                'only_own_core_file_updated': True, 'main_citigame_and_original_modules_unchanged': True,
                'original_conditions_returns_mapping_authentication_and_security_decisions_preserved': True,
                'v10_wine_runtime_fixture_claim': False, 'profiles_sessions_tickets_read_copied_or_reset': False}
            old.update(sha256=diagnostic.CORE_SHA256, bytes=pending.stat().st_size, origin=diagnostic.ORIGIN)
            write_pending(transaction_pending, record)
            manifest = dict(previous, at=record['at'], developer_code_version=10, files=files,
                null_target_previous_manifest=diagnostic.PREVIOUS_MANIFEST,
                null_target_previous_manifest_sha256=sha(previous_path), null_target_update_transaction=diagnostic.TRANSACTION,
                null_target_update_transaction_sha256=sha(transaction_pending))
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
                clone(backup, pending, diagnostic.PREVIOUS_CORE_SHA256)
                os.replace(pending, target)
            for path in created + [pending, transaction_pending, manifest_pending]:
                if path.exists():
                    path.unlink()
            raise
    print('Explicit v10 NULL-target Core transaction complete; all other code and user data unchanged')


if __name__ == '__main__':
    main()
