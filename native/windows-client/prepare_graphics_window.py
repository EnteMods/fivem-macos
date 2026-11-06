#!/usr/bin/env python3
"""Explicit V11-to-V12 graphics-only publication with its own CoW checkpoint."""
import datetime
import os
import stat
import subprocess
import sys

import graphics_window_identity as diagnostic
from prepare_hook_diagnostic import write_pending
from run_main import ROOT, REVISION, plain, sha
from source_code_identity import STAGE, validate_code_inputs

sys.path.insert(0, str(ROOT / 'scripts'))


def main():
    from source_main_environment import source_main_prefix
    diagnostic._pins()
    previous_path, manifest_path, transaction_path, backup, source = [ROOT / name for name in (
        diagnostic.PREVIOUS_MANIFEST, diagnostic.MANIFEST, diagnostic.TRANSACTION,
        diagnostic.BACKUP, diagnostic.SOURCE)]
    target = STAGE / 'rage-graphics-five.dll'
    pending = STAGE / '.rage-graphics-five.dll.graphics-window-v12.pending'
    manifest_pending, transaction_pending = [path.with_suffix('.json.pending') for path in (manifest_path, transaction_path)]

    def require_absent_outputs():
        for path in (manifest_path, transaction_path, pending, manifest_pending, transaction_pending):
            plain(path)
            if path.exists():
                raise RuntimeError('Refusing an existing V12 graphics-window update or pending file')
        diagnostic.validated_previous_graphics_backup(ROOT)

    def clone(before, after, digest):
        plain(before)
        plain(after)
        if after.exists():
            raise RuntimeError('A graphics-window CoW destination already exists')
        original = before.lstat()
        if not stat.S_ISREG(original.st_mode) or original.st_nlink != 1:
            raise RuntimeError('Graphics-window source must be regular single-link code')
        subprocess.run(['/bin/cp', '-c', '-n', str(before), str(after)], check=True)
        plain(after)
        value = after.lstat()
        if (not stat.S_ISREG(value.st_mode) or value.st_nlink != 1
                or (value.st_dev, value.st_ino) == (original.st_dev, original.st_ino)
                or sha(after) != digest):
            raise RuntimeError('A graphics-window CoW copy differs or aliases its source')

    require_absent_outputs()
    with source_main_prefix(ROOT / 'prefixes/fivem-source-main', root=ROOT):
        require_absent_outputs()
        previous = validate_code_inputs(previous_path)
        if type(previous.get('developer_code_version')) is not int or previous['developer_code_version'] != 11:
            raise RuntimeError('Window diagnostics require exact V11 code inputs')
        evidence = diagnostic.validate_evidence(ROOT)
        command = [sys.executable, '-m', 'unittest', 'discover', '-s', 'native/windows-graphics-window-diagnostics',
                   '-p', 'test_overlay.py', '-v']
        checks = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
        if (checks.returncode != 0 or f'Ran {diagnostic.HEADER_TEST_COUNT} tests' not in checks.stderr
                or '\nOK\n' not in checks.stderr):
            raise RuntimeError('Native graphics-window checks must pass before replacing code')
        if validate_code_inputs(previous_path) != previous or diagnostic.validate_evidence(ROOT) != evidence:
            raise RuntimeError('V11 code or graphics-window evidence changed during checks')
        files = [dict(item) for item in previous['files']]
        candidates = [item for item in files if item['name'] == 'rage-graphics-five.dll']
        if len(files) != 474 or len(candidates) != 1 or candidates[0]['sha256'] != diagnostic.PREVIOUS_GRAPHICS_SHA256:
            raise RuntimeError('Unexpected previous V11 graphics inventory')
        old = candidates[0]
        backup.parent.mkdir(parents=True, exist_ok=True)
        if diagnostic.validated_previous_graphics_backup(ROOT) is None:
            clone(target, backup, old['sha256'])
        changed, created = False, []
        try:
            evidence = diagnostic.validate_evidence(ROOT)
            clone(source, pending, diagnostic.GRAPHICS_SHA256)
            record = {'at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'source_revision': REVISION,
                'developer_code_version': 12, 'target': str(target.relative_to(ROOT)),
                'previous_sha256': old['sha256'], 'new_sha256': diagnostic.GRAPHICS_SHA256,
                'source': diagnostic.SOURCE, 'previous_code_backup': diagnostic.BACKUP,
                'graphics_window_previous_manifest': diagnostic.PREVIOUS_MANIFEST,
                'graphics_window_previous_manifest_sha256': sha(previous_path), 'diagnostic_evidence': evidence,
                'header_checks': {'exit': 0, 'passed': diagnostic.HEADER_TEST_COUNT},
                'only_graphics_file_updated': True, 'other_473_code_entries_and_core10_unchanged': True,
                'original_window_swapchain_returns_controlflow_and_caches_preserved': True,
                'v12_runtime_compatibility_claim': False, 'profiles_sessions_tickets_read_copied_or_reset': False}
            old.update(sha256=diagnostic.GRAPHICS_SHA256, bytes=pending.stat().st_size, origin=diagnostic.ORIGIN)
            write_pending(transaction_pending, record)
            manifest = dict(previous, at=record['at'], developer_code_version=12, files=files,
                graphics_window_previous_manifest=diagnostic.PREVIOUS_MANIFEST,
                graphics_window_previous_manifest_sha256=sha(previous_path), graphics_window_update_transaction=diagnostic.TRANSACTION,
                graphics_window_update_transaction_sha256=sha(transaction_pending))
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
                clone(backup, pending, diagnostic.PREVIOUS_GRAPHICS_SHA256)
                os.replace(pending, target)
            for path in created + [pending, transaction_pending, manifest_pending]:
                if path.exists():
                    path.unlink()
            raise
    print('Explicit V12 graphics-window transaction complete; other code and user data unchanged')


if __name__ == '__main__':
    main()
