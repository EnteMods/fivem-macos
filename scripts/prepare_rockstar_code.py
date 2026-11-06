#!/usr/bin/env python3
"""Prepare an account-free copy of the already installed Rockstar program files."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import subprocess

from source_main_environment import source_main_prefix

ROOT = Path(__file__).resolve().parents[1]
DONOR = ROOT.parent / 'GTA-V-macOS/prefixes/rockstar-legacy'
PREFIX = ROOT / 'prefixes/fivem-source-main'
SOURCE_RECORD = ROOT / 'research/rockstar-code-only-source.json'
INSTALL_RECORD = ROOT / 'research/rockstar-code-only-install.json'
CODE_ROOTS = (
    'drive_c/Program Files/Rockstar Games/Launcher',
    'drive_c/Program Files/Rockstar Games/Social Club',
)


def plain(path):
    if path.absolute() != path.resolve():
        raise RuntimeError('Refusing a redirected Rockstar code path: ' + str(path))


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def source_inventory():
    files = []
    for relative in CODE_ROOTS:
        directory = DONOR / relative
        plain(directory)
        if not directory.is_dir():
            raise RuntimeError('Required existing Rockstar program directory is missing')
        for path in sorted(directory.rglob('*')):
            plain(path)
            if not path.is_file():
                if not path.is_dir():
                    raise RuntimeError('Unexpected non-file in program directory')
                continue
            if any(token in path.name.casefold() for token in ('cfxticket', 'ros_login', 'cookies', 'login.json', 'login.dat')):
                raise RuntimeError('Account artifact must never be imported as program code')
            stat = path.stat()
            files.append({'path': str(path.relative_to(DONOR)), 'bytes': stat.st_size,
                          'sha256': sha(path), 'source_inode': stat.st_ino,
                          'source_mtime_ns': stat.st_mtime_ns})
    return files


def prepare_inventory():
    record = {
        'at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'kind': 'existing-official-rockstar-program-files', 'source_prefix': str(DONOR),
        'roots': list(CODE_ROOTS), 'files': source_inventory(),
        'scope': 'Only installed program binaries and shipping assets, from the legal existing installation on this Mac.',
        'user_profiles_registry_hives_tickets_or_sessions_read_or_copied': False,
        'whole_prefix_copy': False, 'software_executed': False,
    }
    if SOURCE_RECORD.exists():
        plain(SOURCE_RECORD)
        previous = json.loads(SOURCE_RECORD.read_text())
        comparable = lambda value: {key: item for key, item in value.items() if key != 'at'}
        if comparable(previous) != comparable(record):
            raise RuntimeError('Existing pinned Rockstar evidence differs; use a separately reviewed update transaction')
        print('Existing identical Rockstar source evidence retained; no rewrite.')
        return
    SOURCE_RECORD.write_text(json.dumps(record, indent=2) + '\n')
    print('Rockstar program-only source inventory:', len(record['files']), 'files')
    print('Evidence:', SOURCE_RECORD)


def install():
    # The caller must review the source inventory and the exact prefix policy first.
    from source_main_environment import bind_rockstar_code_manifest, assert_source_main_prefix
    plain(SOURCE_RECORD)
    record = json.loads(SOURCE_RECORD.read_text())
    if record['roots'] != list(CODE_ROOTS) or record['source_prefix'] != str(DONOR):
        raise RuntimeError('Unexpected source program roots')
    if source_inventory() != record['files']:
        raise RuntimeError('Original installed program files changed after inventory')
    files = [{key: entry[key] for key in ('path', 'bytes', 'sha256')} for entry in record['files']]
    manifest = {
        'schema': 1, 'kind': 'rockstar-code-only', 'roots': list(CODE_ROOTS),
        'files': files,
        'source_evidence': {'path': str(SOURCE_RECORD.relative_to(ROOT)), 'sha256': sha(SOURCE_RECORD)},
        'excluded_account_profiles_registry_sessions': True,
    }
    with source_main_prefix(PREFIX, root=ROOT):
        container = PREFIX / 'drive_c/Program Files/Rockstar Games'
        container_existed = container.exists()
        for relative in CODE_ROOTS:
            target = PREFIX / relative
            plain(target)
            if target.exists():
                raise RuntimeError('Refusing to replace an existing Rockstar installation')
        created = []
        try:
            for relative in CODE_ROOTS:
                target = PREFIX / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                created.append(target)
                subprocess.run(['/bin/cp', '-cRp', str(DONOR / relative), str(target)], check=True)
            for entry in files:
                target = PREFIX / entry['path']
                plain(target)
                if target.stat().st_size != entry['bytes'] or sha(target) != entry['sha256']:
                    raise RuntimeError('Cloned Rockstar program differs: ' + entry['path'])
                if target.stat().st_ino == (DONOR / entry['path']).stat().st_ino:
                    raise RuntimeError('Refusing a hard-linked Rockstar program copy')
            if source_inventory() != record['files']:
                raise RuntimeError('Original installed program files changed during cloning')
            bind_rockstar_code_manifest(PREFIX, manifest, root=ROOT)
            assert_source_main_prefix(PREFIX, root=ROOT)
        except BaseException:
            # Preserve an incomplete copy for diagnosis instead of deleting files.
            if created:
                quarantine = ROOT / 'build/rockstar-code-incomplete' / datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
                quarantine.mkdir(parents=True)
                for directory in created:
                    if directory.exists():
                        directory.rename(quarantine / directory.name)
                if not container_existed and container.is_dir() and not any(container.iterdir()):
                    container.rmdir()
            raise
    result = {
        'at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'source_evidence': str(SOURCE_RECORD.relative_to(ROOT)), 'source_sha256': sha(SOURCE_RECORD),
        'prefix': str(PREFIX.relative_to(ROOT)), 'roots': list(CODE_ROOTS),
        'file_count': len(files), 'all_program_file_hashes_verified': True,
        'source_files_unchanged': True, 'copied_profile_registry_hives_tickets_sessions': False,
        'registry_registration_performed': False, 'launcher_executed': False,
        'limit': 'Program files and prefix policy only; launcher/service registration and normal authentication are separate.',
    }
    INSTALL_RECORD.write_text(json.dumps(result, indent=2) + '\n')
    print('Program-only Rockstar copy installed in the isolated MAIN prefix; no account/session copied.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('inventory', 'install'))
    action = parser.parse_args().action
    prepare_inventory() if action == 'inventory' else install()


if __name__ == '__main__':
    main()
