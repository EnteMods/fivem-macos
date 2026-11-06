#!/usr/bin/env python3
"""Clone only the legal game directory and expose it as G: in the MAIN test prefix."""
import datetime
import hashlib
import json
from pathlib import Path
import subprocess

from source_main_environment import source_main_prefix

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT.parent / 'GTA-V-macOS/prefixes/rockstar-legacy/drive_c/Program Files/Rockstar Games/Grand Theft Auto V Legacy'
TARGET = ROOT / 'build/game-library/gta-v-legacy'
PREFIX = ROOT / 'prefixes/fivem-source-main'
RECORD = ROOT / 'research/game-library-clone.json'


def inventory(directory):
    entries = {}
    for path in sorted(directory.rglob('*')):
        if path.is_symlink():
            raise RuntimeError('Game library must contain ordinary local paths: ' + str(path))
        info = path.stat()
        entries[str(path.relative_to(directory))] = {
            'directory': path.is_dir(), 'bytes': info.st_size if path.is_file() else None,
            'mtime_ns': info.st_mtime_ns,
        }
    return entries


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def main():
    for path in (SOURCE, TARGET, PREFIX):
        if path.absolute() != path.resolve():
            raise RuntimeError('Refusing redirected game-library path: ' + str(path))
    if not (SOURCE / 'GTA5.exe').is_file():
        raise RuntimeError('The existing legal Legacy game executable is missing')
    before = inventory(SOURCE)
    if TARGET.exists():
        raise RuntimeError('Game snapshot already exists; refusing replacement')
    TARGET.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(['/bin/cp', '-cRp', str(SOURCE), str(TARGET)], check=True)
    if inventory(SOURCE) != before or inventory(TARGET) != before:
        raise RuntimeError('Source changed during cloning or clone metadata differs')
    for relative, entry in before.items():
        if not entry['directory'] and (SOURCE / relative).stat().st_ino == (TARGET / relative).stat().st_ino:
            raise RuntimeError('Refusing a hard-linked game copy')
    executables = {}
    for name in ('GTA5.exe', 'PlayGTAV.exe', 'GTAVLauncher.exe'):
        original = sha(SOURCE / name)
        if sha(TARGET / name) != original:
            raise RuntimeError('Game executable clone hash differs: ' + name)
        executables[name] = original
    with source_main_prefix(PREFIX, root=ROOT):
        mapping = PREFIX / 'dosdevices/g:'
        if mapping.exists() or mapping.is_symlink():
            raise RuntimeError('Refusing to replace an existing G: mapping')
        mapping.symlink_to(TARGET, target_is_directory=True)
        if mapping.resolve(strict=True) != TARGET:
            raise RuntimeError('Game-only G: mapping verification failed')
    record = {
        'at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'source': str(SOURCE), 'target': str(TARGET.relative_to(ROOT)),
        'prefix': str(PREFIX.relative_to(ROOT)), 'wine_game_executable': 'G:\\GTA5.exe',
        'copy_command': ['/bin/cp', '-cRp'], 'clone_required_no_full_copy_fallback': True,
        'entries': len(before), 'logical_file_bytes': sum(item['bytes'] or 0 for item in before.values()),
        'all_file_inodes_distinct': True, 'source_metadata_unchanged_after_clone': True,
        'clone_metadata_matches_source': True, 'executable_sha256': executables,
        'copied_scope': 'game directory only; no prefix registry, account, launcher profile or session',
        'whole_game_content_hashes_verified': False,
    }
    RECORD.write_text(json.dumps(record, indent=2) + '\n')
    print('Game-only APFS clone ready at G:\\GTA5.exe')
    print('Evidence:', RECORD)


if __name__ == '__main__':
    main()
