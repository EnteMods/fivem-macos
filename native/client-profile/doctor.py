#!/usr/bin/env python3
"""Read-only identity checks for a local SourceDev profile; never launches a client."""
import argparse
import configparser
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys

ROOT = Path(__file__).resolve().parents[2]
PROFILE = ROOT / 'config/active-client-profile.json'
PREFIX = 'prefixes/fivem-source-update-prelogin-1257409'
STAGE = PREFIX + '/drive_c/source-update-game-client'
GAME = 'build/source-update-candidate-nqwlz36g/game-run/gta-v-legacy'
VENDOR_MANIFEST = 'config/rockstar-code-reuse-current-20261106.json'
VENDOR_SHA = '3d1befb9a11e9d2e98203fd6cf56642e1e7397460b922b85ad72299b5035f1a4'
STAGE_INVENTORY_SHA = 'f7f865eb7f7df0e6c11e8b8eaccb4fb6b10e63b337eb379a8b7ba6144e242640'
GAME_INVENTORY_SHA = '9893d3e514b2bec4fab7ab82250f9971b739446649bda2abb1dd1fbb83a175ef'
sys.path.insert(0, str(ROOT / 'scripts'))
from rockstar_code_policy import UPDATED_CODE_ROOTS, FORBIDDEN_CODE_PARTS

class Invalid(Exception):
    pass

def safe_relative(value):
    if not isinstance(value, str) or not value or '\\' in value or '\x00' in value:
        raise Invalid('INVALID_PATH')
    p = PurePosixPath(value)
    if p.is_absolute() or any(x in ('..', '.') for x in value.split('/')) or p.as_posix() != value:
        raise Invalid('INVALID_PATH')
    return p

def plain(root, relative, directory=False):
    path = root
    for part in safe_relative(relative).parts:
        path = path / part
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise Invalid('SYMLINK')
    if directory:
        if not stat.S_ISDIR(info.st_mode): raise Invalid('NOT_DIRECTORY')
    elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise Invalid('NOT_SINGLE_FILE')
    return path

def fingerprint(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as f:
        before = os.fstat(f.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1: raise Invalid('NOT_SINGLE_FILE')
        digest = hashlib.sha256()
        for block in iter(lambda: f.read(1024 * 1024), b''): digest.update(block)
        after = os.fstat(f.fileno())
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise Invalid('FILE_CHANGED')
    return {'bytes': before.st_size, 'sha256': digest.hexdigest()}

def inventory_hash(rows):
    return hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

def check_rows(root, base, rows):
    if not isinstance(rows, list) or not rows: raise Invalid('INVENTORY')
    seen = set()
    for row in rows:
        if set(row) != {'path', 'bytes', 'sha256'}: raise Invalid('INVENTORY')
        rel = str(safe_relative(row['path']))
        if rel.casefold() in seen: raise Invalid('INVENTORY')
        seen.add(rel.casefold())
        if type(row['bytes']) is not int or row['bytes'] < 0 or not re.fullmatch('[0-9a-f]{64}', row['sha256']): raise Invalid('INVENTORY')
        if fingerprint(plain(root, base + '/' + rel)) != {'bytes':row['bytes'], 'sha256':row['sha256']}:
            raise Invalid('FILE_MISMATCH')
    return len(rows)

def load_graphics(root):
    spec = importlib.util.spec_from_file_location('profile_graphics', root / 'native/wine-parity-probes/graphics.py')
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod

def validate(profile, root=ROOT, verify_graphics=True):
    if profile.get('schema') != 1 or profile.get('role') != 'SourceDev' or profile.get('code_verified_is_auth_ready') is not False:
        raise Invalid('SCHEMA')
    if (profile.get('prefix') != PREFIX or profile.get('stage') != STAGE or profile.get('game') != GAME or profile.get('source_revision') != '88a413835e9d7f56633f249880a13f42297153a2' or profile.get('official_version') != 1257409):
        raise Invalid('BINDING')
    prefix = plain(root, PREFIX, True); drive = plain(root, PREFIX + '/drive_c', True)
    info = prefix.stat(); drive_info = drive.stat()
    if profile.get('prefix_identity') != {'device':info.st_dev,'inode':info.st_ino} or profile.get('drive_identity') != {'device':drive_info.st_dev,'inode':drive_info.st_ino}:
        raise Invalid('PREFIX_REPLACED')
    plain(root, STAGE, True); game = plain(root, GAME, True)
    link = prefix / 'dosdevices/g:'
    plain(root, PREFIX + '/dosdevices', True)
    if not link.is_symlink() or link.resolve(strict=True) != game.resolve(strict=True): raise Invalid('G_MAPPING')
    c = prefix / 'dosdevices/c:'
    if not c.is_symlink() or c.resolve(strict=True) != drive.resolve(strict=True): raise Invalid('C_MAPPING')
    manifest_path = plain(root, VENDOR_MANIFEST)
    if fingerprint(manifest_path)['sha256'] != VENDOR_SHA: raise Invalid('VENDOR_MANIFEST')
    manifest = json.loads(manifest_path.read_text())
    if tuple(manifest['roots']) != UPDATED_CODE_ROOTS or manifest.get('excluded_account_profiles_registry_sessions') is not True or len(manifest['files']) != 145:
        raise Invalid('VENDOR_MANIFEST')
    for row in manifest['files']:
        p = safe_relative(row['path'])
        if not any(p.is_relative_to(PurePosixPath(x)) for x in UPDATED_CODE_ROOTS) or FORBIDDEN_CODE_PARTS.intersection(x.casefold() for x in p.parts): raise Invalid('VENDOR_SCOPE')
    if profile.get('vendor_files') != manifest['files']: raise Invalid('VENDOR_INVENTORY')
    if inventory_hash(profile['stage_files']) != STAGE_INVENTORY_SHA or inventory_hash(profile['game_executables']) != GAME_INVENTORY_SHA: raise Invalid('INVENTORY_IDENTITY')
    stage_count = check_rows(root, STAGE, profile['stage_files'])
    if stage_count != 422: raise Invalid('STAGE_COUNT')
    vendor_count = check_rows(root, PREFIX, profile['vendor_files'])
    exes = profile['game_executables']
    if {r['path'].casefold() for r in exes} != {'gta5.exe','playgtav.exe','gtavlauncher.exe'} or len(exes) != 3: raise Invalid('GAME_INVENTORY')
    game_names = {}
    for item in game.iterdir():
        key = item.name.casefold()
        if key in {'gta5.exe', 'playgtav.exe', 'gtavlauncher.exe'}:
            if key in game_names: raise Invalid('GAME_INVENTORY')
            game_names[key] = item.name
    if set(game_names) != {'gta5.exe', 'playgtav.exe', 'gtavlauncher.exe'}: raise Invalid('GAME_INVENTORY')
    resolved_exes = [dict(row, path=game_names[row['path'].casefold()]) for row in exes]
    game_count = check_rows(root, GAME, resolved_exes)
    ini = plain(root, STAGE + '/CitizenFX.ini')
    cfg = configparser.ConfigParser(); cfg.read(ini, encoding='utf-8-sig')
    if cfg.get('Game','IVPath').rstrip('\\').upper() != 'G:': raise Invalid('GAME_CONFIG')
    if verify_graphics:
        graphics = load_graphics(root); runtime = graphics.runtime.verify_runtime(); renderer = graphics.verify_renderer()
        if profile['runtime_manifest_sha256'] != runtime['manifest_sha256'] or profile['renderer_review_sha256'] != renderer['review']['sha256']: raise Invalid('GRAPHICS_IDENTITY')
    return {'status':'OK','role':'SourceDev','stage_files':stage_count,'vendor_files':vendor_count,'game_executables':game_count,'code_verified':True,'auth_ready':'UNKNOWN'}

def main():
    parser=argparse.ArgumentParser(); parser.parse_args()
    try:
        profile=json.loads(plain(ROOT, str(PROFILE.relative_to(ROOT))).read_text())
        result=validate(profile); print(json.dumps(result)); return 0
    except (Invalid, OSError, KeyError, TypeError, ValueError, RuntimeError, configparser.Error) as e:
        code=str(e) if isinstance(e,Invalid) else 'VALIDATION_FAILED'
        print(json.dumps({'status':'FAIL','code':code})); return 1
if __name__ == '__main__': sys.exit(main())
