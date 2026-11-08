#!/usr/bin/env python3
"""Prepare or explicitly apply the fixed canonical-GTA binding; never remove GTA."""
import argparse
import base64
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

import doctor
import run_current

ROOT = doctor.ROOT
REPORT = ROOT / 'research/canonical-gta-dedup-20261108.json'
WORK = ROOT / 'research/single-install-consolidation-20261108/canonical-game-transaction'
PLAN = WORK / 'plan.json'
TARGETS = {'profile': doctor.PROFILE, 'binding': run_current.BINDING,
           'launcher': ROOT / 'native/client-profile/run_current.py'}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(data):
    return base64.b64encode(data).decode('ascii')


def decoded(value):
    return base64.b64decode(value, validate=True)


def document(value):
    return (json.dumps(value, indent=2) + '\n').encode()


def read_plain(path):
    doctor.plain(ROOT, str(path.relative_to(ROOT)))
    return path.read_bytes()


def no_client_processes():
    result = subprocess.run(['/bin/ps', '-axo', 'comm='], check=True,
                            capture_output=True, text=True)
    terms = ('wine', 'wineserver', 'fivem', 'rockstar', 'socialclub', 'gta5', 'playgtav')
    for line in result.stdout.splitlines():
        path = Path(line.strip())
        if path.parts[-4:] == ('FiveM.app', 'Contents', 'MacOS', 'FiveMLauncher'):
            continue
        if any(term in path.name.casefold() for term in terms):
            return False
    return True


@contextmanager
def locked():
    prefix = doctor.plain(ROOT, doctor.PREFIX, True)
    path = prefix.parent / ('.' + prefix.name + '.probe.lock')
    fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise RuntimeError('Unexpected prefix lock')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if not no_client_processes():
            raise RuntimeError('Client or Wine process is running')
        yield prefix
    finally:
        os.close(fd)


def tree_metadata(directory):
    rows = []
    def visit(path, relative):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            kind = 'directory'
        elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
            kind = 'regular'
        else:
            raise RuntimeError('Unexpected GTA tree entry')
        rows.append({'path': relative, 'device': info.st_dev, 'inode': info.st_ino,
                     'kind': kind, 'mode': stat.S_IMODE(info.st_mode), 'size': info.st_size,
                     'mtime_ns': info.st_mtime_ns, 'nlink': info.st_nlink})
        if kind == 'directory':
            for child in sorted(path.iterdir(), key=lambda item: item.name):
                visit(child, child.name if relative == '.' else relative + '/' + child.name)
    visit(directory, '.')
    return sorted(rows, key=lambda row: row['path'])


def check_comparison(expected_sha=None, include_clone=True):
    data = read_plain(REPORT)
    if expected_sha is not None and digest(data) != expected_sha:
        raise RuntimeError('Full GTA comparison report changed')
    report = json.loads(data)
    comparison = report['comparison']
    if (report['schema'] != 'canonical-gta-tree-comparison/v1'
            or comparison['identical_regular_file_path_size_hash_set'] is not True
            or comparison['identical_symlink_set'] is not True
            or any(comparison[key] for key in ('regular_file_differences', 'symlink_differences', 'other_entry_differences'))):
        raise RuntimeError('Full GTA comparison did not establish identical trees')
    canonical = doctor.plain(ROOT.parent, doctor.SIBLING_GAME, True)
    locations = {'original': canonical}
    if include_clone:
        locations['active'] = doctor.plain(ROOT, doctor.GAME, True)
    for name, path in locations.items():
        evidence = report['roots'][name]
        summary = comparison['summary'][name]
        if (evidence['root'] != str(path) or evidence['hashes_completed'] != 443
                or evidence['bytes_read'] != 128918230441
                or summary['regular_files'] != 443 or summary['symlinks'] != 0
                or any(evidence[key] for key in ('read_errors', 'unstable_file_reads', 'metadata_changes_during_measurement'))
                or tree_metadata(path) != sorted(evidence['post_metadata_inventory'], key=lambda row: row['path'])):
            raise RuntimeError('GTA metadata changed since full byte comparison: ' + name)
    return digest(data)


def proposed(old_profile, old_binding, old_launcher, report_sha):
    profile = json.loads(old_profile)
    if profile['schema'] != 1 or profile['game'] != doctor.GAME:
        raise RuntimeError('Only the current schema-1 clone can be migrated')
    profile.update(schema=2, game=dict(doctor.GAME_REFERENCE))
    profile_bytes = document(profile)
    binding = json.loads(old_binding)
    if binding['schema'] != 1:
        raise RuntimeError('Unexpected old binding schema')
    binding.update(schema=2, reason='canonical original GTA install; unchanged code and executable inventories',
                   game_reference=dict(doctor.GAME_REFERENCE), active_profile_sha256=digest(profile_bytes),
                   canonical_game_comparison_sha256=report_sha,
                   previous_active_profile_sha256=digest(old_profile), previous_binding_sha256=digest(old_binding))
    binding_bytes = document(binding)
    launcher = old_launcher.decode()
    for name, previous, replacement in (('PROFILE_SHA', digest(old_profile), digest(profile_bytes)),
                                        ('BINDING_SHA', digest(old_binding), digest(binding_bytes))):
        pattern = re.compile(r"^" + name + r" = '" + previous + r"'$", re.MULTILINE)
        launcher, count = pattern.subn(name + " = '" + replacement + "'", launcher)
        if count != 1:
            raise RuntimeError('Expected launcher pin missing')
    return {'profile': profile_bytes, 'binding': binding_bytes, 'launcher': launcher.encode()}


def create_exclusive(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())


def make_work_directory():
    path = ROOT
    for part in WORK.relative_to(ROOT).parts:
        path = path / part
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            pass
        doctor.plain(ROOT, str(path.relative_to(ROOT)), True)


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_bytes(path, data):
    mode = stat.S_IMODE(path.lstat().st_mode)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data); stream.flush(); os.fchmod(stream.fileno(), mode); os.fsync(stream.fileno())
        os.replace(temporary, path); sync_directory(path.parent)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def atomic_link(path, target):
    fd, temporary = tempfile.mkstemp(prefix='.g-mapping-', dir=path.parent)
    os.close(fd); os.unlink(temporary)
    try:
        os.symlink(target, temporary); os.replace(temporary, path); sync_directory(path.parent)
    finally:
        if os.path.lexists(temporary): os.unlink(temporary)


def prepare():
    with locked() as prefix:
        run_current.check_binding(run_current.load_helper())
        report_sha = check_comparison()
        old = {key: read_plain(path) for key, path in TARGETS.items()}
        new = proposed(old['profile'], old['binding'], old['launcher'], report_sha)
        # Verify the same three executable bytes at the original directory, without changing G:.
        doctor.check_rows(ROOT.parent, doctor.SIBLING_GAME, json.loads(old['profile'])['game_executables'])
        plan = {'schema': 'canonical-game-binding-transaction/v1', 'comparison_sha256': report_sha,
                'prefix_identity': json.loads(old['profile'])['prefix_identity'],
                'old_g': os.readlink(prefix / 'dosdevices/g:'), 'new_g': str(ROOT.parent / doctor.SIBLING_GAME),
                'files': {key: {'old': encoded(old[key]), 'new': encoded(new[key]),
                                'old_sha256': digest(old[key]), 'new_sha256': digest(new[key])} for key in TARGETS}}
        make_work_directory()
        data = document(plan); create_exclusive(PLAN, data); sync_directory(WORK)
        return {'status': 'PREPARED', 'plan_sha256': digest(data),
                'new_sha256': {key: digest(value) for key, value in new.items()}, 'active_binding_changed': False}


def load_plan(expected_sha):
    data = run_current.checked(PLAN, expected_sha)
    plan = json.loads(data)
    if (plan['schema'] != 'canonical-game-binding-transaction/v1' or set(plan['files']) != set(TARGETS)
            or plan['new_g'] != str(ROOT.parent / doctor.SIBLING_GAME)):
        raise RuntimeError('Unexpected transaction scope')
    for row in plan['files'].values():
        for state in ('old', 'new'):
            if digest(decoded(row[state])) != row[state + '_sha256']:
                raise RuntimeError('Transaction snapshot mismatch')
    profile = json.loads(decoded(plan['files']['profile']['old']))
    if profile['prefix_identity'] != plan['prefix_identity']:
        raise RuntimeError('Transaction prefix binding differs')
    expected_new = proposed(decoded(plan['files']['profile']['old']), decoded(plan['files']['binding']['old']),
                            decoded(plan['files']['launcher']['old']), plan['comparison_sha256'])
    # Pin substitution uses the prior source constants even after a successful migration.
    for key, value in expected_new.items():
        if value != decoded(plan['files'][key]['new']):
            raise RuntimeError('Transaction proposal differs')
    return plan


def check_state(plan, prefix, allowed):
    info = prefix.stat()
    if {'device': info.st_dev, 'inode': info.st_ino} != plan['prefix_identity']:
        raise RuntimeError('Transaction prefix replaced')
    for key, path in TARGETS.items():
        if digest(read_plain(path)) not in {plan['files'][key][state + '_sha256'] for state in allowed}:
            raise RuntimeError('Transaction target changed: ' + key)
    link = prefix / 'dosdevices/g:'
    if not link.is_symlink() or os.readlink(link) not in {plan[state + '_g'] for state in allowed}:
        raise RuntimeError('Transaction G: mapping changed')


def restore(plan, prefix):
    check_state(plan, prefix, ('old', 'new'))
    for key, path in TARGETS.items():
        atomic_bytes(path, decoded(plan['files'][key]['old']))
    atomic_link(prefix / 'dosdevices/g:', plan['old_g'])


def transition(action, expected_sha):
    plan = load_plan(expected_sha)
    with locked() as prefix:
        check_state(plan, prefix, ('old',) if action == 'apply' else ('old', 'new'))
        if action == 'rollback':
            check_comparison(plan['comparison_sha256'])
            restore(plan, prefix)
            subprocess.run([sys.executable, '-B', str(TARGETS['launcher']), '--check'], check=True)
        else:
            run_current.check_binding(run_current.load_helper())
            check_comparison(plan['comparison_sha256'])
            try:
                atomic_link(prefix / 'dosdevices/g:', plan['new_g'])
                for key, path in TARGETS.items():
                    atomic_bytes(path, decoded(plan['files'][key]['new']))
                doctor.validate(json.loads(read_plain(TARGETS['profile'])))
                subprocess.run([sys.executable, '-B', str(TARGETS['launcher']), '--check'], check=True)
            except BaseException:
                restore(plan, prefix)
                raise
        check_state(plan, prefix, ('new',) if action == 'apply' else ('old',))
        return {'status': 'APPLIED' if action == 'apply' else 'ROLLED_BACK', 'client_started': False,
                'clone_deleted': False, 'plan_sha256': expected_sha}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'apply', 'rollback'))
    parser.add_argument('--plan-sha256')
    args = parser.parse_args()
    if args.action == 'prepare':
        if args.plan_sha256: parser.error('prepare takes no existing plan')
        result = prepare()
    else:
        if not args.plan_sha256 or not re.fullmatch('[0-9a-f]{64}', args.plan_sha256):
            parser.error('apply/rollback requires the reviewed plan SHA-256')
        result = transition(args.action, args.plan_sha256)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
