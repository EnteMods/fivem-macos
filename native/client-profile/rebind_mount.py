#!/usr/bin/env python3
"""Record the current mount identity and restore the reviewed baseline module."""
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

import doctor

ROOT = doctor.ROOT
OLD_PROFILE_SHA = '986e2ac271ccee412e2350fbb2cc6051d0ef66cda427ce86baded2f06a675f16'
OLD_RECEIPT_SHA = '68be4e8f75e00f526f134d8088b1cb84d3bc3ee3cf56acf50f1142d72e6345c7'
REVIEWED_VENDOR_SHA = '6cf2e59f34b427e72f144d1a9db2026a1f2863440d56c211175684e4713b03e1'
OLD_MARKER_SHA = '1abe0d42a37cf08b69b30c083e0e9215a9814f2bacce93b4e6cdf202bfa82f99'
OLD_FIRST_STATUS_SHA = 'c4f67299aabebff30a8a2c4fc7d36716ae0939d60da9542bf60ad526e66ac43c'
EXPECTED_NEW_DEVICE = 16777232
OLD_PROFILE_ARCHIVE = ROOT / 'config/active-client-profile-20261105.archived.json'
OLD_RECEIPT_ARCHIVE = ROOT / 'research/source-update-component-init-20261105.archived.json'
CURRENT_VENDOR = ROOT / 'config/rockstar-code-reuse-current-20261106.json'
CURRENT_BINDING = ROOT / 'config/current-client-binding-20261106.json'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_pinned(path, expected):
    if path.resolve(strict=True) != path or not path.is_file() or path.stat().st_nlink != 1:
        raise RuntimeError('Pinned input redirected')
    data = path.read_bytes()
    if digest(data) != expected:
        raise RuntimeError('Pinned input differs')
    return data


def create_exclusive(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def no_client_processes():
    result = subprocess.run(['/bin/ps', '-axo', 'comm='], check=True, capture_output=True, text=True)
    names = ('wine', 'wineserver', 'fivem', 'rockstar', 'socialclub', 'gta5', 'playgtav')
    return not any(any(part in Path(line.strip()).name.casefold() for part in names)
                   for line in result.stdout.splitlines())


def main():
    if len(sys.argv) != 1:
        raise RuntimeError('No arguments or alternate target accepted')
    old_profile_bytes = read_pinned(doctor.PROFILE, OLD_PROFILE_SHA)
    old_receipt_path = ROOT / 'research/source-update-component-init-20261105.json'
    old_receipt_bytes = read_pinned(old_receipt_path, OLD_RECEIPT_SHA)
    old_status = ROOT / 'build/source-update-candidate-nqwlz36g/first-start/status.json'
    old_status_bytes = read_pinned(old_status, OLD_FIRST_STATUS_SHA)
    prefix = doctor.plain(ROOT, doctor.PREFIX, True)
    drive = doctor.plain(ROOT, doctor.PREFIX + '/drive_c', True)
    old_marker = prefix / '.source-update-prelogin'
    marker = json.loads(read_pinned(old_marker, OLD_MARKER_SHA))
    original_profile = json.loads(old_profile_bytes)
    status = json.loads(old_status_bytes)
    old_binding = original_profile['prefix_identity']
    current_binding = {'device': prefix.stat().st_dev, 'inode': prefix.stat().st_ino}
    current_drive = {'device': drive.stat().st_dev, 'inode': drive.stat().st_ino}
    if (marker != old_binding or status['prefix_binding'] != old_binding
            or old_binding != {'device': 16777234, 'inode': 21757137}
            or original_profile['drive_identity'] != {'device': 16777234, 'inode': 21757139}
            or current_binding != {'device': EXPECTED_NEW_DEVICE, 'inode': old_binding['inode']}
            or current_drive != {'device': EXPECTED_NEW_DEVICE, 'inode': 21757139}):
        raise RuntimeError('Mount rebinding preconditions differ')

    reviewed_path = ROOT / 'build/rockstar-vendor-admission-0bogf2cm/vendor-code-manifest.json'
    reviewed = json.loads(read_pinned(reviewed_path, REVIEWED_VENDOR_SHA))
    if (reviewed['prefix_binding'] != {'prefix': doctor.PREFIX, **old_binding}
            or len(reviewed['files']) != 145
            or reviewed.get('excluded_account_profiles_registry_sessions') is not True):
        raise RuntimeError('Reviewed vendor generation differs')
    doctor.check_rows(ROOT, doctor.PREFIX, reviewed['files'])
    resume = load(ROOT / 'build/source-update-candidate-nqwlz36g/resume-candidate.py', 'rebind_resume')
    transaction = load(ROOT / 'native/windows-component-init-trace/transaction.py', 'rebind_transaction')
    if resume.game.verify_finished_prelogin()['prefix_binding'] != old_binding:
        raise RuntimeError('Prior prelogin evidence differs')
    if resume.identity.verify_input(resume.game, component_init_trace=True) != 422:
        raise RuntimeError('Diagnostic stage differs')
    if transaction.verify_receipt(resume.game.STAGE)['selection'] != 'diagnostic':
        raise RuntimeError('Diagnostic transaction differs')
    if not no_client_processes():
        raise RuntimeError('Client or Wine process is running')

    lock_path = prefix.parent / ('.' + prefix.name + '.probe.lock')
    fd = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if not no_client_processes():
            raise RuntimeError('Client or Wine process appeared')
        if (prefix.stat().st_dev, prefix.stat().st_ino) != (current_binding['device'], current_binding['inode']):
            raise RuntimeError('Prefix changed under lock')
        resume.game.first._check_c_drive(prefix)
        resume.game.first._check_shell_folders(prefix)
        create_exclusive(OLD_PROFILE_ARCHIVE, old_profile_bytes)
        create_exclusive(OLD_RECEIPT_ARCHIVE, old_receipt_bytes)
        restored = transaction.transition('restore', ROOT, resume.game.STAGE,
            lambda expected: transaction.verify_inventory(resume.game, resume.identity, expected),
            no_client_processes)
        if restored['status'] != 'restored' or resume.identity.verify_input(resume.game) != 422:
            raise RuntimeError('Baseline restoration incomplete')

        vendor = dict(reviewed, prefix_binding={'prefix': doctor.PREFIX, **current_binding})
        vendor_bytes = (json.dumps(vendor, indent=2) + '\n').encode()
        create_exclusive(CURRENT_VENDOR, vendor_bytes)
        baseline_profile = dict(original_profile)
        baseline_profile['prefix_identity'] = current_binding
        baseline_profile['drive_identity'] = current_drive
        baseline_profile['vendor_files'] = vendor['files']
        baseline_profile['stage_files'] = [
            {'path': row['path'], **doctor.fingerprint(doctor.plain(ROOT, doctor.STAGE + '/' + row['path']))}
            for row in original_profile['stage_files']]
        baseline_profile['source_fingerprints'] = dict(original_profile['source_fingerprints'],
            rockstar_manifest_sha256=digest(vendor_bytes))
        binding_record = {
            'schema': 1, 'reason': 'same inodes after device-id change; reviewed vendor generation and baseline restore',
            'old_prefix_identity': old_binding, 'current_prefix_identity': current_binding,
            'old_drive_identity': original_profile['drive_identity'], 'current_drive_identity': current_drive,
            'archived_profile_sha256': OLD_PROFILE_SHA, 'archived_component_receipt_sha256': OLD_RECEIPT_SHA,
            'first_status_sha256': OLD_FIRST_STATUS_SHA, 'prelogin_marker_sha256': OLD_MARKER_SHA,
            'reviewed_vendor_manifest_sha256': REVIEWED_VENDOR_SHA,
            'current_vendor_manifest_sha256': digest(vendor_bytes),
            'stage_inventory_sha256': doctor.inventory_hash(baseline_profile['stage_files']),
            'game_inventory_sha256': doctor.inventory_hash(baseline_profile['game_executables']),
            'stage_files': 422, 'vendor_files': 145, 'game_executables': 3,
            'component_selection': 'baseline', 'auth_ready': 'unknown'}
        binding_bytes = (json.dumps(binding_record, indent=2) + '\n').encode()
        create_exclusive(CURRENT_BINDING, binding_bytes)
        candidate_profile = doctor.PROFILE.with_name('active-client-profile-20261106.pending.json')
        create_exclusive(candidate_profile, (json.dumps(baseline_profile, indent=2) + '\n').encode())
        print(json.dumps({'restored': True, 'stage_inventory_sha256': binding_record['stage_inventory_sha256'],
            'vendor_manifest_sha256': binding_record['current_vendor_manifest_sha256'],
            'binding_sha256': digest(binding_bytes), 'pending_profile': str(candidate_profile.relative_to(ROOT))}))
    finally:
        os.close(fd)


if __name__ == '__main__':
    main()
