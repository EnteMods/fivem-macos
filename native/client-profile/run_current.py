#!/usr/bin/env python3
"""Start the reviewed baseline candidate under its current mount identity."""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import doctor

ROOT = doctor.ROOT
HELPER = ROOT / 'build/source-update-candidate-nqwlz36g/resume-candidate.py'
HELPER_SHA = '7ebcacf4029947eff1868c8f6485c9975bbe434d12be4880f850b271be89efe0'
BINDING = ROOT / 'config/current-client-binding-20261106.json'
BINDING_SHA = '8ace2ab06d0660fe4ee4f5fef62c979a158a797ea3dfdacc6f821d1dd8e77a1f'
PROFILE_SHA = '2c109e0216686e87782d509776452b8eaa64ef2f88b7923fe7c5ba97e894171d'
OLD_MARKER_SHA = '1abe0d42a37cf08b69b30c083e0e9215a9814f2bacce93b4e6cdf202bfa82f99'
OLD_FIRST_STATUS_SHA = 'c4f67299aabebff30a8a2c4fc7d36716ae0939d60da9542bf60ad526e66ac43c'
OLD_RECEIPT_SHA = '68be4e8f75e00f526f134d8088b1cb84d3bc3ee3cf56acf50f1142d72e6345c7'


def checked(path, expected):
    if path.resolve(strict=True) != path or not path.is_file() or path.stat().st_nlink != 1:
        raise RuntimeError('Pinned launcher input redirected')
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise RuntimeError('Pinned launcher input changed')
    return data


def load_helper():
    data = checked(HELPER, HELPER_SHA)
    spec = importlib.util.spec_from_file_location('current_pinned_resume', HELPER)
    module = importlib.util.module_from_spec(spec)
    exec(compile(data, str(HELPER), 'exec'), module.__dict__)
    return module


def check_binding(helper):
    record = json.loads(checked(BINDING, BINDING_SHA))
    profile = json.loads(checked(doctor.PROFILE, PROFILE_SHA))
    if doctor.validate(profile)['status'] != 'OK':
        raise RuntimeError('Active profile did not pass full doctor')
    if profile['schema'] == 2:
        if (record.get('schema') != 2 or record.get('game_reference') != doctor.GAME_REFERENCE
                or record.get('active_profile_sha256') != PROFILE_SHA):
            raise RuntimeError('Canonical game binding differs')
    elif record.get('schema') != 1:
        raise RuntimeError('Historical game binding differs')
    # The frozen helper accepts a verified game directory; its prior status stays historical.
    helper.game.GAME = doctor.game_location(profile)[2]
    prefix = helper.game.PREFIX
    current = {'device': prefix.stat().st_dev, 'inode': prefix.stat().st_ino}
    drive = prefix / 'drive_c'
    drive_current = {'device': drive.stat().st_dev, 'inode': drive.stat().st_ino}
    if (current != record['current_prefix_identity'] or current != profile['prefix_identity']
            or drive_current != record['current_drive_identity'] or drive_current != profile['drive_identity']
            or record['component_selection'] != 'baseline' or record['stage_files'] != 422
            or record['vendor_files'] != 145 or record['game_executables'] != 3
            or record['current_vendor_manifest_sha256'] != doctor.VENDOR_SHA
            or record['stage_inventory_sha256'] != doctor.STAGE_INVENTORY_SHA
            or record['game_inventory_sha256'] != doctor.GAME_INVENTORY_SHA):
        raise RuntimeError('Current mount binding differs')
    marker = json.loads(checked(prefix / '.source-update-prelogin', OLD_MARKER_SHA))
    previous = json.loads(checked(helper.game.first.STATUS, OLD_FIRST_STATUS_SHA))
    if marker != record['old_prefix_identity'] or previous['prefix_binding'] != marker:
        raise RuntimeError('Historical prelogin binding differs')
    checked(ROOT / 'config/active-client-profile-20261105.archived.json', record['archived_profile_sha256'])
    checked(ROOT / 'research/source-update-component-init-20261105.archived.json', OLD_RECEIPT_SHA)
    state = helper.identity.component_init_state(helper.game)
    if state['status'] != 'restored' or state['selection'] != 'baseline':
        raise RuntimeError('Baseline CitizenGame transaction not restored')
    if helper.identity.verify_input(helper.game) != 422:
        raise RuntimeError('Baseline stage differs')
    helper.reuse.MANIFEST = ROOT / doctor.VENDOR_MANIFEST
    helper.reuse.MANIFEST_SHA = doctor.VENDOR_SHA
    helper.reuse.verify(prefix, helper.reuse.inventory())
    return record


@contextmanager
def current_prelogin_lock(helper, old_record):
    prefix, _ = helper.game.first._location(helper.game.PREFIX, ROOT)
    lock_path = prefix.parent / ('.' + prefix.name + '.probe.lock')
    descriptor = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise RuntimeError('Unexpected prefix lock')
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        check_binding(helper)
        if old_record.get('prefix_binding') != json.loads(checked(prefix / '.source-update-prelogin', OLD_MARKER_SHA)):
            raise RuntimeError('Prior prelogin status changed')
        helper.game.first._check_c_drive(prefix)
        helper.game.first._check_shell_folders(prefix)
        yield
    finally:
        os.close(descriptor)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='Run all read-only preflight checks; do not launch Wine')
    args = parser.parse_args()
    helper = load_helper()
    check_binding(helper)
    if args.check:
        print(json.dumps({'status': 'OK', 'stage_files': 422, 'vendor_files': 145,
                          'game_executables': 3, 'auth_ready': 'UNKNOWN', 'client_started': False}))
        return 0
    helper.game.first.prelogin_lock = lambda old_record: current_prelogin_lock(helper, old_record)
    sys.argv = [str(HELPER), '--dxmt-resource-usage']
    return helper.main()


if __name__ == '__main__':
    raise SystemExit(main())
