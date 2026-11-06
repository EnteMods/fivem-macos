#!/usr/bin/env python3
"""Keep the original RGL open for the user's authorized installation; never kill Wine."""
import datetime
import getpass
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
PREFIX = ROOT / 'prefixes/fivem-source-main'
sys.path.insert(0, str(ROOT / 'scripts'))
from probe_environment import _location, _check_c_drive, _check_shell_folders, _plain_path, ProbePrefixError
from source_main_environment import _read_identity, _manual_login_authorized, _source_main_file_lock
from rockstar_code_policy import (MANIFEST_NAME, CODE_ROOTS, UPDATED_CODE_ROOTS,
                                 _regular_file, _sha, _verify_code, validated_update_origin)

GAME_FOLDERS = ('Grand Theft Auto V Legacy', 'Grand Theft Auto V')


def preflight():
    prefix, root = _location(PREFIX, ROOT)
    if prefix.name != 'fivem-source-main':
        raise ProbePrefixError('Only the existing isolated user-authorized source prefix is permitted.')
    user = getpass.getuser()
    identity = _read_identity(prefix, root, user)
    if not _manual_login_authorized(identity, prefix, root, user):
        raise ProbePrefixError('Require the existing user-confirmed manual login context.')
    _check_c_drive(prefix)
    _check_shell_folders(prefix)
    path = prefix / MANIFEST_NAME
    reference = identity.get('rockstar_code_manifest', {})
    if reference.get('path') != MANIFEST_NAME or _sha(path, prefix) != reference.get('sha256'):
        raise ProbePrefixError('Original Rockstar code-manifest binding differs.')
    _regular_file(path, prefix)
    manifest = json.loads(path.read_text())
    info = prefix.stat()
    if manifest.get('prefix_binding') != {'project_root': str(root), 'prefix_device': info.st_dev,
            'prefix_inode': info.st_ino, 'user': user}:
        raise ProbePrefixError('Rockstar code binding belongs to a different prefix.')
    update = validated_update_origin(prefix, root, identity, user, manifest)
    _verify_code(manifest, prefix, root, allowed_game_folders=GAME_FOLDERS,
                 expected_roots=UPDATED_CODE_ROOTS if update is not None else CODE_ROOTS)
    expected_count = 145 if update is not None else 142
    if len(manifest['files']) != expected_count:
        raise ProbePrefixError('Require the exact reviewed Rockstar code installation.')
    return {'prefix_device': info.st_dev, 'prefix_inode': info.st_ino,
            'rockstar_code_manifest_sha256': reference['sha256'],
            'authorized_game_folder_names': list(GAME_FOLDERS)}


def main():
    adopt_pid = None
    inspect_only = sys.argv[1:] == ['inspect']
    if len(sys.argv) == 3 and sys.argv[1] == '--adopt-native-pid' and sys.argv[2].isdigit():
        adopt_pid = int(sys.argv[2])
    elif sys.argv[1:] and not inspect_only:
        raise SystemExit('Usage: run_user_rockstar_session.py [inspect | --adopt-native-pid PID]')
    # This is explicitly a user-owned installation session, not an account-free probe.
    binding = preflight()
    with _source_main_file_lock(PREFIX):
        binding = preflight()
        if inspect_only:
            print(json.dumps(dict(binding, inspection_passed=True, runtime_started=False), indent=2))
            return 0
        spec = importlib.util.spec_from_file_location('user_rgl_runtime', ROOT.parent / 'GTA-V-macOS/scripts/gta-macos.py')
        runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runtime)
        environment = runtime.environment()
        environment['WINEPREFIX'] = str(PREFIX)
        environment['WINEDEBUG'] = '-all,err+all'
        if any(key.lower().startswith('citizenfx_') for key in environment):
            raise ProbePrefixError('Refusing inherited CitizenFX role variables.')
        executable = PREFIX / CODE_ROOTS[0] / 'Launcher.exe'
        _plain_path(executable, PREFIX)
        if adopt_pid is not None:
            observed = subprocess.check_output(['/bin/ps', '-p', str(adopt_pid), '-o', 'comm='], text=True).strip()
            if adopt_pid <= 1 or observed != str(executable):
                raise ProbePrefixError('Only the known currently running source-prefix Launcher.exe may be adopted.')
        label = 'user-rockstar-install-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        result = ROOT / 'research' / (label + '.json')
        record = dict(binding, at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            scope='User-authorized manual GTA installation through original Rockstar Launcher',
            prefix='prefixes/fivem-source-main', prefix_is_account_free=False,
            user_requested_leave_open=True, automatic_time_limit_seconds=None,
            automatic_wineserver_kill=False, authentication_or_session_contents_read_or_copied=False,
            existing_shell_folder_configuration_metadata_checked=True,
            fresh_probe_account_directory_policy_applied=False,
            original_authentication_integrity_or_anticheat_modified=False,
            native_controller_pid=os.getpid(), arguments=[], status='starting', adopted_existing_process=adopt_pid is not None)
        descriptor = os.open(ROOT / 'logs' / (label + '.log'), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'w') as log:
            process = None if adopt_pid is not None else subprocess.Popen(
                [str(runtime.WINE), str(executable)], cwd=executable.parent,
                env=environment, stdout=subprocess.DEVNULL, stderr=log, start_new_session=True)
            native_pid = adopt_pid if adopt_pid is not None else process.pid
            record.update(status='user-installation-session-supervised', native_wine_pid=native_pid)
            result.write_text(json.dumps(record, indent=2) + '\n')
            print('Original Rockstar Launcher open; no automatic timeout or Wine termination.', flush=True)
            print('Native Wine PID:', native_pid, '; controller PID:', os.getpid(), flush=True)
            print('Session evidence:', result, flush=True)
            try:
                # Hold ownership until an explicit operator handoff. Parent exit does
                # not prove that the launcher's service/helper children have ended.
                while True:
                    time.sleep(5)
            except KeyboardInterrupt:
                # A user install may still be active; interruption never terminates it.
                record.update(status='controller-detached-without-terminating-wine')
            finally:
                record['controller_ended_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
                result.write_text(json.dumps(record, indent=2) + '\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
