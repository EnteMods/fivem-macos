#!/usr/bin/env python3
"""Stage or commit this observed original-RGL update's code binding; never run a client."""
import argparse
import datetime
import getpass
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from types import ModuleType

ROOT = Path(__file__).resolve().parents[2]
PREFIX = ROOT / 'prefixes/fivem-source-main'
CHECKPOINT = ROOT / 'build/checkpoints/rockstar-official-update-20261103'
STAGED = CHECKPOINT / 'finalization-x86-complete'
OBSERVATION = 'research/rockstar-post-update-observation-20261103.json'
OBSERVATION_BYTES = 1543
OBSERVATION_SHA = 'd7f19473983182619590eae507dd6e8b2c224e502599af25c81916ae5043e573'
HELPER = 'native/windows-client/run_user_rockstar_update.py'
HELPER_BYTES = 29599
HELPER_SHA = 'e83823a99ae1832e31f80be6e1092b77ea2ce0ab6f25933592287311a37e7c36'
sys.path.insert(0, str(ROOT / 'scripts'))
import source_main_environment as main_policy
import rockstar_code_policy as policy
from probe_environment import ProbePrefixError, _location, _plain_path, _check_c_drive, _check_shell_folders
from user_game_data_policy import validated_game_root

OLD_FILES = tuple(policy.CODE_ROOTS[0] + '/' + name for name in ('Launcher.exe.old', 'RockstarService.exe.old'))
STAGE_NAMES = ('plan.json', 'new-code-manifest.json', 'update-origin.json', 'new-marker.json')


def encoded(value):
    return (json.dumps(value, indent=2) + '\n').encode()


def identity(raw, path):
    return {'path': path, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def load_helper():
    path = ROOT / HELPER
    before = policy._regular_file(path, ROOT)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as source:
        raw = source.read(HELPER_BYTES + 1)
        after = os.fstat(source.fileno())
    current = policy._regular_file(path, ROOT)
    if any((value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns, value.st_nlink) !=
           (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns, before.st_nlink)
           for value in (after, current)):
        raise ProbePrefixError('The frozen update-controller bytes changed during admission.')
    if len(raw) != HELPER_BYTES or hashlib.sha256(raw).hexdigest() != HELPER_SHA:
        raise ProbePrefixError('The frozen original update controller changed.')
    module = ModuleType('_one_off_update_finalization_helper')
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def inputs(helper):
    observation = policy._update_record(ROOT, {'path': OBSERVATION, 'sha256': OBSERVATION_SHA},
                                         lambda value: value == OBSERVATION, OBSERVATION_BYTES)
    prefix, root = _location(PREFIX, ROOT)
    info = prefix.stat()
    user = getpass.getuser()
    marker_path = prefix / main_policy.MARKER_NAME
    old_marker = helper.read_metadata(marker_path, 4096)
    marker = main_policy._read_identity(prefix, root, user)
    old_ref = {'path': policy.MANIFEST_NAME, 'sha256': policy.UPDATE_PREVIOUS_SHA256}
    if marker.get('rockstar_code_manifest') != old_ref or policy.UPDATE_MARKER_KEY in marker:
        raise ProbePrefixError('Only the original not-yet-finalized code binding may advance.')
    old_manifest_raw = helper.read_metadata(prefix / policy.MANIFEST_NAME)
    if hashlib.sha256(old_manifest_raw).hexdigest() != old_ref['sha256']:
        raise ProbePrefixError('The old code binding changed.')
    old_manifest = json.loads(old_manifest_raw)
    if (prefix != PREFIX or root != ROOT or observation.get('prefix') != 'prefixes/fivem-source-main'
            or observation.get('prefix_device') != info.st_dev or observation.get('prefix_inode') != info.st_ino
            or observation.get('user') != user or observation.get('kind') != 'root-observed-rockstar-post-update-state'
            or observation.get('library_confirmed_by_user') is not True
            or observation.get('library_observed_by_root_sck') is not True
            or observation.get('validated_close_exit') != 0 or observation.get('scoped_wait_exit') != 0
            or observation.get('known_native_pids_gone') != [69967, 70009]
            or observation.get('manual_user_login') != marker.get('manual_user_login')
            or observation.get('user_game_data_origin') != marker.get('user_game_data_origin')):
        raise ProbePrefixError('Require the exact actual post-update library and terminal observation.')
    if not main_policy._manual_login_authorized(marker, prefix, root, user):
        raise ProbePrefixError('The original manual login context is required.')
    game_root = validated_game_root(prefix, root, marker, user)
    _check_c_drive(prefix)
    _check_shell_folders(prefix)
    sdk = observation['sdk_user_data']
    sdk_path = prefix / policy.sdk_user_root(user)
    _plain_path(sdk_path, prefix)
    sdk_info = sdk_path.lstat()
    if (not stat.S_ISDIR(sdk_info.st_mode) or sdk.get('relative_root') != policy.sdk_user_root(user)
            or (sdk_info.st_dev, sdk_info.st_ino, policy._birthtime_ns(sdk_info)) != (
                sdk.get('root_device'), sdk.get('root_inode'), sdk.get('root_birthtime_ns'))):
        raise ProbePrefixError('The observed SDK directory identity changed.')
    roots = list(policy.user_roots(user)) + [policy.sdk_user_root(user)] + ([game_root] if game_root else [])
    policy._verify_user_tree(prefix, roots)
    machine = old_manifest.get('machine_runtime_policy')
    machine_path = prefix / policy.MACHINE_ROOT
    _plain_path(machine_path, prefix)
    if not machine or policy._directory_identity(machine_path) != machine['directory']:
        raise ProbePrefixError('The original machine-runtime directory identity changed.')
    context = {'prefix_identity': [info.st_dev, info.st_ino], 'identity': marker, 'manifest': old_manifest,
        'code_manifest_sha256': old_ref['sha256'], 'staging_review': {
            'path': helper.FROZEN, 'bytes': helper.FROZEN_BYTES, 'sha256': helper.FROZEN_SHA}}
    checkpoint = helper.verify_checkpoint(context)
    session_ref = observation['update_session']
    policy._update_record(ROOT, session_ref, lambda value: bool(policy.re.fullmatch(
        r'research/user-rockstar-official-update-\d{8}T\d{12}Z\.json', value)))
    return {'context': context, 'observation': observation, 'checkpoint': checkpoint,
            'old_marker': old_marker, 'old_manifest': old_manifest_raw, 'user': user}


def inventory(old_manifest):
    expected_old = {row['path']: row for row in old_manifest['files']}
    files, moves, aliases = [], [], set()
    for root_name in policy.UPDATED_CODE_ROOTS:
        directory = PREFIX / root_name
        _plain_path(directory, PREFIX)
        if not directory.is_dir():
            raise ProbePrefixError('An updated code root is absent.')
        def fail(error):
            raise error
        for base, folders, names in os.walk(directory, followlinks=False, onerror=fail):
            for name in folders + names:
                path = Path(base) / name
                _plain_path(path, PREFIX)
                value = path.lstat()
                relative = path.relative_to(PREFIX).as_posix()
                if any(part.casefold() in policy.FORBIDDEN_CODE_PARTS or part.casefold().startswith(('cfxticket', 'ros_login.'))
                       for part in path.relative_to(directory).parts):
                    raise ProbePrefixError('Profile, registry and account artifacts cannot enter the code inventory.')
                if stat.S_ISDIR(value.st_mode):
                    continue
                if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1 or relative.casefold() in aliases:
                    raise ProbePrefixError('Updated code must remain local, unaliased regular single-link files.')
                aliases.add(relative.casefold())
                if len(aliases) > 10000 or name.casefold().endswith('.swap'):
                    raise ProbePrefixError('Unfinished staging or excessive code inventory remains.')
                digest = policy._sha(path, PREFIX)
                row = {'path': relative, 'bytes': value.st_size, 'sha256': digest}
                if name.casefold().endswith('.old'):
                    original = expected_old.get(relative[:-4])
                    if relative not in OLD_FILES or original is None or (row['bytes'], digest) != (original['bytes'], original['sha256']):
                        raise ProbePrefixError('Only the two byte-verified original vendor code backups may move.')
                    destination = CHECKPOINT / 'post-update-code-backups' / name
                    _plain_path(destination, ROOT)
                    if destination.exists() or destination.is_symlink():
                        raise ProbePrefixError('Preserve any existing post-update code backup.')
                    moves.append(dict(row, destination=str(destination.relative_to(ROOT)),
                        device=value.st_dev, inode=value.st_ino))
                else:
                    files.append(row)
    if not files:
        raise ProbePrefixError('The updated code inventory is empty.')
    if {row['path'] for row in moves} != set(OLD_FILES):
        raise ProbePrefixError('Require both exact verified old vendor code-backup files for this one-off transaction.')
    return sorted(files, key=lambda row: row['path']), sorted(moves, key=lambda row: row['path'])


def plan(helper):
    state = inputs(helper)
    context, observation = state['context'], state['observation']
    previous = context['manifest']
    files, moves = inventory(previous)
    manifest = json.loads(json.dumps(previous))
    manifest.update(files=files, roots=list(policy.UPDATED_CODE_ROOTS), source_evidence=observation['update_session'],
                    previous_source_evidence=previous['source_evidence'],
                    user_data_roots=list(policy.user_roots(state['user'])) + [policy.sdk_user_root(state['user'])])
    manifest_raw = encoded(manifest)
    new_ref = {'path': policy.MANIFEST_NAME, 'sha256': hashlib.sha256(manifest_raw).hexdigest()}
    info = PREFIX.stat()
    proof = {'schema': 1, 'kind': 'user-authorized-rockstar-code-update-origin',
        'scope': 'same-source-prefix-code-update-metadata-only', 'prefix': 'prefixes/fivem-source-main',
        'prefix_device': info.st_dev, 'prefix_inode': info.st_ino, 'user': state['user'],
        'previous_code_manifest': context['identity']['rockstar_code_manifest'], 'current_code_manifest': new_ref,
        'previous_manifest_backup': {'path': policy.UPDATE_PREVIOUS_BACKUP, 'sha256': policy.UPDATE_PREVIOUS_SHA256},
        'manual_user_login': context['identity']['manual_user_login'],
        'user_game_data_origin': context['identity']['user_game_data_origin'],
        'update_session': observation['update_session'],
        'update_session_outcome': 'old-policy-rejected-new-sdk-user-root',
        'vendor_update_completed_observed': True, 'post_update_library_observed': True,
        'post_update_prefix_quiescent': True, 'copied_or_imported': False,
        'sdk_user_data': observation['sdk_user_data'], 'machine_runtime': {
            'root': policy.MACHINE_ROOT, 'directory': previous['machine_runtime_policy']['directory'],
            'unchanged_from_previous_binding': True},
        'post_update_observation': {'path': OBSERVATION, 'bytes': OBSERVATION_BYTES, 'sha256': OBSERVATION_SHA}}
    x86 = {'root': policy.UPDATE_X86_CODE_ROOT, 'created_during_update': True, 'copied_or_imported': False}
    for key, relative in (('container', policy.UPDATE_X86_CONTAINER), ('directory', policy.UPDATE_X86_CODE_ROOT)):
        directory = PREFIX / relative
        _plain_path(directory, PREFIX)
        value = directory.lstat()
        if not stat.S_ISDIR(value.st_mode):
            raise ProbePrefixError('The actual 32-bit Social Club code directory must remain local.')
        x86[key] = {'device': value.st_dev, 'inode': value.st_ino, 'birthtime_ns': policy._birthtime_ns(value)}
    proof['social_club_x86'] = x86
    proof_raw = encoded(proof)
    marker = dict(context['identity'], rockstar_code_manifest=new_ref)
    marker[policy.UPDATE_MARKER_KEY] = {'path': policy.UPDATE_EVIDENCE_PATH, 'sha256': hashlib.sha256(proof_raw).hexdigest()}
    payloads = {'new-code-manifest.json': manifest_raw, 'update-origin.json': proof_raw, 'new-marker.json': encoded(marker)}
    record = {'schema_version': 1, 'kind': 'one-off-rockstar-code-finalization-plan',
        'prefix_identity': context['prefix_identity'], 'checkpoint': state['checkpoint'],
        'post_update_observation': proof['post_update_observation'], 'old_code_manifest_sha256': policy.UPDATE_PREVIOUS_SHA256,
        'new_code_manifest': new_ref, 'new_code_files': len(files), 'code_backup_relocations': moves,
        'staged_payloads': {name: identity(raw, str((STAGED / name).relative_to(ROOT))) for name, raw in payloads.items()},
        'vendor_code_rollback_or_downgrade': False, 'historical_login_origin_or_installation_rewrites': False}
    payloads['plan.json'] = encoded(record)
    state.update(payloads=payloads, plan=record)
    return state


def stage(helper, state):
    _plain_path(STAGED, ROOT)
    if STAGED.exists():
        if not STAGED.is_dir() or {path.name for path in STAGED.iterdir()} != set(STAGE_NAMES):
            raise ProbePrefixError('Preserve an unexpected or partial finalization staging directory.')
        for name, raw in state['payloads'].items():
            if helper.read_metadata(STAGED / name) != raw:
                raise ProbePrefixError('The staged finalization plan differs; preserve it for review.')
    else:
        STAGED.mkdir(mode=0o700)
        for name, raw in state['payloads'].items():
            path = STAGED / name
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as target:
                target.write(raw); target.flush(); os.fsync(target.fileno())
    return dict(state['plan'], plan_sha256=hashlib.sha256(state['payloads']['plan.json']).hexdigest(),
                prefix_files_written=False, wine_or_client_started=False)


def quiescent(helper, state):
    from run_source import select_runtime_profile
    runtime, _ = select_runtime_profile('parity')
    env = helper.runtime_environment(runtime)
    runtime.before_source_spawn()
    helper.cleanup_identity(runtime, env, state['context'])
    for pid in state['observation']['known_native_pids_gone']:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            continue
        raise ProbePrefixError('A previously closed native launcher PID is currently present; review PID reuse.')
    result = subprocess.run([str(runtime.ENGINE / 'bin/wineserver'), '-w'], env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15, check=False)
    if result.returncode != 0:
        raise ProbePrefixError('The bound Source-prefix server did not confirm quiescence.')
    helper.cleanup_identity(runtime, env, state['context'])
    return {'flag': '-w', 'exit': result.returncode, 'timeout_seconds': 15, 'kill_issued': False}


def same_prefix(state):
    prefix, root = _location(PREFIX, ROOT)
    value = prefix.stat()
    if prefix != PREFIX or root != ROOT or [value.st_dev, value.st_ino] != state['context']['prefix_identity']:
        raise ProbePrefixError('Finalization refuses a replaced Source prefix.')


def commit(helper, state):
    label = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    output = ROOT / 'research' / ('rockstar-update-finalization-' + label + '.json')
    record = {'schema_version': 1, 'kind': 'one-off-rockstar-code-finalization-result',
        'at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'plan': identity(state['payloads']['plan.json'],
            str((STAGED / 'plan.json').relative_to(ROOT))), 'status': 'checking-quiescence',
        'code_binding_finalized': False, 'vendor_code_rollback_or_downgrade': False,
        'historical_login_origin_or_installation_rewrites': False, 'relocated_code_backups': []}
    helper.save(output, record, new=True)
    manifest_path, marker_path = PREFIX / policy.MANIFEST_NAME, PREFIX / main_policy.MARKER_NAME
    metadata_attempted = False
    try:
        record['precommit_wait'] = quiescent(helper, state)
        fresh = plan(helper)
        if fresh['payloads'] != state['payloads']:
            raise ProbePrefixError('Code or metadata changed after staging/quiescence.')
        stage(helper, fresh)
        proof_path = ROOT / policy.UPDATE_EVIDENCE_PATH
        if proof_path.exists() or proof_path.is_symlink():
            if helper.read_metadata(proof_path) != state['payloads']['update-origin.json']:
                raise ProbePrefixError('Preserve the existing different update-origin evidence.')
        else:
            helper.save(proof_path, json.loads(state['payloads']['update-origin.json']), new=True)
        for move in state['plan']['code_backup_relocations']:
            same_prefix(state)
            source, target = PREFIX / move['path'], ROOT / move['destination']
            _plain_path(source, PREFIX); _plain_path(target, ROOT)
            value = policy._regular_file(source, PREFIX)
            if (value.st_dev, value.st_ino, value.st_size, policy._sha(source, PREFIX)) != (
                    move['device'], move['inode'], move['bytes'], move['sha256']):
                raise ProbePrefixError('A verified old code-backup file changed before relocation.')
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            _plain_path(target, ROOT)
            if target.exists() or target.is_symlink() or target.parent.stat().st_dev != value.st_dev:
                raise ProbePrefixError('Code-backup relocation must be a fresh same-volume checkpoint target.')
            os.rename(source, target)
            record['relocated_code_backups'].append(move)
        policy._verify_code(json.loads(state['payloads']['new-code-manifest.json']), PREFIX, ROOT,
                            expected_roots=policy.UPDATED_CODE_ROOTS)
        metadata_attempted = True
        same_prefix(state)
        policy._write_bytes(manifest_path, state['payloads']['new-code-manifest.json'], PREFIX)
        same_prefix(state)
        policy._write_bytes(marker_path, state['payloads']['new-marker.json'], PREFIX)
        main_policy.assert_source_main_prefix(PREFIX, root=ROOT)
        record.update(status='finalized', code_binding_finalized=True,
            current_code_manifest=state['plan']['new_code_manifest'], code_files=state['plan']['new_code_files'],
            update_origin=identity(state['payloads']['update-origin.json'], policy.UPDATE_EVIDENCE_PATH))
    except BaseException as error:
        record.update(status='failed-needs-review', failure_type=type(error).__name__, rollback=[])
        if isinstance(error, ProbePrefixError):
            record['failure_message'] = str(error)
        if metadata_attempted:
            for path, raw in ((marker_path, state['old_marker']), (manifest_path, state['old_manifest'])):
                try:
                    same_prefix(state)
                    policy._write_bytes(path, raw, PREFIX)
                    record['rollback'].append({'path': path.name, 'restored': True})
                except BaseException as rollback_error:
                    record['rollback'].append({'path': path.name, 'restored': False, 'failure_type': type(rollback_error).__name__})
        for move in reversed(record['relocated_code_backups']):
            source, target = PREFIX / move['path'], ROOT / move['destination']
            try:
                same_prefix(state)
                _plain_path(source, PREFIX); _plain_path(target, ROOT)
                if source.exists() or source.is_symlink():
                    raise ProbePrefixError('Preserve an occupied original code-backup location.')
                if policy._sha(target, ROOT) != move['sha256']:
                    raise ProbePrefixError('Preserve changed checkpoint code-backup bytes.')
                os.rename(target, source)
                record['rollback'].append({'path': move['path'], 'restored': True})
            except BaseException as rollback_error:
                record['rollback'].append({'path': move['path'], 'restored': False, 'failure_type': type(rollback_error).__name__})
        record['unbound_update_proof_preserved_if_written'] = True
    finally:
        record['ended_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        helper.save(output, record)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('inspect', 'commit'))
    args = parser.parse_args()
    helper = load_helper()
    with main_policy._source_main_file_lock(PREFIX):
        state = plan(helper)
        summary = stage(helper, state)
        result = summary if args.action == 'inspect' else commit(helper, state)
    print(json.dumps(result, indent=2))
    return 0 if args.action == 'inspect' or result['code_binding_finalized'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
