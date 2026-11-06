#!/usr/bin/env python3
"""One authorized original-RGL update session; no FiveM, installer, or code rebinding."""
import argparse
import ctypes
import datetime
import errno
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
PREFIX = ROOT / 'prefixes/fivem-source-main'
CHECKPOINT = ROOT / 'build/checkpoints/rockstar-official-update-20261103'
FROZEN = 'research/rockstar-old142-pending-zero-swap-20261103.json'
FROZEN_BYTES = 5819
FROZEN_SHA = '2f0a6e3ee7cffe0edf4fd4d2a17c993c69cd7334d6b3567cf65ead4e997084e7'
sys.path.insert(0, str(ROOT / 'scripts'))
import source_main_environment as main_policy
import rockstar_code_policy as code_policy
from probe_environment import ProbePrefixError, _location, _plain_path, _check_c_drive, _check_shell_folders
from user_game_data_policy import validated_game_root, game_metadata_directory_allowed

STAGE_BASE = 'drive_c/Program Files/Rockstar Games/Launcher/swap/'
STAGES = {
    STAGE_BASE + '130345C50F8201EA1CA6B873C8038FEBFAE0E60A6DD8413C889B353CAE2EA29815423.swap': 2775672,
    STAGE_BASE + '134AB2569161F774D08F767CAFDE9A3B3B9787B4E4B09815D6A660CFD782877E975.swap': 1198712,
    STAGE_BASE + '5E622FAD2B8AFFB68B76F8D2412CCA9B8329745444342CA941D291097494AAE2978.swap': 1741944,
    STAGE_BASE + '7FC674746507BFBF6EE7CE8C4E8C2E31703F965D4E482D0BE2A127528F1E8F97981.swap': 172607608,
    STAGE_BASE + '92D7A4B82EC38D2CA3A1F3006D87F3DE5384FED09363262CC825EA1172AD4FC018439.swap': 614008,
    STAGE_BASE + '9CF5DD2E20371E7992B528F83B24F0548C06C2E060801DAE8C32943BD864DF0A979.swap': 1354360,
    STAGE_BASE + '9E271E2E512397FAA1784F8CA5B25F07885E82C6F6FE3723C5BF60B5A341386B973.swap': 30613112,
    STAGE_BASE + 'AA81324EE2939EB21B54AE2F3B6057776F2E80DF4E0AE4155DCACFB38A3247C4974.swap': 1562624,
    STAGE_BASE + 'EF8AE59F79C25991D1965D74DCA18FC5BB1FDBA3BA5B727DEF7758BBC8856FBE16987.swap': 213624,
}
ZERO_STAGE = STAGE_BASE + 'EF8AE59F79C25991D1965D74DCA18FC5BB1FDBA3BA5B727DEF7758BBC8856FBE16987.swap'
GAME_FOLDERS = {'Grand Theft Auto V Legacy', 'Grand Theft Auto V'}


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def regular(path, boundary=ROOT):
    _plain_path(path, boundary)
    value = path.lstat()
    if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1:
        raise ProbePrefixError('Require a local regular single-link file.')
    return value


def fingerprint(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)


def read_metadata(path, maximum=4194304):
    before = regular(path)
    if before.st_size > maximum:
        raise ProbePrefixError('Bounded technical metadata is too large.')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as source:
        if fingerprint(os.fstat(source.fileno())) != fingerprint(before):
            raise ProbePrefixError('Technical metadata changed before reading.')
        raw = source.read(maximum + 1)
        if (fingerprint(os.fstat(source.fileno())) != fingerprint(before)
                or fingerprint(path.lstat()) != fingerprint(before)):
            raise ProbePrefixError('Technical metadata changed while reading.')
    if len(raw) != before.st_size:
        raise ProbePrefixError('Technical metadata read is incomplete.')
    return raw


def frozen_inventory():
    raw = read_metadata(ROOT / FROZEN, FROZEN_BYTES)
    if len(raw) != FROZEN_BYTES or hashlib.sha256(raw).hexdigest() != FROZEN_SHA:
        raise ProbePrefixError('The reviewed old142/staging report changed.')
    record = json.loads(raw)
    known = record['known_zero_staging']
    others = record['unclassified_additional_files_metadata_only']
    declared = {row['path']: row['bytes'] for row in others}
    declared[known['path']] = known['bytes']
    if (declared != STAGES or len(others) != 8 or known['path'] != ZERO_STAGE
            or record['prefix'] != 'prefixes/fivem-source-main'
            or record['baseline']['files'] != 142
            or record['baseline']['all_bound_original_files_exact_size_and_sha256'] is not True
            or record['inventory']['observed_regular_files'] != 151):
        raise ProbePrefixError('The fixed report does not describe exactly the reviewed 142+9 roles.')
    return record


def walk_local(directory, forbidden=False, required=True):
    _plain_path(directory, PREFIX)
    if not directory.exists() and not required:
        return {}
    if not directory.is_dir():
        raise ProbePrefixError('A reviewed local directory is absent or invalid.')
    result, aliases = {}, set()
    def fail(error):
        if isinstance(error, FileNotFoundError) and error.errno == errno.ENOENT and isinstance(error.filename, str):
            candidate = Path(error.filename)
            try:
                relative = candidate.relative_to(directory)
                if relative.parts and '..' not in relative.parts:
                    _plain_path(candidate, PREFIX)
                    try:
                        candidate.lstat()
                    except FileNotFoundError:
                        return
            except ValueError:
                pass
        raise error
    for base, folders, files in os.walk(directory, followlinks=False, onerror=fail):
        for name in folders + files:
            path = Path(base) / name
            _plain_path(path, PREFIX)
            try:
                info = path.lstat()
            except FileNotFoundError:
                # An updater may atomically replace or retire one of its own files.
                continue
            relative = path.relative_to(PREFIX).as_posix()
            if forbidden and any(part.casefold() in code_policy.FORBIDDEN_CODE_PARTS
                                 or part.casefold().startswith(('cfxticket', 'ros_login.'))
                                 for part in path.relative_to(directory).parts):
                raise ProbePrefixError('Account artifacts cannot become updater code or machine data.')
            if stat.S_ISDIR(info.st_mode):
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ProbePrefixError('Update boundaries reject aliases, special files and hard links.')
            if relative.casefold() in aliases:
                raise ProbePrefixError('Update boundaries reject Windows-case aliases.')
            aliases.add(relative.casefold())
            result[relative] = info
    return result


def isolation(context):
    prefix, root = _location(PREFIX, ROOT)
    info = prefix.stat()
    if (root != ROOT or prefix != PREFIX
            or (info.st_dev, info.st_ino) != tuple(context['prefix_identity'])):
        raise ProbePrefixError('Only the same authorized Source prefix may be updated.')
    identity = main_policy._read_identity(prefix, root, getpass.getuser())
    if identity != context['identity']:
        raise ProbePrefixError('Existing Source metadata bindings changed during the update.')
    raw = read_metadata(prefix / code_policy.MANIFEST_NAME)
    if hashlib.sha256(raw).hexdigest() != context['code_manifest_sha256']:
        raise ProbePrefixError('Only later reviewed finalization may change the code binding.')
    for relative in ('system.reg', 'user.reg', 'userdef.reg', 'drive_c', 'drive_c/users'):
        _plain_path(prefix / relative, prefix)
    if (prefix / '.account-free-probe').exists() or (prefix / '.account-free-probe').is_symlink():
        raise ProbePrefixError('The updater cannot use an account-free role.')
    _check_c_drive(prefix)
    _check_shell_folders(prefix)
    manifest, game_root = context['manifest'], context['game_root']
    roots = manifest['user_data_roots'] + ([game_root] if game_root else [])
    code_policy._verify_user_tree(prefix, roots)
    users = prefix / 'drive_c/users'
    for relative, data in walk_local(users).items():
        path = prefix / relative
        lowered = path.name.casefold()
        if lowered in main_policy.ACCOUNT_FILE_NAMES or lowered.startswith('cfxticket'):
            if not (main_policy._is_own_cache(path, prefix)
                    or code_policy.user_path_allowed(path, prefix, manifest)):
                raise ProbePrefixError('Login artifacts remain restricted to existing approved roots.')
    for base, folders, _ in os.walk(users, followlinks=False):
        for name in folders:
            path = Path(base) / name
            if any(token in name.casefold() for token in main_policy.ACCOUNT_DIRECTORY_NAMES):
                cache = main_policy._is_own_cache(path, prefix) and not any(
                    token in name.casefold() for token in ('rockstar', 'social club', 'socialclub'))
                if not (cache or code_policy.user_path_allowed(path, prefix, manifest)
                        or game_metadata_directory_allowed(path, prefix, game_root)):
                    raise ProbePrefixError('Unexpected client/profile directory outside approved roots.')
    container = prefix / code_policy.CODE_CONTAINER
    _plain_path(container, prefix)
    if not container.is_dir() or not {p.name for p in container.iterdir()} <= {'Launcher', 'Social Club'} | GAME_FOLDERS:
        raise ProbePrefixError('Only the original two code roots and existing game folder names are allowed.')
    code = {}
    for name in code_policy.CODE_ROOTS:
        code.update(walk_local(prefix / name, forbidden=True))
    machine = manifest.get('machine_runtime_policy')
    if machine:
        directory = prefix / code_policy.MACHINE_ROOT
        _plain_path(directory, prefix)
        if code_policy._directory_identity(directory) != machine['directory']:
            raise ProbePrefixError('The enrolled machine-runtime directory changed identity.')
        parent = prefix / code_policy.MACHINE_CONTAINER
        _plain_path(parent, prefix)
        if {p.name for p in parent.iterdir()} != {'Launcher'}:
            raise ProbePrefixError('Unexpected Rockstar machine-runtime sibling.')
        walk_local(directory, forbidden=True)
    for relative in ('drive_c', 'drive_c/Program Files', 'drive_c/Program Files (x86)', 'drive_c/ProgramData'):
        directory = prefix / relative
        _plain_path(directory, prefix)
        if directory.is_dir():
            for child in directory.iterdir():
                if any(token in child.name.casefold() for token in main_policy.ACCOUNT_DIRECTORY_NAMES):
                    allowed = child == container or (machine and child == prefix / code_policy.MACHINE_CONTAINER)
                    if not allowed:
                        raise ProbePrefixError('Unexpected client installation outside updater roots.')
    return {'code_files_currently_observed': len(code), 'metadata_boundaries_passed': True,
            'runtime_code_immutability_enforced': False}


def preflight():
    reviewed = frozen_inventory()
    prefix, root = _location(PREFIX, ROOT)
    info = prefix.stat()
    if (prefix != PREFIX or root != ROOT or prefix.name != 'fivem-source-main'
            or (info.st_dev, info.st_ino) != (reviewed['prefix_device'], reviewed['prefix_inode'])):
        raise ProbePrefixError('The fixed staging review belongs to another prefix.')
    user = getpass.getuser()
    identity = main_policy._read_identity(prefix, root, user)
    if not main_policy._manual_login_authorized(identity, prefix, root, user):
        raise ProbePrefixError('Require the existing user-authorized manual login context.')
    reference = identity.get('rockstar_code_manifest')
    if reference != reviewed['binding']['manifest'] or reference.get('path') != code_policy.MANIFEST_NAME:
        raise ProbePrefixError('Require the exact original code-manifest binding.')
    raw = read_metadata(prefix / code_policy.MANIFEST_NAME)
    if hashlib.sha256(raw).hexdigest() != reference['sha256']:
        raise ProbePrefixError('The original code manifest changed.')
    manifest = json.loads(raw)
    if (manifest.get('schema') != 1 or manifest.get('kind') != 'rockstar-code-only'
            or manifest.get('roots') != list(code_policy.CODE_ROOTS)
            or manifest.get('prefix_binding') != code_policy._binding(prefix, root, user)
            or manifest.get('user_data_roots') != list(code_policy.user_roots(user))
            or manifest.get('user_data_initial_state') != 'absent_or_empty_before_runtime'
            or manifest.get('excluded_account_profiles_registry_sessions') is not True
            or len(manifest.get('files', [])) != 142):
        raise ProbePrefixError('Require the exact reviewed original 142-file code policy.')
    code_policy._source_evidence(manifest, root)
    machine = manifest.get('machine_runtime_policy')
    if machine:
        if (not isinstance(machine, dict) or set(machine) != {'root', 'directory', 'origin_evidence'}
                or machine['root'] != code_policy.MACHINE_ROOT):
            raise ProbePrefixError('Require the existing exact machine-runtime policy.')
        origin = code_policy._json_reference(machine['origin_evidence'], root)
        if (origin.get('schema') != 1 or origin.get('kind') != 'fresh-rockstar-machine-runtime'
                or origin.get('copied_from_other_prefix') is not False
                or origin.get('prefix') != 'prefixes/fivem-source-main'
                or origin.get('directory') != machine['directory']):
            raise ProbePrefixError('Machine-runtime origin evidence changed.')
    game_root = validated_game_root(prefix, root, identity, user)
    context = {'prefix_identity': [info.st_dev, info.st_ino], 'identity': identity,
               'manifest': manifest, 'code_manifest_sha256': reference['sha256'], 'game_root': game_root}
    isolation(context)
    actual = {}
    for name in code_policy.CODE_ROOTS:
        actual.update(walk_local(prefix / name, forbidden=True))
    baseline = checkpoint_items(manifest)
    if set(actual) != {item['path'] for item in baseline[:142]} | set(STAGES):
        raise ProbePrefixError('Require exactly the old 142 files plus the fixed nine pending stages.')
    for item in baseline[:142]:
        path = prefix / item['path']
        if path.stat().st_size != item['bytes'] or code_policy._sha(path, prefix) != item['sha256']:
            raise ProbePrefixError('The original code differs before the updater starts.')
    for row in reviewed['unclassified_additional_files_metadata_only']:
        value = actual[row['path']]
        if value.st_size != row['bytes']:
            raise ProbePrefixError('A reviewed pending-stage size changed.')
        if (value.st_dev, value.st_ino, value.st_nlink, value.st_mtime_ns, value.st_ctime_ns) != (
                row['device'], row['inode'], row['nlink'], row['mtime_ns'], row['ctime_ns']):
            raise ProbePrefixError('A reviewed pending-stage filesystem identity changed.')
    known = reviewed['known_zero_staging']
    if actual[ZERO_STAGE].st_size != known['bytes'] or code_policy._sha(prefix / ZERO_STAGE, prefix) != known['sha256']:
        raise ProbePrefixError('The separately reviewed zero-filled stage changed.')
    context['staging_review'] = {'path': FROZEN, 'bytes': FROZEN_BYTES, 'sha256': FROZEN_SHA}
    return context


def checkpoint_items(manifest):
    items = manifest.get('files', [])
    if len(items) != 142:
        raise ProbePrefixError('Checkpoint requires exactly 142 reviewed code files.')
    seen = set()
    for item in items:
        if not isinstance(item, dict) or set(item) != {'path', 'bytes', 'sha256'}:
            raise ProbePrefixError('Invalid original code role.')
        if (type(item['bytes']) is not int or item['bytes'] < 0
                or type(item['sha256']) is not str or not re.fullmatch('[0-9a-f]{64}', item['sha256'])):
            raise ProbePrefixError('Invalid original code identity.')
        relative = code_policy._relative(item['path'])
        if (not any(relative != Path(r) and code_policy._under(relative, Path(r)) for r in code_policy.CODE_ROOTS)
                or item['path'] in STAGES or item['path'].casefold() in seen
                or any(part.casefold() in code_policy.FORBIDDEN_CODE_PARTS
                       or part.casefold().startswith(('cfxticket', 'ros_login.')) for part in relative.parts)):
            raise ProbePrefixError('Checkpoint cannot copy staging, registry, account or non-code paths.')
        seen.add(item['path'].casefold())
    return [dict(item) for item in items] + [{'path': name} for name in (
        main_policy.MARKER_NAME, code_policy.MANIFEST_NAME)]


def save(path, record, new=False):
    _plain_path(path, ROOT)
    raw = (json.dumps(record, indent=2) + '\n').encode()
    if new:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as target:
            target.write(raw); target.flush(); os.fsync(target.fileno())
        return
    regular(path)
    fd, temporary = tempfile.mkstemp(prefix='.rgl-update-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as target:
            target.write(raw); target.flush(); os.fsync(target.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def verify_checkpoint(context):
    path = CHECKPOINT / 'checkpoint.json'
    record = json.loads(read_metadata(path))
    expected = checkpoint_items(context['manifest'])
    if (record.get('kind') != 'one-off-original-rockstar-code-checkpoint' or record.get('complete') is not True
            or record.get('prefix_identity') != context['prefix_identity']
            or record.get('old_code_manifest_sha256') != context['code_manifest_sha256']
            or record.get('staging_review') != context['staging_review']
            or [row.get('path') for row in record.get('files', [])] != [row['path'] for row in expected]):
        raise ProbePrefixError('The fixed code-only checkpoint is missing or belongs to another state.')
    for row, original in zip(record['files'], expected):
        if 'sha256' in original and (row.get('sha256'), row.get('bytes')) != (original['sha256'], original['bytes']):
            raise ProbePrefixError('Checkpoint must preserve the exact old code identities.')
        if 'sha256' not in original:
            source = PREFIX / row['path']
            if (row.get('sha256'), row.get('bytes')) != (code_policy._sha(source, PREFIX), regular(source, PREFIX).st_size):
                raise ProbePrefixError('Checkpoint must preserve the exact unchanged metadata anchors.')
        target = CHECKPOINT / 'files' / row['path']
        value = regular(target)
        if value.st_size != row['bytes'] or code_policy._sha(target, ROOT) != row['sha256']:
            raise ProbePrefixError('A code-only checkpoint file changed.')
    return {'path': str(path.relative_to(ROOT)), 'sha256': hashlib.sha256(read_metadata(path)).hexdigest(),
            'files': 144, 'complete': True}


def prepare():
    with main_policy._source_main_file_lock(PREFIX):
        context = preflight()
        _plain_path(CHECKPOINT, ROOT)
        if CHECKPOINT.exists() or CHECKPOINT.is_symlink():
            raise ProbePrefixError('Preserve the existing fixed checkpoint; never overwrite it.')
        items = checkpoint_items(context['manifest'])
        CHECKPOINT.mkdir(parents=True, mode=0o700)
        record = {'schema_version': 1, 'kind': 'one-off-original-rockstar-code-checkpoint', 'at': now(),
            'prefix_identity': context['prefix_identity'], 'old_code_manifest_sha256': context['code_manifest_sha256'],
            'staging_review': context['staging_review'], 'complete': False, 'files': [],
            'copied_registry_user_profile_login_or_staging_files': False, 'runtime_started': False}
        output = CHECKPOINT / 'checkpoint.json'
        save(output, record, new=True)
        try:
            libc = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
            libc.clonefile.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
            libc.clonefile.restype = ctypes.c_int
            for item in items:
                source, target = PREFIX / item['path'], CHECKPOINT / 'files' / item['path']
                before = regular(source, PREFIX)
                _plain_path(target, ROOT)
                if target.exists() or target.is_symlink():
                    raise ProbePrefixError('A code-checkpoint destination already exists.')
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                if source.stat().st_dev != target.parent.stat().st_dev:
                    raise ProbePrefixError('Code checkpoint must use the same CoW filesystem.')
                digest = code_policy._sha(source, PREFIX)
                if libc.clonefile(os.fsencode(source), os.fsencode(target), 0x0008) != 0:
                    raise OSError(ctypes.get_errno(), 'Code-only clonefile failed')
                after = regular(target)
                if ((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino)
                        or fingerprint(source.lstat()) != fingerprint(before)
                        or after.st_size != before.st_size or code_policy._sha(target, ROOT) != digest):
                    raise ProbePrefixError('Code-only CoW clone did not preserve separate exact bytes.')
                record['files'].append({'path': item['path'], 'bytes': before.st_size, 'sha256': digest,
                    'source_device': before.st_dev, 'source_inode': before.st_ino,
                    'checkpoint_device': after.st_dev, 'checkpoint_inode': after.st_ino})
            if preflight() != context:
                raise ProbePrefixError('Original updater prerequisites changed during checkpoint preparation.')
            record.update(complete=True, completed_at=now())
        except BaseException as error:
            record.update(failure_type=type(error).__name__, partial_checkpoint_preserved=True)
            raise
        finally:
            save(output, record)
        return verify_checkpoint(context)


def runtime_environment(runtime):
    engine = ROOT / 'runtime/wine-job-query-parity/engine'
    if runtime.ENGINE != engine or runtime.WINE != engine / 'bin/wine':
        raise ProbePrefixError('Only the verified baseline Parity runtime is allowed.')
    env = dict(runtime.environment())
    if any(key.casefold().startswith('citizenfx_') for key in env):
        raise ProbePrefixError('No inherited CitizenFX roles may enter the normal updater session.')
    env.update(WINEPREFIX=str(PREFIX), WINESERVER=str(engine / 'bin/wineserver'), WINEDEBUG='-all')
    for name in ('WINESERVERSOCKET', 'WINELOADER', 'WINELOADERNOEXEC'):
        env.pop(name, None)
    return env


def cleanup_identity(runtime, env, context):
    prefix, root = _location(PREFIX, ROOT)
    value = prefix.stat()
    if (prefix != PREFIX or root != ROOT
            or (value.st_dev, value.st_ino) != tuple(context['prefix_identity'])
            or env.get('WINEPREFIX') != str(PREFIX)
            or env.get('WINESERVER') != str(runtime.ENGINE / 'bin/wineserver')):
        raise ProbePrefixError('Scoped cleanup refuses a replaced prefix or altered server binding.')


def supervise(runtime, env, context, checkpoint, output):
    executable = PREFIX / code_policy.CODE_ROOTS[0] / 'Launcher.exe'
    record = {'schema_version': 1, 'kind': 'one-off-user-authorized-original-rockstar-update-session',
        'at': now(), 'prefix': 'prefixes/fivem-source-main', 'prefix_identity': context['prefix_identity'],
        'old_code_manifest_sha256': context['code_manifest_sha256'], 'staging_review': context['staging_review'],
        'checkpoint': checkpoint, 'manual_user_login': context['identity'].get('manual_user_login'),
        'user_game_data_origin': context['identity'].get('user_game_data_origin'),
        'runtime_profile': 'parity', 'runtime_manifest_sha256': 'e4fc3167813864102909da696cf3a03e89bd00a4a9abe26d8478c88316600f9c',
        'controller_pid': os.getpid(), 'arguments': [], 'automatic_time_limit_seconds': None,
        'stdout_or_stderr_persisted': False, 'registry_or_user_profile_files_copied_or_hashed': False,
        'shellfolder_fields_checked_by_existing_helper': True, 'original_security_authentication_or_update_decisions_changed': False,
        'code_binding_changed': False, 'five_m_or_installer_started': False,
        'status': 'starting', 'final_code_binding_pending': True, 'cleanup': []}
    process = None
    cleanup_reason = None
    save(output, record, new=True)
    try:
        isolation(context)
        runtime.before_source_spawn()
        process = subprocess.Popen([str(runtime.WINE), str(executable)], cwd=executable.parent,
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        record.update(status='original-updater-supervised', native_wine_pid=process.pid)
        save(output, record)
        print('Original Rockstar update session open; no automatic deadline.', flush=True)
        print('Controller PID:', os.getpid(), '; original Launcher Wine PID:', process.pid, flush=True)
        print('Session:', output, flush=True)
        while True:
            record['last_isolation'] = isolation(context)
            exited = process.poll()
            if exited is not None and 'original_launcher_exit' not in record:
                record.update(original_launcher_exit=exited, parent_exit_does_not_prove_updater_children_ended=True)
                save(output, record)
            time.sleep(2)
    except KeyboardInterrupt:
        cleanup_reason = 'root-sigint-requested-stop'
        record['root_requested_stop_at'] = now()
    except BaseException as error:
        cleanup_reason = 'isolation-or-controller-failure' if process is not None else None
        record.update(failure_type=type(error).__name__, status='failed-pending-review')
    finally:
        if cleanup_reason is not None:
            record['cleanup_reason'] = cleanup_reason
            try:
                runtime.before_source_spawn()
                for flag in ('-k', '-w'):
                    try:
                        cleanup_identity(runtime, env, context)
                        stopped = subprocess.run([str(runtime.ENGINE / 'bin/wineserver'), flag], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60, check=False)
                        record['cleanup'].append({'flag': flag, 'exit': stopped.returncode, 'timed_out': False})
                    except subprocess.TimeoutExpired:
                        record['cleanup'].append({'flag': flag, 'exit': None, 'timed_out': True})
                if process is not None:
                    try:
                        record['original_launcher_exit_after_cleanup'] = process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        record['original_launcher_wait_timed_out'] = True
            except BaseException as error:
                record['cleanup_failure_type'] = type(error).__name__
        clean = record['cleanup'] == [{'flag': '-k', 'exit': 0, 'timed_out': False},
                                     {'flag': '-w', 'exit': 0, 'timed_out': False}]
        clean = clean and not record.get('original_launcher_wait_timed_out', False)
        if 'failure_type' not in record and clean:
            record['status'] = 'root-stopped-pending-final-code-review'
        else:
            record['status'] = 'stopped-or-detached-needs-review'
        record.update(controller_ended_at=now(), cleanup_confirmed=clean,
                      updater_success_claim=False, new_code_admitted=False)
        save(output, record)
    return record


def run():
    from run_source import select_runtime_profile
    with main_policy._source_main_file_lock(PREFIX):
        context = preflight()
        checkpoint = verify_checkpoint(context)
        runtime, _ = select_runtime_profile('parity')
        env = runtime_environment(runtime)
        if preflight() != context or verify_checkpoint(context) != checkpoint:
            raise ProbePrefixError('Updater inputs changed before process creation.')
        label = 'user-rockstar-official-update-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        return supervise(runtime, env, context, checkpoint, ROOT / 'research' / (label + '.json'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('inspect', 'prepare', 'run'))
    args = parser.parse_args()
    if args.action == 'prepare':
        result = prepare()
    elif args.action == 'run':
        result = run()
    else:
        with main_policy._source_main_file_lock(PREFIX):
            context = preflight()
            result = {'inspection_passed': True, 'runtime_started': False, 'old_code_files': 142,
                'pending_stages': 9, 'prefix_identity': context['prefix_identity'],
                'old_code_manifest_sha256': context['code_manifest_sha256'], 'staging_review': context['staging_review'],
                'checkpoint_exists': CHECKPOINT.exists(), 'checkpoint': str(CHECKPOINT.relative_to(ROOT)),
                'no_finalize_command_or_code_binding_change': True}
    print(json.dumps(result, indent=2))
    return 0 if args.action != 'run' or result['cleanup_confirmed'] and 'failure_type' not in result else 1


if __name__ == '__main__':
    raise SystemExit(main())
