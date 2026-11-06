"""Fresh, isolated prefix policy for the reviewed normal MAIN first-window stage."""
from contextlib import contextmanager
import datetime
import fcntl
import getpass
import hashlib
import json
import os
from pathlib import Path
import stat

from probe_environment import (PERSONAL_FOLDERS, ROOT, ProbePrefixError,
                               _check_c_drive, _check_shell_folders, _location, _plain_path)
from rockstar_code_policy import (CODE_CONTAINER, MACHINE_CONTAINER,
                                 UPDATE_X86_CONTAINER, UPDATED_CODE_ROOTS,
                                 apply_machine_migration as _apply_machine_migration,
                                 prepare_machine_migration as _prepare_machine_migration,
                                 bind_manifest as _bind_rockstar_manifest,
                                 user_path_allowed as _rockstar_user_path_allowed,
                                 validate_binding as _validate_rockstar_binding)
from rockstar_code_policy import _write_bytes as _write_marker_bytes, _write_json as _write_marker_json
from user_game_data_policy import (MARKER_KEY as GAME_DATA_MARKER_KEY,
                                   validated_game_root as _validated_game_root,
                                   game_metadata_directory_allowed as _game_metadata_directory_allowed)

PREFIX_NAME = 'fivem-source-main'
MARKER_NAME = '.source-main-probe'
ACCOUNT_DIRECTORY_NAMES = ('rockstar', 'social club', 'socialclub', 'fivem', 'citizenfx')
ACCOUNT_FILE_NAMES = ('cfxticket', 'cfxticket2', 'ros_login.dat', 'ros_login.json')
_ACTIVE_MAIN_LOCKS = {}


def _username():
    user = getpass.getuser()
    if not user or user in ('.', '..') or any(char in user for char in ('/', '\\', ':', '\0')):
        raise ProbePrefixError('Source-MAIN username must be one local path component.')
    return user


def _cache_roots(prefix):
    user = prefix / 'drive_c/users' / _username() / 'AppData'
    return (user / 'Local/FiveM', user / 'Local/CitizenFX', user / 'Roaming/CitizenFX')


def _is_own_cache(path, prefix):
    parts = tuple(part.casefold() for part in path.relative_to(prefix).parts)
    for allowed in _cache_roots(prefix):
        allowed_parts = tuple(part.casefold() for part in allowed.relative_to(prefix).parts)
        if parts[:len(allowed_parts)] == allowed_parts:
            return True
    return False


def _is_own_save_data(path, prefix):
    parts = tuple(part.casefold() for part in path.relative_to(prefix).parts)
    save_root = prefix / 'drive_c/users' / _username() / 'Saved Games/CitizenFX'
    allowed = tuple(part.casefold() for part in save_root.relative_to(prefix).parts)
    game = allowed + ('gta5',)
    return parts == allowed or parts[:len(game)] == game


def _read_identity(prefix, root, user):
    marker = prefix / MARKER_NAME
    _plain_path(marker, prefix)
    if not marker.is_file() or marker.stat().st_nlink != 1 or marker.stat().st_size > 4096:
        raise ProbePrefixError('Refusing an existing prefix without its own fresh-MAIN marker.')
    try:
        identity = json.loads(marker.read_text())
    except (ValueError, OSError):
        raise ProbePrefixError('Invalid source-MAIN marker.')
    info = prefix.stat()
    expected = {'schema': 1, 'project_root': str(root), 'prefix_name': PREFIX_NAME,
                'prefix_device': info.st_dev, 'prefix_inode': info.st_ino,
                'created_without_copy': True, 'user': user}
    if not isinstance(identity, dict) or any(identity.get(key) != value for key, value in expected.items()):
        raise ProbePrefixError('Source-MAIN marker belongs to a copied or different prefix.')
    return identity


def _manual_login_authorized(identity, prefix, root, user):
    reference = identity.get('manual_user_login')
    if reference is None:
        return False
    if (not isinstance(reference, dict) or set(reference) != {'path', 'sha256'}
            or reference.get('path') != 'research/manual-user-login.json'):
        raise ProbePrefixError('Invalid manual MAIN login evidence reference.')
    evidence = root / reference['path']
    _plain_path(evidence, root)
    try:
        info = evidence.stat()
    except OSError as error:
        raise ProbePrefixError('Manual login evidence is unavailable: ' + str(error))
    if not evidence.is_file() or info.st_nlink != 1 or info.st_size > 16384:
        raise ProbePrefixError('Manual login evidence must be a bounded local regular file.')
    raw = evidence.read_bytes()
    if hashlib.sha256(raw).hexdigest() != reference.get('sha256'):
        raise ProbePrefixError('Manual login evidence changed.')
    try:
        record = json.loads(raw)
    except ValueError:
        raise ProbePrefixError('Invalid manual login evidence JSON.')
    expected = {'schema': 1, 'kind': 'user-confirmed-manual-login', 'prefix': str(prefix.relative_to(root)),
                'prefix_device': prefix.stat().st_dev, 'prefix_inode': prefix.stat().st_ino,
                'user': user, 'confirmed_by_user': True, 'scope': 'launcher-ui-only',
                'account_data_copied': False}
    if not isinstance(record, dict) or any(record.get(key) != value for key, value in expected.items()):
        raise ProbePrefixError('Manual login evidence belongs to a different prefix, user or task scope.')
    return True


def _assert_source_main_prefix(prefix, root=ROOT, allow_missing=False, pending_machine_policy=None,
                               pending_user_game_reference=None):
    user = _username()
    prefix, root = _location(prefix, root)
    if prefix.name != PREFIX_NAME:
        raise ProbePrefixError('Source MAIN uses only prefixes/' + PREFIX_NAME + '.')
    if not prefix.exists():
        if allow_missing:
            return prefix
        raise ProbePrefixError('Create a fresh source-MAIN prefix first.')
    if not prefix.is_dir():
        raise ProbePrefixError('Source-MAIN prefix is not a directory.')
    identity = _read_identity(prefix, root, user)
    manual_login = _manual_login_authorized(identity, prefix, root, user)
    game_root = _validated_game_root(prefix, root, identity, user, pending_user_game_reference)
    if game_root is not None and not manual_login:
        raise ProbePrefixError('GTA user-data enrollment requires the existing approved manual login.')
    rockstar = _validate_rockstar_binding(prefix, root, identity, user, gta_user_root=game_root)
    if (prefix / '.account-free-probe').exists() or (prefix / '.account-free-probe').is_symlink():
        raise ProbePrefixError('Source MAIN must not reuse the generic API-probe marker.')
    for relative in ('system.reg', 'user.reg', 'userdef.reg', 'drive_c', 'drive_c/users'):
        _plain_path(prefix / relative, prefix)
    _check_c_drive(prefix)
    users = prefix / 'drive_c/users'
    if users.exists():
        def fail(error):
            raise ProbePrefixError('Cannot inspect source-MAIN user paths: ' + str(error))
        for directory, folders, files in os.walk(users, followlinks=False, onerror=fail):
            for name in folders + files:
                path = Path(directory) / name
                _plain_path(path, prefix)
                lowered = name.casefold()
                if path.is_dir() and any(token in lowered for token in ACCOUNT_DIRECTORY_NAMES):
                    own_cache = _is_own_cache(path, prefix) and not any(token in lowered for token in ('rockstar', 'social club', 'socialclub'))
                    own_saves = _is_own_save_data(path, prefix) and not any(token in lowered for token in ('rockstar', 'social club', 'socialclub'))
                    if (not own_cache and not own_saves and not _rockstar_user_path_allowed(path, prefix, rockstar)
                            and not _game_metadata_directory_allowed(path, prefix, game_root)):
                        raise ProbePrefixError('Refusing an account/client directory outside the MAIN-owned installation/cache policy.')
                if path.is_file() and (lowered in ACCOUNT_FILE_NAMES or lowered.startswith('cfxticket')):
                    own_auth_root = _is_own_cache(path, prefix) or _rockstar_user_path_allowed(path, prefix, rockstar)
                    if not manual_login or not own_auth_root or path.stat().st_nlink != 1:
                        raise ProbePrefixError('Refusing unapproved or externally linked account-ticket/login artifacts in source MAIN.')
    for relative in ('drive_c', 'drive_c/Program Files', 'drive_c/Program Files (x86)', 'drive_c/ProgramData'):
        directory = prefix / relative
        _plain_path(directory, prefix)
        if directory.is_dir():
            for child in directory.iterdir():
                if any(token in child.name.casefold() for token in ACCOUNT_DIRECTORY_NAMES):
                    if rockstar is not None and child == prefix / CODE_CONTAINER:
                        continue
                    if (rockstar is not None and rockstar.get('roots') == list(UPDATED_CODE_ROOTS)
                            and child == prefix / UPDATE_X86_CONTAINER):
                        continue
                    if rockstar is not None and child == prefix / MACHINE_CONTAINER and (rockstar.get('machine_runtime_policy') or pending_machine_policy):
                        continue
                    raise ProbePrefixError('Refusing a client installation in the fresh source-MAIN prefix.')
    _check_shell_folders(prefix)
    return prefix


def assert_source_main_prefix(prefix, root=ROOT, allow_missing=False):
    return _assert_source_main_prefix(prefix, root=root, allow_missing=allow_missing)


def bind_rockstar_code_manifest(prefix, manifest, root=ROOT):
    """Bind reviewed code after copying only code roots inside this held MAIN context."""
    prefix, root = _location(prefix, root)
    if prefix.name != PREFIX_NAME or _ACTIVE_MAIN_LOCKS.get(str(prefix), (None,))[0] != os.getpid():
        raise ProbePrefixError('Rockstar code binding requires the held source-MAIN prefix context.')
    user = _username()
    identity = _read_identity(prefix, root, user)
    for relative in ('system.reg', 'user.reg', 'userdef.reg', 'drive_c', 'drive_c/users'):
        _plain_path(prefix / relative, prefix)
    _check_c_drive(prefix)
    _check_shell_folders(prefix)
    return _bind_rockstar_manifest(prefix, root, identity, user, manifest, MARKER_NAME)


def record_manual_user_login(prefix, reference, root=ROOT):
    """Record the user's actual login; never read, synthesize or copy client auth data."""
    prefix, root = _location(prefix, root)
    if prefix.name != PREFIX_NAME or _ACTIVE_MAIN_LOCKS.get(str(prefix), (None,))[0] != os.getpid():
        raise ProbePrefixError('Manual login enrollment requires the held MAIN prefix context.')
    marker = prefix / MARKER_NAME
    before = marker.read_bytes()
    identity = _read_identity(prefix, root, _username())
    updated = dict(identity, manual_user_login=reference,
                   scope='User-confirmed login in isolated MAIN; launcher UI only; no copied account state.')
    _manual_login_authorized(updated, prefix, root, _username())
    try:
        _write_marker_json(marker, updated, prefix)
        assert_source_main_prefix(prefix, root=root)
    except BaseException:
        _write_marker_bytes(marker, before, prefix)
        raise


def enroll_user_game_data(prefix, reference, root=ROOT):
    """Bind one user-created GTA data directory; never open or copy its contents."""
    if not isinstance(reference, dict):
        raise ProbePrefixError('GTA user-data enrollment requires an explicit origin evidence reference.')
    prefix, root = _location(prefix, root)
    if prefix.name != PREFIX_NAME:
        raise ProbePrefixError('GTA user-data enrollment uses only the exact source-MAIN prefix.')
    user = _username()
    _read_identity(prefix, root, user)
    with _source_main_file_lock(prefix):
        identity = _read_identity(prefix, root, user)
        if not _manual_login_authorized(identity, prefix, root, user):
            raise ProbePrefixError('GTA user-data enrollment requires the existing approved manual login.')
        _assert_source_main_prefix(prefix, root=root, pending_user_game_reference=reference)
        if identity.get(GAME_DATA_MARKER_KEY) == reference:
            return dict(reference)
        marker = prefix / MARKER_NAME
        before = marker.read_bytes()
        try:
            _write_marker_json(marker, dict(identity, **{GAME_DATA_MARKER_KEY: dict(reference)}), prefix)
            assert_source_main_prefix(prefix, root=root)
        except BaseException:
            _write_marker_bytes(marker, before, prefix)
            raise
        return dict(reference)


@contextmanager
def _source_main_file_lock(prefix):
    lock = prefix.parent / ('.' + PREFIX_NAME + '.source-main.lock')
    try:
        descriptor = os.open(lock, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    except OSError as error:
        raise ProbePrefixError('Cannot open the source-MAIN lock safely: ' + str(error))
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ProbePrefixError('Source-MAIN lock must be a regular file with one link.')
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ProbePrefixError('Another source-MAIN stage owns this prefix.')
        yield descriptor
    finally:
        os.close(descriptor)


def migrate_rockstar_machine_runtime(prefix, evidence, root=ROOT):
    """One-time observed-runtime enrollment; holds the ordinary MAIN lock and never changes data files."""
    prefix, root = _location(prefix, root)
    if prefix.name != PREFIX_NAME:
        raise ProbePrefixError('Machine-runtime migration uses only the exact source-MAIN prefix.')
    user = _username()
    _read_identity(prefix, root, user)
    with _source_main_file_lock(prefix):
        identity = _read_identity(prefix, root, user)
        manifest, policy = _prepare_machine_migration(prefix, root, identity, user, evidence, MARKER_NAME)
        _assert_source_main_prefix(prefix, root=root, pending_machine_policy=policy)
        return _apply_machine_migration(prefix, root, identity, manifest, policy, MARKER_NAME,
                                        lambda: assert_source_main_prefix(prefix, root=root))


@contextmanager
def source_main_prefix(prefix, root=ROOT, create=False):
    """Keep the lock until the caller's final Wine cleanup; never clone a prefix."""
    prefix = assert_source_main_prefix(prefix, root=root, allow_missing=create)
    root = Path(root).resolve()
    prefix.parent.mkdir(parents=True, exist_ok=True)
    with _source_main_file_lock(prefix) as descriptor:
        assert_source_main_prefix(prefix, root=root, allow_missing=create)
        if not prefix.exists():
            prefix.mkdir()
            info = prefix.stat()
            identity = {
                'schema': 1, 'project_root': str(root), 'prefix_name': PREFIX_NAME,
                'prefix_device': info.st_dev, 'prefix_inode': info.st_ino,
                'created_without_copy': True, 'user': _username(),
                'created_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'scope': 'Fresh normal source MAIN first window or refusal only; no account clone or login.',
            }
            (prefix / MARKER_NAME).write_text(json.dumps(identity, indent=2) + '\n')
        for user in (_username(), 'Public'):
            for folder in PERSONAL_FOLDERS:
                (prefix / 'drive_c/users' / user / folder).mkdir(parents=True, exist_ok=True)
        assert_source_main_prefix(prefix, root=root)
        os.ftruncate(descriptor, 0)
        os.write(descriptor, ('pid=' + str(os.getpid()) + '\n').encode())
        _ACTIVE_MAIN_LOCKS[str(prefix)] = (os.getpid(), descriptor)
        try:
            yield prefix
        finally:
            _ACTIVE_MAIN_LOCKS.pop(str(prefix), None)
