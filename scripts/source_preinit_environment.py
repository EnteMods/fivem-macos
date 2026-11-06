"""Fresh, isolated prefix policy for the reviewed source-client PreInit stage."""
from contextlib import contextmanager
import datetime
import fcntl
import getpass
import json
import os
from pathlib import Path
import stat

from probe_environment import (PERSONAL_FOLDERS, ROOT, ProbePrefixError,
                               _check_c_drive, _check_shell_folders, _location, _plain_path)

PREFIX_NAME = 'fivem-source-preinit'
MARKER_NAME = '.source-preinit-probe'
ACCOUNT_DIRECTORY_NAMES = ('rockstar', 'social club', 'socialclub', 'fivem', 'citizenfx')
ACCOUNT_FILE_NAMES = ('cfxticket', 'cfxticket2', 'ros_login.dat', 'ros_login.json')


def _username():
    user = getpass.getuser()
    if not user or user in ('.', '..') or any(char in user for char in ('/', '\\', ':', '\0')):
        raise ProbePrefixError('Source-PreInit username must be one local path component.')
    return user


def _cache_roots(prefix):
    user = prefix / 'drive_c/users' / _username() / 'AppData'
    return (user / 'Local/CitizenFX', user / 'Roaming/CitizenFX')


def _is_own_cache(path, prefix):
    parts = tuple(part.casefold() for part in path.relative_to(prefix).parts)
    for allowed in _cache_roots(prefix):
        allowed_parts = tuple(part.casefold() for part in allowed.relative_to(prefix).parts)
        if parts[:len(allowed_parts)] == allowed_parts:
            return True
    return False


def assert_source_preinit_prefix(prefix, root=ROOT, allow_missing=False):
    user = _username()
    prefix, root = _location(prefix, root)
    if prefix.name != PREFIX_NAME:
        raise ProbePrefixError('Source PreInit uses only prefixes/' + PREFIX_NAME + '.')
    if not prefix.exists():
        if allow_missing:
            return prefix
        raise ProbePrefixError('Create a fresh source-PreInit prefix first.')
    if not prefix.is_dir():
        raise ProbePrefixError('Source-PreInit prefix is not a directory.')
    marker = prefix / MARKER_NAME
    _plain_path(marker, prefix)
    if not marker.is_file() or marker.stat().st_nlink != 1 or marker.stat().st_size > 4096:
        raise ProbePrefixError('Refusing an existing prefix without its own fresh-PreInit marker.')
    try:
        identity = json.loads(marker.read_text())
    except (ValueError, OSError):
        raise ProbePrefixError('Invalid source-PreInit marker.')
    info = prefix.stat()
    expected = {'schema': 1, 'project_root': str(root), 'prefix_name': PREFIX_NAME,
                'prefix_device': info.st_dev, 'prefix_inode': info.st_ino,
                'created_without_copy': True, 'user': user}
    if not isinstance(identity, dict) or any(identity.get(key) != value for key, value in expected.items()):
        raise ProbePrefixError('Source-PreInit marker belongs to a copied or different prefix.')
    if (prefix / '.account-free-probe').exists() or (prefix / '.account-free-probe').is_symlink():
        raise ProbePrefixError('Source PreInit must not reuse the generic API-probe marker.')
    for relative in ('system.reg', 'user.reg', 'userdef.reg', 'drive_c', 'drive_c/users'):
        _plain_path(prefix / relative, prefix)
    _check_c_drive(prefix)
    users = prefix / 'drive_c/users'
    if users.exists():
        def fail(error):
            raise ProbePrefixError('Cannot inspect source-PreInit user paths: ' + str(error))
        for directory, folders, files in os.walk(users, followlinks=False, onerror=fail):
            for name in folders + files:
                path = Path(directory) / name
                _plain_path(path, prefix)
                lowered = name.casefold()
                if path.is_dir() and any(token in lowered for token in ACCOUNT_DIRECTORY_NAMES):
                    if not _is_own_cache(path, prefix) or any(token in lowered for token in ('rockstar', 'social club', 'socialclub')):
                        raise ProbePrefixError('Refusing an account/client directory outside the source-owned cache policy.')
                if path.is_file() and (lowered in ACCOUNT_FILE_NAMES or lowered.startswith('cfxticket')):
                    raise ProbePrefixError('Refusing account-ticket/login artifacts in source PreInit.')
    for relative in ('drive_c', 'drive_c/Program Files', 'drive_c/Program Files (x86)', 'drive_c/ProgramData'):
        directory = prefix / relative
        _plain_path(directory, prefix)
        if directory.is_dir():
            for child in directory.iterdir():
                if any(token in child.name.casefold() for token in ACCOUNT_DIRECTORY_NAMES):
                    raise ProbePrefixError('Refusing a client installation in the fresh source-PreInit prefix.')
    _check_shell_folders(prefix)
    return prefix


@contextmanager
def source_preinit_prefix(prefix, root=ROOT, create=False):
    """Keep the lock until the caller's final Wine cleanup; never clone a prefix."""
    prefix = assert_source_preinit_prefix(prefix, root=root, allow_missing=create)
    root = Path(root).resolve()
    prefix.parent.mkdir(parents=True, exist_ok=True)
    lock = prefix.parent / ('.' + PREFIX_NAME + '.source-preinit.lock')
    try:
        descriptor = os.open(lock, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    except OSError as error:
        raise ProbePrefixError('Cannot open the source-PreInit lock safely: ' + str(error))
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ProbePrefixError('Source-PreInit lock must be a regular file with one link.')
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ProbePrefixError('Another source-PreInit stage owns this prefix.')
        assert_source_preinit_prefix(prefix, root=root, allow_missing=create)
        if not prefix.exists():
            prefix.mkdir()
            info = prefix.stat()
            identity = {
                'schema': 1, 'project_root': str(root), 'prefix_name': PREFIX_NAME,
                'prefix_device': info.st_dev, 'prefix_inode': info.st_ino,
                'created_without_copy': True, 'user': _username(),
                'created_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'scope': 'Fresh source Chrome/CitiGame/NUI PreInit only; no account clone or login.',
            }
            (prefix / MARKER_NAME).write_text(json.dumps(identity, indent=2) + '\n')
        for user in (_username(), 'Public'):
            for folder in PERSONAL_FOLDERS:
                (prefix / 'drive_c/users' / user / folder).mkdir(parents=True, exist_ok=True)
        assert_source_preinit_prefix(prefix, root=root)
        os.ftruncate(descriptor, 0)
        os.write(descriptor, ('pid=' + str(os.getpid()) + '\n').encode())
        yield prefix
    finally:
        # Do not unlink a lock inode that another process may already have opened.
        os.close(descriptor)
