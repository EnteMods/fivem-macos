"""Canonical prefix checks and a process-scoped lock for account-free Wine probes."""
from contextlib import contextmanager
import fcntl
import getpass
import os
from pathlib import Path, PureWindowsPath
import re
import stat

ROOT = Path(__file__).resolve().parents[1]
PERSONAL_FOLDERS = ('Desktop', 'Documents', 'Downloads', 'Music', 'Pictures', 'Videos')
ACCOUNT_NAMES = ('rockstar', 'social club', 'socialclub', 'fivem', 'citizenfx')


class ProbePrefixError(SystemExit):
    pass


def _plain_path(path, boundary):
    """Check every existing component without following a symlink."""
    current = boundary
    for part in path.relative_to(boundary).parts:
        current /= part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(mode):
            raise ProbePrefixError('Refusing a redirected probe path: ' + str(current))


def _location(prefix, root):
    original_root = Path(root).absolute()
    try:
        relative = Path(prefix).absolute().relative_to(original_root)
    except ValueError:
        raise ProbePrefixError('Probe prefix must be inside this project.')
    if len(relative.parts) != 2 or relative.parts[0] != 'prefixes':
        raise ProbePrefixError('Probe prefix must be a direct child of project/prefixes.')
    if relative.name in ('rockstar-legacy', 'fivem-legacy', 'fivem-enhanced-probe'):
        raise ProbePrefixError('Refusing a productive or copied client/account prefix.')
    root = original_root.resolve()
    prefix = root / relative
    _plain_path(prefix, root)
    return prefix, root


def _check_shell_folders(prefix):
    registry = prefix / 'user.reg'
    if not registry.is_file():
        return
    section = ''
    substitutions = {
        '%userprofile%': 'C:\\users\\' + getpass.getuser(),
        '%public%': 'C:\\users\\Public',
        '%appdata%': 'C:\\users\\' + getpass.getuser() + '\\AppData\\Roaming',
        '%localappdata%': 'C:\\users\\' + getpass.getuser() + '\\AppData\\Local',
        '%systemroot%': 'C:\\windows',
        '%windir%': 'C:\\windows',
    }
    for line in registry.read_text(errors='strict').splitlines():
        if line.startswith('['):
            section = line.lower()
            continue
        if 'shell folders]' not in section:
            continue
        value = re.match(r'^"[^"]+"=(?:str\(\d+\):)?"(.*)"$', line)
        if not value:
            continue
        location = value.group(1).replace('\\\\', '\\').replace('\\"', '"')
        for token, replacement in substitutions.items():
            location = re.sub(re.escape(token), lambda _: replacement, location, flags=re.IGNORECASE)
        windows = PureWindowsPath(location)
        if windows.drive.lower() != 'c:' or not windows.is_absolute() or '%' in location or '..' in windows.parts:
            raise ProbePrefixError('Refusing a host-mapped or unresolved Windows Shell Folder.')
        _plain_path(prefix / 'drive_c' / Path(*windows.parts[1:]), prefix)


def _check_c_drive(prefix):
    devices = prefix / 'dosdevices'
    _plain_path(devices, prefix)
    if devices.exists() and not devices.is_dir():
        raise ProbePrefixError('Wine dosdevices must be a local directory.')
    mapping = devices / 'c:'
    if not mapping.exists() and not mapping.is_symlink():
        if (prefix / 'system.reg').is_file():
            raise ProbePrefixError('A booted probe prefix is missing its C: mapping.')
        return
    try:
        target = mapping.resolve(strict=True)
    except (OSError, RuntimeError):
        raise ProbePrefixError('Wine C: mapping is broken or cyclic.')
    if target != prefix / 'drive_c':
        raise ProbePrefixError('Wine C: must resolve exactly to this prefix/drive_c.')


def assert_account_free_prefix(prefix, root=ROOT, allow_missing=False):
    prefix, root = _location(prefix, root)
    if not prefix.exists():
        if allow_missing:
            return prefix
        raise ProbePrefixError('Initialize the account-free probe prefix first.')
    if not prefix.is_dir():
        raise ProbePrefixError('Probe prefix is not a directory.')
    marker = prefix / '.account-free-probe'
    _plain_path(marker, prefix)
    if not marker.is_file():
        raise ProbePrefixError('Refusing an existing prefix without the account-free marker.')
    for relative in ('system.reg', 'user.reg', 'userdef.reg', 'drive_c', 'drive_c/users'):
        _plain_path(prefix / relative, prefix)
    _check_c_drive(prefix)
    users = prefix / 'drive_c/users'
    if users.exists():
        def fail(error):
            raise ProbePrefixError('Cannot inspect probe user paths: ' + str(error))
        for directory, folders, files in os.walk(users, followlinks=False, onerror=fail):
            for name in folders + files:
                path = Path(directory) / name
                _plain_path(path, prefix)
                if path.is_dir() and any(token in name.lower() for token in ACCOUNT_NAMES):
                    raise ProbePrefixError('Refusing a probe prefix containing client/account directories.')
    for relative in ('drive_c', 'drive_c/Program Files', 'drive_c/Program Files (x86)', 'drive_c/ProgramData'):
        directory = prefix / relative
        _plain_path(directory, prefix)
        if directory.is_dir():
            for child in directory.iterdir():
                if any(token in child.name.lower() for token in ACCOUNT_NAMES):
                    raise ProbePrefixError('Refusing a probe prefix containing a client installation.')
    _check_shell_folders(prefix)
    return prefix


@contextmanager
def probe_prefix(prefix, root=ROOT, create=False):
    """Validate before writes, lock until all Wine processes have been cleaned up."""
    prefix = assert_account_free_prefix(prefix, root=root, allow_missing=create)
    root = Path(root).resolve()
    parent = prefix.parent
    parent.mkdir(parents=True, exist_ok=True)
    lock_path = parent / ('.' + prefix.name + '.probe.lock')
    flags = os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0)
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as error:
        raise ProbePrefixError('Cannot open the probe lock safely: ' + str(error))
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ProbePrefixError('Probe lock must be a regular file with one link.')
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ProbePrefixError('Another probe is using this prefix; wait for that run to finish.')
        assert_account_free_prefix(prefix, root=root, allow_missing=create)
        if not prefix.exists():
            prefix.mkdir()
            (prefix / '.account-free-probe').write_text('Only local API/ABI probes; no client or account installation.\n')
        assert_account_free_prefix(prefix, root=root)
        os.ftruncate(descriptor, 0)
        os.write(descriptor, ('pid=' + str(os.getpid()) + '\n').encode())
        yield prefix
    finally:
        # Keep the inode: unlinking could let another process lock a different file.
        os.close(descriptor)
