"""Metadata-only permission for one user-created GTA V data directory in MAIN."""
import hashlib
import json
import re
import stat

from probe_environment import ProbePrefixError, _plain_path

EVIDENCE_PATH = 'research/user-game-install-origin.json'
MARKER_KEY = 'user_game_data_origin'
INSTALL_SCOPE = 'User-authorized manual GTA installation through original Rockstar Launcher'


def game_user_root(user):
    return 'drive_c/users/' + user + '/Documents/Rockstar Games/GTA V'


def _record(root, reference, allowed_path):
    if (not isinstance(reference, dict) or set(reference) != {'path', 'sha256'}
            or not isinstance(reference.get('path'), str)
            or not allowed_path(reference['path'])
            or not isinstance(reference.get('sha256'), str)
            or not re.fullmatch('[0-9a-f]{64}', reference['sha256'])):
        raise ProbePrefixError('Invalid GTA user-data origin evidence reference.')
    path = root / reference['path']
    _plain_path(path, root)
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 32768:
            raise ProbePrefixError('GTA origin evidence must be bounded local single-link JSON.')
        raw = path.read_bytes()
    except OSError as error:
        raise ProbePrefixError('Cannot read GTA origin metadata evidence: ' + str(error))
    if hashlib.sha256(raw).hexdigest() != reference['sha256']:
        raise ProbePrefixError('GTA origin metadata evidence changed.')
    try:
        value = json.loads(raw)
    except ValueError:
        raise ProbePrefixError('Invalid GTA origin metadata JSON.')
    if not isinstance(value, dict):
        raise ProbePrefixError('GTA origin metadata must be a JSON object.')
    return value


def validated_game_root(prefix, root, identity, user, pending_reference=None):
    reference = identity.get(MARKER_KEY)
    if pending_reference is not None:
        if reference is not None and reference != pending_reference:
            raise ProbePrefixError('GTA user-data enrollment cannot replace an existing origin.')
        reference = pending_reference
    if reference is None:
        return None
    origin = _record(root, reference, lambda path: path == EVIDENCE_PATH)
    from rockstar_code_policy import validated_update_origin
    update = validated_update_origin(prefix, root, identity, user)
    origin_code = update['previous_code_manifest'] if update is not None else identity.get('rockstar_code_manifest')
    info = prefix.stat()
    relative = game_user_root(user)
    expected = {
        'schema': 1, 'kind': 'user-authorized-gta-v-data-origin',
        'prefix': str(prefix.relative_to(root)), 'prefix_device': info.st_dev,
        'prefix_inode': info.st_ino, 'user': user, 'relative_root': relative,
        'scope': 'gta-v-user-data-metadata-only',
        'created_in_user_authorized_install_session': True,
        'copied_or_imported': False,
        'manual_user_login': identity.get('manual_user_login'),
        'rockstar_code_manifest': origin_code,
    }
    if (any(origin.get(key) != value or type(origin.get(key)) is not type(value)
            for key, value in expected.items())
            or not isinstance(expected['manual_user_login'], dict)
            or not isinstance(expected['rockstar_code_manifest'], dict)):
        raise ProbePrefixError('GTA user-data origin belongs to a different prefix, user, scope or code/login binding.')
    for key in ('prefix_device', 'prefix_inode', 'root_device', 'root_inode'):
        if type(origin.get(key)) is not int or origin[key] < 0:
            raise ProbePrefixError('GTA user-data origin requires actual integer filesystem identities.')
    directory = prefix / relative
    _plain_path(directory, prefix)
    try:
        directory_info = directory.lstat()
    except FileNotFoundError:
        directory_info = None
    except OSError as error:
        raise ProbePrefixError('Cannot inspect the enrolled GTA data directory: ' + str(error))
    if directory_info is not None and (not stat.S_ISDIR(directory_info.st_mode)
            or (directory_info.st_dev, directory_info.st_ino) != (origin['root_device'], origin['root_inode'])):
        raise ProbePrefixError('GTA user-data origin belongs to a different local directory.')
    installation = _record(root, origin.get('user_install_session'), lambda path: bool(re.fullmatch(
        r'research/user-rockstar-install-\d{8}T\d{12}Z\.json', path)))
    session_expected = {
        'scope': INSTALL_SCOPE, 'prefix': str(prefix.relative_to(root)),
        'prefix_device': info.st_dev, 'prefix_inode': info.st_ino,
        'rockstar_code_manifest_sha256': expected['rockstar_code_manifest'].get('sha256'),
        'prefix_is_account_free': False, 'user_requested_leave_open': True,
        'automatic_wineserver_kill': False,
        'original_authentication_integrity_or_anticheat_modified': False,
    }
    if any(installation.get(key) != value or type(installation.get(key)) is not type(value)
           for key, value in session_expected.items()):
        raise ProbePrefixError('GTA data origin lacks the matching user-authorized installation session.')
    return relative


def game_metadata_directory_allowed(path, prefix, relative_root):
    """Directory traversal only; never use this permission to authorize ticket files."""
    if relative_root is None:
        return False
    parts = path.relative_to(prefix).parts
    allowed = (prefix / relative_root).relative_to(prefix).parts
    return parts[:len(allowed)] == allowed
