"""Exact code-only Rockstar dependency policy used only by the source MAIN guard."""
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile

from probe_environment import ProbePrefixError, _plain_path

MANIFEST_NAME = '.source-main-rockstar-code.json'
CODE_ROOTS = (
    'drive_c/Program Files/Rockstar Games/Launcher',
    'drive_c/Program Files/Rockstar Games/Social Club',
)
CODE_CONTAINER = 'drive_c/Program Files/Rockstar Games'
UPDATE_X86_CONTAINER = 'drive_c/Program Files (x86)/Rockstar Games'
UPDATE_X86_CODE_ROOT = UPDATE_X86_CONTAINER + '/Social Club'
UPDATED_CODE_ROOTS = CODE_ROOTS + (UPDATE_X86_CODE_ROOT,)
UPDATE_X86_BASENAMES = frozenset(('overlay.pak', 'scui.pak', 'socialclub.dll', 'socialclub.pak',
                                 'uninstallRGSCRedistributable.exe'))
UPDATE_MARKER_KEY = 'rockstar_code_update_origin'
UPDATE_EVIDENCE_PATH = 'research/rockstar-code-update-origin-20261103.json'
UPDATE_PREVIOUS_SHA256 = '4144afcb944857a49798252ebbfcb94a8a24a2952b1136241d84a8720cafaf4c'
UPDATE_PREVIOUS_BACKUP = 'build/checkpoints/rockstar-official-update-20261103/files/' + MANIFEST_NAME
_HASH_CACHE = {}
FORBIDDEN_CODE_PARTS = {'profiles', 'cookies', 'cookies-journal', 'login data', 'login data-journal',
                        'web data', 'web data-journal', 'local state', 'user.reg', 'userdef.reg', 'system.reg',
                        'ros_login.dat', 'ros_login.json', 'digitalentitlements'}


def user_roots(user):
    base = 'drive_c/users/' + user + '/'
    return (base + 'Documents/Rockstar Games/Launcher',
            base + 'Documents/Rockstar Games/Social Club',
            base + 'AppData/Local/Rockstar Games/Launcher')


def sdk_user_root(user):
    return 'drive_c/users/' + user + '/AppData/Local/Rockstar Games/SDK'


def _update_record(root, reference, allowed_path, maximum=32768):
    if (not isinstance(reference, dict) or set(reference) != {'path', 'sha256'}
            or not isinstance(reference.get('path'), str) or not allowed_path(reference['path'])
            or not isinstance(reference.get('sha256'), str)
            or not re.fullmatch('[0-9a-f]{64}', reference['sha256'])):
        raise ProbePrefixError('Invalid one-off Rockstar update metadata reference.')
    path = root / _relative(reference['path'])
    before = _regular_file(path, root)
    if before.st_size > maximum:
        raise ProbePrefixError('One-off update metadata exceeds its fixed byte boundary.')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as source:
        def identity(value):
            return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns, value.st_nlink)
        if identity(os.fstat(source.fileno())) != identity(before):
            raise ProbePrefixError('One-off update metadata changed before reading.')
        raw = source.read(maximum + 1)
        if (identity(os.fstat(source.fileno())) != identity(before)
                or identity(_regular_file(path, root)) != identity(before)):
            raise ProbePrefixError('One-off update metadata changed while reading.')
    if len(raw) != before.st_size or hashlib.sha256(raw).hexdigest() != reference['sha256']:
        raise ProbePrefixError('One-off update metadata differs from its explicit hash.')
    try:
        value = json.loads(raw)
    except ValueError:
        raise ProbePrefixError('Invalid one-off update metadata JSON.')
    if not isinstance(value, dict):
        raise ProbePrefixError('One-off update metadata must be an object.')
    return value


def _birthtime_ns(info):
    value = getattr(info, 'st_birthtime_ns', None)
    if type(value) is int:
        return value
    value = getattr(info, 'st_birthtime', None)
    if type(value) not in (int, float):
        raise ProbePrefixError('SDK origin requires the actual local directory birth time.')
    return round(value * 1000000000)


def validated_update_origin(prefix, root, identity, user, manifest=None):
    """Accept this one old-to-new code transition; never read SDK/profile contents."""
    reference = identity.get(UPDATE_MARKER_KEY)
    if reference is None:
        return None
    proof = _update_record(root, reference, lambda value: value == UPDATE_EVIDENCE_PATH)
    info = prefix.stat()
    previous = {'path': MANIFEST_NAME, 'sha256': UPDATE_PREVIOUS_SHA256}
    current = identity.get('rockstar_code_manifest')
    if (not isinstance(current, dict) or set(current) != {'path', 'sha256'}
            or current.get('path') != MANIFEST_NAME or current == previous
            or type(current.get('sha256')) is not str or not re.fullmatch('[0-9a-f]{64}', current['sha256'])):
        raise ProbePrefixError('The one-off forward proof requires its actual new code binding.')
    expected = {'schema': 1, 'kind': 'user-authorized-rockstar-code-update-origin',
        'scope': 'same-source-prefix-code-update-metadata-only',
        'prefix': str(prefix.relative_to(root)), 'prefix_device': info.st_dev, 'prefix_inode': info.st_ino,
        'user': user, 'previous_code_manifest': previous, 'current_code_manifest': current,
        'manual_user_login': identity.get('manual_user_login'),
        'user_game_data_origin': identity.get('user_game_data_origin'),
        'update_session_outcome': 'old-policy-rejected-new-sdk-user-root',
        'vendor_update_completed_observed': True, 'post_update_library_observed': True,
        'post_update_prefix_quiescent': True, 'copied_or_imported': False}
    if (any(proof.get(key) != value or type(proof.get(key)) is not type(value) for key, value in expected.items())
            or not isinstance(expected['manual_user_login'], dict)
            or not isinstance(expected['user_game_data_origin'], dict)):
        raise ProbePrefixError('The update proof belongs to another prefix, history or unconfirmed terminal state.')
    backup = {'path': UPDATE_PREVIOUS_BACKUP, 'sha256': UPDATE_PREVIOUS_SHA256}
    if proof.get('previous_manifest_backup') != backup:
        raise ProbePrefixError('Require the separately preserved exact old code manifest.')
    old_manifest = _update_record(root, backup, lambda value: value == UPDATE_PREVIOUS_BACKUP, 4194304)
    current_path = str((prefix / MANIFEST_NAME).relative_to(root))
    bound_manifest = _update_record(root, {'path': current_path, 'sha256': current['sha256']},
                                    lambda value: value == current_path, 4194304)
    if manifest is not None and manifest != bound_manifest:
        raise ProbePrefixError('The supplied updated manifest differs from its bound bytes.')
    if (old_manifest.get('prefix_binding') != _binding(prefix, root, user)
            or old_manifest.get('roots') != list(CODE_ROOTS)
            or bound_manifest.get('roots') != list(UPDATED_CODE_ROOTS)
            or old_manifest.get('user_data_roots') != list(user_roots(user))
            or bound_manifest.get('prefix_binding') != old_manifest['prefix_binding']
            or bound_manifest.get('user_data_initial_state') != old_manifest.get('user_data_initial_state')
            or bound_manifest.get('user_data_roots') != list(user_roots(user)) + [sdk_user_root(user)]
            or bound_manifest.get('machine_runtime_policy') != old_manifest.get('machine_runtime_policy')):
        raise ProbePrefixError('Code forwarding cannot replace the existing user roots or machine origin.')
    session = _update_record(root, proof.get('update_session'), lambda value: bool(re.fullmatch(
        r'research/user-rockstar-official-update-\d{8}T\d{12}Z\.json', value)))
    session_expected = {'kind': 'one-off-user-authorized-original-rockstar-update-session',
        'prefix': str(prefix.relative_to(root)), 'prefix_identity': [info.st_dev, info.st_ino],
        'old_code_manifest_sha256': UPDATE_PREVIOUS_SHA256, 'runtime_profile': 'parity',
        'runtime_manifest_sha256': 'e4fc3167813864102909da696cf3a03e89bd00a4a9abe26d8478c88316600f9c',
        'manual_user_login': expected['manual_user_login'], 'user_game_data_origin': expected['user_game_data_origin'],
        'original_security_authentication_or_update_decisions_changed': False,
        'code_binding_changed': False, 'five_m_or_installer_started': False,
        'final_code_binding_pending': True, 'cleanup_confirmed': True,
        'failure_type': 'ProbePrefixError', 'status': 'stopped-or-detached-needs-review',
        'cleanup_reason': 'isolation-or-controller-failure', 'updater_success_claim': False, 'new_code_admitted': False}
    if (any(session.get(key) != value or type(session.get(key)) is not type(value) for key, value in session_expected.items())
            or session.get('cleanup') != [{'flag': '-k', 'exit': 0, 'timed_out': False},
                                          {'flag': '-w', 'exit': 0, 'timed_out': False}]
            or any(type(row.get('exit')) is not int or row.get('timed_out') is not False
                   for row in session.get('cleanup', []))
            or session.get('original_launcher_wait_timed_out', False) is not False):
        raise ProbePrefixError('Preserve the actual SDK-policy rejection and require its confirmed scoped cleanup.')
    sdk = proof.get('sdk_user_data')
    required_sdk = {'relative_root', 'root_device', 'root_inode', 'root_birthtime_ns',
                    'created_during_update', 'copied_or_imported'}
    if (not isinstance(sdk, dict) or set(sdk) != required_sdk
            or sdk['relative_root'] != sdk_user_root(user) or sdk['created_during_update'] is not True
            or sdk['copied_or_imported'] is not False
            or any(type(sdk[key]) is not int or sdk[key] < 0 for key in ('root_device', 'root_inode', 'root_birthtime_ns'))):
        raise ProbePrefixError('Only the one actual vendor-created SDK user-data root is permitted.')
    directory = prefix / sdk_user_root(user)
    _plain_path(directory, prefix)
    try:
        sdk_info = directory.lstat()
    except OSError:
        raise ProbePrefixError('The explicitly enrolled SDK directory is unavailable.')
    if (not stat.S_ISDIR(sdk_info.st_mode) or (sdk_info.st_dev, sdk_info.st_ino) != (sdk['root_device'], sdk['root_inode'])
            or _birthtime_ns(sdk_info) != sdk['root_birthtime_ns']):
        raise ProbePrefixError('The SDK origin belongs to another local directory.')
    try:
        started = datetime.datetime.fromisoformat(session['at'])
        ended = datetime.datetime.fromisoformat(session['controller_ended_at'])
        if started.tzinfo is None or ended.tzinfo is None or not started <= ended:
            raise ValueError
        birth = sdk['root_birthtime_ns'] / 1000000000
        if not started.timestamp() <= birth <= ended.timestamp():
            raise ValueError
    except (KeyError, TypeError, ValueError):
        raise ProbePrefixError('SDK directory creation must fall within the preserved authorized update session.')
    x86 = proof.get('social_club_x86')
    if (not isinstance(x86, dict) or set(x86) != {'root', 'container', 'directory', 'created_during_update', 'copied_or_imported'}
            or x86['root'] != UPDATE_X86_CODE_ROOT or x86['created_during_update'] is not True
            or x86['copied_or_imported'] is not False):
        raise ProbePrefixError('The third code root requires this actual vendor-created 32-bit Social Club origin.')
    for key, relative in (('container', UPDATE_X86_CONTAINER), ('directory', UPDATE_X86_CODE_ROOT)):
        entry = x86[key]
        if (not isinstance(entry, dict) or set(entry) != {'device', 'inode', 'birthtime_ns'}
                or any(type(entry[field]) is not int or entry[field] < 0 for field in entry)):
            raise ProbePrefixError('32-bit Social Club origin requires actual numeric directory identities.')
        path = prefix / relative
        _plain_path(path, prefix)
        try:
            value = path.lstat()
        except OSError:
            raise ProbePrefixError('The actual 32-bit Social Club installation is unavailable.')
        if (not stat.S_ISDIR(value.st_mode) or (value.st_dev, value.st_ino, _birthtime_ns(value)) != (
                entry['device'], entry['inode'], entry['birthtime_ns'])
                or not started.timestamp() <= entry['birthtime_ns'] / 1000000000 <= ended.timestamp()):
            raise ProbePrefixError('32-bit Social Club directories must be the actual ones created during the update.')
    x86_files = [item.get('path') for item in bound_manifest.get('files', []) if isinstance(item, dict)
                 and isinstance(item.get('path'), str) and item['path'].startswith(UPDATE_X86_CODE_ROOT + '/')]
    if set(x86_files) != {UPDATE_X86_CODE_ROOT + '/' + name for name in UPDATE_X86_BASENAMES} or len(x86_files) != 5:
        raise ProbePrefixError('Only the five actual 32-bit Social Club code files belong to this update.')
    machine = old_manifest.get('machine_runtime_policy')
    expected_machine = {'root': MACHINE_ROOT, 'directory': machine.get('directory') if isinstance(machine, dict) else None,
                        'unchanged_from_previous_binding': True}
    if (not isinstance(machine, dict) or machine.get('root') != MACHINE_ROOT
            or proof.get('machine_runtime') != expected_machine):
        raise ProbePrefixError('The update cannot enroll or replace a machine-runtime root.')
    machine_path = prefix / MACHINE_ROOT
    _plain_path(machine_path, prefix)
    if not machine_path.is_dir() or _directory_identity(machine_path) != machine['directory']:
        raise ProbePrefixError('The original machine-runtime directory identity changed.')
    return proof


def _under(path, root):
    path_parts = tuple(part.casefold() for part in path.parts)
    root_parts = tuple(part.casefold() for part in root.parts)
    return path_parts[:len(root_parts)] == root_parts


def user_path_allowed(path, prefix, policy):
    if policy is None:
        return False
    relative = path.relative_to(prefix)
    roots = policy['user_data_roots'] + ([policy['local_game_runtime_root']]
                                       if policy.get('local_game_runtime_root') else [])
    return any(_under(relative, Path(root)) or _under(Path(root), relative) for root in roots)


def _regular_file(path, prefix):
    _plain_path(path, prefix)
    try:
        info = path.stat()
    except OSError as error:
        raise ProbePrefixError('Cannot inspect a Rockstar code/manifest file: ' + str(error))
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ProbePrefixError('Rockstar code/manifest files must be regular, separate-inode files.')
    return info


def _sha(path, prefix):
    info = _regular_file(path, prefix)
    fingerprint = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)
    cached = _HASH_CACHE.get(str(path))
    if cached is not None and cached[0] == fingerprint:
        return cached[1]
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
        after = os.fstat(stream.fileno())
    final = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_nlink)
    if fingerprint != final:
        raise ProbePrefixError('A Rockstar code/manifest file changed while hashing.')
    value = digest.hexdigest()
    _HASH_CACHE[str(path)] = (fingerprint, value)
    return value


def _relative(value):
    if not isinstance(value, str) or '\\' in value or ':' in value:
        raise ProbePrefixError('Rockstar inventory uses canonical relative POSIX paths.')
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in ('.', '..') for part in path.parts) or path.as_posix() != value:
        raise ProbePrefixError('Rockstar inventory path is not canonical.')
    return Path(*path.parts)


def _source_evidence(manifest, root):
    evidence = manifest.get('source_evidence')
    if not isinstance(evidence, dict) or set(evidence) != {'path', 'sha256'}:
        raise ProbePrefixError('Rockstar code requires its separate source evidence path and SHA256.')
    relative = _relative(evidence['path'])
    if relative.parts[0] != 'research' or relative.suffix != '.json':
        raise ProbePrefixError('Rockstar source evidence must be a project research JSON file.')
    if not isinstance(evidence['sha256'], str) or not re.fullmatch('[0-9a-f]{64}', evidence['sha256']):
        raise ProbePrefixError('Invalid Rockstar source evidence SHA256.')
    if _sha(root / relative, root) != evidence['sha256']:
        raise ProbePrefixError('Rockstar source evidence changed.')


def _walk_error(error):
    raise ProbePrefixError('Cannot inspect all Rockstar policy paths: ' + str(error))


def _verify_code(manifest, prefix, root, allowed_game_folders=(), expected_roots=CODE_ROOTS):
    expected_roots = tuple(expected_roots)
    if expected_roots not in (CODE_ROOTS, UPDATED_CODE_ROOTS):
        raise ProbePrefixError('Only the original roots or the one reviewed three-root update set are permitted.')
    if manifest.get('schema') != 1 or manifest.get('kind') != 'rockstar-code-only':
        raise ProbePrefixError('Unsupported Rockstar code-only manifest.')
    if manifest.get('roots') != list(expected_roots) or manifest.get('excluded_account_profiles_registry_sessions') is not True:
        raise ProbePrefixError('Rockstar manifest must describe only the two reviewed code roots, without account inputs.')
    _source_evidence(manifest, root)
    items = manifest.get('files')
    if not isinstance(items, list) or not items or len(items) > 10000:
        raise ProbePrefixError('Rockstar code requires a bounded complete file inventory.')
    expected = {}
    aliases = set()
    for item in items:
        if not isinstance(item, dict) or set(item) != {'path', 'bytes', 'sha256'}:
            raise ProbePrefixError('Rockstar file inventory requires exactly path, bytes and SHA256.')
        relative = _relative(item['path'])
        if not any(relative != Path(code) and _under(relative, Path(code)) for code in expected_roots):
            raise ProbePrefixError('Rockstar manifest path is outside the exact reviewed code roots.')
        if any(part.casefold() in FORBIDDEN_CODE_PARTS or part.casefold().startswith('cfxticket') for part in relative.parts):
            raise ProbePrefixError('Refusing profile/session/registry artifacts in the Rockstar code inventory.')
        alias = item['path'].casefold()
        if alias in aliases:
            raise ProbePrefixError('Duplicate or Windows-case-aliased Rockstar inventory path.')
        aliases.add(alias)
        if type(item['bytes']) is not int or item['bytes'] < 0 or not isinstance(item['sha256'], str) or not re.fullmatch('[0-9a-f]{64}', item['sha256']):
            raise ProbePrefixError('Invalid Rockstar code byte count or SHA256.')
        expected[item['path']] = item
    actual = set()
    container = prefix / CODE_CONTAINER
    _plain_path(container, prefix)
    children = {p.name for p in container.iterdir()} if container.is_dir() else set()
    required = {'Launcher', 'Social Club'}
    if not required.issubset(children) or not children.issubset(required | set(allowed_game_folders)):
        raise ProbePrefixError('Only Launcher and Social Club belong in the reviewed Rockstar code container.')
    for name in children - required:
        directory = container / name
        _plain_path(directory, prefix)
        if not directory.is_dir():
            raise ProbePrefixError('An authorized game installation root must be a local directory.')
    if expected_roots == UPDATED_CODE_ROOTS:
        x86_container = prefix / UPDATE_X86_CONTAINER
        _plain_path(x86_container, prefix)
        if not x86_container.is_dir() or {path.name for path in x86_container.iterdir()} != {'Social Club'}:
            raise ProbePrefixError('The update permits only Social Club under the exact 32-bit Rockstar container.')
    for code in expected_roots:
        directory = prefix / code
        _plain_path(directory, prefix)
        if not directory.is_dir():
            raise ProbePrefixError('A reviewed Rockstar code root is absent.')
        for base, folders, files in os.walk(directory, followlinks=False, onerror=_walk_error):
            for name in folders + files:
                path = Path(base) / name
                _plain_path(path, prefix)
                info = path.stat()
                if path.is_dir():
                    if name.casefold() in FORBIDDEN_CODE_PARTS or name.casefold().startswith('cfxticket'):
                        raise ProbePrefixError('Profile/session directories cannot be Rockstar code dependencies.')
                    continue
                if not stat.S_ISREG(info.st_mode):
                    raise ProbePrefixError('Special files cannot be Rockstar code dependencies.')
                relative = path.relative_to(prefix).as_posix()
                if relative not in expected:
                    raise ProbePrefixError('Uninventoried file in the Rockstar code installation: ' + relative)
                item = expected[relative]
                if info.st_size != item['bytes'] or _sha(path, prefix) != item['sha256']:
                    raise ProbePrefixError('Rockstar code differs from its exact source inventory: ' + relative)
                actual.add(relative)
    if actual != set(expected):
        raise ProbePrefixError('Rockstar code inventory contains missing files.')
    launcher = CODE_ROOTS[0] + '/Launcher.exe'
    if launcher not in actual or not any(name.startswith(CODE_ROOTS[1] + '/') for name in actual):
        raise ProbePrefixError('Require the actual Launcher.exe and Social Club code inventories.')


def _verify_user_tree(prefix, roots, require_empty=False):
    containers = {str(Path(relative).parent) for relative in roots}
    for relative in containers:
        container = prefix / relative
        _plain_path(container, prefix)
        if not container.exists():
            continue
        if not container.is_dir():
            raise ProbePrefixError('Rockstar user-data containers must be local directories.')
        for base, folders, files in os.walk(container, followlinks=False, onerror=_walk_error):
            for name in folders + files:
                path = Path(base) / name
                _plain_path(path, prefix)
                try:
                    info = path.lstat()
                except FileNotFoundError:
                    continue
                relative_path = path.relative_to(prefix)
                inside = any(_under(relative_path, Path(allowed)) for allowed in roots)
                if not inside:
                    raise ProbePrefixError('Unexpected Rockstar user-data sibling outside the three fresh UI roots.')
                if not stat.S_ISDIR(info.st_mode):
                    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                        raise ProbePrefixError('Rockstar runtime data must be local regular single-link files.')
                    if require_empty:
                        raise ProbePrefixError('Rockstar UI data must be absent or completely empty before code binding; never import sessions.')


def _binding(prefix, root, user):
    info = prefix.stat()
    return {'project_root': str(root), 'prefix_device': info.st_dev, 'prefix_inode': info.st_ino, 'user': user}


def validate_binding(prefix, root, identity, user, gta_user_root=None):
    expected_game_root = 'drive_c/users/' + user + '/Documents/Rockstar Games/GTA V'
    if gta_user_root is not None and gta_user_root != expected_game_root:
        raise ProbePrefixError('Only the separately enrolled exact GTA V user-data root is permitted.')
    path = prefix / MANIFEST_NAME
    binding = identity.get('rockstar_code_manifest')
    if binding is None:
        if path.exists() or path.is_symlink():
            raise ProbePrefixError('Unbound Rockstar manifest cannot grant an installation exception.')
        return None
    if not isinstance(binding, dict) or set(binding) != {'path', 'sha256'} or binding.get('path') != MANIFEST_NAME:
        raise ProbePrefixError('Invalid Rockstar manifest marker binding.')
    info = _regular_file(path, prefix)
    if info.st_size > 4 * 1024 * 1024 or _sha(path, prefix) != binding.get('sha256'):
        raise ProbePrefixError('Rockstar prefix manifest differs from its inode-bound marker.')
    try:
        manifest = json.loads(path.read_text())
    except (ValueError, OSError):
        raise ProbePrefixError('Invalid Rockstar prefix manifest JSON.')
    if not isinstance(manifest, dict) or manifest.get('prefix_binding') != _binding(prefix, root, user):
        raise ProbePrefixError('Rockstar code manifest belongs to a different prefix or user.')
    update = validated_update_origin(prefix, root, identity, user, manifest)
    expected_roots = list(user_roots(user)) + ([sdk_user_root(user)] if update is not None else [])
    if manifest.get('user_data_roots') != expected_roots or manifest.get('user_data_initial_state') != 'absent_or_empty_before_runtime':
        raise ProbePrefixError('Rockstar UI data exception lacks its exact fresh-directory policy.')
    _verify_code(manifest, prefix, root, expected_roots=UPDATED_CODE_ROOTS if update is not None else CODE_ROOTS)
    from rockstar_local_game_origin import validated_local_game_runtime_root
    local_game_root = validated_local_game_runtime_root(prefix, root, user)
    roots = manifest['user_data_roots'] + ([gta_user_root] if gta_user_root is not None else [])
    if local_game_root is not None:
        roots.append(local_game_root)
    _verify_user_tree(prefix, roots)
    validate_machine_runtime(manifest, prefix, root)
    return dict(manifest, local_game_runtime_root=local_game_root) if local_game_root is not None else manifest


def _write_bytes(path, value, prefix):
    _plain_path(path, prefix)
    if path.exists():
        _regular_file(path, prefix)
    descriptor, temporary = tempfile.mkstemp(prefix='.rockstar-policy-', dir=prefix)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _write_json(path, value, prefix):
    _write_bytes(path, (json.dumps(value, indent=2) + '\n').encode(), prefix)


def _mkdir_tracked(path, prefix, created):
    current = prefix
    for part in path.relative_to(prefix).parts:
        current /= part
        _plain_path(current, prefix)
        if not current.exists():
            current.mkdir()
            created.append(current)
        elif not current.is_dir():
            raise ProbePrefixError('Rockstar UI directory parent is not a local directory.')


def _quarantine_manifest(path, prefix):
    _regular_file(path, prefix)
    descriptor, temporary = tempfile.mkstemp(prefix='.source-main-rockstar-code.failed-', suffix='.json', dir=prefix)
    os.close(descriptor)
    try:
        os.replace(path, temporary)
    except BaseException:
        os.unlink(temporary)
        raise
    return Path(temporary)


def bind_manifest(prefix, root, identity, user, manifest, marker_name):
    """Caller must hold the source-MAIN lock; this function never copies installation data."""
    if not isinstance(manifest, dict):
        raise ProbePrefixError('Rockstar code manifest must be a JSON object.')
    manifest = json.loads(json.dumps(manifest))
    manifest['prefix_binding'] = _binding(prefix, root, user)
    manifest['user_data_roots'] = list(user_roots(user))
    manifest['user_data_initial_state'] = 'absent_or_empty_before_runtime'
    _verify_code(manifest, prefix, root)
    if identity.get('rockstar_code_manifest') is not None:
        previous = validate_binding(prefix, root, identity, user)
        if previous == manifest:
            return identity['rockstar_code_manifest']
        raise ProbePrefixError('Rockstar code rebinding requires a separately reviewed update transaction.')
    _verify_user_tree(prefix, manifest['user_data_roots'], require_empty=True)
    path = prefix / MANIFEST_NAME
    if path.exists() or path.is_symlink():
        raise ProbePrefixError('Refusing an existing unbound Rockstar prefix manifest.')
    marker = prefix / marker_name
    _regular_file(marker, prefix)
    marker_before = marker.read_bytes()
    created = []
    marker_write_attempted = False
    try:
        for relative in manifest['user_data_roots']:
            _mkdir_tracked(prefix / relative, prefix, created)
        _write_json(path, manifest, prefix)
        binding = {'path': MANIFEST_NAME, 'sha256': _sha(path, prefix)}
        updated = dict(identity, rockstar_code_manifest=binding)
        marker_write_attempted = True
        _write_json(marker, updated, prefix)
        validate_binding(prefix, root, updated, user)
        return binding
    except BaseException as original_error:
        rollback_errors = []
        if marker_write_attempted:
            try:
                _write_bytes(marker, marker_before, prefix)
            except BaseException as error:
                rollback_errors.append('marker restore: ' + str(error))
        if path.exists() or path.is_symlink():
            try:
                _quarantine_manifest(path, prefix)
            except BaseException as error:
                rollback_errors.append('new manifest quarantine: ' + str(error))
        for directory in reversed(created):
            try:
                _plain_path(directory, prefix)
                directory.rmdir()
            except OSError as error:
                # A newly nonempty directory may contain new data; preserve it.
                rollback_errors.append('preserved new directory: ' + str(error))
            except ProbePrefixError as error:
                rollback_errors.append('preserved redirected directory: ' + str(error))
        if rollback_errors:
            raise ProbePrefixError('Rockstar binding failed and rollback needs review: ' + '; '.join(rollback_errors)) from original_error
        raise


MACHINE_ROOT = 'drive_c/ProgramData/Rockstar Games/Launcher'
MACHINE_CONTAINER = 'drive_c/ProgramData/Rockstar Games'
MIGRATION_FILE_NAMES = {'service_log.txt', 'svc_events.json'}


def _json_reference(reference, root):
    _source_evidence({'source_evidence': reference}, root)
    path = root / _relative(reference['path'])
    if path.stat().st_size > 4 * 1024 * 1024:
        raise ProbePrefixError('Rockstar origin evidence is too large.')
    try:
        result = json.loads(path.read_text())
    except (ValueError, OSError):
        raise ProbePrefixError('Invalid Rockstar runtime-origin evidence JSON.')
    if not isinstance(result, dict):
        raise ProbePrefixError('Rockstar runtime-origin evidence must be an object.')
    return result


def _machine_tree(prefix):
    container = prefix / MACHINE_CONTAINER
    directory = prefix / MACHINE_ROOT
    for path in (container, directory):
        _plain_path(path, prefix)
        if not path.is_dir():
            raise ProbePrefixError('Rockstar machine-runtime paths must remain local directories.')
    if {path.name for path in container.iterdir()} != {'Launcher'}:
        raise ProbePrefixError('Only the machine-runtime Launcher directory is allowed under ProgramData/Rockstar Games.')
    files = []
    for base, folders, names in os.walk(directory, followlinks=False, onerror=_walk_error):
        for name in folders + names:
            path = Path(base) / name
            _plain_path(path, prefix)
            lowered = name.casefold()
            if lowered in FORBIDDEN_CODE_PARTS or lowered.startswith(('cfxticket', 'ros_login.')):
                raise ProbePrefixError('Refusing credential/profile artifacts in Rockstar machine-runtime data.')
            if path.is_dir():
                continue
            info = _regular_file(path, prefix)
            files.append({'path': path.relative_to(prefix).as_posix(), 'bytes': info.st_size, 'sha256': _sha(path, prefix)})
    return sorted(files, key=lambda item: item['path'])


def _directory_identity(path):
    try:
        info = path.stat()
    except OSError as error:
        raise ProbePrefixError('Cannot inspect the exact Rockstar machine-runtime directory: ' + str(error))
    return {'device': info.st_dev, 'inode': info.st_ino}


def validate_machine_runtime(manifest, prefix, root):
    policy = manifest.get('machine_runtime_policy')
    if policy is None:
        return
    if (not isinstance(policy, dict) or set(policy) != {'root', 'directory', 'origin_evidence'}
            or policy.get('root') != MACHINE_ROOT
            or policy.get('directory') != _directory_identity(prefix / MACHINE_ROOT)):
        raise ProbePrefixError('Rockstar machine-runtime policy belongs to a different local directory.')
    origin = _json_reference(policy['origin_evidence'], root)
    if (origin.get('schema') != 1 or origin.get('kind') != 'fresh-rockstar-machine-runtime'
            or origin.get('copied_from_other_prefix') is not False
            or origin.get('prefix') != str(prefix.relative_to(root))
            or origin.get('directory') != policy['directory']):
        raise ProbePrefixError('Rockstar machine-runtime exception lacks its recorded fresh origin.')
    _machine_tree(prefix)


def prepare_machine_migration(prefix, root, identity, user, reference, marker_name):
    manifest = validate_binding(prefix, root, identity, user)
    if manifest is None:
        raise ProbePrefixError('Machine-runtime migration requires the existing exact Rockstar code binding.')
    if manifest.get('machine_runtime_policy') is not None:
        if manifest['machine_runtime_policy']['origin_evidence'] == reference:
            return manifest, None
        raise ProbePrefixError('Rockstar machine-runtime migration is one-time, not generic adoption.')
    origin = _json_reference(reference, root)
    if (origin.get('schema') != 1 or origin.get('kind') != 'fresh-rockstar-machine-runtime'
            or origin.get('prefix') != str(prefix.relative_to(root))
            or origin.get('copied_from_other_prefix') is not False
            or origin.get('prior_marker_sha256') != _sha(prefix / marker_name, prefix)
            or origin.get('prior_code_manifest_sha256') != identity['rockstar_code_manifest']['sha256']
            or origin.get('directory') != _directory_identity(prefix / MACHINE_ROOT)):
        raise ProbePrefixError('Rockstar runtime origin does not match the existing prefix/marker/code/directory identity.')
    before = _json_reference(origin.get('strict_before'), root)
    run = _json_reference(origin.get('source_run'), root)
    cleanup = run.get('prefix_cleanup', {})
    failure = run.get('isolation_guard_failure') or {}
    if (before.get('passed') is not True or before.get('prefix') != str(prefix.relative_to(root))
            or before.get('launcher_or_main_started') is not False
            or before.get('only_two_actual_installfolder_values_written') is not True
            or before.get('registry_hives_or_accounts_copied') is not False
            or before.get('prefix_cleanup', {}).get('wait_exit') != 0
            or run.get('prefix') != str(prefix.relative_to(root))
            or run.get('stage') != 'build/windows-source-integration'
            or run.get('resumed_from_exact_source_run_and_checkpoint') is not True
            or run.get('arguments') != [] or run.get('copied_account_or_profile_inputs') is not False
            or run.get('runtime_security_branches_modified') is not False
            or run.get('agent_issued_story_mode_gameplay_or_connect_arguments') is not False
            or run.get('runner_failure') is not None
            or failure.get('type') != 'ProbePrefixError'
            or failure.get('message') != 'Refusing a client installation in the fresh source-MAIN prefix.'
            or cleanup.get('kill_exit') != 0 or cleanup.get('wait_exit') != 0 or cleanup.get('wait_timed_out') is not False
            or run.get('diagnostic', {}).get('unhandled_c0000409') is not False):
        raise ProbePrefixError('Require the strict pre-run guard and the safely stopped source-run ProgramData rejection.')
    from datetime import datetime
    try:
        if datetime.fromisoformat(before['at']) >= datetime.fromisoformat(run['at']):
            raise ValueError('wrong evidence order')
    except (KeyError, ValueError, TypeError):
        raise ProbePrefixError('Rockstar runtime origin lacks ordered pre-run/source-run evidence.')
    files = _machine_tree(prefix)
    if (files != origin.get('files') or len(files) != 2
            or {Path(item['path']).name for item in files} != MIGRATION_FILE_NAMES
            or any(str(Path(item['path']).parent) != MACHINE_ROOT for item in files)):
        raise ProbePrefixError('One-time migration accepts only the two exactly evidenced fresh diagnostic files.')
    policy = {'root': MACHINE_ROOT, 'directory': _directory_identity(prefix / MACHINE_ROOT), 'origin_evidence': reference}
    return manifest, policy


def apply_machine_migration(prefix, root, identity, manifest, policy, marker_name, final_validate):
    if policy is None:
        return identity['rockstar_code_manifest']
    path, marker = prefix / MANIFEST_NAME, prefix / marker_name
    before_manifest, before_marker = path.read_bytes(), marker.read_bytes()
    updated_manifest = dict(manifest, machine_runtime_policy=policy)
    try:
        _write_json(path, updated_manifest, prefix)
        binding = {'path': MANIFEST_NAME, 'sha256': _sha(path, prefix)}
        _write_json(marker, dict(identity, rockstar_code_manifest=binding), prefix)
        final_validate()
        return binding
    except BaseException as original:
        errors = []
        for target, contents in ((path, before_manifest), (marker, before_marker)):
            try:
                _write_bytes(target, contents, prefix)
            except BaseException as error:
                errors.append(str(error))
        if errors:
            raise ProbePrefixError('Machine-runtime migration failed; metadata rollback needs review: ' + '; '.join(errors)) from original
        raise
