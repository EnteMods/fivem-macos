"""One metadata-only Local/GTA V origin tied to the observed Source10 attempt."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from probe_environment import ProbePrefixError, _plain_path

EVIDENCE_PATH = 'research/rockstar-local-game-runtime-origin-20261103.json'
SOURCE_RESULT = 'research/client-source-ui-resume-20261103T145139316532Z-results.json'
SOURCE_BYTES = 223516
SOURCE_SHA256 = '2cb159763b3f78a0283507cc01974d5607d77bde82c40c3051a9ba27d7328ae4'
PREFIX = 'prefixes/fivem-source-main'
REVISION = '9f0e34e1cbdfc34fd05079416791f01938279097'
FAILURE = {'type': 'ProbePrefixError',
    'message': 'Unexpected Rockstar user-data sibling outside the three fresh UI roots.'}


def _read_json(path, root, limit, digest=None, size=None):
    _plain_path(path, root)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= limit
                or size is not None and before.st_size != size):
            raise ProbePrefixError('Local GTA origin evidence must be bounded regular single-link metadata.')
        raw = bytearray()
        while len(raw) <= before.st_size:
            block = os.read(descriptor, before.st_size + 1 - len(raw))
            if not block:
                break
            raw.extend(block)
        after, named = os.fstat(descriptor), path.lstat()
        identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_nlink, value.st_size, value.st_mtime_ns)
        if identity(before) != identity(after) or identity(before) != identity(named) or len(raw) != before.st_size:
            raise ProbePrefixError('Local GTA origin metadata changed during its bounded read.')
        if digest is not None and hashlib.sha256(raw).hexdigest() != digest:
            raise ProbePrefixError('The fixed Source10 result changed.')
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ProbePrefixError('Local GTA origin evidence must be JSON objects.')
        return value
    finally:
        os.close(descriptor)


def _birthtime_ns(value):
    if hasattr(value, 'st_birthtime_ns'):
        return value.st_birthtime_ns
    if not hasattr(value, 'st_birthtime'):
        raise ProbePrefixError('Local GTA runtime origin requires filesystem creation metadata.')
    return int(value.st_birthtime * 1_000_000_000)


def _timestamp_ns(value):
    if type(value) is not str:
        raise ProbePrefixError('The Source10 runtime timestamp is invalid.')
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset().total_seconds() != 0:
        raise ProbePrefixError('The Source10 runtime timestamp must be UTC.')
    return int(parsed.timestamp() * 1_000_000_000)


def validated_local_game_runtime_root(prefix, root, user):
    """Return one exact origin-bound directory; never inspect its contents."""
    root, prefix = Path(root).absolute(), Path(prefix).absolute()
    evidence = root / EVIDENCE_PATH
    _plain_path(evidence, root)
    try:
        evidence.lstat()
    except FileNotFoundError:
        return None
    try:
        if (root.resolve(strict=True) != root or prefix != root / PREFIX
                or type(user) is not str or re.fullmatch(r'[A-Za-z0-9_-]+', user) is None):
            raise ProbePrefixError('Local GTA runtime origin belongs to a different source prefix or user.')
        record = _read_json(evidence, root, 16384)
        relative = 'drive_c/users/' + user + '/AppData/Local/Rockstar Games/GTA V'
        expected = {'schema': 1, 'kind': 'rockstar-local-game-runtime-origin',
            'scope': 'runtime-directory-metadata-only', 'prefix': PREFIX, 'user': user,
            'relative_root': relative, 'created_during_source_run': True, 'copied_or_imported': False,
            'source_result': {'path': SOURCE_RESULT, 'bytes': SOURCE_BYTES, 'sha256': SOURCE_SHA256}}
        numeric = {'prefix_device', 'prefix_inode', 'root_device', 'root_inode', 'root_birthtime_ns'}
        if (set(record) != set(expected) | numeric
                or any(type(record.get(key)) is not type(value) or json.dumps(record.get(key), sort_keys=True) != json.dumps(value, sort_keys=True)
                       for key, value in expected.items())
                or any(type(record.get(key)) is not int or record[key] < 0 for key in numeric)):
            raise ProbePrefixError('Unexpected Local GTA runtime origin role or filesystem identity.')
        result = _read_json(root / SOURCE_RESULT, root, 524288, SOURCE_SHA256, SOURCE_BYTES)
        checks = {'prefix': PREFIX, 'developer_code_version': 10, 'source_revision': REVISION,
            'runtime_engine_profile': 'parity', 'isolation_guard_failure': FAILURE,
            'prefix_cleanup': {'kill_exit': 0, 'wait_exit': 0, 'wait_timed_out': False}}
        if any(json.dumps(result.get(key), sort_keys=True) != json.dumps(value, sort_keys=True)
               for key, value in checks.items()):
            raise ProbePrefixError('Local GTA runtime origin requires the unchanged Source10 guard-stop result.')
        label = re.fullmatch(r'research/client-source-ui-resume-(\d{8}T\d{12})Z-results\.json', SOURCE_RESULT)
        start = datetime.strptime(label[1], '%Y%m%dT%H%M%S%f').replace(tzinfo=timezone.utc)
        start_ns, end_ns = int(start.timestamp() * 1_000_000_000), _timestamp_ns(result.get('at'))
        if not start_ns <= record['root_birthtime_ns'] <= end_ns:
            raise ProbePrefixError('Local GTA runtime directory was not created within the bound Source10 attempt.')
        _plain_path(prefix, root)
        directory = prefix / relative
        _plain_path(directory, prefix)
        prefix_info, info = prefix.lstat(), directory.lstat()
        if (not stat.S_ISDIR(prefix_info.st_mode) or not stat.S_ISDIR(info.st_mode)
                or (prefix_info.st_dev, prefix_info.st_ino) != (record['prefix_device'], record['prefix_inode'])
                or (info.st_dev, info.st_ino, _birthtime_ns(info)) != (
                    record['root_device'], record['root_inode'], record['root_birthtime_ns'])):
            raise ProbePrefixError('Local GTA runtime origin no longer identifies the same local directories.')
        return relative
    except (OSError, ValueError, TypeError, KeyError) as error:
        raise ProbePrefixError('Invalid Local GTA runtime origin metadata: ' + type(error).__name__)
