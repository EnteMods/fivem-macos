"""Exact Core-only v8-to-v9 lifecycle diagnostics; no new runtime claim."""
import hashlib
import json
import re

import toolmode_diagnostic_identity as previous_version
from hook_diagnostic_identity import _group, _identity_shape
from run_main import ROOT, REVISION, sha

VERSION = 9
CORE_SHA256 = '51b7d6432f8a32b404144d19a5abf0a16bcadc764971e99e6fcb12e708a16396'
BUILD_RECORD_SHA256 = 'bb309c253a6c1e77d1ed520ffe04a81668728801f722437ab9d42944299511ae'
TBB_SHA256 = 'c3931068206dc672fc8a070285b8623804d45c051d1ac73f33a13c6497e33038'
PREVIOUS_CORE_SHA256 = previous_version.CORE_SHA256
SOURCE = 'build/windows-core-lifecycle-diagnostic/CoreRT.dll'
TBB = 'build/windows-core-lifecycle-diagnostic/clang_23.1_cxx17_64_md_relwithdebinfo/tbb12.dll'
PREVIOUS_MANIFEST = previous_version.MANIFEST
MANIFEST = 'research/client-source-code-inputs-v9.json'
TRANSACTION = 'research/client-source-core-lifecycle-update-v9.json'
BACKUP = 'build/checkpoints/source-code-updates/lifecycle-v9/CoreRT.dll.previous'
BUILD_RECORD = 'research/core-lifecycle-diagnostic-build.json'
ORIGINAL = 'port/fivem/code/client/citicore/SEHTableHandler.Win32.cpp'
ORIGIN = 'public-source-Core-v9-fixed-field-minhook-lifecycle-diagnostics'
HEADER_TEST_COUNT = 3
HEADER_LOG = 'build/windows-core-lifecycle-diagnostic/header-tests.log'
EXPECTED_SOURCES = {'native/windows-core-lifecycle-diagnostic/' + name for name in
                    ('build.py', 'LifecycleDiagnostics.h', 'test_lifecycle_diagnostics.py')}
BASE_OVERLAY = previous_version.EXPECTED_OVERLAY
EXPECTED_OVERLAY = {'build/windows-core-lifecycle-diagnostic/overlay/' + name for name in
                    (*previous_version.OVERLAY_DIGESTS, 'SEHTableHandler.Win32.cpp', 'LifecycleDiagnostics.h')}
BUILD_FILES = {'toolchain': 'native/windows-core/toolchain.cmake', **{
    key: 'build/windows-core-lifecycle-diagnostic/' + name for key, name in (
        ('log', 'build.log'), ('compile_commands', 'compile_commands.json'), ('source_scope', 'source-scope.txt'))}}
PRESERVED_INPUTS = {previous_version.BUILD_RECORD, previous_version.SOURCE, previous_version.TBB, ORIGINAL} \
                   | BASE_OVERLAY
ALLOWED_INPUTS = set(previous_version.ALLOWED_INPUTS) | PRESERVED_INPUTS | EXPECTED_SOURCES | EXPECTED_OVERLAY \
                 | set(BUILD_FILES.values()) | {SOURCE, TBB, BUILD_RECORD, HEADER_LOG, PREVIOUS_MANIFEST,
                                               TRANSACTION, BACKUP}
SCOPE_TRUE = (
    'stripped_seh_equals_exact_original_bytes', 'stripped_cmake_equals_exact_v8_bytes',
    'v8_mapping_toolmode_and_headers_byte_identical', 'original_calls_evaluated_once',
    'original_statuses_and_controlflow_preserved', 'last_error_and_errno_preserved')
SCOPE_FALSE = ('dllmain_added', 'original_auth_security_or_mapping_policy_changed',
               'additional_minhook_calls', 'addresses_stacks_or_authentication_values_logged')


def _same(before, after):
    return json.dumps(before, sort_keys=True, separators=(',', ':')) == json.dumps(after, sort_keys=True, separators=(',', ':'))


def allowed_input(root, name):
    if type(name) is not str or name not in ALLOWED_INPUTS:
        raise RuntimeError('Refusing an undeclared lifecycle diagnostic input')
    # Reuse the existing canonical/local/single-link guard with this exact role set.
    from pathlib import PurePosixPath
    import stat
    from run_main import plain
    relative = PurePosixPath(name)
    if relative.is_absolute() or str(relative) != name or any(part in ('.', '..') for part in relative.parts):
        raise RuntimeError('Lifecycle input must be canonical and project-relative')
    path = root / relative
    plain(path)
    value = path.lstat()
    if (not stat.S_ISREG(value.st_mode) or value.st_nlink != 1 or path.resolve(strict=True) != path
            or not path.is_relative_to(root)):
        raise RuntimeError('Require an unaliased regular lifecycle code/evidence file')
    return path


def _pins():
    if (any(type(value) is not str or re.fullmatch('[0-9a-f]{64}', value) is None
            for value in (CORE_SHA256, BUILD_RECORD_SHA256, TBB_SHA256))
            or type(HEADER_TEST_COUNT) is not int or HEADER_TEST_COUNT <= 0):
        raise RuntimeError('The completed lifecycle build has not been admitted')


def validate_evidence(root):
    _pins()
    report = allowed_input(root, BUILD_RECORD)
    raw = report.read_bytes()
    if hashlib.sha256(raw).hexdigest() != BUILD_RECORD_SHA256:
        raise RuntimeError('The lifecycle build report changed')
    build = json.loads(raw)
    for key, name in (('artifact', SOURCE), ('tbb_artifact', TBB),
                      ('base_v8_build_record', previous_version.BUILD_RECORD), ('original_seh', ORIGINAL)):
        _identity_shape(build.get(key), name)
    for key, names in (('base_v8_overlay', BASE_OVERLAY), ('source_evidence', EXPECTED_SOURCES),
                       ('generated_overlay', EXPECTED_OVERLAY)):
        _group(build.get(key), names)
    settings, tests = build.get('build', {}), build.get('header_and_overlay_tests', {})
    for key, name in BUILD_FILES.items():
        _identity_shape(settings.get(key), name)
    _identity_shape(tests.get('log'), HEADER_LOG)
    preserved = build.get('preserved_original_and_v8_input_sha256')
    if (not isinstance(preserved, dict) or set(preserved) != PRESERVED_INPUTS
            or any(type(value) is not str or re.fullmatch('[0-9a-f]{64}', value) is None
                   for value in preserved.values())):
        raise RuntimeError('Unexpected preserved v8 code scope')
    # Admit every selected role before hashing any path supplied by the report.
    identities = [build['artifact'], build['tbb_artifact'], build['base_v8_build_record'],
                  build['original_seh'], *build['base_v8_overlay'], *build['source_evidence'],
                  *build['generated_overlay'], *(settings[key] for key in BUILD_FILES), tests['log']]
    paths = {name: allowed_input(root, name) for name in
             set(preserved) | {item['path'] for item in identities}}
    scope = build.get('scope_proof', {})
    if (build.get('source_revision') != REVISION or build.get('compiled') is not True
            or build['artifact']['sha256'] != CORE_SHA256
            or build['tbb_artifact']['sha256'] != TBB_SHA256
            or build['base_v8_build_record']['sha256'] != preserved[previous_version.BUILD_RECORD]
            or build['original_seh']['sha256'] != preserved[ORIGINAL]
            or any(scope.get(key) is not True for key in SCOPE_TRUE)
            or any(scope.get(key) is not False for key in SCOPE_FALSE)
            or scope.get('stripped_seh_sha256') != preserved[ORIGINAL]
            or scope.get('stripped_cmake_sha256') != previous_version.OVERLAY_DIGESTS['CMakeLists.txt']):
        raise RuntimeError('Require exact v8-preserving lifecycle-only build scope')
    expected_payload = {'fixed_prefix': 'CFX_CORE_MH',
        'fields': ['pid', 'tid', 'phase', 'status_valid', 'status'], 'phase_range': [1, 4],
        'status_valid_range': [0, 1], 'status_range': [-1, 12], 'default': 'OFF',
        'paths_addresses_stacks_arguments_authentication_or_profile_values_logged': False}
    if build.get('payload') != expected_payload:
        raise RuntimeError('Unexpected lifecycle diagnostic metadata contract')
    if (settings.get('directory') != 'build/windows-core-lifecycle-diagnostic'
            or type(settings.get('exit')) is not int or settings['exit'] != 0
            or settings.get('CFX_SOURCE_DIR') != 'port/fivem'
            or any(settings.get(name) != 'ON' for name in (
                'CFX_CORE_MAPPING_DIAGNOSTICS', 'CFX_CORE_TOOLMODE_DIAGNOSTICS', 'CFX_CORE_LIFECYCLE_DIAGNOSTICS'))
            or settings.get('CFX_CORE_ACCOUNT_FREE_TESTS') != 'OFF' or settings.get('runtime') != '/MD'
            or settings.get('target') != 'AMD64 Windows CoreRT'
            or type(tests.get('exit')) is not int or tests['exit'] != 0
            or type(tests.get('passed')) is not int or tests['passed'] != HEADER_TEST_COUNT
            or any(build.get(key) is not False for key in (
                'wine_client_or_game_started', 'stage_or_prefix_accessed', 'existing_patch_queue_changed', 'runtime_tested'))):
        raise RuntimeError('Require successful separate diagnostic build and native checks only')
    references = list(previous_version.validate_evidence(root))
    references.append({'path': BUILD_RECORD, 'sha256': BUILD_RECORD_SHA256})
    for item in identities:
        path = paths[item['path']]
        digest = sha(path)
        if digest != item['sha256'] or path.stat().st_size != item['bytes']:
            raise RuntimeError('A bound lifecycle build input changed')
        references.append({'path': item['path'], 'sha256': digest})
    for name, digest in preserved.items():
        if sha(paths[name]) != digest:
            raise RuntimeError('A preserved v8 input changed')
        references.append({'path': name, 'sha256': digest})
    for name, digest in previous_version.OVERLAY_DIGESTS.items():
        if name == 'CMakeLists.txt':
            continue
        path = 'build/windows-core-lifecycle-diagnostic/overlay/' + name
        if sha(paths[path]) != digest:
            raise RuntimeError('An existing v8 diagnostic source/header changed')
    output = paths[HEADER_LOG].read_text()
    if (f'Ran {HEADER_TEST_COUNT} tests' not in output or re.search(r'(?m)^OK\s*$', output) is None
            or 'FAILED' in output):
        raise RuntimeError('The actual lifecycle native test log must pass')
    return references


def validate_version(record):
    _pins()
    for key, expected in (('lifecycle_previous_manifest', PREVIOUS_MANIFEST),
                          ('lifecycle_update_transaction', TRANSACTION)):
        if record.get(key) != expected or sha(allowed_input(ROOT, expected)) != record.get(key + '_sha256'):
            raise RuntimeError('Unexpected or changed lifecycle evidence reference')
    previous = json.loads(allowed_input(ROOT, PREVIOUS_MANIFEST).read_text())
    if type(previous.get('developer_code_version')) is not int or previous['developer_code_version'] != 8:
        raise RuntimeError('Lifecycle diagnostics require exact previous v8 metadata')
    previous_version.validate_version(previous)
    additions = {'lifecycle_previous_manifest', 'lifecycle_previous_manifest_sha256',
                 'lifecycle_update_transaction', 'lifecycle_update_transaction_sha256'}
    if (set(record) != set(previous) | additions or type(record.get('developer_code_version')) is not int
            or record['developer_code_version'] != VERSION):
        raise RuntimeError('Unexpected v9 fields or developer role')
    for key, value in previous.items():
        if key not in ('at', 'developer_code_version', 'files') and not _same(record.get(key), value):
            raise RuntimeError('v9 must preserve existing v8 metadata: ' + key)
    old, new = previous.get('files'), record.get('files')
    if (not isinstance(old, list) or not isinstance(new, list) or len(old) != len(new)
            or any(not isinstance(item, dict) or type(item.get('name')) is not str for item in old + new)
            or len({item['name'] for item in old}) != len(old)
            or sum(item['name'] == 'CoreRT.dll' for item in old) != 1):
        raise RuntimeError('Unexpected v8/v9 code inventory')
    for before, after in zip(old, new):
        if before['name'] != 'CoreRT.dll':
            if not _same(before, after):
                raise RuntimeError('v9 may update only its own CoreRT code input')
        elif (before.get('sha256') != PREVIOUS_CORE_SHA256 or not _same(after, dict(
                before, sha256=CORE_SHA256, bytes=allowed_input(ROOT, SOURCE).stat().st_size, origin=ORIGIN))):
            raise RuntimeError('Unexpected v9 own-Core delta')
    transaction = json.loads(allowed_input(ROOT, TRANSACTION).read_text())
    expected = {
        'source_revision': REVISION, 'developer_code_version': VERSION,
        'lifecycle_previous_manifest': PREVIOUS_MANIFEST,
        'lifecycle_previous_manifest_sha256': record['lifecycle_previous_manifest_sha256'],
        'previous_sha256': PREVIOUS_CORE_SHA256, 'new_sha256': CORE_SHA256,
        'target': 'build/windows-source-integration/CoreRT.dll', 'source': SOURCE,
        'previous_code_backup': BACKUP, 'only_own_core_file_updated': True,
        'main_citigame_and_original_modules_unchanged': True,
        'original_conditions_returns_mapping_authentication_and_security_decisions_preserved': True,
        'v9_wine_runtime_fixture_claim': False, 'profiles_sessions_tickets_read_copied_or_reset': False}
    if (set(transaction) != set(expected) | {'at', 'header_checks', 'diagnostic_evidence'}
            or any(type(transaction.get(key)) is not type(value) or transaction.get(key) != value
            for key, value in expected.items())
            or not _same(transaction.get('header_checks'), {'exit': 0, 'passed': HEADER_TEST_COUNT})
            or sha(allowed_input(ROOT, BACKUP)) != PREVIOUS_CORE_SHA256
            or transaction.get('diagnostic_evidence') != validate_evidence(ROOT)):
        raise RuntimeError('Unexpected lifecycle-only Core transaction or evidence')
