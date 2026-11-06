"""Core-only v9-to-v10 admission for the public optional-hook ownership fix."""
import hashlib
import json
import re
from pathlib import PurePosixPath
import stat

import lifecycle_diagnostic_identity as previous_version
from hook_diagnostic_identity import _group, _identity_shape
from run_main import ROOT, REVISION, plain, sha

VERSION = 10
CORE_SHA256 = '04e4a47108a1f6d2c1459a28efb1e58575a91de042cf6e1e8cd4ccbe043eb88d'
BUILD_RECORD_SHA256 = '445bea6733b6a0b009a68fe0d8bac2741d38448e2033ed26cd6449d071901e5f'
TBB_SHA256 = '76dc938842dce2d506d5f43f935efa62761df8b2ce89a66f11cec7c0c1ee7767'
PREVIOUS_CORE_SHA256 = previous_version.CORE_SHA256
SOURCE = 'build/windows-core-null-target-fix/CoreRT.dll'
TBB = 'build/windows-core-null-target-fix/clang_23.1_cxx17_64_md_relwithdebinfo/tbb12.dll'
PREVIOUS_MANIFEST = previous_version.MANIFEST
MANIFEST = 'research/client-source-code-inputs-v10.json'
TRANSACTION = 'research/client-source-core-null-target-update-v10.json'
BACKUP = 'build/checkpoints/source-code-updates/null-target-v10/CoreRT.dll.previous'
BUILD_RECORD = 'research/core-null-target-fix-build.json'
ORIGINAL = 'port/fivem/code/client/citicore/DllGameComponent.Win32.cpp'
ORIGIN = 'public-source-Core-v10-optional-minhook-target-ownership-fix'
HEADER_TEST_COUNT = 3
HEADER_LOG = 'build/windows-core-null-target-fix/native-tests.log'
EXPECTED_SOURCES = {'native/windows-core-null-target-fix/' + name for name in
                    ('build.py', 'test_null_target_fix.py')}
BASE_OVERLAY = previous_version.EXPECTED_OVERLAY
EXPECTED_OVERLAY = {'build/windows-core-null-target-fix/overlay/' + PurePosixPath(name).name
                    for name in BASE_OVERLAY} | {
    'build/windows-core-null-target-fix/overlay/DllGameComponent.Win32.cpp'}
BUILD_FILES = {'toolchain': 'native/windows-core/toolchain.cmake', **{
    key: 'build/windows-core-null-target-fix/' + name for key, name in (
        ('log', 'build.log'), ('compile_commands', 'compile_commands.json'), ('source_scope', 'source-scope.txt'))}}
PRESERVED_INPUTS = {previous_version.BUILD_RECORD, previous_version.SOURCE, previous_version.TBB, ORIGINAL} | BASE_OVERLAY
ALLOWED_INPUTS = set(previous_version.ALLOWED_INPUTS) | PRESERVED_INPUTS | EXPECTED_SOURCES | EXPECTED_OVERLAY \
    | set(BUILD_FILES.values()) | {SOURCE, TBB, BUILD_RECORD, HEADER_LOG, PREVIOUS_MANIFEST, TRANSACTION, BACKUP}
SCOPE_TRUE = ('stripped_component_equals_exact_original_bytes', 'stripped_cmake_equals_exact_v9_bytes',
    'v9_other_seven_overlay_files_byte_identical', 'mh_initialize_call_unchanged',
    'nonnull_and_successful_create_required_for_owned_targets', 'enable_disable_remove_only_for_owned_targets',
    'failed_or_already_created_targets_not_modified', 'other_original_branches_and_calls_byte_identical')
SCOPE_FALSE = ('dllmain_added', 'original_auth_security_or_mapping_policy_changed',
    'global_minhook_uninitialize_added', 'additional_minhook_calls', 'addresses_stacks_or_authentication_values_logged')


def allowed_input(root, name):
    if type(name) is not str or name not in ALLOWED_INPUTS:
        raise RuntimeError('Refusing an undeclared NULL-target fix input')
    relative = PurePosixPath(name)
    if relative.is_absolute() or str(relative) != name or any(part in ('.', '..') for part in relative.parts):
        raise RuntimeError('NULL-target input must be canonical and project-relative')
    path = root / relative
    plain(path)
    value = path.lstat()
    if (not stat.S_ISREG(value.st_mode) or value.st_nlink != 1 or path.resolve(strict=True) != path
            or not path.is_relative_to(root)):
        raise RuntimeError('Require an unaliased regular NULL-target code/evidence file')
    return path


def _pins():
    if (any(type(value) is not str or re.fullmatch('[0-9a-f]{64}', value) is None
            for value in (CORE_SHA256, BUILD_RECORD_SHA256, TBB_SHA256))
            or type(HEADER_TEST_COUNT) is not int or HEADER_TEST_COUNT <= 0):
        raise RuntimeError('The completed NULL-target build has not been admitted')


def validate_evidence(root):
    _pins()
    raw = allowed_input(root, BUILD_RECORD).read_bytes()
    if hashlib.sha256(raw).hexdigest() != BUILD_RECORD_SHA256:
        raise RuntimeError('The NULL-target build report changed')
    build = json.loads(raw)
    for key, name in (('artifact', SOURCE), ('tbb_artifact', TBB),
                      ('base_v9_build_record', previous_version.BUILD_RECORD), ('original_component', ORIGINAL)):
        _identity_shape(build.get(key), name)
    for key, expected in (('base_v9_overlay', BASE_OVERLAY), ('source_evidence', EXPECTED_SOURCES),
                          ('generated_overlay', EXPECTED_OVERLAY)):
        _group(build.get(key), expected)
    settings, tests = build.get('build', {}), build.get('native_and_overlay_tests', {})
    for key, name in BUILD_FILES.items():
        _identity_shape(settings.get(key), name)
    _identity_shape(tests.get('log'), HEADER_LOG)
    preserved = build.get('preserved_original_and_v9_input_sha256')
    if (not isinstance(preserved, dict) or set(preserved) != PRESERVED_INPUTS
            or any(type(value) is not str or re.fullmatch('[0-9a-f]{64}', value) is None for value in preserved.values())):
        raise RuntimeError('Unexpected preserved v9 scope')
    identities = [build['artifact'], build['tbb_artifact'], build['base_v9_build_record'], build['original_component'],
        *build['base_v9_overlay'], *build['source_evidence'], *build['generated_overlay'],
        *(settings[key] for key in BUILD_FILES), tests['log']]
    paths = {name: allowed_input(root, name) for name in set(preserved) | {item['path'] for item in identities}}
    base_hashes = {PurePosixPath(item['path']).name: item['sha256'] for item in build['base_v9_overlay']}
    scope = build.get('scope_proof', {})
    if (build.get('source_revision') != REVISION or build.get('compiled') is not True
            or build['artifact']['sha256'] != CORE_SHA256 or build['tbb_artifact']['sha256'] != TBB_SHA256
            or build['base_v9_build_record']['sha256'] != previous_version.BUILD_RECORD_SHA256
            or build['original_component']['sha256'] != preserved[ORIGINAL]
            or any(scope.get(key) is not True for key in SCOPE_TRUE)
            or any(scope.get(key) is not False for key in SCOPE_FALSE)
            or scope.get('stripped_component_sha256') != preserved[ORIGINAL]
            or scope.get('stripped_cmake_sha256') != base_hashes['CMakeLists.txt']):
        raise RuntimeError('Require the exact optional-hook ownership-only scope')
    if (settings.get('directory') != 'build/windows-core-null-target-fix'
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
        raise RuntimeError('Require the separate native build/checks without runtime claims')
    references = list(previous_version.validate_evidence(root)) + [{'path': BUILD_RECORD, 'sha256': BUILD_RECORD_SHA256}]
    for item in identities:
        path = paths[item['path']]
        if sha(path) != item['sha256'] or path.stat().st_size != item['bytes']:
            raise RuntimeError('A bound NULL-target build input changed')
        references.append({'path': item['path'], 'sha256': item['sha256']})
    for name, digest in preserved.items():
        if sha(paths[name]) != digest:
            raise RuntimeError('A preserved v9 input changed')
        references.append({'path': name, 'sha256': digest})
    for name, digest in base_hashes.items():
        if name != 'CMakeLists.txt' and sha(paths['build/windows-core-null-target-fix/overlay/' + name]) != digest:
            raise RuntimeError('An existing v9 diagnostic source/header changed')
    output = paths[HEADER_LOG].read_text()
    if (f'Ran {HEADER_TEST_COUNT} tests' not in output or re.search(r'(?m)^OK\s*$', output) is None or 'FAILED' in output):
        raise RuntimeError('The actual NULL-target native test log must pass')
    return references


def validate_version(record):
    _pins()
    for key, expected in (('null_target_previous_manifest', PREVIOUS_MANIFEST),
                          ('null_target_update_transaction', TRANSACTION)):
        if record.get(key) != expected or sha(allowed_input(ROOT, expected)) != record.get(key + '_sha256'):
            raise RuntimeError('Unexpected or changed NULL-target evidence reference')
    previous = json.loads(allowed_input(ROOT, PREVIOUS_MANIFEST).read_text())
    if type(previous.get('developer_code_version')) is not int or previous['developer_code_version'] != 9:
        raise RuntimeError('The NULL-target fix requires exact previous v9 metadata')
    previous_version.validate_version(previous)
    additions = {'null_target_previous_manifest', 'null_target_previous_manifest_sha256',
                 'null_target_update_transaction', 'null_target_update_transaction_sha256'}
    if (set(record) != set(previous) | additions or type(record.get('developer_code_version')) is not int
            or record['developer_code_version'] != VERSION):
        raise RuntimeError('Unexpected v10 fields or developer role')
    for key, value in previous.items():
        if key not in ('at', 'developer_code_version', 'files') and not previous_version._same(record.get(key), value):
            raise RuntimeError('v10 must preserve existing v9 metadata: ' + key)
    old, new = previous.get('files'), record.get('files')
    if (not isinstance(old, list) or not isinstance(new, list) or len(old) != len(new)
            or any(not isinstance(item, dict) or type(item.get('name')) is not str for item in old + new)
            or len({item['name'] for item in old}) != len(old)
            or sum(item['name'] == 'CoreRT.dll' for item in old) != 1):
        raise RuntimeError('Unexpected v9/v10 code inventory')
    for before, after in zip(old, new):
        expected = dict(before, sha256=CORE_SHA256, bytes=allowed_input(ROOT, SOURCE).stat().st_size, origin=ORIGIN) \
            if before['name'] == 'CoreRT.dll' else before
        if (not previous_version._same(after, expected)
                or before['name'] == 'CoreRT.dll' and before.get('sha256') != PREVIOUS_CORE_SHA256):
            raise RuntimeError('v10 may update only its own CoreRT code input')
    transaction = json.loads(allowed_input(ROOT, TRANSACTION).read_text())
    expected = {'source_revision': REVISION, 'developer_code_version': VERSION,
        'null_target_previous_manifest': PREVIOUS_MANIFEST,
        'null_target_previous_manifest_sha256': record['null_target_previous_manifest_sha256'],
        'previous_sha256': PREVIOUS_CORE_SHA256, 'new_sha256': CORE_SHA256,
        'target': 'build/windows-source-integration/CoreRT.dll', 'source': SOURCE, 'previous_code_backup': BACKUP,
        'only_own_core_file_updated': True, 'main_citigame_and_original_modules_unchanged': True,
        'original_conditions_returns_mapping_authentication_and_security_decisions_preserved': True,
        'v10_wine_runtime_fixture_claim': False, 'profiles_sessions_tickets_read_copied_or_reset': False}
    if (set(transaction) != set(expected) | {'at', 'header_checks', 'diagnostic_evidence'}
            or any(type(transaction.get(key)) is not type(value) or transaction.get(key) != value for key, value in expected.items())
            or not previous_version._same(transaction.get('header_checks'), {'exit': 0, 'passed': HEADER_TEST_COUNT})
            or sha(allowed_input(ROOT, BACKUP)) != PREVIOUS_CORE_SHA256
            or transaction.get('diagnostic_evidence') != validate_evidence(ROOT)):
        raise RuntimeError('Unexpected NULL-target Core-only transaction or evidence')
