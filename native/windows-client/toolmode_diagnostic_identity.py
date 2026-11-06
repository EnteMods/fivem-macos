"""Fixed v8 public ToolMode diagnostics; v7 mapping evidence remains historical."""
import json
from pathlib import PurePosixPath
import re
import stat

import file_policy_diagnostic_identity as previous_version
from hook_diagnostic_identity import _group, _identity_shape
from run_main import ROOT, REVISION, plain, sha

CORE_SHA256 = '0dd03dfff845d3a154f2e3c1a0d90374b57fb5a25e0bdc2d489d96920d847650'
PREVIOUS_CORE_SHA256 = previous_version.CORE_SHA256
TBB_SHA256 = '2231daa77496b6676e33fd01269b2154ab904e692de5b525b04e551c69170e0e'
SOURCE = 'build/windows-core-toolmode-diagnostic/CoreRT.dll'
TBB = 'build/windows-core-toolmode-diagnostic/clang_23.1_cxx17_64_md_relwithdebinfo/tbb12.dll'
PREVIOUS_MANIFEST = previous_version.MANIFEST
MANIFEST = 'research/client-source-code-inputs-v8.json'
TRANSACTION = 'research/client-source-toolmode-diagnostic-update-v8.json'
BACKUP = 'build/checkpoints/source-code-updates/toolmode-v8/CoreRT.dll.previous'
BUILD_RECORD = 'research/core-toolmode-diagnostic-build.json'
ORIGINAL = 'port/fivem/code/client/citicore/ToolMode.Win32.cpp'
ORIGINAL_SHA256 = 'dfe069826208b2f4ce70a66e93b570de4b718125f990cca37efd8c22b86de15d'
ORIGIN = 'public-source-Core-v8-fixed-field-toolmode-diagnostics'
HEADER_TEST_COUNT = 8
HEADER_LOG = 'build/windows-core-toolmode-diagnostic/header-tests.log'
EXPECTED_SOURCES = {'native/windows-core-toolmode-diagnostic/' + name for name in
                    ('build.py', 'ToolModeDiagnostics.h', 'test_toolmode_diagnostics.py')}
OVERLAY_DIGESTS = {
    'CMakeLists.txt': 'd7cb88f70a2afb0fab2293e5c62a4af969f0179df2ebc1b99b02157070b5c010',
    'ToolMode.Win32.cpp': 'f468552c49618b6f0c01c103e0c21b40f058fa50b0d225ed71128aa374ae8e82',
    'ToolModeDiagnostics.h': '400a9cd2b87b047018935639defc0ca19f3f9281a5d72ebac0a36f2f8e12ca30',
    'FileMapping.Win32.cpp': '06c62a368aabf0abf3e249f98272b1bb2466fe63dc92b927c49497f97566f156',
    'HookDiagnostics.h': 'ab71b69fa81864d10ad12d08f3fd82b2251e29684e5cac81f5c9a1060140b59d',
    'FilePolicyDiagnostics.h': 'dbd834cd1d94e89886d898c51e3d4946f18c6c071b315cf01e12dcf60d234feb',
}
EXPECTED_OVERLAY = {'build/windows-core-toolmode-diagnostic/overlay/' + name for name in OVERLAY_DIGESTS}
BUILD_FILES = {'toolchain': 'native/windows-core/toolchain.cmake', **{
    key: 'build/windows-core-toolmode-diagnostic/' + name for key, name in (
        ('log', 'build.log'), ('compile_commands', 'compile_commands.json'), ('source_scope', 'source-scope.txt'))}}
PRESERVED_INPUTS = {previous_version.BUILD_RECORD, previous_version.SOURCE, previous_version.TBB, ORIGINAL} \
                   | previous_version.EXPECTED_SOURCES | previous_version.EXPECTED_OVERLAY
ALLOWED_INPUTS = set(previous_version.ALLOWED_INPUTS) | PRESERVED_INPUTS | EXPECTED_SOURCES | EXPECTED_OVERLAY \
                 | set(BUILD_FILES.values()) | {SOURCE, TBB, BUILD_RECORD, HEADER_LOG, PREVIOUS_MANIFEST,
                                               TRANSACTION, BACKUP}
PHASES = (
    'enter', 'loader.before', 'loader.after', 'instances.before', 'instance.before', 'instance.result',
    'instances.after', 'discovery.before', 'discovery.after', 'global-parser.before', 'global-parser.after',
    'command.missing', 'command.matched', 'dependencies.before', 'dependencies.result', 'tool-cast.before',
    'tool-cast.after', 'command.before', 'command.after', 'command-parser.before', 'command-parser.after',
    'invoke.before', 'invoke.after', 'command.unknown', 'exception.required-option', 'exception.options-error', 'return')


def allowed_input(root, name):
    if type(name) is not str or name not in ALLOWED_INPUTS:
        raise RuntimeError('Refusing an undeclared ToolMode diagnostic input')
    relative = PurePosixPath(name)
    if relative.is_absolute() or str(relative) != name or any(part in ('.', '..') for part in relative.parts):
        raise RuntimeError('ToolMode input must be canonical and project-relative')
    path = root / relative
    plain(path)
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or path.resolve(strict=True) != path
            or not path.is_relative_to(root)):
        raise RuntimeError('Require a local regular unaliased ToolMode code/evidence input')
    return path


def validate_evidence(root):
    # These remain evidence for their original v5/v6/v7 binaries, never a v8 Wine claim.
    references = list(previous_version.validate_evidence(root))

    def bind(name):
        path = allowed_input(root, name)
        references.append({'path': name, 'sha256': sha(path)})
        return path

    build = json.loads(bind(BUILD_RECORD).read_text())
    _identity_shape(build.get('artifact'), SOURCE)
    _identity_shape(build.get('tbb_artifact'), TBB)
    _identity_shape(build.get('base_v7_build_record'), previous_version.BUILD_RECORD)
    _identity_shape(build.get('original_toolmode'), ORIGINAL)
    _group(build.get('base_v7_overlay'), previous_version.EXPECTED_OVERLAY)
    _group(build.get('source_evidence'), EXPECTED_SOURCES)
    _group(build.get('generated_overlay'), EXPECTED_OVERLAY)
    for key, name in BUILD_FILES.items():
        _identity_shape(build.get('build', {}).get(key), name)
    _identity_shape(build.get('header_and_overlay_tests', {}).get('log'), HEADER_LOG)
    preserved = build.get('preserved_original_and_v7_input_sha256')
    if (not isinstance(preserved, dict) or set(preserved) != PRESERVED_INPUTS
            or any(type(value) is not str or re.fullmatch('[0-9a-f]{64}', value) is None
                   for value in preserved.values())):
        raise RuntimeError('Unexpected preserved original/v7 path set')
    if (build.get('source_revision') != REVISION or build.get('compiled') is not True
            or build['artifact']['sha256'] != CORE_SHA256 or build['tbb_artifact']['sha256'] != TBB_SHA256
            or build['original_toolmode']['sha256'] != ORIGINAL_SHA256):
        raise RuntimeError('Require the exact separate compiled ToolMode Core and original source')
    scope = build.get('scope_proof', {})
    if (any(scope.get(key) is not True for key in (
            'stripped_toolmode_equals_exact_original_bytes', 'stripped_cmake_equals_exact_v7_bytes',
            'v7_mapping_and_headers_byte_identical', 'original_expressions_evaluated_once',
            'original_boolean_results_preserved', 'dependency_initialization_result_still_ignored'))
            or any(scope.get(key) is not False for key in (
                'original_toolmode_controlflow_catches_callbacks_and_arguments_changed',
                'private_mtl_invoke_implementation_changed', 'auth_anticheat_integrity_or_filename_policy_changed'))
            or scope.get('stripped_toolmode_sha256') != ORIGINAL_SHA256
            or scope.get('stripped_cmake_sha256') != 'beb5907b6eea81f75c5435569a9edff74f820434a263ad97749f0ab12f759ca9'):
        raise RuntimeError('Require reversible ToolMode scope and unchanged original behavior')
    expected_payload = {'fixed_prefix': 'CFX_TOOLMODE', 'fields': ['pid', 'phase', 'value'],
        'value_range': [0, 1], 'phase_vocabulary': list(PHASES),
        'paths_pointers_commands_arguments_components_exceptions_auth_or_profile_values_logged': False,
        'last_error_after_original_expression_preserved': True, 'default': 'OFF'}
    if build.get('payload') != expected_payload:
        raise RuntimeError('Unexpected ToolMode diagnostic payload contract')
    settings = build.get('build', {})
    if (settings.get('directory') != 'build/windows-core-toolmode-diagnostic'
            or settings.get('exit') != 0 or settings.get('CFX_SOURCE_DIR') != 'port/fivem'
            or settings.get('CFX_CORE_MAPPING_DIAGNOSTICS') != 'ON'
            or settings.get('CFX_CORE_TOOLMODE_DIAGNOSTICS') != 'ON'
            or settings.get('CFX_CORE_ACCOUNT_FREE_TESTS') != 'OFF' or settings.get('runtime') != '/MD'
            or settings.get('target') != 'AMD64 Windows CoreRT'
            or any(build.get(key) is not False for key in (
                'wine_client_or_game_started', 'stage_or_prefix_accessed', 'existing_patch_queue_changed', 'runtime_tested'))):
        raise RuntimeError('Require separate /MD opt-in compilation with no runtime or stage action')
    tests = build.get('header_and_overlay_tests', {})
    if (type(tests.get('exit')) is not int or tests['exit'] != 0
            or type(tests.get('passed')) is not int or tests['passed'] != HEADER_TEST_COUNT):
        raise RuntimeError('Require all native header/wrapper/scope checks')
    identities = [build['artifact'], build['tbb_artifact'], build['base_v7_build_record'],
                  build['original_toolmode'], *build['base_v7_overlay'], *build['source_evidence'],
                  *build['generated_overlay'], *(settings[key] for key in BUILD_FILES), tests['log']]
    for item in identities:
        path = bind(item['path'])
        if sha(path) != item['sha256'] or path.stat().st_size != item['bytes']:
            raise RuntimeError('A bound ToolMode code/build/test input changed')
    for name, digest in preserved.items():
        if sha(bind(name)) != digest:
            raise RuntimeError('A preserved original/v7 input changed')
    for name, digest in OVERLAY_DIGESTS.items():
        if sha(allowed_input(root, 'build/windows-core-toolmode-diagnostic/overlay/' + name)) != digest:
            raise RuntimeError('Unexpected ToolMode overlay bytes')
    if sha(allowed_input(root, ORIGINAL)) != ORIGINAL_SHA256:
        raise RuntimeError('The public original ToolMode source changed')
    test_output = allowed_input(root, HEADER_LOG).read_text()
    if (f'Ran {HEADER_TEST_COUNT} tests' not in test_output
            or re.search(r'(?m)^OK\s*$', test_output) is None or 'FAILED' in test_output):
        raise RuntimeError('The bound native test output must actually pass')
    return references


def validate_version(record):
    for key, expected in (('toolmode_previous_manifest', PREVIOUS_MANIFEST),
                          ('toolmode_update_transaction', TRANSACTION)):
        if record.get(key) != expected:
            raise RuntimeError('Unexpected v8 ToolMode evidence reference')
        if sha(allowed_input(ROOT, expected)) != record.get(key + '_sha256'):
            raise RuntimeError('Bound v8 ToolMode evidence changed')
    previous = json.loads(allowed_input(ROOT, PREVIOUS_MANIFEST).read_text())
    transaction = json.loads(allowed_input(ROOT, TRANSACTION).read_text())
    if previous.get('developer_code_version') != 7:
        raise RuntimeError('ToolMode diagnostics require exact previous v7 metadata')
    previous_version.validate_version(previous)
    additions = {'toolmode_previous_manifest', 'toolmode_previous_manifest_sha256',
                 'toolmode_update_transaction', 'toolmode_update_transaction_sha256'}
    if set(record) != set(previous) | additions:
        raise RuntimeError('Unexpected v8 role or metadata fields')
    for key, value in previous.items():
        if key not in ('at', 'developer_code_version', 'files') and record.get(key) != value:
            raise RuntimeError('v8 must preserve existing v7 role and provenance: ' + key)
    old, new = previous.get('files'), record.get('files')
    if (not isinstance(old, list) or not isinstance(new, list) or len(old) != len(new)
            or any(not isinstance(item, dict) or type(item.get('name')) is not str for item in old + new)
            or len({item['name'] for item in old}) != len(old)
            or sum(item['name'] == 'CoreRT.dll' for item in old) != 1):
        raise RuntimeError('Unexpected v7/v8 code inventory')
    for before, after in zip(old, new):
        if before['name'] != 'CoreRT.dll':
            if before != after:
                raise RuntimeError('v8 may update only its own CoreRT code input')
        elif (before.get('sha256') != PREVIOUS_CORE_SHA256 or after != dict(
                before, sha256=CORE_SHA256, bytes=allowed_input(ROOT, SOURCE).stat().st_size, origin=ORIGIN)):
            raise RuntimeError('Unexpected v8 own-Core delta')
    if (record.get('developer_code_version') != 8 or transaction.get('developer_code_version') != 8
            or transaction.get('source_revision') != REVISION
            or transaction.get('toolmode_previous_manifest') != PREVIOUS_MANIFEST
            or transaction.get('toolmode_previous_manifest_sha256') != record['toolmode_previous_manifest_sha256']
            or transaction.get('previous_sha256') != PREVIOUS_CORE_SHA256 or transaction.get('new_sha256') != CORE_SHA256
            or transaction.get('target') != 'build/windows-source-integration/CoreRT.dll'
            or transaction.get('source') != SOURCE or transaction.get('previous_code_backup') != BACKUP
            or transaction.get('header_checks', {}).get('exit') != 0
            or transaction.get('header_checks', {}).get('passed') != HEADER_TEST_COUNT
            or transaction.get('only_own_core_file_updated') is not True
            or transaction.get('main_citigame_and_original_modules_unchanged') is not True
            or transaction.get('original_conditions_returns_mapping_authentication_and_security_decisions_preserved') is not True
            or transaction.get('v8_wine_runtime_fixture_claim') is not False
            or transaction.get('profiles_sessions_tickets_read_copied_or_reset') is not False):
        raise RuntimeError('Unexpected ToolMode-only Core transaction')
    if sha(allowed_input(ROOT, BACKUP)) != PREVIOUS_CORE_SHA256:
        raise RuntimeError('Previous v7 own Core backup changed')
    if transaction.get('diagnostic_evidence') != validate_evidence(ROOT):
        raise RuntimeError('Exact ToolMode diagnostic evidence changed')
