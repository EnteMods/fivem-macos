"""V12 graphics-only admission with immutable build-context snapshots."""
import hashlib
import json
import re

import graphics_diagnostic_identity as previous_version
from hook_diagnostic_identity import _group, _identity_shape
from lifecycle_diagnostic_identity import _same
from run_main import ROOT, REVISION, sha

VERSION = 12
GRAPHICS_SHA256 = 'a68f20b246393a24db05c727e6479c4cbfe3110c649df57d55871dc74f033cdf'
BUILD_RECORD_SHA256 = '83da0a6ae0e4576c85e7d1d6985eeb2de5b791e891b5b0d05cd9adeae5e6b0a6'
PREVIOUS_GRAPHICS_SHA256 = '2b405d25839176b8e8898344c9ea5e493887adef0fa78cf98d510cfe1ad1f7e7'
SOURCE = 'build/windows-graphics-window-diagnostics/rage-graphics-five.dll'
BUILD_RECORD = 'research/graphics-window-diagnostics-build.json'
PREVIOUS_MANIFEST = previous_version.MANIFEST
MANIFEST = 'research/client-source-code-inputs-v12.json'
TRANSACTION = 'research/client-source-graphics-window-update-v12.json'
BACKUP = 'build/checkpoints/source-code-updates/graphics-window-v12/rage-graphics-five.dll.previous'
ORIGIN = 'public-source-graphics-v12-fixed-window-creation-and-availability-diagnostics'
BUILD = 'build/windows-graphics-window-diagnostics'
BASELINE_REPORT = previous_version.BUILD_RECORD
BASELINE_REPORT_SHA256 = 'a9705c9d54bcc886adae294f681c6144a8ff2b826c31fa9cd9072a99f34f0995'
BASELINE_REPORT_BYTES = 37218
BASELINE_CODE_COUNT = 194
HEADER_TEST_COUNT = 3
HEADER_LOG = BUILD + '/overlay-tests.log'
EXPECTED_SOURCES = {'native/windows-graphics-window-diagnostics/' + name for name in
                    ('build.py', 'GraphicsWindowDiagnostics.h', 'overlay.py', 'test_overlay.py')}
EXPECTED_OVERLAY = {BUILD + '/overlay/' + name for name in
                    ('RenderHooks.cpp', 'GraphicsWindowDiagnostics.h', 'GraphicsSwapChainDiagnostics.h')}
CONTEXT_NAMES = ('file_policy_diagnostic_identity.py', 'graphics_diagnostic_identity.py',
    'hook_diagnostic_identity.py', 'lifecycle_diagnostic_identity.py', 'null_target_fix_identity.py',
    'run_main.py', 'source_code_identity.py', 'toolmode_diagnostic_identity.py')
CONTEXT_ROLES = {'native/windows-client/' + name for name in CONTEXT_NAMES}
EXPECTED_SNAPSHOTS = {BUILD + '/inputs/' + name for name in CONTEXT_NAMES}
BUILD_FILES = {'log': BUILD + '/build.log', 'compile_commands': BUILD + '/compile_commands.json'}
INPUT_RENDER_SHA256 = '39ab3f4966e9434894c004977914a39869782891b5d5ebd55c13f1be7d2d874e'
PATCHED_RENDER_SHA256 = 'f5e1f2dbf02c7b910392f291e7249dc494b07c6e96a512107966e4687a1e9977'
SCOPE_TRUE = ('stripped_equals_exact_v11_bytes', 'original_window_calls_arguments_and_returns_preserved',
    'last_error_captured_immediately_after_both_original_window_calls',
    'style_and_parent_metadata_match_actual_original_call_branch', 'original_swapchain_request_presence_logged',
    'window_result_logging_only_in_existing_grcWindow_branch', 'original_sc_call_and_diagnostics_preserved',
    'original_hresult_and_error_path_unchanged', 'class_query_only_after_own_process_check')
SCOPE_FALSE = ('core_get_game_window_find_window_or_fallback_selection_added',
    'raw_handles_titles_class_strings_or_candidate_pids_logged', 'default_logging_enabled')


def _pins():
    if any(type(value) is not str or re.fullmatch('[0-9a-f]{64}', value) is None
           for value in (GRAPHICS_SHA256, BUILD_RECORD_SHA256)):
        raise RuntimeError('The completed graphics-window diagnostic build has not been admitted')


def validated_previous_graphics_backup(root):
    path = root / BACKUP
    previous_version.plain(path)
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    path = previous_version._path(root, BACKUP, {BACKUP})
    target = previous_version._path(root, previous_version.HISTORICAL_GRAPHICS,
                                    {previous_version.HISTORICAL_GRAPHICS})
    before, current = path.lstat(), target.lstat()
    if ((before.st_dev, before.st_ino) == (current.st_dev, current.st_ino)
            or sha(path) != PREVIOUS_GRAPHICS_SHA256):
        raise RuntimeError('The preserved V11 graphics backup differs or aliases the stage file')
    return path


def _context_snapshots(value):
    if (type(value) is not dict or set(value) != {'original_live_requirement_after_build',
            'source_context_unchanged_during_build', 'execution_from_preverified_captured_bytes', 'snapshots'}
            or value['original_live_requirement_after_build'] is not False
            or value['source_context_unchanged_during_build'] is not True
            or value['execution_from_preverified_captured_bytes'] is not True):
        raise RuntimeError('Require immutable captured build-context provenance')
    rows = value['snapshots']
    if (type(rows) is not list or len(rows) != 8 or any(type(item) is not dict for item in rows)
            or any(set(item) != {'original_role', 'original_bytes', 'original_sha256', 'snapshot'} for item in rows)
            or any(type(item['original_role']) is not str for item in rows)
            or {item['original_role'] for item in rows} != CONTEXT_ROLES):
        raise RuntimeError('Unexpected graphics-window build-context roles')
    snapshots = []
    for item in rows:
        name = item['original_role'].rsplit('/', 1)[1]
        _identity_shape(item['snapshot'], BUILD + '/inputs/' + name)
        if (type(item['original_bytes']) is not int or item['original_bytes'] <= 0
                or type(item['original_sha256']) is not str
                or re.fullmatch('[0-9a-f]{64}', item['original_sha256']) is None
                or item['snapshot']['bytes'] != item['original_bytes']
                or item['snapshot']['sha256'] != item['original_sha256']):
            raise RuntimeError('A build-context snapshot differs from its historical captured identity')
        snapshots.append(item['snapshot'])
    return snapshots


def validate_evidence(root):
    _pins()
    raw = previous_version._path(root, BUILD_RECORD, {BUILD_RECORD}).read_bytes()
    if hashlib.sha256(raw).hexdigest() != BUILD_RECORD_SHA256:
        raise RuntimeError('The graphics-window build report changed')
    build = json.loads(raw)
    _identity_shape(build.get('baseline_build_record'), BASELINE_REPORT)
    if (build['baseline_build_record']['bytes'], build['baseline_build_record']['sha256']) != (BASELINE_REPORT_BYTES, BASELINE_REPORT_SHA256):
        raise RuntimeError('Unexpected V11 graphics baseline report')
    _identity_shape(build.get('baseline_artifact'), previous_version.SOURCE)
    for key, name in (('baseline_recipe_source', 'native/windows-graphics-diagnostics/build.py'),
                      ('source_recipe_source', 'native/windows-graphics-source/build.py')):
        _identity_shape(build.get(key), name)
    _identity_shape(build.get('artifact'), SOURCE)
    _group(build.get('source_evidence'), EXPECTED_SOURCES)
    _group(build.get('generated_overlay'), EXPECTED_OVERLAY)
    snapshots = _context_snapshots(build.get('support_context_before_after'))
    objects, resource = previous_version._object_paths(root, BUILD)
    base = BUILD + '/CMakeFiles/rage_graphics.dir/' + root.as_posix().lstrip('/') + '/port/fivem/code/'
    objects.remove(base + 'components/rage-graphics-five/src/RenderHooks.cpp.obj')
    objects.add(BUILD + '/CMakeFiles/rage_graphics.dir/overlay/RenderHooks.cpp.obj')
    _group(build.get('objects'), objects)
    for key, name in (('resource_object', resource), ('cmake_manifest_resource', BUILD + '/CMakeFiles/rage_graphics.dir/manifest.res'),
                      ('generated_build_configuration', BUILD + '/CMakeLists.txt'),
                      ('object_directives', BUILD + '/object-directives.txt'), ('pe_inspection', BUILD + '/pe-inspection.txt')):
        _identity_shape(build.get(key), name)
    settings, tests = build.get('build', {}), build.get('overlay_tests', {})
    for key, name in BUILD_FILES.items():
        _identity_shape(settings.get(key), name)
    _identity_shape(tests.get('log'), HEADER_LOG)
    # These older validated references are code roles, never the eight mutable source-context roles.
    previous_refs = previous_version.validate_evidence(root)
    previous_hashes = {}
    for item in previous_refs:
        name, digest = item['path'], item['sha256']
        if name in previous_hashes and previous_hashes[name] != digest:
            raise RuntimeError('Conflicting previous graphics evidence identities')
        previous_hashes[name] = digest
    if len(previous_hashes) != BASELINE_CODE_COUNT or CONTEXT_ROLES.intersection(previous_hashes):
        raise RuntimeError('Unexpected stable V11 code/evidence scope')
    _group(build.get('baseline_evidence'), set(previous_hashes))
    previous_paths = {name: previous_version._path(root, name, set(previous_hashes)) for name in previous_hashes}
    expected_baseline = {name: {'path': name, 'bytes': path.stat().st_size, 'sha256': previous_hashes[name]}
                         for name, path in previous_paths.items()}
    if not _same({item['path']: item for item in build['baseline_evidence']}, expected_baseline):
        raise RuntimeError('Require the complete unchanged V11 evidence identities')
    if (type(build.get('baseline_evidence_reference_count')) is not int
            or build['baseline_evidence_reference_count'] != len(previous_refs)
            or any(build[key] != expected_baseline.get(build[key]['path'])
                   for key in ('baseline_artifact', 'baseline_recipe_source', 'source_recipe_source'))):
        raise RuntimeError('Unexpected preserved V11 artifact, recipes or raw reference count')
    identities = [*build['baseline_evidence'], build['baseline_build_record'], build['baseline_artifact'], build['artifact'],
        build['baseline_recipe_source'], build['source_recipe_source'],
        *build['source_evidence'], *build['generated_overlay'], *snapshots, *build['objects'],
        build['resource_object'], build['cmake_manifest_resource'], build['generated_build_configuration'],
        build['object_directives'], build['pe_inspection'], *(settings[key] for key in BUILD_FILES), tests['log']]
    paths = {item['path']: previous_version._path(root, item['path'], {row['path'] for row in identities}) for item in identities}
    scope = build.get('scope_proof', {})
    window = scope.get('render_overlay', {})
    if (build.get('compiled') is not True or build.get('source_revision') != REVISION
            or build['artifact']['sha256'] != GRAPHICS_SHA256
            or build['baseline_artifact']['sha256'] != PREVIOUS_GRAPHICS_SHA256
            or any(window.get(key) is not True for key in SCOPE_TRUE)
            or any(window.get(key) is not False for key in SCOPE_FALSE)
            or window.get('input_sha256') != INPUT_RENDER_SHA256
            or window.get('patched_sha256') != PATCHED_RENDER_SHA256
            or type(window.get('replacement_count')) is not int or window['replacement_count'] != 6
            or not _same(window.get('modified_regions'), ['header_include', 'HookCreateWindowExW', 'swapchain_checkpoint'])
            or scope.get('cmake_reversed_equals_baseline') is not True
            or scope.get('no_new_translation_units') is not True
            or type(scope.get('replacement_tu_count')) is not int or scope['replacement_tu_count'] != 1
            or scope.get('definition') != 'CFX_GRAPHICS_WINDOW_DIAGNOSTICS=1'
            or scope.get('preserved_definition') != 'CFX_GRAPHICS_SWAPCHAIN_DIAGNOSTICS=1'
            or scope.get('previous_swapchain_header_preserved') is not True
            or scope.get('hresult_fix_applied') is not False
            or any(build.get(key) is not True for key in ('exports_match_baseline', 'original_export_coverage_complete', 'baseline_preserved'))
            or any(build.get(key) is not False for key in ('hresult_fix_applied', 'stage_or_prefix_modified',
                'runtime_started', 'deployment_or_runtime_compatibility_claimed'))
            or type(build.get('md_verified_object_count')) is not int or build['md_verified_object_count'] != 13
            or type(settings.get('exit')) is not int or settings['exit'] != 0
            or type(tests.get('exit')) is not int or tests['exit'] != 0
            or type(tests.get('passed')) is not int or tests['passed'] != HEADER_TEST_COUNT):
        raise RuntimeError('Require the completed window-metadata-only graphics build')
    for name in ('GraphicsWindowDiagnostics.h', 'GraphicsSwapChainDiagnostics.h'):
        items = [item for item in identities if item['path'] in (BUILD + '/overlay/' + name,
                  'native/windows-graphics-window-diagnostics/' + name,
                  previous_version.BUILD + '/overlay/' + name)]
        if len(items) < 2 or len({(item['bytes'], item['sha256']) for item in items}) != 1:
            raise RuntimeError('A generated graphics diagnostic header differs from its admitted source')
    references = []
    for item in identities:
        path = paths[item['path']]
        if sha(path) != item['sha256'] or path.stat().st_size != item['bytes']:
            raise RuntimeError('A bound graphics-window code/build input changed')
        references.append({'path': item['path'], 'sha256': item['sha256']})
    if sha(paths[BUILD + '/overlay/RenderHooks.cpp']) != PATCHED_RENDER_SHA256:
        raise RuntimeError('Unexpected generated window diagnostic overlay')
    output = paths[HEADER_LOG].read_text()
    if f'Ran {HEADER_TEST_COUNT} tests' not in output or re.search(r'(?m)^OK\s*$', output) is None or 'FAILED' in output:
        raise RuntimeError('Require the actual passing window native/overlay test log')
    return [{'path': BUILD_RECORD, 'sha256': BUILD_RECORD_SHA256}, *references]


def validate_version(record):
    _pins()
    roles = {PREVIOUS_MANIFEST, TRANSACTION, BACKUP, SOURCE}
    for key, expected in (('graphics_window_previous_manifest', PREVIOUS_MANIFEST),
                          ('graphics_window_update_transaction', TRANSACTION)):
        if record.get(key) != expected or sha(previous_version._path(ROOT, expected, roles)) != record.get(key + '_sha256'):
            raise RuntimeError('Unexpected or changed graphics-window evidence reference')
    previous = json.loads(previous_version._path(ROOT, PREVIOUS_MANIFEST, roles).read_bytes())
    if type(previous.get('developer_code_version')) is not int or previous['developer_code_version'] != 11:
        raise RuntimeError('Window diagnostics require exact previous V11 metadata')
    previous_version.validate_version(previous)
    additions = {'graphics_window_previous_manifest', 'graphics_window_previous_manifest_sha256',
                 'graphics_window_update_transaction', 'graphics_window_update_transaction_sha256'}
    if set(record) != set(previous) | additions or type(record.get('developer_code_version')) is not int or record['developer_code_version'] != VERSION:
        raise RuntimeError('Unexpected V12 metadata or developer role')
    for key, value in previous.items():
        if key not in ('at', 'developer_code_version', 'files') and not _same(record.get(key), value):
            raise RuntimeError('V12 must preserve previous V11 metadata: ' + key)
    old, new = previous.get('files'), record.get('files')
    if (not isinstance(old, list) or not isinstance(new, list) or len(old) != 474 or len(new) != 474
            or any(type(item) is not dict or type(item.get('name')) is not str for item in old + new)
            or len({item['name'] for item in old}) != 474
            or sum(item['name'] == 'rage-graphics-five.dll' for item in old) != 1):
        raise RuntimeError('Require the unchanged 474-entry graphics inventory')
    source = previous_version._path(ROOT, SOURCE, roles)
    for before, after in zip(old, new):
        expected = dict(before, sha256=GRAPHICS_SHA256, bytes=source.stat().st_size, origin=ORIGIN) \
            if before['name'] == 'rage-graphics-five.dll' else before
        if not _same(after, expected) or before['name'] == 'rage-graphics-five.dll' and before.get('sha256') != PREVIOUS_GRAPHICS_SHA256:
            raise RuntimeError('V12 may replace only its previous V11 graphics DLL')
    transaction = json.loads(previous_version._path(ROOT, TRANSACTION, roles).read_bytes())
    expected = {'source_revision': REVISION, 'developer_code_version': VERSION,
        'graphics_window_previous_manifest': PREVIOUS_MANIFEST,
        'graphics_window_previous_manifest_sha256': record['graphics_window_previous_manifest_sha256'],
        'previous_sha256': PREVIOUS_GRAPHICS_SHA256, 'new_sha256': GRAPHICS_SHA256,
        'target': 'build/windows-source-integration/rage-graphics-five.dll', 'source': SOURCE,
        'previous_code_backup': BACKUP, 'only_graphics_file_updated': True,
        'other_473_code_entries_and_core10_unchanged': True,
        'original_window_swapchain_returns_controlflow_and_caches_preserved': True,
        'v12_runtime_compatibility_claim': False, 'profiles_sessions_tickets_read_copied_or_reset': False}
    if (set(transaction) != set(expected) | {'at', 'header_checks', 'diagnostic_evidence'}
            or any(not _same(transaction.get(key), value) for key, value in expected.items())
            or not _same(transaction.get('header_checks'), {'exit': 0, 'passed': HEADER_TEST_COUNT})
            or sha(previous_version._path(ROOT, BACKUP, roles)) != PREVIOUS_GRAPHICS_SHA256
            or not _same(transaction.get('diagnostic_evidence'), validate_evidence(ROOT))):
        raise RuntimeError('Unexpected graphics-window transaction or build evidence')
