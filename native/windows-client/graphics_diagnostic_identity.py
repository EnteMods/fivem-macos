"""V11 graphics-only admission; the previous graphics DLL is unchanged vendor code."""
import hashlib
import json
from pathlib import PurePosixPath
import re
import stat

import null_target_fix_identity as previous_version
from lifecycle_diagnostic_identity import _same
from hook_diagnostic_identity import _group, _identity_shape
from run_main import ROOT, REVISION, plain, sha

VERSION = 11
GRAPHICS_SHA256 = '2b405d25839176b8e8898344c9ea5e493887adef0fa78cf98d510cfe1ad1f7e7'
BUILD_RECORD_SHA256 = 'a9705c9d54bcc886adae294f681c6144a8ff2b826c31fa9cd9072a99f34f0995'
PREVIOUS_GRAPHICS_SHA256 = 'edb22d90c4eea18c4ebbab31a0dfc89423ea43481ab25487dc7b11531debb58a'
SOURCE = 'build/windows-graphics-diagnostics/rage-graphics-five.dll'
BUILD_RECORD = 'research/graphics-swapchain-diagnostics-build.json'
PREVIOUS_MANIFEST = previous_version.MANIFEST
MANIFEST = 'research/client-source-code-inputs-v11.json'
TRANSACTION = 'research/client-source-graphics-diagnostic-update-v11.json'
BACKUP = 'build/checkpoints/source-code-updates/graphics-v11/rage-graphics-five.dll.previous'
HISTORICAL_GRAPHICS = 'build/windows-source-integration/rage-graphics-five.dll'
ORIGIN = 'public-source-graphics-v11-fixed-swapchain-argument-and-result-diagnostics'
BASELINE_REPORT = 'research/graphics-source-build-attempt3.json'
BASELINE_REPORT_BYTES = 48095
BASELINE_REPORT_SHA256 = 'f03428b5818cfe82cdd06ee802c9603f3e83fdafbc499add5f85a31c27b8c958'
BASELINE_ARTIFACT = 'build/windows-graphics-source-attempt3/rage-graphics-five.dll'
BASELINE_ARTIFACT_SHA256 = '54aaaa580701ed9d6d1943f71450b0493bee28db8de657beb14f91e5f06bacfe'
BASELINE_RECIPE = 'native/windows-graphics-source/build.py'
BASELINE_RECIPE_SHA256 = 'c3763de7580dbaa39126530a81300be3a27f1f81ae8944b87391679272b99065'
BUILD = 'build/windows-graphics-diagnostics'
ORIGINAL = 'port/fivem/code/components/rage-graphics-five/src/RenderHooks.cpp'
ORIGINAL_SHA256 = 'f2420634493bf813db3b810f5deac1594f94468c6c2b3384f740d6bd6014ae09'
PATCHED_SHA256 = '39ab3f4966e9434894c004977914a39869782891b5d5ebd55c13f1be7d2d874e'
EXPECTED_SOURCES = {'native/windows-graphics-diagnostics/' + name for name in
                    ('build.py', 'GraphicsSwapChainDiagnostics.h', 'overlay.py', 'test_overlay.py')}
EXPECTED_OVERLAY = {BUILD + '/overlay/' + name for name in
                    ('RenderHooks.cpp', 'GraphicsSwapChainDiagnostics.h')}
HEADER_TEST_COUNT = 3
HEADER_LOG = BUILD + '/overlay-tests.log'
BUILD_FILES = {'log': BUILD + '/build.log', 'compile_commands': BUILD + '/compile_commands.json'}
CPP_NAMES = ('AMDDriverFixups', 'Component', 'DrawCommands', 'GameViewCapture', 'GfxFixups',
             'ReShadeFixups', 'RenderHooks', 'StubD3D11Device', 'ZOffThreadWindowing', 'dxerr', 'grcTexture')
SCOPE_TRUE = ('stripped_equals_exact_original', 'factory_call_evaluated_once',
    'final_arguments_captured_once_and_forwarded', 'query_interface_after_call_byte_identical',
    'original_hresult_propagation_and_error_path_unchanged',
    'output_release_equivalent_to_original_com_ptr_address_operator')


def _pins():
    if any(type(value) is not str or re.fullmatch('[0-9a-f]{64}', value) is None
           for value in (GRAPHICS_SHA256, BUILD_RECORD_SHA256)):
        raise RuntimeError('The completed graphics diagnostic build has not been admitted')


def _path(root, name, allowed):
    if type(name) is not str or name not in allowed:
        raise RuntimeError('Refusing an undeclared graphics code/evidence input')
    relative = PurePosixPath(name)
    if relative.is_absolute() or str(relative) != name or any(part in ('.', '..') for part in relative.parts):
        raise RuntimeError('Graphics input must be canonical and project-relative')
    path = root / name
    plain(path)
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or path.resolve(strict=True) != path
            or not path.is_relative_to(root)):
        raise RuntimeError('Require an unaliased regular graphics code/evidence input')
    return path


def _fixed_record(root, name, length, digest):
    raw = _path(root, name, {name}).read_bytes()
    if (len(raw), hashlib.sha256(raw).hexdigest()) != (length, digest):
        raise RuntimeError('The fixed graphics baseline report changed')
    return json.loads(raw)


def validated_previous_graphics_backup(root):
    """Admit only this fixed, separate-inode copy of the original vendor DLL."""
    path = root / BACKUP
    plain(path)
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    path = _path(root, BACKUP, {BACKUP})
    target = _path(root, HISTORICAL_GRAPHICS, {HISTORICAL_GRAPHICS})
    before, current = path.lstat(), target.lstat()
    if ((before.st_dev, before.st_ino) == (current.st_dev, current.st_ino)
            or sha(path) != PREVIOUS_GRAPHICS_SHA256):
        raise RuntimeError('The preserved vendor graphics backup differs or aliases the stage file')
    return path


def _project_identities(value):
    found = []
    if isinstance(value, dict):
        if set(value) == {'path', 'bytes', 'sha256'}:
            if type(value['path']) is str and not PurePosixPath(value['path']).is_absolute():
                _identity_shape(value, value['path'])
                found.append(value)
        else:
            for child in value.values():
                found.extend(_project_identities(child))
    elif isinstance(value, list):
        for child in value:
            found.extend(_project_identities(child))
    return found


def _object_paths(root, build):
    base = build + '/CMakeFiles/rage_graphics.dir/' + root.as_posix().lstrip('/') + '/port/fivem/code/'
    objects = {base + 'components/rage-graphics-five/src/' + name + '.cpp.obj' for name in CPP_NAMES}
    objects |= {base + 'client/common/' + name + '.cpp.obj' for name in ('StdInc', 'Error')}
    if build == BUILD:
        objects.remove(base + 'components/rage-graphics-five/src/RenderHooks.cpp.obj')
        objects.add(build + '/CMakeFiles/rage_graphics.dir/overlay/RenderHooks.cpp.obj')
    return objects, base + 'components/rage-graphics-five/component.rc.res'


def validate_evidence(root):
    _pins()
    raw = _path(root, BUILD_RECORD, {BUILD_RECORD}).read_bytes()
    if hashlib.sha256(raw).hexdigest() != BUILD_RECORD_SHA256:
        raise RuntimeError('The graphics diagnostic build report changed')
    build = json.loads(raw)
    _identity_shape(build.get('baseline_build_record'), BASELINE_REPORT)
    if (build['baseline_build_record']['bytes'], build['baseline_build_record']['sha256']) != (BASELINE_REPORT_BYTES, BASELINE_REPORT_SHA256):
        raise RuntimeError('Unexpected graphics baseline report identity')
    baseline = _fixed_record(root, BASELINE_REPORT, BASELINE_REPORT_BYTES, BASELINE_REPORT_SHA256)
    baseline_inputs = _project_identities(baseline)
    _group(build.get('baseline_inputs'), {item['path'] for item in baseline_inputs})
    if (len(baseline_inputs) != 59 or len({item['path'] for item in baseline_inputs}) != 59
            or not _same({item['path']: item for item in build['baseline_inputs']},
                         {item['path']: item for item in baseline_inputs})):
        raise RuntimeError('Require all unchanged project inputs from the fixed public graphics baseline')
    _identity_shape(build.get('artifact'), SOURCE)
    for key, name in (('baseline_artifact', BASELINE_ARTIFACT), ('baseline_recipe_source', BASELINE_RECIPE),
                      ('generated_build_configuration', BUILD + '/CMakeLists.txt'),
                      ('object_directives', BUILD + '/object-directives.txt'),
                      ('pe_inspection', BUILD + '/pe-inspection.txt')):
        _identity_shape(build.get(key), name)
    _group(build.get('source_evidence'), EXPECTED_SOURCES)
    _group(build.get('generated_overlay'), EXPECTED_OVERLAY)
    objects, resource = _object_paths(root, BUILD)
    _group(build.get('objects'), objects)
    _identity_shape(build.get('resource_object'), resource)
    _identity_shape(build.get('cmake_manifest_resource'), BUILD + '/CMakeFiles/rage_graphics.dir/manifest.res')
    settings, tests = build.get('build', {}), build.get('overlay_tests', {})
    for key, name in BUILD_FILES.items():
        _identity_shape(settings.get(key), name)
    _identity_shape(tests.get('log'), HEADER_LOG)
    identities = [*baseline_inputs, build['artifact'], build['baseline_artifact'], build['baseline_recipe_source'],
        *build['source_evidence'], *build['generated_overlay'], *build['objects'], build['resource_object'],
        build['cmake_manifest_resource'], build['generated_build_configuration'], build['object_directives'],
        build['pe_inspection'], *(settings[key] for key in BUILD_FILES), tests['log']]
    allowed = {item['path'] for item in identities}
    # All data-provided roles above are matched to literals or the immutable baseline before selected reads.
    paths = {name: _path(root, name, allowed) for name in allowed}
    scope = build.get('scope_proof', {})
    overlay = scope.get('render_overlay', {})
    if (build.get('compiled') is not True or build.get('source_revision') != REVISION
            or build['artifact']['sha256'] != GRAPHICS_SHA256
            or build['baseline_artifact'] != baseline.get('artifact')
            or build['baseline_recipe_source'] != baseline.get('recipe_source')
            or build['baseline_artifact']['sha256'] != BASELINE_ARTIFACT_SHA256
            or build['baseline_recipe_source']['sha256'] != BASELINE_RECIPE_SHA256
            or any(overlay.get(key) is not True for key in SCOPE_TRUE)
            or overlay.get('original') != ORIGINAL or overlay.get('original_sha256') != ORIGINAL_SHA256
            or overlay.get('patched_sha256') != PATCHED_SHA256
            or type(overlay.get('replacement_count')) is not int or overlay['replacement_count'] != 2
            or type(overlay.get('original_factory_call_count')) is not int or overlay['original_factory_call_count'] != 1
            or overlay.get('default_logging_enabled') is not False
            or overlay.get('raw_pointers_titles_or_arguments_logged') is not False
            or scope.get('cmake_reversed_equals_baseline') is not True
            or type(scope.get('replacement_tu_count')) is not int or scope['replacement_tu_count'] != 1
            or scope.get('no_new_translation_units') is not True
            or scope.get('definition') != 'CFX_GRAPHICS_SWAPCHAIN_DIAGNOSTICS=1'
            or scope.get('hresult_fix_applied') is not False
            or any(build.get(key) is not True for key in (
                'exports_match_baseline', 'original_export_coverage_complete', 'baseline_preserved'))
            or any(build.get(key) is not False for key in (
                'hresult_fix_applied', 'stage_or_prefix_modified', 'runtime_started',
                'deployment_or_runtime_compatibility_claimed'))
            or type(build.get('md_verified_object_count')) is not int or build['md_verified_object_count'] != 13
            or type(settings.get('exit')) is not int or settings['exit'] != 0
            or type(tests.get('exit')) is not int or tests['exit'] != 0
            or type(tests.get('passed')) is not int or tests['passed'] != HEADER_TEST_COUNT):
        raise RuntimeError('Require the completed trace-only public graphics build without runtime claims')
    headers = [item for item in build['source_evidence'] + build['generated_overlay']
               if item['path'].endswith('/GraphicsSwapChainDiagnostics.h')]
    if len(headers) != 2 or not _same(headers[0]['sha256'], headers[1]['sha256']) or headers[0]['bytes'] != headers[1]['bytes']:
        raise RuntimeError('Generated graphics diagnostic header differs from its source')
    historical = [item for item in baseline_inputs if item['path'] == HISTORICAL_GRAPHICS]
    if historical and (len(historical) != 1 or historical[0]['sha256'] != PREVIOUS_GRAPHICS_SHA256):
        raise RuntimeError('Unexpected historical vendor graphics identity')
    backup = validated_previous_graphics_backup(root) if historical else None
    references = list(previous_version.validate_evidence(root)) + [
        {'path': BUILD_RECORD, 'sha256': BUILD_RECORD_SHA256},
        {'path': BASELINE_REPORT, 'sha256': BASELINE_REPORT_SHA256}]
    for item in identities:
        path = backup if item['path'] == HISTORICAL_GRAPHICS and backup is not None else paths[item['path']]
        if sha(path) != item['sha256'] or path.stat().st_size != item['bytes']:
            raise RuntimeError('A bound graphics code/build input changed')
        references.append({'path': str(path.relative_to(root)), 'sha256': item['sha256']})
    if sha(paths[BUILD + '/overlay/RenderHooks.cpp']) != PATCHED_SHA256:
        raise RuntimeError('Unexpected generated graphics call overlay')
    output = paths[HEADER_LOG].read_text()
    if f'Ran {HEADER_TEST_COUNT} tests' not in output or re.search(r'(?m)^OK\s*$', output) is None or 'FAILED' in output:
        raise RuntimeError('Require the actual passing native header/overlay test log')
    return references


def validate_version(record):
    _pins()
    roles = {PREVIOUS_MANIFEST, TRANSACTION, BACKUP, SOURCE}
    for key, expected in (('graphics_previous_manifest', PREVIOUS_MANIFEST),
                          ('graphics_update_transaction', TRANSACTION)):
        if record.get(key) != expected or sha(_path(ROOT, expected, roles)) != record.get(key + '_sha256'):
            raise RuntimeError('Unexpected or changed graphics evidence reference')
    previous = json.loads(_path(ROOT, PREVIOUS_MANIFEST, roles).read_bytes())
    if type(previous.get('developer_code_version')) is not int or previous['developer_code_version'] != 10:
        raise RuntimeError('The graphics diagnostic requires exact previous V10 metadata')
    previous_version.validate_version(previous)
    additions = {'graphics_previous_manifest', 'graphics_previous_manifest_sha256',
                 'graphics_update_transaction', 'graphics_update_transaction_sha256'}
    if set(record) != set(previous) | additions or type(record.get('developer_code_version')) is not int or record['developer_code_version'] != VERSION:
        raise RuntimeError('Unexpected V11 fields or developer role')
    for key, value in previous.items():
        if key not in ('at', 'developer_code_version', 'files') and not _same(record.get(key), value):
            raise RuntimeError('V11 must preserve existing V10 metadata: ' + key)
    old, new = previous.get('files'), record.get('files')
    if (not isinstance(old, list) or not isinstance(new, list) or len(old) != 474 or len(new) != 474
            or any(not isinstance(item, dict) or type(item.get('name')) is not str for item in old + new)
            or len({item['name'] for item in old}) != 474
            or sum(item['name'] == 'rage-graphics-five.dll' for item in old) != 1):
        raise RuntimeError('Require exactly the existing 474-entry graphics code inventory')
    source = _path(ROOT, SOURCE, roles)
    for before, after in zip(old, new):
        expected = dict(before, sha256=GRAPHICS_SHA256, bytes=source.stat().st_size, origin=ORIGIN) \
            if before['name'] == 'rage-graphics-five.dll' else before
        if not _same(after, expected) or before['name'] == 'rage-graphics-five.dll' and before.get('sha256') != PREVIOUS_GRAPHICS_SHA256:
            raise RuntimeError('V11 may replace only the previous unchanged vendor graphics DLL')
    transaction = json.loads(_path(ROOT, TRANSACTION, roles).read_bytes())
    expected = {'source_revision': REVISION, 'developer_code_version': VERSION,
        'graphics_previous_manifest': PREVIOUS_MANIFEST,
        'graphics_previous_manifest_sha256': record['graphics_previous_manifest_sha256'],
        'previous_sha256': PREVIOUS_GRAPHICS_SHA256, 'new_sha256': GRAPHICS_SHA256,
        'target': 'build/windows-source-integration/rage-graphics-five.dll', 'source': SOURCE,
        'previous_code_backup': BACKUP, 'only_graphics_file_updated': True,
        'other_473_code_entries_and_core10_unchanged': True,
        'previous_graphics_origin': 'unchanged-vendor-code',
        'original_factory_call_arguments_query_interface_and_hresult_path_preserved': True,
        'v11_runtime_compatibility_claim': False, 'profiles_sessions_tickets_read_copied_or_reset': False}
    if (set(transaction) != set(expected) | {'at', 'header_checks', 'diagnostic_evidence'}
            or any(not _same(transaction.get(key), value) for key, value in expected.items())
            or not _same(transaction.get('header_checks'), {'exit': 0, 'passed': HEADER_TEST_COUNT})
            or sha(_path(ROOT, BACKUP, roles)) != PREVIOUS_GRAPHICS_SHA256
            or not _same(transaction.get('diagnostic_evidence'), validate_evidence(ROOT))):
        raise RuntimeError('Unexpected graphics-only transaction or build evidence')
