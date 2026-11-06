"""Own code snapshots and temporary metadata; never a real prefix or runtime."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / 'native/windows-client'))
import graphics_window_identity as policy
import run_main
from test_graphics_diagnostic_identity import put, save, previous_manifest


def fixture(root):
    old, new, vendor = b'own graphics eleven', b'own graphics twelve', b'own original vendor graphics'
    source_id = put(root, policy.SOURCE, new)
    baseline = [put(root, policy.previous_version.SOURCE, old),
        put(root, policy.previous_version.BACKUP, vendor),
        put(root, 'build/windows-source-integration/CoreRT.dll', b'own stable Core10'),
        save(root, policy.BASELINE_REPORT, {'own_completed_v11_build': True}),
        put(root, 'native/windows-graphics-diagnostics/build.py', b'own earlier diagnostic recipe'),
        put(root, 'native/windows-graphics-source/build.py', b'own earlier baseline recipe'),
        put(root, policy.previous_version.BUILD + '/overlay/GraphicsSwapChainDiagnostics.h', b'own SC header')]
    baseline += [put(root, 'build/own-stable/%03d.obj' % index, b'own stable code') for index in range(187)]
    by_path = {item['path']: item for item in baseline}
    baseline = [by_path[name] for name in sorted(by_path)]
    refs = [{'path': item['path'], 'sha256': item['sha256']} for item in baseline]
    refs += refs[:102]
    snapshots = []
    for name in policy.CONTEXT_NAMES:
        original = put(root, 'native/windows-client/' + name, ('own captured ' + name).encode())
        copied = put(root, policy.BUILD + '/inputs/' + name, (root / original['path']).read_bytes())
        snapshots.append({'original_role': original['path'], 'original_bytes': original['bytes'],
                          'original_sha256': original['sha256'], 'snapshot': copied})
    def item(name):
        return put(root, name, b'own window diagnostic code')
    source_inputs = [item(name) for name in sorted(policy.EXPECTED_SOURCES)]
    window_header = 'native/windows-graphics-window-diagnostics/GraphicsWindowDiagnostics.h'
    source_inputs = [put(root, window_header, b'own WND header') if row['path'] == window_header else row
                     for row in source_inputs]
    generated = [put(root, policy.BUILD + '/overlay/' + name, raw) for name, raw in (
        ('RenderHooks.cpp', b'own window Render overlay'), ('GraphicsWindowDiagnostics.h', b'own WND header'),
        ('GraphicsSwapChainDiagnostics.h', b'own SC header'))]
    objects, resource = policy.previous_version._object_paths(root, policy.BUILD)
    base = policy.BUILD + '/CMakeFiles/rage_graphics.dir/' + root.as_posix().lstrip('/') + '/port/fivem/code/'
    objects.remove(base + 'components/rage-graphics-five/src/RenderHooks.cpp.obj')
    objects.add(policy.BUILD + '/CMakeFiles/rage_graphics.dir/overlay/RenderHooks.cpp.obj')
    overlay = {key: True for key in policy.SCOPE_TRUE}
    overlay.update({key: False for key in policy.SCOPE_FALSE})
    overlay.update(input_sha256=policy.INPUT_RENDER_SHA256, patched_sha256=generated[0]['sha256'],
        replacement_count=6, modified_regions=['header_include', 'HookCreateWindowExW', 'swapchain_checkpoint'])
    build = {'compiled': True, 'source_revision': run_main.REVISION, 'artifact': source_id,
        'baseline_build_record': by_path[policy.BASELINE_REPORT],
        'baseline_artifact': by_path[policy.previous_version.SOURCE],
        'baseline_recipe_source': by_path['native/windows-graphics-diagnostics/build.py'],
        'source_recipe_source': by_path['native/windows-graphics-source/build.py'],
        'baseline_evidence': baseline, 'baseline_evidence_reference_count': len(refs),
        'support_context_before_after': {'original_live_requirement_after_build': False,
            'source_context_unchanged_during_build': True, 'execution_from_preverified_captured_bytes': True,
            'snapshots': snapshots},
        'source_evidence': source_inputs, 'generated_overlay': generated,
        'generated_build_configuration': item(policy.BUILD + '/CMakeLists.txt'),
        'objects': [item(name) for name in sorted(objects)], 'resource_object': item(resource),
        'cmake_manifest_resource': item(policy.BUILD + '/CMakeFiles/rage_graphics.dir/manifest.res'),
        'object_directives': item(policy.BUILD + '/object-directives.txt'),
        'pe_inspection': item(policy.BUILD + '/pe-inspection.txt'),
        'scope_proof': {'render_overlay': overlay, 'cmake_reversed_equals_baseline': True,
            'no_new_translation_units': True, 'replacement_tu_count': 1,
            'definition': 'CFX_GRAPHICS_WINDOW_DIAGNOSTICS=1',
            'preserved_definition': 'CFX_GRAPHICS_SWAPCHAIN_DIAGNOSTICS=1',
            'previous_swapchain_header_preserved': True, 'hresult_fix_applied': False},
        'overlay_tests': {'exit': 0, 'passed': 3,
            'log': put(root, policy.HEADER_LOG, b'Ran 3 tests in 0.1s\n\nOK\n')},
        'build': dict(exit=0, **{key: item(name) for key, name in policy.BUILD_FILES.items()}),
        'exports_match_baseline': True, 'original_export_coverage_complete': True,
        'baseline_preserved': True, 'hresult_fix_applied': False, 'stage_or_prefix_modified': False,
        'runtime_started': False, 'deployment_or_runtime_compatibility_claimed': False,
        'md_verified_object_count': 13}
    previous = previous_manifest(hashlib.sha256(old).hexdigest(), len(old))
    previous['developer_code_version'] = 11
    previous['files'][0]['origin'] = 'own previous source graphics11'
    save(root, policy.PREVIOUS_MANIFEST, previous)
    put(root, policy.previous_version.HISTORICAL_GRAPHICS, old)
    report_id = save(root, policy.BUILD_RECORD, build)
    return {'old': old, 'new': new, 'vendor': vendor, 'build': build,
            'refs': refs, 'previous': previous, 'report_id': report_id}


def bind(test, value):
    build = value['build']
    patches = [mock.patch.object(policy, 'ROOT', test.root), mock.patch.object(run_main, 'ROOT', test.root),
        mock.patch.object(policy, 'GRAPHICS_SHA256', build['artifact']['sha256']),
        mock.patch.object(policy, 'BUILD_RECORD_SHA256', value['report_id']['sha256']),
        mock.patch.object(policy, 'PREVIOUS_GRAPHICS_SHA256', build['baseline_artifact']['sha256']),
        mock.patch.object(policy, 'BASELINE_REPORT_BYTES', build['baseline_build_record']['bytes']),
        mock.patch.object(policy, 'BASELINE_REPORT_SHA256', build['baseline_build_record']['sha256']),
        mock.patch.object(policy, 'PATCHED_RENDER_SHA256', build['generated_overlay'][0]['sha256']),
        mock.patch.object(policy.previous_version, 'validate_evidence', return_value=value['refs']),
        mock.patch.object(policy.previous_version, 'validate_version')]
    for patch in patches:
        patch.start()
        test.addCleanup(patch.stop)


def rewrite_report(test, value):
    identity = save(test.root, policy.BUILD_RECORD, value)
    patch = mock.patch.object(policy, 'BUILD_RECORD_SHA256', identity['sha256'])
    patch.start()
    test.addCleanup(patch.stop)


class GraphicsWindowIdentityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.value = fixture(self.root)
        bind(self, self.value)

    def test_complete_scope_uses_snapshots_after_original_support_files_change(self):
        for name in policy.CONTEXT_NAMES:
            (self.root / 'native/windows-client' / name).write_bytes(b'own newer root code version12')
        with mock.patch.object(policy, 'sha', wraps=policy.sha) as hashed:
            result = policy.validate_evidence(self.root)
        self.assertTrue(policy.EXPECTED_SNAPSHOTS.issubset({row['path'] for row in result}))
        self.assertFalse(policy.CONTEXT_ROLES.intersection({row['path'] for row in result}))
        self.assertTrue(all(mock.call(self.root / name) not in hashed.call_args_list for name in policy.CONTEXT_ROLES))
        self.assertIn({'path': policy.SOURCE, 'sha256': self.value['build']['artifact']['sha256']}, result)

    def test_foreign_snapshot_role_and_wrong_snapshot_hash_are_rejected(self):
        for kind in ('foreign', 'mismatch', 'live-required'):
            build = copy.deepcopy(self.value['build'])
            if kind == 'foreign': build['support_context_before_after']['snapshots'][0]['snapshot']['path'] = 'prefixes/private/user.reg'
            elif kind == 'mismatch': build['support_context_before_after']['snapshots'][0]['original_sha256'] = '0' * 64
            else: build['support_context_before_after']['original_live_requirement_after_build'] = True
            rewrite_report(self, build)
            with self.subTest(kind=kind), mock.patch.object(policy, 'sha') as hashed, self.assertRaises(RuntimeError):
                policy.validate_evidence(self.root)
            hashed.assert_not_called()

    def test_baseline_set_is_complete_order_independent_and_immutable(self):
        build = copy.deepcopy(self.value['build'])
        build['baseline_evidence'].reverse()
        rewrite_report(self, build)
        policy.validate_evidence(self.root)
        for kind in ('missing', 'duplicate', 'changed', 'core'):
            invalid = copy.deepcopy(build)
            if kind == 'missing': invalid['baseline_evidence'].pop()
            elif kind == 'duplicate': invalid['baseline_evidence'][0] = dict(invalid['baseline_evidence'][1])
            elif kind == 'changed': invalid['baseline_evidence'][0]['sha256'] = '0' * 64
            else:
                row = next(row for row in invalid['baseline_evidence'] if row['path'].endswith('/CoreRT.dll'))
                row['bytes'] += 1
            rewrite_report(self, invalid)
            with self.subTest(kind=kind), self.assertRaises(RuntimeError):
                policy.validate_evidence(self.root)

    def test_snapshot_drift_or_runtime_claim_does_not_pass(self):
        (self.root / next(iter(policy.EXPECTED_SNAPSHOTS))).write_bytes(b'own modified snapshot')
        with self.assertRaises(RuntimeError): policy.validate_evidence(self.root)
        build = copy.deepcopy(self.value['build'])
        build['runtime_started'] = True
        rewrite_report(self, build)
        with self.assertRaisesRegex(RuntimeError, 'metadata-only'):
            policy.validate_evidence(self.root)

    def test_v12_dispatch_precedes_other_reads_and_preserves_v11_diagnostic_channels(self):
        import source_code_identity
        import run_source
        record = {'source_revision': source_code_identity.REVISION,
            'stage': str(source_code_identity.STAGE.relative_to(source_code_identity.ROOT)),
            'developer_code_version': 12, 'manual_login_user_confirmed': True, 'prefix_is_account_free': False}
        path = self.root / 'own-dispatch.json'
        path.write_text(json.dumps(record))
        with mock.patch.object(source_code_identity, 'plain'), \
                mock.patch.object(source_code_identity, 'sha') as hashed, \
                mock.patch.object(policy, 'validate_version', side_effect=RuntimeError('own V12 admission stop')) as admit, \
                self.assertRaisesRegex(RuntimeError, 'own V12 admission stop'):
            source_code_identity.validate_code_inputs(path)
        admit.assert_called_once_with(record)
        hashed.assert_not_called()
        self.assertEqual(run_source.diagnostic_winedebug(12, True), run_source.diagnostic_winedebug(11, True))


if __name__ == '__main__':
    unittest.main()
