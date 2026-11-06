"""Own temporary code/evidence only; no prefix, Wine, client or dump access."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from unittest import mock
import unittest

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / 'native/windows-client'))
import graphics_diagnostic_identity as policy
import run_main


def put(root, name, raw):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return {'path': name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def save(root, name, value):
    return put(root, name, json.dumps(value).encode())


def previous_manifest(old_sha, old_bytes):
    files = [
        {'name': 'rage-graphics-five.dll', 'bytes': old_bytes, 'sha256': old_sha, 'origin': 'original-vendor'},
        {'name': 'CoreRT.dll', 'bytes': 2365952, 'sha256': policy.previous_version.CORE_SHA256, 'origin': 'Core10'},
        {'name': 'legitimacy.dll', 'bytes': 8, 'sha256': 'd' * 64, 'origin': 'unchanged vendor'},
        {'name': 'FiveM.exe.formaldev', 'bytes': 2, 'sha256': 'e' * 64}]
    files += [{'name': 'own-preserved-%03d.dll' % index, 'bytes': 1, 'sha256': 'a' * 64}
              for index in range(470)]
    return {'at': 'own-v10', 'source_revision': run_main.REVISION, 'developer_code_version': 10,
            'manual_login_user_confirmed': True, 'prefix_is_account_free': False,
            'role': 'original source-developer role', 'files': files,
            'auth_confirmation_evidence': 'research/own-confirmation.json'}


def version_fixture(root):
    old, new = b'own unchanged vendor graphics', b'own public diagnostic graphics'
    old_sha, new_sha = [hashlib.sha256(value).hexdigest() for value in (old, new)]
    put(root, policy.SOURCE, new)
    put(root, policy.BACKUP, old)
    previous = previous_manifest(old_sha, len(old))
    previous_id = save(root, policy.PREVIOUS_MANIFEST, previous)
    evidence = [{'path': policy.BUILD_RECORD, 'sha256': 'b' * 64}]
    transaction = {'at': 'own-v11', 'source_revision': run_main.REVISION, 'developer_code_version': 11,
        'graphics_previous_manifest': policy.PREVIOUS_MANIFEST,
        'graphics_previous_manifest_sha256': previous_id['sha256'],
        'previous_sha256': old_sha, 'new_sha256': new_sha,
        'target': 'build/windows-source-integration/rage-graphics-five.dll', 'source': policy.SOURCE,
        'previous_code_backup': policy.BACKUP, 'header_checks': {'exit': 0, 'passed': 3},
        'diagnostic_evidence': evidence, 'only_graphics_file_updated': True,
        'other_473_code_entries_and_core10_unchanged': True, 'previous_graphics_origin': 'unchanged-vendor-code',
        'original_factory_call_arguments_query_interface_and_hresult_path_preserved': True,
        'v11_runtime_compatibility_claim': False, 'profiles_sessions_tickets_read_copied_or_reset': False}
    transaction_id = save(root, policy.TRANSACTION, transaction)
    record = copy.deepcopy(previous)
    record.update(developer_code_version=11, graphics_previous_manifest=policy.PREVIOUS_MANIFEST,
        graphics_previous_manifest_sha256=previous_id['sha256'], graphics_update_transaction=policy.TRANSACTION,
        graphics_update_transaction_sha256=transaction_id['sha256'])
    record['files'][0].update(sha256=new_sha, bytes=len(new), origin=policy.ORIGIN)
    return old, new, previous, record, evidence


class GraphicsIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.old, self.new, self.previous, self.record, self.evidence = version_fixture(self.root)
        for patch in (mock.patch.object(policy, 'ROOT', self.root), mock.patch.object(run_main, 'ROOT', self.root),
                      mock.patch.object(policy, 'GRAPHICS_SHA256', hashlib.sha256(self.new).hexdigest()),
                      mock.patch.object(policy, 'PREVIOUS_GRAPHICS_SHA256', hashlib.sha256(self.old).hexdigest()),
                      mock.patch.object(policy, 'BUILD_RECORD_SHA256', 'b' * 64)):
            patch.start()
            self.addCleanup(patch.stop)

    def test_only_graphics_changes_while_core10_and_other_473_metadata_remain_exact(self):
        with mock.patch.object(policy.previous_version, 'validate_version') as previous, \
                mock.patch.object(policy, 'validate_evidence', return_value=self.evidence):
            policy.validate_version(self.record)
            previous.assert_called_once_with(self.previous)
            for kind in ('core', 'vendor', 'formaldev', 'role', 'order', 'integer-type', 'extra', 'count'):
                value = copy.deepcopy(self.record)
                if kind == 'core': value['files'][1]['sha256'] = '0' * 64
                elif kind == 'vendor': value['files'][2]['bytes'] += 1
                elif kind == 'formaldev': value['files'][3]['bytes'] += 1
                elif kind == 'role': value['role'] = 'another role'
                elif kind == 'order': value['files'][1:3] = reversed(value['files'][1:3])
                elif kind == 'integer-type': value['files'][3]['bytes'] = 2.0
                elif kind == 'extra': value['unapproved'] = True
                else: value['files'].pop()
                with self.subTest(kind=kind), self.assertRaises(RuntimeError):
                    policy.validate_version(value)

    def test_previous_metadata_validator_never_uses_old_live_stage_guard(self):
        invalid = copy.deepcopy(self.record)
        invalid['auth_confirmation_evidence'] = 'prefixes/private/user.reg'
        with mock.patch.object(policy.previous_version, 'validate_version') as previous, \
                mock.patch.object(policy, 'validate_evidence', return_value=self.evidence), \
                mock.patch.object(policy, 'sha', wraps=policy.sha) as hashed, \
                self.assertRaisesRegex(RuntimeError, 'preserve'):
            policy.validate_version(invalid)
        previous.assert_called_once_with(self.previous)
        self.assertNotIn(mock.call(self.root / 'prefixes/private/user.reg'), hashed.call_args_list)

    def build_fixture(self):
        baseline = {'artifact': put(self.root, policy.BASELINE_ARTIFACT, b'own baseline DLL'),
                    'recipe_source': put(self.root, policy.BASELINE_RECIPE, b'own baseline recipe'),
                    'sources': [put(self.root, policy.HISTORICAL_GRAPHICS, self.old)]
                    + [put(self.root, 'build/own-baseline/%02d.obj' % index, b'own baseline input')
                       for index in range(56)]}
        baseline_id = save(self.root, policy.BASELINE_REPORT, baseline)
        def item(name):
            return put(self.root, name, b'own diagnostic input')
        objects, resource = policy._object_paths(self.root, policy.BUILD)
        overlay = {key: True for key in policy.SCOPE_TRUE}
        overlay.update(original=policy.ORIGINAL, original_sha256=policy.ORIGINAL_SHA256,
                       patched_sha256=policy.PATCHED_SHA256, replacement_count=2, original_factory_call_count=1,
                       default_logging_enabled=False, raw_pointers_titles_or_arguments_logged=False)
        build = {'compiled': True, 'source_revision': run_main.REVISION,
            'artifact': item(policy.SOURCE), 'baseline_build_record': baseline_id,
            'baseline_artifact': baseline['artifact'], 'baseline_recipe_source': baseline['recipe_source'],
            'baseline_inputs': policy._project_identities(baseline),
            'source_evidence': [item(name) for name in sorted(policy.EXPECTED_SOURCES)],
            'generated_overlay': [item(name) for name in sorted(policy.EXPECTED_OVERLAY)],
            'generated_build_configuration': item(policy.BUILD + '/CMakeLists.txt'),
            'objects': [item(name) for name in sorted(objects)], 'resource_object': item(resource),
            'cmake_manifest_resource': item(policy.BUILD + '/CMakeFiles/rage_graphics.dir/manifest.res'),
            'object_directives': item(policy.BUILD + '/object-directives.txt'),
            'pe_inspection': item(policy.BUILD + '/pe-inspection.txt'),
            'build': dict(exit=0, **{key: item(name) for key, name in policy.BUILD_FILES.items()}),
            'overlay_tests': {'exit': 0, 'passed': 3,
                              'log': put(self.root, policy.HEADER_LOG, b'Ran 3 tests in 0.1s\n\nOK\n')},
            'scope_proof': {'render_overlay': overlay, 'cmake_reversed_equals_baseline': True,
                'replacement_tu_count': 1, 'no_new_translation_units': True,
                'definition': 'CFX_GRAPHICS_SWAPCHAIN_DIAGNOSTICS=1', 'hresult_fix_applied': False},
            'exports_match_baseline': True, 'original_export_coverage_complete': True,
            'baseline_preserved': True, 'stage_or_prefix_modified': False, 'runtime_started': False,
            'hresult_fix_applied': False, 'deployment_or_runtime_compatibility_claimed': False,
            'md_verified_object_count': 13}
        return build, baseline_id

    def build_controls(self, build, baseline_id):
        report_id = save(self.root, policy.BUILD_RECORD, build)
        for name, value in (
            ('BASELINE_REPORT_BYTES', baseline_id['bytes']), ('BASELINE_REPORT_SHA256', baseline_id['sha256']),
            ('BASELINE_ARTIFACT_SHA256', build['baseline_artifact']['sha256']),
            ('BASELINE_RECIPE_SHA256', build['baseline_recipe_source']['sha256']),
            ('BUILD_RECORD_SHA256', report_id['sha256']), ('GRAPHICS_SHA256', build['artifact']['sha256']),
            ('PATCHED_SHA256', build['generated_overlay'][0]['sha256'])):
            patch = mock.patch.object(policy, name, value)
            patch.start()
            self.addCleanup(patch.stop)
        # All fixture overlay files contain the same own bytes.
        build['scope_proof']['render_overlay']['patched_sha256'] = policy.PATCHED_SHA256
        report_id = save(self.root, policy.BUILD_RECORD, build)
        patch = mock.patch.object(policy, 'BUILD_RECORD_SHA256', report_id['sha256'])
        patch.start()
        self.addCleanup(patch.stop)

    def test_fixed_build_scope_and_native_log_are_bound_without_runtime_claims(self):
        build, baseline_id = self.build_fixture()
        self.build_controls(build, baseline_id)
        with mock.patch.object(policy.previous_version, 'validate_evidence', return_value=[]):
            result = policy.validate_evidence(self.root)
        self.assertIn({'path': policy.SOURCE, 'sha256': build['artifact']['sha256']}, result)
        (self.root / policy.HEADER_LOG).write_bytes(b'Ran 3 tests\nFAILED\n')
        with mock.patch.object(policy.previous_version, 'validate_evidence', return_value=[]), self.assertRaises(RuntimeError):
            policy.validate_evidence(self.root)

    def test_foreign_report_input_is_rejected_before_any_selected_hash(self):
        build, baseline_id = self.build_fixture()
        build['source_evidence'][0]['path'] = 'prefixes/private/user.reg'
        self.build_controls(build, baseline_id)
        with mock.patch.object(policy, 'sha') as hashed, \
                self.assertRaisesRegex(RuntimeError, 'input path set'):
            policy.validate_evidence(self.root)
        hashed.assert_not_called()

    def test_baseline_order_is_irrelevant_but_duplicates_and_old_render_object_are_rejected(self):
        build, baseline_id = self.build_fixture()
        build['baseline_inputs'].reverse()
        self.build_controls(build, baseline_id)
        with mock.patch.object(policy.previous_version, 'validate_evidence', return_value=[]):
            policy.validate_evidence(self.root)
        original = copy.deepcopy(build)
        for kind in ('duplicate-baseline', 'original-render-object'):
            invalid = copy.deepcopy(original)
            if kind == 'duplicate-baseline':
                invalid['baseline_inputs'][0] = dict(invalid['baseline_inputs'][1])
            else:
                render = next(item for item in invalid['objects'] if item['path'].endswith('/overlay/RenderHooks.cpp.obj'))
                render['path'] = (policy.BUILD + '/CMakeFiles/rage_graphics.dir/'
                    + self.root.as_posix().lstrip('/')
                    + '/port/fivem/code/components/rage-graphics-five/src/RenderHooks.cpp.obj')
            self.build_controls(invalid, baseline_id)
            with self.subTest(kind=kind), mock.patch.object(policy, 'sha') as hashed, self.assertRaises(RuntimeError):
                policy.validate_evidence(self.root)
            hashed.assert_not_called()

    def test_v11_dispatch_precedes_other_reads_and_preserves_existing_channels(self):
        import source_code_identity
        import run_source
        record = {'source_revision': source_code_identity.REVISION,
                  'stage': str(source_code_identity.STAGE.relative_to(source_code_identity.ROOT)),
                  'developer_code_version': 11, 'manual_login_user_confirmed': True,
                  'prefix_is_account_free': False}
        path = self.root / 'own-dispatch.json'
        path.write_text(json.dumps(record))
        with mock.patch.object(source_code_identity, 'plain'), \
                mock.patch.object(source_code_identity, 'sha') as hashed, \
                mock.patch.object(policy, 'validate_version', side_effect=RuntimeError('own admission stop')) as admission, \
                self.assertRaisesRegex(RuntimeError, 'own admission stop'):
            source_code_identity.validate_code_inputs(path)
        admission.assert_called_once_with(record)
        hashed.assert_not_called()
        self.assertEqual(run_source.diagnostic_winedebug(11, True), run_source.diagnostic_winedebug(10, True))


if __name__ == '__main__':
    unittest.main()
