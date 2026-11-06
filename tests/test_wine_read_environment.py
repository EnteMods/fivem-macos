import hashlib
import importlib.util
import copy
import json
from pathlib import Path
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('own_read_environment', ROOT / 'native/wine-read-diagnostics/environment.py')
environment = importlib.util.module_from_spec(spec)
spec.loader.exec_module(environment)


class ReadEnvironmentTests(unittest.TestCase):
    def tearDown(self):
        environment._verified_input_report = None

    def manifest_fixture(self):
        spec = importlib.util.spec_from_file_location('own_read_proof_reference', ROOT / 'native/wine-read-diagnostics/build.py')
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        rendered = builder.derive_builder(builder.read(builder.FROZEN_BUILDER))
        value = {'separate_read_completion_diagnostic_profile': True,
                 'numeric_recipe_inputs': builder.recipe_inputs(),
                 'read_diagnostic_inputs': builder.identity(builder.INPUT_REPORT),
                 'read_diagnostic_builder_adapter': builder.adapter_proof(rendered)}
        return json.loads(json.dumps(value)), builder

    def test_derivation_binds_frozen_exact_bytes_and_is_reversible(self):
        original = environment.BASE.read_bytes()
        self.assertEqual(hashlib.sha256(original).hexdigest(), environment.BASE_SHA)
        rendered = environment.derive(original).decode()
        for before, after, count in reversed(environment.REPLACEMENTS):
            self.assertEqual(rendered.count(after), count)
            rendered = rendered.replace(after, before)
        self.assertEqual(rendered.encode(), original)
        self.assertEqual(environment.BASE.read_bytes(), original)
        self.assertTrue(environment.derivation_evidence()['private_module_namespace'])

    def test_changed_frozen_verifier_fails_before_derivation(self):
        with self.assertRaisesRegex(RuntimeError, 'exact frozen'):
            environment.derive(environment.BASE.read_bytes() + b'\n')

    def test_read_roles_are_separate_and_literal(self):
        self.assertEqual(environment.WORK, ROOT / 'build/wine-read-diagnostics')
        self.assertEqual(environment.ENGINE, ROOT / 'runtime/wine-read-diagnostics/engine')
        self.assertEqual(environment.PREFIX, ROOT / 'prefixes/wine-read-regression')
        self.assertEqual(environment.ROLE, 'wine-read-api-probes')
        self.assertEqual(environment.PROTOCOL, 1810)
        environment.provider._locations()

    def test_authenticated_prefix_redirect_fails_before_root_pin_read(self):
        with mock.patch.object(environment.provider, 'PREFIX', ROOT / 'prefixes/fivem-source-main'), \
                mock.patch.object(environment.provider, 'read_regular') as read:
            with self.assertRaisesRegex(RuntimeError, 'roles may not select'):
                environment.provider.read_root_pin()
            read.assert_not_called()

    def test_all_recipe_roles_have_exact_known_paths(self):
        expected = ({ROOT / 'native/wine-read-diagnostics' / name for name in environment.OWN_RECIPES}
                    | {ROOT / name for name in environment.FROZEN_RECIPE_INPUTS}
                    | {ROOT / name for name in environment.EXTERNAL_TESTS})
        self.assertEqual(environment.recipe_paths(), expected)
        self.assertEqual(len(expected), 24)
        self.assertEqual(environment.provider._recipe_paths(), expected)
        self.assertEqual(sum(environment.provider.PREFLIGHT.values()), 52)

    def test_unknown_overlay_never_selects_or_reads_a_file(self):
        with mock.patch.object(environment, 'bootstrap_read') as read:
            with self.assertRaisesRegex(RuntimeError, 'Undeclared'):
                environment.overlay_path('../foreign.py')
            read.assert_not_called()

    def test_changed_reused_overlay_is_rejected_before_replay(self):
        with mock.patch.object(environment, 'bootstrap_read', return_value=b'changed'):
            with self.assertRaisesRegex(RuntimeError, 'dependency changed'):
                environment.overlay_path('wininet_overlay.py')

    def test_missing_root_pin_cannot_start_baseline_verification(self):
        with mock.patch.object(environment.provider, 'read_regular', side_effect=FileNotFoundError) as read, \
                mock.patch.object(environment.provider.baseline, 'verify_runtime') as baseline:
            with self.assertRaises(FileNotFoundError):
                environment.verify_runtime()
            self.assertEqual(read.call_args_list, [mock.call(environment.ROOT_PIN, ROOT)])
            baseline.assert_not_called()

    def test_authenticated_storage_cannot_be_a_provenance_input(self):
        with mock.patch.object(environment.provider, 'read_regular') as read:
            with self.assertRaises(RuntimeError):
                environment.admit_provenance(ROOT / 'prefixes/fivem-source-main/foreign')
            read.assert_not_called()

    def test_missing_read_profile_fails_before_recipe_read_or_code_execution(self):
        with mock.patch.object(environment.provider, '_group') as group, \
                mock.patch.object(environment.provider, '_bound') as read:
            with self.assertRaisesRegex(RuntimeError, 'explicit separate'):
                environment.validate_manifest({}, {}, {})
        group.assert_not_called()
        read.assert_not_called()

    def test_complete_manifest_bound_builder_proof_is_derived_without_a_build_phase(self):
        value, builder = self.manifest_fixture()
        baseline_result = ([], [])
        with mock.patch.object(environment, '_original_validate', return_value=baseline_result) as validate:
            entries, direct = environment.validate_manifest(value, {}, {})
        validate.assert_called_once_with(value, {}, {})
        self.assertEqual(entries, [])
        self.assertTrue(any(path == builder.INPUT_REPORT for _, path, _ in direct))
        self.assertIsNotNone(environment._verified_input_report)
        self.assertEqual(environment.provider._validate_manifest, environment.validate_manifest)
        self.assertEqual(environment.provider._collect_provenance, environment.collect_provenance)

    def test_changed_root_manifest_builder_hash_rejects_before_exec(self):
        value, _ = self.manifest_fixture()
        next(item for item in value['numeric_recipe_inputs'] if item['path'] == str(environment.BUILDER))['sha256'] = '0' * 64
        with mock.patch('builtins.compile') as compile_code, \
                mock.patch.object(environment, '_original_validate') as validate:
            with self.assertRaisesRegex(RuntimeError, 'Bound numeric artifact changed'):
                environment.validate_manifest(value, {}, {})
        compile_code.assert_not_called()
        validate.assert_not_called()

    def test_full_proof_including_nested_bindings_must_match_canonical_derived_document(self):
        value, _ = self.manifest_fixture()
        value['read_diagnostic_builder_adapter']['bindings']['SOURCE'] = str(ROOT / 'prefixes/fivem-source-main')
        with mock.patch.object(environment, '_original_validate') as validate:
            with self.assertRaisesRegex(RuntimeError, 'Complete read diagnostic builder adapter proof differs'):
                environment.validate_manifest(value, {}, {})
        validate.assert_not_called()
        self.assertIsNone(environment._verified_input_report)

    def test_foreign_input_or_recipe_paths_are_rejected_before_any_selected_read(self):
        value, _ = self.manifest_fixture()
        changed_input, changed_recipe = copy.deepcopy(value), copy.deepcopy(value)
        changed_input['read_diagnostic_inputs']['path'] = str(ROOT / 'prefixes/fivem-source-main/private')
        changed_recipe['numeric_recipe_inputs'][-1]['path'] = str(ROOT / 'prefixes/fivem-source-main/private')
        for bad in (changed_input, changed_recipe):
            with mock.patch.object(environment.provider, '_bound') as read:
                with self.assertRaises(RuntimeError):
                    environment.validate_manifest(bad, {}, {})
            read.assert_not_called()

    def test_exact_relative_input_report_container_requires_prior_full_input_verification(self):
        value, builder = self.manifest_fixture()
        report = builder.verify_inputs()
        with self.assertRaisesRegex(RuntimeError, 'prior bound builder'):
            environment.collect_provenance(report)
        with mock.patch.object(environment, '_original_validate', return_value=([], [])):
            environment.validate_manifest(value, {}, {})
        self.assertEqual(environment.collect_provenance(report), [])
        changed = copy.deepcopy(report)
        changed['source_evidence'][-1]['path'] = 'prefixes/fivem-source-main/private'
        with self.assertRaisesRegex(RuntimeError, 'complete exact pinned'):
            environment.collect_provenance(changed)
        self.assertEqual(environment.collect_provenance({'fixed': [1, True, None]}), [])

    def test_unrelated_relative_identity_never_inherits_input_container_authority(self):
        value, _ = self.manifest_fixture()
        with mock.patch.object(environment, '_original_validate', return_value=([], [])):
            environment.validate_manifest(value, {}, {})
        with mock.patch.object(environment.provider, 'read_regular') as read:
            with self.assertRaisesRegex(RuntimeError, 'Unadmitted relative'):
                environment.collect_provenance({'path': 'prefixes/fivem-source-main/private', 'bytes': 1, 'sha256': 'a' * 64})
        read.assert_not_called()

    def test_input_container_context_cannot_survive_runtime_verification_or_environment_return(self):
        def verified(*args, **kwargs):
            environment._verified_input_report = {'own': 'sentinel'}
            return {'own': 'verified'}

        with mock.patch.object(environment.provider, 'verify_runtime', side_effect=verified):
            self.assertEqual(environment.verify_runtime()['own'], 'verified')
        self.assertIsNone(environment._verified_input_report)
        with mock.patch.object(environment.provider, 'environment', side_effect=verified):
            self.assertEqual(environment.environment()['own'], 'verified')
        self.assertIsNone(environment._verified_input_report)


if __name__ == '__main__':
    unittest.main()
