"""Pure source/admission tests; never invoke a build phase, Wine or a prefix."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / 'native/wine-read-diagnostics/build.py'
SPEC = importlib.util.spec_from_file_location('own_read_builder_tests', PATH)
adapter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(adapter)


class ReadBuilderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = adapter.read(adapter.FROZEN_BUILDER)

    def original_module(self):
        module = types.ModuleType('independent_frozen_builder_reference')
        module.__file__ = str(adapter.FROZEN_BUILDER)
        exec(compile(self.original, str(adapter.FROZEN_BUILDER), 'exec'), module.__dict__)
        return module

    def test_source_derivation_is_exactly_reversible_with_three_literal_sites(self):
        rendered = adapter.derive_builder(self.original)
        self.assertNotEqual(rendered.encode(), self.original)
        restored = rendered
        for before, after, count in reversed(adapter.SOURCE_EDITS):
            self.assertEqual(restored.count(after), count)
            restored = restored.replace(after, before)
        self.assertEqual(restored.encode(), self.original)
        self.assertEqual(sum(item[2] for item in adapter.SOURCE_EDITS), 3)

    def test_changed_frozen_builder_is_never_executed(self):
        with self.assertRaisesRegex(RuntimeError, 'exact frozen numeric builder'):
            adapter.derive_builder(self.original + b'\n')
        with mock.patch.object(adapter, 'read', return_value=b'raise AssertionError("executed")'), \
                mock.patch.object(adapter, 'verify_inputs', return_value={}):
            with self.assertRaisesRegex(RuntimeError, 'exact frozen numeric builder'):
                adapter.load_builder()

    def test_module_namespaces_never_mutate_the_frozen_original_or_another_instance(self):
        original = self.original_module()
        old = (original.WORK, original.BUILD, original.SOURCE, original.INSTALL, original.HEADER_SHA)
        first, second = adapter.load_builder(), adapter.load_builder()
        self.assertIsNot(first.__dict__, second.__dict__)
        self.assertIsNot(first.prepare.__globals__, original.__dict__)
        first.WORK = Path('/own-invalid-sentinel')
        self.assertEqual(second.WORK, adapter.WORK)
        self.assertEqual(old, (original.WORK, original.BUILD, original.SOURCE, original.INSTALL, original.HEADER_SHA))

    def test_all_work_install_owner_and_lock_bindings_are_separate(self):
        module = adapter.load_builder()
        for key, value in adapter.bindings().items():
            self.assertEqual(getattr(module, key), value)
        self.assertEqual(module.OWNER['install'], str(adapter.INSTALL))
        constants = module.operation_lock.__wrapped__.__code__.co_consts
        self.assertIn('build/.wine-read-diagnostics.lock', constants)
        self.assertNotIn('build/.wine-numeric-diagnostics.lock', constants)
        self.assertEqual(module.HERE, PATH.parent)

    def test_only_the_four_fixed_overlay_providers_are_admitted(self):
        self.assertEqual(adapter.overlay_path('kernel_overlay.py'), adapter.HERE / 'kernel_overlay.py')
        for name in ('wininet_overlay.py', 'unix_debug_overlay.py', 'registry_overlay.py'):
            self.assertEqual(adapter.overlay_path(name), adapter.OLD / name)
        with self.assertRaises(RuntimeError):
            adapter.overlay_path('../outside.py')

    def test_real_pure_overlay_keeps_eight_files_and_exact_old_provider_identities(self):
        module = adapter.load_builder()
        names = {name for group in module.OVERLAYS.values() for name in group}
        originals = {name: adapter.read(module.OLD_SOURCE / name) for name in names}
        changed, proofs = module.combined_overlay(originals, adapter.read(adapter.HERE / 'cfx_numeric.h'))
        self.assertEqual(len(changed), 8)
        self.assertEqual(set(changed), names | {module.HEADER_PATH})
        self.assertEqual(proofs[0]['scope']['entry_sites'], 6)
        self.assertEqual(proofs[0]['scope']['return_expression_sites'], 16)
        self.assertEqual({item['module']['path'] for item in proofs},
                         {str(path) for path in adapter.OVERLAY_PROVIDERS.values()})

    def test_nine_own_names_and_twenty_four_recipe_identities_are_complete(self):
        inputs = adapter.recipe_inputs()
        self.assertEqual(len(adapter.OWN_NAMES), 9)
        self.assertEqual(len(inputs), 24)
        self.assertEqual(len({item['path'] for item in inputs}), 24)
        expected = {str(adapter.HERE / name) for name in adapter.OWN_NAMES}
        self.assertEqual({item['path'] for item in inputs if Path(item['path']).parent == adapter.HERE}, expected)
        self.assertIn(str(adapter.FROZEN_BUILDER), {item['path'] for item in inputs})
        self.assertIn(str(adapter.INPUT_REPORT), {item['path'] for item in inputs})
        for name in adapter.ORIGINAL_NAMES:
            self.assertIn(str(adapter.OLD / name), {item['path'] for item in inputs})

    def test_changed_input_report_fails_before_any_selected_identity_reads(self):
        with mock.patch.object(adapter, 'read', return_value=b'{}') as read, \
                mock.patch.object(adapter, 'identity') as identify:
            with self.assertRaisesRegex(RuntimeError, 'preparation report changed'):
                adapter.verify_inputs()
        self.assertEqual(read.call_args_list, [mock.call(adapter.INPUT_REPORT)])
        identify.assert_not_called()

    def test_all_selected_path_groups_including_last_test_log_precede_reads(self):
        report = json.loads(adapter.read(adapter.INPUT_REPORT))
        report['tests'][-1]['log']['path'] = 'prefixes/fivem-source-main/private'
        raw = json.dumps(report).encode()
        with mock.patch.object(adapter, 'INPUT_REPORT_SHA', hashlib.sha256(raw).hexdigest()), \
                mock.patch.object(adapter, 'read', return_value=raw) as read, \
                mock.patch.object(adapter, 'identity') as identify:
            with self.assertRaises(RuntimeError):
                adapter.verify_inputs()
        self.assertEqual(read.call_args_list, [mock.call(adapter.INPUT_REPORT)])
        identify.assert_not_called()

    def test_inspector_has_five_scoped_replacements_and_roundtrips_original(self):
        module = adapter.load_builder()
        source = adapter.read(ROOT / 'native/wine-job-query-parity/inspect_engine.py')
        rendered = module.inspector_source(source)
        self.assertEqual(len(module.INSPECTOR_EDITS), 5)
        self.assertEqual(module.INSPECTOR_EDITS[0][1], "'.read-numeric-runtime-owner.json'")
        self.assertEqual(module.INSPECTOR_EDITS[1][1], "'native/wine-read-diagnostics'")
        self.assertEqual(module.INSPECTOR_EDITS[2][1], 'if path.is_file() and path.name in ' + repr(adapter.OWN_NAMES))
        for before, after in reversed(module.INSPECTOR_EDITS):
            rendered = rendered.replace(after, before, 1)
        self.assertEqual(rendered.encode(), source)

    def test_reused_build_source_diff_and_pe_proof_logic_is_unchanged(self):
        old, current = self.original_module(), adapter.load_builder()
        for name in ('prepare', 'verify_prepared_source', 'full_diff', 'run_recipe_tests', 'adapted_builder',
                     'configuration_boundaries', 'pe_targets', 'parse_pe_commands', 'capture_pe_plan',
                     'capture_pe_proof', 'verify_pe_plan', 'verify_pe_proof'):
            self.assertEqual(getattr(old, name).__code__.co_code, getattr(current, name).__code__.co_code)
        self.assertEqual(old.DIAGNOSTIC_FLAGS, current.DIAGNOSTIC_FLAGS)
        self.assertEqual(len(current.pe_targets()), 10)
        self.assertEqual(len(current.TESTS), 7)
        self.assertEqual(sum(count for _, _, count in current.TESTS), 52)

    def test_alias_code_is_rejected_without_following_the_link(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / 'own').write_bytes(b'own')
            (root / 'alias').symlink_to(root / 'own')
            with mock.patch.object(adapter, 'ROOT', root):
                with self.assertRaisesRegex(RuntimeError, 'aliases'):
                    adapter.read(root / 'alias')


if __name__ == '__main__':
    unittest.main()
