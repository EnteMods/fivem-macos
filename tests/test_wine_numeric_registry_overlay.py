"""Only fixed registry byte transformations; no source writes or build actions."""
import hashlib
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('own_numeric_registry_overlay', ROOT / 'native/wine-numeric-diagnostics/registry_overlay.py')
registry = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(registry)


class NumericRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = (ROOT / 'build/wine-job-query/source' / registry.SOURCE).read_bytes()

    def test_exact_one_header_registration_and_byte_exact_roundtrip(self):
        result, proof = registry.apply_all({registry.SOURCE: self.original})
        self.assertEqual(set(result), {registry.SOURCE})
        self.assertEqual(result[registry.SOURCE].count(registry.ENTRY), 1)
        self.assertEqual(registry.strip(registry.SOURCE, result[registry.SOURCE]), self.original)
        self.assertTrue(proof['stripped_equals_original'])
        self.assertEqual(proof['registration_entries_added'], 1)

    def test_sources_list_and_sorted_local_anchor_are_preserved(self):
        result, _ = registry.apply_all({registry.SOURCE: self.original})
        changed = result[registry.SOURCE]
        self.assertTrue(changed.startswith(b'SOURCES = \\\n'))
        self.assertIn(registry.ANCHOR + registry.ENTRY + b'\twine/condrv.h \\\n', changed)
        self.assertEqual(changed.replace(registry.ENTRY, b'', 1), self.original)

    def test_changed_or_already_registered_original_is_rejected(self):
        changed, _ = registry.apply_all({registry.SOURCE: self.original})
        for source in (self.original + b'\n', changed[registry.SOURCE], bytearray(self.original)):
            with self.assertRaises(RuntimeError):
                registry.apply_all({registry.SOURCE: source})

    def test_missing_extra_or_foreign_paths_cannot_select_input_files(self):
        for source in ({}, {'../private': self.original}, {registry.SOURCE: self.original, 'extra': b'own'}):
            with self.assertRaises(RuntimeError):
                registry.apply_all(source)
        with self.assertRaises(RuntimeError):
            registry.strip('/private/foreign', self.original)

    def test_duplicate_reordered_or_outside_scope_edits_cannot_strip(self):
        result, _ = registry.apply_all({registry.SOURCE: self.original})
        changed = result[registry.SOURCE]
        for source in (changed + registry.ENTRY, changed + b'\n',
                       changed.replace(registry.ANCHOR + registry.ENTRY, registry.ENTRY + registry.ANCHOR, 1)):
            with self.assertRaises(RuntimeError):
                registry.strip(registry.SOURCE, source)
        self.assertEqual(hashlib.sha256(self.original).hexdigest(), registry.SOURCE_SHA256)


if __name__ == '__main__':
    unittest.main()
