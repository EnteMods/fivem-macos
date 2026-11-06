import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import stage_official_client_update as update


def manifest(*names):
    root = ET.Element('CacheInfo')
    for name in names:
        ET.SubElement(root, 'ContentFile', Name=name, Size='3', CompressedSize='64',
                      SHA1Hash=hashlib.sha1(b'abc').hexdigest(), SHA256Hash=hashlib.sha256(b'abc').hexdigest())
    raw = ET.tostring(root)
    return raw, hashlib.sha256(raw).hexdigest()


class StageOfficialClientUpdateTests(unittest.TestCase):
    def test_manifest_hash_and_xz_larger_than_source(self):
        raw, digest = manifest('bin/own.dll')
        file, = update.parse_manifest(raw, digest)
        self.assertEqual((file.size, file.packed_size), (3, 64))
        with self.assertRaisesRegex(ValueError, 'pinned SHA-256'):
            update.parse_manifest(raw, '0' * 64)

    def test_unsafe_names_and_collisions_rejected(self):
        for names in (('../own.dll',), ('/own.dll',), ('bin/../own.dll',), ('bin\\own.dll',),
                      ('bin/Own.dll', 'bin/own.dll'), ('bin', 'bin/own.dll')):
            with self.subTest(names=names), self.assertRaises(ValueError):
                update.parse_manifest(*manifest(*names))

    def test_seed_requires_hash_even_with_matching_size(self):
        file, = update.parse_manifest(*manifest('own.dll'))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            dll = root / 'own.dll'
            dll.write_bytes(b'bad')
            self.assertIsNone(update.read_seed(root, file))
            dll.write_bytes(b'abc')
            self.assertEqual(update.read_seed(root, file), b'abc')
