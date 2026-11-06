import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('distribution_guard', ROOT / 'scripts/check_distribution.py')
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class DistributionGuardTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        self.stage = root / 'stage'
        self.stage.mkdir()
        self.manifest = root / 'approved.json'

    def file(self, name, data):
        path = self.stage / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return {'path': name, 'sha256': hashlib.sha256(data).hexdigest(), 'origin': 'own fixture', 'license': 'MIT'}

    def verify(self, mode, *rows):
        self.manifest.write_text(json.dumps({'mode': mode, 'files': list(rows)}))
        return guard.verify(self.stage, self.manifest, mode)

    def test_source_and_installer_require_exact_content(self):
        row = self.file('src/launcher.swift', b'// own test\n')
        self.assertEqual(self.verify('source', row), 1)
        app = self.file('Own.app/Contents/MacOS/launcher', b'\xcf\xfa\xed\xfe\x00fixture')
        self.assertEqual(self.verify('installer', row, app), 2)
        with self.assertRaisesRegex(ValueError, 'text source only'):
            self.verify('source', row, app)
        self.file('src/launcher.swift', b'// changed\n')
        with self.assertRaisesRegex(ValueError, 'changed staging bytes'):
            self.verify('installer', row, app)

    def test_game_and_profile_paths_rejected_even_with_explicit_allowlist(self):
        for name in ('App/Resources/UPDATE.RPF', 'Game/GTA5.EXE', 'profiles/user.txt', 'Contents/data/system.reg',
                     'Contents/Resources/scene.ydr', 'research/private.json', 'Contents/FiveM.exe'):
            with self.subTest(name=name):
                row = self.file(name, b'fixture')
                with self.assertRaisesRegex(ValueError, 'path excluded'):
                    self.verify('installer', row)
                (self.stage / name).unlink()

    def test_renamed_game_or_archive_magic_is_rejected_in_both_modes(self):
        for signature in (b'7FPR', b'RPF7', b'RSC7', b'PK\x03\x04', b'\x1f\x8b', b'\0' * 257 + b'ustar',
                          b'payload' + b'koly' + b'\0' * 500):
            with self.subTest(signature=signature):
                row = self.file('innocent.txt', signature + b'\0fixture')
                for mode in ('source', 'installer'):
                    with self.assertRaisesRegex(ValueError, 'signature excluded'):
                        self.verify(mode, row)

    def test_renamed_known_game_executable_hash_and_binary_source(self):
        row = self.file('README.txt', b'MZ\0fixture')
        with patch.object(guard, 'KNOWN_GAME_HASHES', {row['sha256']}):
            with self.assertRaisesRegex(ValueError, 'Game executable'):
                self.verify('installer', row)
        with self.assertRaisesRegex(ValueError, 'Binary data'):
            self.verify('source', row)

    def test_extra_missing_and_linked_files_are_rejected(self):
        row = self.file('allowed.txt', b'own file')
        extra = self.file('extra.txt', b'extra file')
        with self.assertRaisesRegex(ValueError, 'Undeclared'):
            self.verify('source', row)
        (self.stage / extra['path']).unlink()
        with self.assertRaisesRegex(ValueError, 'Missing'):
            self.verify('source', row, extra)
        (self.stage / 'linked.txt').symlink_to(self.stage / 'allowed.txt')
        with self.assertRaisesRegex(ValueError, 'link excluded'):
            self.verify('source', row, dict(row, path='linked.txt'))
        (self.stage / 'linked.txt').unlink()
        os.link(self.stage / 'allowed.txt', self.stage / 'linked.txt')
        with self.assertRaisesRegex(ValueError, 'independent regular file'):
            self.verify('source', row, dict(row, path='linked.txt'))

    def test_manifest_rejects_duplicate_paths_and_incomplete_provenance(self):
        row = self.file('allowed.txt', b'own file')
        with self.assertRaisesRegex(ValueError, 'Duplicate case-folded'):
            self.verify('source', row, dict(row, path='ALLOWED.txt'))
        with self.assertRaisesRegex(ValueError, 'origin and license'):
            self.verify('source', dict(row, license=''))
