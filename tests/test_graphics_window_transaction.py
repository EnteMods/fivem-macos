"""Real new evidence validation across temporary graphics swaps; old V11 proof mocked."""
from contextlib import nullcontext
import copy
import json
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / 'native/windows-client'))
import graphics_window_identity as policy
import prepare_graphics_window as update
from test_graphics_window_identity import fixture, bind


class GraphicsWindowTransactionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.value = fixture(self.root)
        bind(self, self.value)
        self.stage = self.root / 'build/windows-source-integration'
        self.target = self.stage / 'rage-graphics-five.dll'
        self.backup = self.root / policy.BACKUP
        for patch in (mock.patch.object(update, 'ROOT', self.root), mock.patch.object(update, 'STAGE', self.stage)):
            patch.start()
            self.addCleanup(patch.stop)

    def own_command(self, command, **kwargs):
        if command[:3] == ['/bin/cp', '-c', '-n']:
            self.assertFalse(Path(command[4]).exists())
            shutil.copyfile(command[3], command[4])
            return SimpleNamespace(returncode=0)
        self.assertEqual(command[1:4], ['-m', 'unittest', 'discover'])
        return SimpleNamespace(returncode=0, stderr='Ran 3 tests in 0.1s\n\nOK\n')

    def validate(self, path):
        if path == self.root / policy.PREVIOUS_MANIFEST:
            self.assertEqual(self.target.read_bytes(), self.value['old'])
            return self.value['previous']
        record = json.loads(path.read_bytes())
        policy.validate_version(record)
        self.assertEqual(self.target.read_bytes(), self.value['new'])
        return record

    def controls(self, final=None):
        import source_main_environment
        def checked(path):
            result = self.validate(path)
            if path == self.root / policy.MANIFEST and final is not None:
                raise final
            return result
        return (mock.patch.object(source_main_environment, 'source_main_prefix', return_value=nullcontext()),
                mock.patch.object(update, 'validate_code_inputs', side_effect=checked),
                mock.patch.object(update.subprocess, 'run', side_effect=self.own_command))

    def test_real_validator_postswap_retry_preserves_core473_and_original_vendor_backup(self):
        previous_raw = (self.root / policy.PREVIOUS_MANIFEST).read_bytes()
        vendor = self.root / policy.previous_version.BACKUP
        vendor_identity = (vendor.stat().st_dev, vendor.stat().st_ino, vendor.read_bytes())
        core = (self.stage / 'CoreRT.dll').read_bytes()
        first, second, third = self.controls()
        with first, second, third:
            update.main()
            record = json.loads((self.root / policy.MANIFEST).read_bytes())
            transaction = json.loads((self.root / policy.TRANSACTION).read_bytes())
            self.assertEqual(transaction['diagnostic_evidence'], policy.validate_evidence(self.root))
            self.assertEqual(record['files'][1:], self.value['previous']['files'][1:])
            self.assertEqual(self.backup.read_bytes(), self.value['old'])
            self.assertNotEqual(self.backup.stat().st_ino, self.target.stat().st_ino)
            checkpoint = (self.backup.stat().st_ino, self.backup.read_bytes())
            self.target.write_bytes(self.value['old'])
            (self.root / policy.MANIFEST).unlink()
            (self.root / policy.TRANSACTION).unlink()
            update.main()
        self.assertEqual((self.backup.stat().st_ino, self.backup.read_bytes()), checkpoint)
        self.assertEqual((vendor.stat().st_dev, vendor.stat().st_ino, vendor.read_bytes()), vendor_identity)
        self.assertEqual((self.stage / 'CoreRT.dll').read_bytes(), core)
        self.assertEqual((self.root / policy.PREVIOUS_MANIFEST).read_bytes(), previous_raw)

    def test_metadata_or_other_file_changes_rejected_by_real_version_validator(self):
        first, second, third = self.controls()
        with first, second, third:
            update.main()
        original = json.loads((self.root / policy.MANIFEST).read_bytes())
        for kind in ('core', 'vendor', 'formaldev', 'order', 'type', 'role', 'private-reference'):
            record = copy.deepcopy(original)
            if kind == 'core': record['files'][1]['sha256'] = '0' * 64
            elif kind == 'vendor': record['files'][2]['bytes'] += 1
            elif kind == 'formaldev': record['files'][3]['bytes'] += 1
            elif kind == 'order': record['files'][1:3] = reversed(record['files'][1:3])
            elif kind == 'type': record['files'][3]['bytes'] = 2.0
            elif kind == 'role': record['role'] = 'other source role'
            else: record['auth_confirmation_evidence'] = 'prefixes/private/user.reg'
            with self.subTest(kind=kind), self.assertRaises(RuntimeError):
                policy.validate_version(record)

    def test_final_failure_rolls_back_graphics_and_only_new_metadata(self):
        vendor = self.root / policy.previous_version.BACKUP
        vendor_raw = vendor.read_bytes()
        first, second, third = self.controls(RuntimeError('own final guard failure'))
        with first, second, third, self.assertRaisesRegex(RuntimeError, 'own final guard failure'):
            update.main()
        self.assertEqual(self.target.read_bytes(), self.value['old'])
        self.assertEqual(self.backup.read_bytes(), self.value['old'])
        self.assertFalse((self.root / policy.MANIFEST).exists())
        self.assertFalse((self.root / policy.TRANSACTION).exists())
        self.assertFalse(list(self.stage.glob('.*.pending')))
        self.assertEqual(vendor.read_bytes(), vendor_raw)

    def test_missing_pin_existing_output_or_unknown_backup_blocks_before_commands(self):
        import source_main_environment
        for kind in ('pin', 'output', 'backup'):
            if kind == 'output': (self.root / policy.MANIFEST).write_bytes(b'own existing output')
            if kind == 'backup':
                self.backup.parent.mkdir(parents=True, exist_ok=True)
                self.backup.write_bytes(b'own unknown backup')
            with self.subTest(kind=kind), mock.patch.object(source_main_environment, 'source_main_prefix') as lock, \
                    mock.patch.object(update.subprocess, 'run') as commands, \
                    mock.patch.object(policy, 'BUILD_RECORD_SHA256', None if kind == 'pin' else policy.BUILD_RECORD_SHA256), \
                    self.assertRaises(RuntimeError):
                update.main()
            lock.assert_not_called()
            commands.assert_not_called()
            if kind == 'output': (self.root / policy.MANIFEST).unlink()
        self.assertEqual(self.target.read_bytes(), self.value['old'])


if __name__ == '__main__':
    unittest.main()
