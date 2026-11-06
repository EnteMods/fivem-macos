"""Exercise only temporary graphics files and mocked lock/cp/native-test commands."""
from contextlib import contextmanager, nullcontext
import hashlib
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
import graphics_diagnostic_identity as policy
import prepare_graphics_diagnostic as update
import run_main
from test_graphics_diagnostic_identity import put, save, version_fixture
import test_graphics_diagnostic_identity as identity_tests


class GraphicsTransactionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.stage = self.root / 'build/windows-source-integration'
        self.stage.mkdir(parents=True)
        self.old, self.new, self.previous, self.expected, self.evidence = version_fixture(self.root)
        (self.root / policy.BACKUP).unlink()
        (self.root / policy.TRANSACTION).unlink()
        put(self.root, 'build/windows-source-integration/rage-graphics-five.dll', self.old)
        self.core = self.stage / 'CoreRT.dll'
        self.core.write_bytes(b'own unchanged Core10')
        self.vendor = self.stage / 'legitimacy.dll'
        self.vendor.write_bytes(b'own unchanged vendor control')
        for patch in (mock.patch.object(policy, 'ROOT', self.root), mock.patch.object(update, 'ROOT', self.root),
            mock.patch.object(update, 'STAGE', self.stage), mock.patch.object(run_main, 'ROOT', self.root),
            mock.patch.object(policy, 'GRAPHICS_SHA256', hashlib.sha256(self.new).hexdigest()),
            mock.patch.object(policy, 'PREVIOUS_GRAPHICS_SHA256', hashlib.sha256(self.old).hexdigest()),
            mock.patch.object(policy, 'BUILD_RECORD_SHA256', 'b' * 64),
            mock.patch.object(policy.previous_version, 'validate_version')):
            patch.start()
            self.addCleanup(patch.stop)
        self.evidence_patch = mock.patch.object(policy, 'validate_evidence', return_value=self.evidence)
        self.evidence_patch.start()
        self.addCleanup(self.evidence_patch.stop)

    def own_command(self, command, **kwargs):
        if command[:3] == ['/bin/cp', '-c', '-n']:
            self.assertFalse(Path(command[4]).exists())
            shutil.copyfile(command[3], command[4])
            return SimpleNamespace(returncode=0)
        self.assertEqual(command[1:4], ['-m', 'unittest', 'discover'])
        return SimpleNamespace(returncode=0, stderr='Ran 3 tests in 0.1s\n\nOK\n')

    def controls(self, final):
        import source_main_environment
        return (mock.patch.object(source_main_environment, 'source_main_prefix', return_value=nullcontext()),
                mock.patch.object(update, 'validate_code_inputs', side_effect=[self.previous, self.previous, final]),
                mock.patch.object(update.subprocess, 'run', side_effect=self.own_command))

    def test_success_changes_only_graphics_and_keeps_vendor_backup_and_v10_metadata(self):
        previous_raw = (self.root / policy.PREVIOUS_MANIFEST).read_bytes()
        core_raw, vendor_raw = self.core.read_bytes(), self.vendor.read_bytes()
        first, second, third = self.controls(self.expected)
        with first, second as validated, third:
            update.main()
        record = json.loads((self.root / policy.MANIFEST).read_bytes())
        self.assertEqual((self.stage / 'rage-graphics-five.dll').read_bytes(), self.new)
        self.assertEqual((self.root / policy.BACKUP).read_bytes(), self.old)
        self.assertNotEqual((self.root / policy.BACKUP).stat().st_ino, (self.stage / 'rage-graphics-five.dll').stat().st_ino)
        self.assertEqual((self.root / policy.PREVIOUS_MANIFEST).read_bytes(), previous_raw)
        self.assertEqual(record['files'][1:], self.previous['files'][1:])
        self.assertEqual((self.core.read_bytes(), self.vendor.read_bytes()), (core_raw, vendor_raw))
        self.assertEqual(validated.call_args_list, [mock.call(self.root / policy.PREVIOUS_MANIFEST),
                         mock.call(self.root / policy.PREVIOUS_MANIFEST), mock.call(self.root / policy.MANIFEST)])
        policy.validate_version(record)

    def test_final_guard_failure_rolls_back_graphics_and_removes_only_new_metadata(self):
        first, second, third = self.controls(RuntimeError('own final guard'))
        with first, second, third, self.assertRaisesRegex(RuntimeError, 'own final guard'):
            update.main()
        self.assertEqual((self.stage / 'rage-graphics-five.dll').read_bytes(), self.old)
        self.assertEqual((self.root / policy.BACKUP).read_bytes(), self.old)
        self.assertFalse((self.root / policy.MANIFEST).exists())
        self.assertFalse((self.root / policy.TRANSACTION).exists())
        self.assertFalse(list(self.stage.glob('.*.pending')))
        self.assertEqual(self.core.read_bytes(), b'own unchanged Core10')
        self.assertEqual(self.vendor.read_bytes(), b'own unchanged vendor control')

    def test_missing_build_pin_fails_before_lock_code_reads_or_commands(self):
        import source_main_environment
        with mock.patch.object(policy, 'BUILD_RECORD_SHA256', None), \
                mock.patch.object(source_main_environment, 'source_main_prefix') as lock, \
                mock.patch.object(update, 'validate_code_inputs') as validate, \
                mock.patch.object(update.subprocess, 'run') as commands, \
                self.assertRaisesRegex(RuntimeError, 'not been admitted'):
            update.main()
        lock.assert_not_called()
        validate.assert_not_called()
        commands.assert_not_called()

    def test_output_appearing_during_lock_or_failed_native_checks_never_changes_graphics(self):
        import source_main_environment
        @contextmanager
        def intervening(*args, **kwargs):
            save(self.root, policy.MANIFEST, {'own_intervening_output': True})
            yield
        with mock.patch.object(source_main_environment, 'source_main_prefix', side_effect=intervening), \
                mock.patch.object(update, 'validate_code_inputs') as validate, \
                mock.patch.object(update.subprocess, 'run') as commands, self.assertRaises(RuntimeError):
            update.main()
        validate.assert_not_called()
        commands.assert_not_called()
        (self.root / policy.MANIFEST).unlink()
        first, second, third = self.controls(None)
        with first, second, third as commands:
            commands.side_effect = lambda *a, **k: SimpleNamespace(returncode=1, stderr='own failed native check')
            with self.assertRaisesRegex(RuntimeError, 'checks must pass'):
                update.main()
        self.assertFalse((self.root / policy.BACKUP).exists())
        self.assertEqual((self.stage / 'rage-graphics-five.dll').read_bytes(), self.old)

    def test_real_evidence_validator_survives_swap_and_retries_with_preserved_backup(self):
        import source_main_environment
        self.evidence_patch.stop()
        build, baseline_id = identity_tests.GraphicsIdentityTests.build_fixture(self)
        identity_tests.GraphicsIdentityTests.build_controls(self, build, baseline_id)
        self.new = (self.root / policy.SOURCE).read_bytes()
        old_manifest_raw = (self.root / policy.PREVIOUS_MANIFEST).read_bytes()

        def validate(path):
            if path == self.root / policy.PREVIOUS_MANIFEST:
                self.assertEqual((self.stage / 'rage-graphics-five.dll').read_bytes(), self.old)
                return self.previous
            record = json.loads(path.read_bytes())
            policy.validate_version(record)
            return record

        with mock.patch.object(policy.previous_version, 'validate_evidence', return_value=[]), \
                mock.patch.object(source_main_environment, 'source_main_prefix', return_value=nullcontext()), \
                mock.patch.object(update, 'validate_code_inputs', side_effect=validate), \
                mock.patch.object(update.subprocess, 'run', side_effect=self.own_command):
            before = policy.validate_evidence(self.root)
            self.assertIn({'path': policy.HISTORICAL_GRAPHICS, 'sha256': hashlib.sha256(self.old).hexdigest()}, before)
            update.main()
            record = json.loads((self.root / policy.MANIFEST).read_bytes())
            transaction = json.loads((self.root / policy.TRANSACTION).read_bytes())
            after = policy.validate_evidence(self.root)
            self.assertEqual(transaction['diagnostic_evidence'], after)
            self.assertIn({'path': policy.BACKUP, 'sha256': hashlib.sha256(self.old).hexdigest()}, after)
            self.assertFalse(any(row['path'] == policy.HISTORICAL_GRAPHICS for row in after))
            self.assertEqual((self.stage / 'rage-graphics-five.dll').read_bytes(), self.new)
            self.assertEqual(record['files'][1:], self.previous['files'][1:])
            backup = self.root / policy.BACKUP
            backup_identity = (backup.stat().st_dev, backup.stat().st_ino, backup.read_bytes())
            # Simulate a prior completed rollback, keeping the proven fixed-path backup.
            (self.stage / 'rage-graphics-five.dll').write_bytes(self.old)
            (self.root / policy.MANIFEST).unlink()
            (self.root / policy.TRANSACTION).unlink()
            update.main()
            self.assertEqual((backup.stat().st_dev, backup.stat().st_ino, backup.read_bytes()), backup_identity)
            self.assertEqual((self.root / policy.PREVIOUS_MANIFEST).read_bytes(), old_manifest_raw)
            self.assertEqual((self.stage / 'rage-graphics-five.dll').read_bytes(), self.new)

    def test_existing_wrong_backup_is_rejected_before_lock_or_commands(self):
        import source_main_environment
        backup = self.root / policy.BACKUP
        put(self.root, policy.BACKUP, b'own unknown backup bytes')
        with mock.patch.object(source_main_environment, 'source_main_prefix') as locked, \
                mock.patch.object(update.subprocess, 'run') as commands, self.assertRaisesRegex(RuntimeError, 'backup differs'):
            update.main()
        locked.assert_not_called()
        commands.assert_not_called()
        self.assertEqual(backup.read_bytes(), b'own unknown backup bytes')
        self.assertEqual((self.stage / 'rage-graphics-five.dll').read_bytes(), self.old)


if __name__ == '__main__':
    unittest.main()
