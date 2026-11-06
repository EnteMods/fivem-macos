"""Core-only transaction checks against own temporary bytes, never a live prefix."""
from contextlib import contextmanager, nullcontext
import copy
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
import lifecycle_diagnostic_identity as policy
import prepare_lifecycle_diagnostic as update
import run_main


class LifecycleUpdateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.stage = self.root / 'build/windows-source-integration'
        self.stage.mkdir(parents=True)
        self.old, self.new = b'own old Core 8', b'own diagnostic Core 9'
        self.old_sha, self.new_sha = [hashlib.sha256(value).hexdigest() for value in (self.old, self.new)]
        self.put(policy.SOURCE, self.new)
        self.put(policy.BACKUP, self.old)
        self.put('build/windows-source-integration/CoreRT.dll', self.old)
        self.previous = {'at': 'own-v8', 'source_revision': run_main.REVISION, 'developer_code_version': 8,
            'role': 'own original role', 'manual_login_user_confirmed': True,
            'auth_confirmation_evidence': 'research/own-confirmation.json',
            'files': [{'name': 'CoreRT.dll', 'sha256': self.old_sha, 'bytes': len(self.old), 'origin': 'own-v8'},
                      {'name': 'legitimacy.dll', 'sha256': 'd'*64, 'bytes': 8, 'origin': 'unchanged vendor'},
                      {'name': 'FiveM.exe.formaldev', 'sha256': 'e'*64, 'bytes': 2}]}
        self.save(policy.PREVIOUS_MANIFEST, self.previous)
        self.evidence = [{'path': policy.BUILD_RECORD, 'sha256': 'f'*64}]
        self.transaction = {'at': 'own-v9', 'source_revision': run_main.REVISION, 'developer_code_version': 9,
            'lifecycle_previous_manifest': policy.PREVIOUS_MANIFEST,
            'lifecycle_previous_manifest_sha256': run_main.sha(self.root / policy.PREVIOUS_MANIFEST),
            'previous_sha256': self.old_sha, 'new_sha256': self.new_sha, 'source': policy.SOURCE,
            'target': 'build/windows-source-integration/CoreRT.dll', 'previous_code_backup': policy.BACKUP,
            'header_checks': {'passed': 3, 'exit': 0}, 'diagnostic_evidence': self.evidence,
            'only_own_core_file_updated': True, 'main_citigame_and_original_modules_unchanged': True,
            'original_conditions_returns_mapping_authentication_and_security_decisions_preserved': True,
            'v9_wine_runtime_fixture_claim': False, 'profiles_sessions_tickets_read_copied_or_reset': False}
        self.save(policy.TRANSACTION, self.transaction)
        self.record = copy.deepcopy(self.previous)
        self.record.update(developer_code_version=9, lifecycle_previous_manifest=policy.PREVIOUS_MANIFEST,
            lifecycle_previous_manifest_sha256=run_main.sha(self.root / policy.PREVIOUS_MANIFEST),
            lifecycle_update_transaction=policy.TRANSACTION,
            lifecycle_update_transaction_sha256=run_main.sha(self.root / policy.TRANSACTION))
        self.record['files'][0].update(sha256=self.new_sha, bytes=len(self.new), origin=policy.ORIGIN)
        self.patches = [mock.patch.object(policy, 'ROOT', self.root), mock.patch.object(update, 'ROOT', self.root),
            mock.patch.object(update, 'STAGE', self.stage), mock.patch.object(run_main, 'ROOT', self.root),
            mock.patch.object(policy, 'CORE_SHA256', self.new_sha), mock.patch.object(policy, 'BUILD_RECORD_SHA256', 'b'*64),
            mock.patch.object(policy, 'TBB_SHA256', 'c'*64),
            mock.patch.object(policy, 'PREVIOUS_CORE_SHA256', self.old_sha),
            mock.patch.object(policy.previous_version, 'validate_version'),
            mock.patch.object(policy, 'validate_evidence', return_value=self.evidence)]
        for patch in self.patches:
            patch.start()

    def tearDown(self):
        for patch in reversed(self.patches):
            patch.stop()
        self.temp.cleanup()

    def put(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)

    def save(self, name, value):
        self.put(name, json.dumps(value).encode())

    def test_only_core_changes_and_original_v8_metadata_and_types_remain(self):
        policy.validate_version(self.record)
        policy.previous_version.validate_version.assert_called_once_with(self.previous)
        for kind in ('role', 'legitimacy', 'formaldev', 'order', 'bool', 'float', 'extra'):
            invalid = copy.deepcopy(self.record)
            if kind == 'role': invalid['role'] = 'different'
            elif kind == 'legitimacy': invalid['files'][1]['sha256'] = '0'*64
            elif kind == 'formaldev': invalid['files'][2]['bytes'] = 3
            elif kind == 'order': invalid['files'].reverse()
            elif kind == 'bool': invalid['manual_login_user_confirmed'] = 1
            elif kind == 'float': invalid['files'][2]['bytes'] = 2.0
            else: invalid['unapproved'] = True
            with self.subTest(kind=kind), self.assertRaises(RuntimeError):
                policy.validate_version(invalid)

    def test_private_reference_rejected_without_read_or_hash(self):
        private = self.root / 'prefixes/private/user.reg'
        invalid = copy.deepcopy(self.record)
        invalid['auth_confirmation_evidence'] = 'prefixes/private/user.reg'
        with mock.patch.object(policy, 'sha', wraps=policy.sha) as hashed, self.assertRaisesRegex(RuntimeError, 'preserve'):
            policy.validate_version(invalid)
        self.assertNotIn(mock.call(private), hashed.call_args_list)

    def test_missing_final_pins_fail_before_lock_and_code_reads(self):
        import source_main_environment
        with mock.patch.object(policy, 'BUILD_RECORD_SHA256', None), \
                mock.patch.object(source_main_environment, 'source_main_prefix') as locked, \
                mock.patch.object(update, 'validate_code_inputs') as read, self.assertRaisesRegex(RuntimeError, 'not been admitted'):
            update.main()
        locked.assert_not_called()
        read.assert_not_called()

    def reset(self):
        (self.root / policy.BACKUP).unlink()
        (self.root / policy.TRANSACTION).unlink()

    def own_process(self, command, **kwargs):
        if command[:3] == ['/bin/cp', '-c', '-n']:
            self.assertFalse(Path(command[4]).exists())
            shutil.copyfile(command[3], command[4])
            return SimpleNamespace(returncode=0)
        self.assertEqual(command[1:4], ['-m', 'unittest', 'discover'])
        return SimpleNamespace(returncode=0, stderr='Ran 3 tests in 0.1s\n\nOK\n')

    def transaction_context(self, final):
        import source_main_environment
        return (mock.patch.object(source_main_environment, 'source_main_prefix', return_value=nullcontext()),
                mock.patch.object(update, 'validate_code_inputs', side_effect=[self.previous, self.previous, final]),
                mock.patch.object(update.subprocess, 'run', side_effect=self.own_process))

    def test_success_preserves_previous_manifest_and_all_noncore_metadata(self):
        self.reset()
        before = (self.root / policy.PREVIOUS_MANIFEST).read_bytes()
        first, second, third = self.transaction_context(self.record)
        with first, second, third:
            update.main()
        self.assertEqual((self.stage / 'CoreRT.dll').read_bytes(), self.new)
        self.assertEqual((self.root / policy.BACKUP).read_bytes(), self.old)
        self.assertEqual((self.root / policy.PREVIOUS_MANIFEST).read_bytes(), before)
        result = json.loads((self.root / policy.MANIFEST).read_text())
        self.assertEqual(result['files'][1:], self.previous['files'][1:])
        policy.validate_version(result)

    def test_postcheck_failure_rolls_back_only_core_and_new_metadata(self):
        self.reset()
        first, second, third = self.transaction_context(RuntimeError('own final guard'))
        with first, second, third, self.assertRaisesRegex(RuntimeError, 'own final guard'):
            update.main()
        self.assertEqual((self.stage / 'CoreRT.dll').read_bytes(), self.old)
        self.assertEqual((self.root / policy.BACKUP).read_bytes(), self.old)
        self.assertFalse((self.root / policy.MANIFEST).exists())
        self.assertFalse((self.root / policy.TRANSACTION).exists())
        self.assertFalse(list(self.stage.glob('.*.pending')))

    def test_intervening_output_after_lock_blocks_before_code_access(self):
        self.reset()
        @contextmanager
        def intervening(*args, **kwargs):
            self.put(policy.MANIFEST, b'own intervening output')
            yield
        import source_main_environment
        with mock.patch.object(source_main_environment, 'source_main_prefix', side_effect=intervening), \
                mock.patch.object(update, 'validate_code_inputs') as read, \
                mock.patch.object(update.subprocess, 'run') as process, self.assertRaises(RuntimeError):
            update.main()
        read.assert_not_called()
        process.assert_not_called()

    def test_foreign_build_path_rejected_before_selected_code_read(self):
        # The report is readable; every data-provided code role must still be admitted first.
        def row(name): return {'path': name, 'bytes': 1, 'sha256': 'a'*64}
        build = {'artifact': row(policy.SOURCE), 'tbb_artifact': row(policy.TBB),
            'base_v8_build_record': row(policy.previous_version.BUILD_RECORD), 'original_seh': row(policy.ORIGINAL),
            'base_v8_overlay': [row(name) for name in sorted(policy.BASE_OVERLAY)],
            'source_evidence': [row(name) for name in sorted(policy.EXPECTED_SOURCES)],
            'generated_overlay': [row(name) for name in sorted(policy.EXPECTED_OVERLAY)],
            'build': {key: row(name) for key, name in policy.BUILD_FILES.items()},
            'header_and_overlay_tests': {'log': row(policy.HEADER_LOG)},
            'preserved_original_and_v8_input_sha256': {name: 'a'*64 for name in policy.PRESERVED_INPUTS}}
        build['source_evidence'][0]['path'] = 'prefixes/private/user.reg'
        self.save(policy.BUILD_RECORD, build)
        raw = (self.root / policy.BUILD_RECORD).read_bytes()
        import importlib.util
        spec = importlib.util.spec_from_file_location('_own_lifecycle_policy_test', PROJECT / 'native/windows-client/lifecycle_diagnostic_identity.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.CORE_SHA256, module.BUILD_RECORD_SHA256 = self.new_sha, hashlib.sha256(raw).hexdigest()
        module.TBB_SHA256 = 'c'*64
        with mock.patch.object(module, 'sha', wraps=module.sha) as hashed, \
                self.assertRaisesRegex(RuntimeError, 'input path set'):
            module.validate_evidence(self.root)
        self.assertEqual(hashed.call_args_list, [])


if __name__ == '__main__':
    unittest.main()
