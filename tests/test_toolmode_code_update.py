"""Own temporary code/evidence fixtures; no real stage, Wine or prefix access."""
from contextlib import contextmanager, nullcontext
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / 'native/windows-client'))
import toolmode_diagnostic_identity as policy
import file_policy_diagnostic_identity as hook
import prepare_toolmode_diagnostic as update
import source_code_identity as identity


class ToolModeCodeUpdateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.stage = self.root / 'build/windows-source-integration'
        self.stage.mkdir(parents=True)
        self.old, self.new = b'own previous Core', b'own next Core'
        self.old_sha, self.new_sha = [hashlib.sha256(value).hexdigest() for value in (self.old, self.new)]
        self.write_bytes(policy.SOURCE, self.new)
        self.write_bytes(policy.BACKUP, self.old)
        self.previous = {'at': 'own-v6', 'source_revision': identity.REVISION, 'developer_code_version': 7,
            'stage': 'build/windows-source-integration', 'prefix_is_account_free': False,
            'manual_login_user_confirmed': True, 'role': 'own original role',
            'hook_previous_manifest': 'research/own-v5.json', 'hook_previous_manifest_sha256': 'a'*64,
            'hook_update_transaction': 'research/own-v6-transaction.json', 'hook_update_transaction_sha256': 'b'*64,
            'auth_confirmation_evidence': 'research/own-confirmation.json', 'auth_confirmation_evidence_sha256': 'c'*64,
            'files': [{'name': 'CoreRT.dll', 'sha256': self.old_sha, 'bytes': len(self.old), 'origin': 'own-v6'},
                      {'name': 'FiveM.exe', 'sha256': 'd'*64, 'bytes': 1}]}
        self.write_json(policy.PREVIOUS_MANIFEST, self.previous)
        self.evidence = [{'path': policy.BUILD_RECORD, 'sha256': 'e'*64}]
        self.transaction = {'source_revision': identity.REVISION, 'developer_code_version': 8,
            'toolmode_previous_manifest': policy.PREVIOUS_MANIFEST,
            'toolmode_previous_manifest_sha256': identity.sha(self.root / policy.PREVIOUS_MANIFEST),
            'previous_sha256': self.old_sha, 'new_sha256': self.new_sha, 'source': policy.SOURCE,
            'target': 'build/windows-source-integration/CoreRT.dll', 'previous_code_backup': policy.BACKUP,
            'header_checks': {'passed': 8, 'exit': 0}, 'diagnostic_evidence': self.evidence,
            'only_own_core_file_updated': True, 'main_citigame_and_original_modules_unchanged': True,
            'original_conditions_returns_mapping_authentication_and_security_decisions_preserved': True,
            'v8_wine_runtime_fixture_claim': False,
            'profiles_sessions_tickets_read_copied_or_reset': False}
        self.write_json(policy.TRANSACTION, self.transaction)
        self.record = copy.deepcopy(self.previous)
        self.record.update(developer_code_version=8, toolmode_previous_manifest=policy.PREVIOUS_MANIFEST,
            toolmode_previous_manifest_sha256=identity.sha(self.root / policy.PREVIOUS_MANIFEST),
            toolmode_update_transaction=policy.TRANSACTION,
            toolmode_update_transaction_sha256=identity.sha(self.root / policy.TRANSACTION))
        self.record['files'][0].update(sha256=self.new_sha, bytes=len(self.new), origin=policy.ORIGIN)
        self.patches = [mock.patch.object(policy, 'ROOT', self.root), mock.patch.object(update, 'ROOT', self.root),
                       mock.patch.object(update, 'STAGE', self.stage), mock.patch.dict(identity.plain.__globals__, ROOT=self.root),
                       mock.patch.object(policy, 'CORE_SHA256', self.new_sha),
                       mock.patch.object(policy, 'PREVIOUS_CORE_SHA256', self.old_sha),
                       mock.patch.object(hook, 'validate_version'),
                       mock.patch.object(policy, 'validate_evidence', return_value=self.evidence)]
        for patch in self.patches: patch.start()

    def tearDown(self):
        for patch in reversed(self.patches): patch.stop()
        self.temp.cleanup()

    def write_bytes(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)

    def write_json(self, name, value):
        self.write_bytes(name, json.dumps(value).encode())

    def test_exact_predecessor_and_only_core_delta_admitted(self):
        policy.validate_version(self.record)
        hook.validate_version.assert_called_once_with(self.previous)
        for change in ('role', 'noncore', 'order', 'reference', 'extra', 'origin'):
            invalid = copy.deepcopy(self.record)
            if change == 'role': invalid['role'] = 'different role'
            elif change == 'noncore': invalid['files'][1]['sha256'] = '0'*64
            elif change == 'order': invalid['files'].reverse()
            elif change == 'reference': invalid['toolmode_previous_manifest'] = 'research/own-v5.json'
            elif change == 'extra': invalid['unapproved'] = True
            else: invalid['files'][0]['origin'] = 'unbound'
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                policy.validate_version(invalid)

    def test_changed_predecessor_backup_or_evidence_refused(self):
        with mock.patch.object(policy, 'validate_evidence', return_value=[]), self.assertRaises(RuntimeError):
            policy.validate_version(self.record)
        self.write_bytes(policy.BACKUP, b'own wrong Core')
        with self.assertRaises(RuntimeError): policy.validate_version(self.record)
        self.write_bytes(policy.BACKUP, self.old)
        self.write_json(policy.PREVIOUS_MANIFEST, dict(self.previous, at='changed'))
        with self.assertRaises(RuntimeError): policy.validate_version(self.record)

    def test_private_reference_change_refused_without_open_or_hash(self):
        private = self.root / 'prefixes/private/user.reg'
        self.write_bytes(str(private.relative_to(self.root)), b'OWN PRIVATE SENTINEL')
        original_open = Path.open

        def no_private_open(path, *args, **kwargs):
            self.assertNotEqual(path, private)
            return original_open(path, *args, **kwargs)

        invalid = copy.deepcopy(self.record)
        invalid['auth_confirmation_evidence'] = 'prefixes/private/user.reg'
        with mock.patch.object(Path, 'open', no_private_open), mock.patch.object(policy, 'sha', wraps=policy.sha) as hashed, \
                self.assertRaisesRegex(RuntimeError, 'v8 must preserve existing v7 role'):
            policy.validate_version(invalid)
        self.assertNotIn(mock.call(private), hashed.call_args_list)

    def reset_transaction(self):
        (self.root / policy.TRANSACTION).unlink()
        (self.root / policy.BACKUP).unlink()
        (self.stage / 'CoreRT.dll').write_bytes(self.old)

    def own_process(self, command, **kwargs):
        if command[:2] == ['/bin/cp', '-c']:
            shutil.copyfile(command[2], command[3])
            return SimpleNamespace(returncode=0)
        self.assertEqual(command[1:4], ['-m', 'unittest', 'discover'])
        return SimpleNamespace(returncode=0, stderr='Ran 8 tests in 0.1s\n\nOK\n')

    def test_postcheck_failure_rolls_back_own_core_and_new_metadata(self):
        self.reset_transaction()
        import source_main_environment
        with mock.patch.object(source_main_environment, 'source_main_prefix', return_value=nullcontext()), \
                mock.patch.object(update, 'validate_code_inputs', side_effect=[self.previous, self.previous, RuntimeError('own postcheck')]), \
                mock.patch.object(update.subprocess, 'run', side_effect=self.own_process), self.assertRaises(RuntimeError):
            update.main()
        self.assertEqual((self.stage / 'CoreRT.dll').read_bytes(), self.old)
        self.assertEqual((self.root / policy.BACKUP).read_bytes(), self.old)
        for name in (policy.MANIFEST, policy.TRANSACTION): self.assertFalse((self.root / name).exists())
        self.assertFalse(list(self.stage.glob('*.pending')))

    def test_successful_own_temp_transaction_preserves_v7_bytes_and_noncore(self):
        self.reset_transaction()
        previous_bytes = (self.root / policy.PREVIOUS_MANIFEST).read_bytes()
        import source_main_environment
        with mock.patch.object(source_main_environment, 'source_main_prefix', return_value=nullcontext()), \
                mock.patch.object(update, 'validate_code_inputs', side_effect=[self.previous, self.previous, self.record]), \
                mock.patch.object(update.subprocess, 'run', side_effect=self.own_process):
            update.main()
        self.assertEqual((self.stage / 'CoreRT.dll').read_bytes(), self.new)
        self.assertEqual((self.root / policy.PREVIOUS_MANIFEST).read_bytes(), previous_bytes)
        result = json.loads((self.root / policy.MANIFEST).read_text())
        self.assertEqual(result['files'][1], self.previous['files'][1])
        policy.validate_version(result)

    def test_intervening_output_after_lock_blocks_before_code_access(self):
        self.reset_transaction()

        @contextmanager
        def intervening(*args, **kwargs):
            self.write_bytes(policy.MANIFEST, b'own intervening output')
            yield

        import source_main_environment
        with mock.patch.object(source_main_environment, 'source_main_prefix', side_effect=intervening), \
                mock.patch.object(update, 'validate_code_inputs') as checked, \
                mock.patch.object(update.subprocess, 'run') as process, self.assertRaises(RuntimeError):
            update.main()
        checked.assert_not_called()
        process.assert_not_called()

    def test_missing_own_build_evidence_blocks_before_backup_or_copy(self):
        self.reset_transaction()
        import source_main_environment
        with mock.patch.object(source_main_environment, 'source_main_prefix', return_value=nullcontext()), \
                mock.patch.object(update, 'validate_code_inputs', return_value=self.previous), \
                mock.patch.object(policy, 'validate_evidence', side_effect=RuntimeError('own missing native build evidence')), \
                mock.patch.object(update.subprocess, 'run') as process, self.assertRaises(RuntimeError):
            update.main()
        process.assert_not_called()
        self.assertFalse((self.root / policy.BACKUP).exists())


class ToolModeEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        own_inputs = policy.PRESERVED_INPUTS | policy.EXPECTED_SOURCES | policy.EXPECTED_OVERLAY \
                     | set(policy.BUILD_FILES.values()) | {policy.SOURCE, policy.TBB, policy.HEADER_LOG}
        for name in own_inputs:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(PROJECT / name, path)
        self.build = json.loads((PROJECT / policy.BUILD_RECORD).read_text())
        self.private = self.root / 'prefixes/private/user.reg'
        self.private.parent.mkdir(parents=True)
        self.private.write_text('OWN PRIVATE SENTINEL')
        self.patches = [mock.patch.dict(identity.plain.__globals__, ROOT=self.root),
                        mock.patch.object(hook, 'validate_evidence', return_value=[])]
        for patch in self.patches:
            patch.start()
        self.save()

    def tearDown(self):
        for patch in reversed(self.patches):
            patch.stop()
        self.temp.cleanup()

    def save(self):
        path = self.root / policy.BUILD_RECORD
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.build))

    def test_real_separate_own_build_and_native_scope_checks_are_bound(self):
        refs = policy.validate_evidence(self.root)
        self.assertIn({'path': policy.SOURCE, 'sha256': policy.CORE_SHA256}, refs)
        self.assertTrue(any(item['path'] == policy.HEADER_LOG for item in refs))
        self.assertFalse(self.build['runtime_tested'])
        hook.validate_evidence.assert_called_once_with(self.root)

    def test_private_dynamic_paths_are_rejected_before_any_private_read(self):
        original = copy.deepcopy(self.build)
        original_open = Path.open

        def no_private_open(path, *args, **kwargs):
            self.assertNotEqual(path, self.private)
            return original_open(path, *args, **kwargs)

        for target in ('artifact', 'original_toolmode', 'source_evidence', 'generated_overlay',
                       'base_v7_overlay', 'build_log', 'header_log', 'preserved'):
            self.build = copy.deepcopy(original)
            private_name = str(self.private.relative_to(self.root))
            if target in ('source_evidence', 'generated_overlay', 'base_v7_overlay'):
                self.build[target][0]['path'] = private_name
            elif target == 'build_log':
                self.build['build']['log']['path'] = private_name
            elif target == 'header_log':
                self.build['header_and_overlay_tests']['log']['path'] = private_name
            elif target == 'preserved':
                self.build['preserved_original_and_v7_input_sha256'][private_name] = 'a'*64
            else:
                self.build[target]['path'] = private_name
            self.save()
            with self.subTest(target=target), mock.patch.object(Path, 'open', no_private_open), \
                    mock.patch.object(policy, 'sha', wraps=policy.sha) as hashed, self.assertRaises(RuntimeError):
                policy.validate_evidence(self.root)
            self.assertNotIn(mock.call(self.private), hashed.call_args_list)

    def test_scope_payload_or_unexecuted_runtime_claim_cannot_be_relabeled(self):
        original = copy.deepcopy(self.build)
        for change in ('flow', 'ignored_result', 'runtime_claim', 'header_test', 'payload', 'core_hash'):
            self.build = copy.deepcopy(original)
            if change == 'flow':
                self.build['scope_proof']['original_toolmode_controlflow_catches_callbacks_and_arguments_changed'] = True
            elif change == 'ignored_result':
                self.build['scope_proof']['dependency_initialization_result_still_ignored'] = False
            elif change == 'runtime_claim':
                self.build['runtime_tested'] = True
            elif change == 'header_test':
                self.build['header_and_overlay_tests']['passed'] = 0
            elif change == 'payload':
                self.build['payload']['fields'].append('command')
            else:
                self.build['artifact']['sha256'] = 'f'*64
            self.save()
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                policy.validate_evidence(self.root)

    def test_changed_own_overlay_or_native_result_is_rejected(self):
        for name in ('build/windows-core-toolmode-diagnostic/overlay/ToolMode.Win32.cpp', policy.HEADER_LOG):
            path = self.root / name
            original = path.read_bytes()
            path.write_bytes(original + b'OWN CHANGE')
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                policy.validate_evidence(self.root)
            path.write_bytes(original)


if __name__ == '__main__':
    unittest.main()

