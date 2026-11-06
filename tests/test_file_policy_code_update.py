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
import file_policy_diagnostic_identity as policy
import hook_diagnostic_identity as hook
import prepare_file_policy_diagnostic as update
import source_code_identity as identity


class FilePolicyCodeUpdateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.stage = self.root / 'build/windows-source-integration'
        self.stage.mkdir(parents=True)
        self.old, self.new = b'own v6 Core', b'own v7 Core'
        self.old_sha, self.new_sha = [hashlib.sha256(value).hexdigest() for value in (self.old, self.new)]
        self.write_bytes(policy.SOURCE, self.new)
        self.write_bytes(policy.BACKUP, self.old)
        self.previous = {'at': 'own-v6', 'source_revision': identity.REVISION, 'developer_code_version': 6,
            'stage': 'build/windows-source-integration', 'prefix_is_account_free': False,
            'manual_login_user_confirmed': True, 'role': 'own original role',
            'hook_previous_manifest': 'research/own-v5.json', 'hook_previous_manifest_sha256': 'a'*64,
            'hook_update_transaction': 'research/own-v6-transaction.json', 'hook_update_transaction_sha256': 'b'*64,
            'auth_confirmation_evidence': 'research/own-confirmation.json', 'auth_confirmation_evidence_sha256': 'c'*64,
            'files': [{'name': 'CoreRT.dll', 'sha256': self.old_sha, 'bytes': len(self.old), 'origin': 'own-v6'},
                      {'name': 'FiveM.exe', 'sha256': 'd'*64, 'bytes': 1}]}
        self.write_json(policy.PREVIOUS_MANIFEST, self.previous)
        self.evidence = [{'path': policy.BUILD_RECORD, 'sha256': 'e'*64}]
        self.transaction = {'source_revision': identity.REVISION, 'developer_code_version': 7,
            'file_policy_previous_manifest': policy.PREVIOUS_MANIFEST,
            'file_policy_previous_manifest_sha256': identity.sha(self.root / policy.PREVIOUS_MANIFEST),
            'previous_sha256': self.old_sha, 'new_sha256': self.new_sha, 'source': policy.SOURCE,
            'target': 'build/windows-source-integration/CoreRT.dll', 'previous_code_backup': policy.BACKUP,
            'header_checks': {'passed': 6, 'exit': 0}, 'diagnostic_evidence': self.evidence,
            'only_own_core_file_updated': True, 'main_citigame_and_original_modules_unchanged': True,
            'original_conditions_returns_mapping_authentication_and_security_decisions_preserved': True,
            'profiles_sessions_tickets_read_copied_or_reset': False}
        self.write_json(policy.TRANSACTION, self.transaction)
        self.record = copy.deepcopy(self.previous)
        self.record.update(developer_code_version=7, file_policy_previous_manifest=policy.PREVIOUS_MANIFEST,
            file_policy_previous_manifest_sha256=identity.sha(self.root / policy.PREVIOUS_MANIFEST),
            file_policy_update_transaction=policy.TRANSACTION,
            file_policy_update_transaction_sha256=identity.sha(self.root / policy.TRANSACTION))
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
            elif change == 'reference': invalid['file_policy_previous_manifest'] = 'research/own-v5.json'
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
                self.assertRaisesRegex(RuntimeError, 'v7 must preserve existing v6 role'):
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
        return SimpleNamespace(returncode=0, stderr='Ran 6 tests in 0.1s\n\nOK\n')

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

    def test_successful_own_temp_transaction_preserves_v6_bytes_and_noncore(self):
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

    def test_missing_runtime_evidence_blocks_before_backup_or_copy(self):
        self.reset_transaction()
        import source_main_environment
        with mock.patch.object(source_main_environment, 'source_main_prefix', return_value=nullcontext()), \
                mock.patch.object(update, 'validate_code_inputs', return_value=self.previous), \
                mock.patch.object(policy, 'validate_evidence', side_effect=RuntimeError('own missing real fixture')), \
                mock.patch.object(update.subprocess, 'run') as process, self.assertRaises(RuntimeError):
            update.main()
        process.assert_not_called()
        self.assertFalse((self.root / policy.BACKUP).exists())


class FilePolicyEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        for name in policy.ALLOWED_INPUTS:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(('own inert ' + name).encode())
        # Copy only named own code/build inputs; no stage or prefix traversal.
        code_inputs = (policy.PRESERVED_INPUTS | policy.EXPECTED_SOURCES | policy.EXPECTED_OVERLAY
                       | set(policy.BUILD_FILES.values()) | hook.EXPECTED_ARTIFACTS
                       | {policy.SOURCE, policy.TBB, policy.HEADER_LOG})
        for name in code_inputs:
            shutil.copyfile(PROJECT / name, self.root / name)
        self.build = json.loads((PROJECT / policy.BUILD_RECORD).read_text())
        self.fixture = {'schema_version': 1, 'profile': policy.PROFILE,
            'file_event_fields': list(policy.FILE_FIELDS), 'file_operations': list(policy.FILE_OPERATIONS),
            'cases': [{'location': location, 'mode': mode} for location, mode in hook.CASES],
            'build_record': {'path': policy.BUILD_RECORD, 'sha256': '0'*64},
            'policy_build_evidence': {'path': hook.POLICY_BUILD_RECORD, 'sha256': self.ident(hook.POLICY_BUILD_RECORD)['sha256']},
            'diagnostic_core_input': self.ident(policy.SOURCE), 'tbb_input': self.ident(hook.ORDINARY_TBB),
            'artifacts': [self.ident(name) for name in sorted(hook.EXPECTED_ARTIFACTS)],
            'hook_phases': sorted(hook.PHASES), 'runner_source': self.ident(policy.RUNNER_SOURCE),
            'policy_runner_source': self.ident(policy.POLICY_RUNNER_SOURCE), 'hook_runner_source': self.ident(policy.HOOK_RUNNER_SOURCE)}
        self.private = self.root / 'prefixes/private/user.reg'
        self.private.parent.mkdir(parents=True)
        self.private.write_text('OWN PRIVATE SENTINEL')
        self.patches = [mock.patch.dict(identity.plain.__globals__, ROOT=self.root),
                        mock.patch.object(hook, 'validate_evidence', return_value=[])]
        for patch in self.patches: patch.start()
        self.results = self.save()

    def tearDown(self):
        for patch in reversed(self.patches): patch.stop()
        self.temp.cleanup()

    def ident(self, name):
        path = self.root / name
        return {'path': name, 'sha256': identity.sha(path), 'bytes': path.stat().st_size}

    def save(self, build=None, fixture=None, results=None):
        build = copy.deepcopy(self.build if build is None else build)
        fixture = copy.deepcopy(self.fixture if fixture is None else fixture)
        (self.root / policy.BUILD_RECORD).write_text(json.dumps(build))
        fixture['build_record']['sha256'] = identity.sha(self.root / policy.BUILD_RECORD)
        (self.root / policy.FIXTURE_BUILD_RECORD).write_text(json.dumps(fixture))
        if results is None:
            results = {'schema_version': 1, 'core_profile': policy.PROFILE, 'core_sha256': policy.CORE_SHA256, 'passed': True,
                'fixture_build_sha256': identity.sha(self.root / policy.FIXTURE_BUILD_RECORD),
                'only_own_marker_dlls': True, 'client_started': False, 'real_rockstar_code_staged': False,
                'cleanup': [{'flag': '-k', 'exit': 0}, {'flag': '-w', 'exit': 0}], 'cases': []}
            for location, mode in hook.CASES:
                mapped = mode.startswith('--mapped-')
                route = 'import' if mode.endswith('-import') else 'explicit'
                should_map = mapped and (route == 'explicit' or location == 'canonical')
                events = []
                if mode == '--mapped-import':
                    bit = int(location == 'canonical')
                    events = [{'pid': 42, 'operation': 'open', 'allowed': bit,
                               'canonical_fragment': bit, 'folded_fragment': bit, 'nt_prefix': 1}]
                results['cases'].append({'location': location, 'mode': mode, 'exit': 0, 'passed': True,
                    'metadata': [f'MAPPING_POLICY_FIXTURE location={location} route={route} mapped={int(mapped)} '
                                 f'preloaded_before=0 preloaded_after=0 callback_count={int(should_map)} '
                                 f'fixed_path_hits={int(should_map)} load_error=0 marker=0x4658523{2 if should_map else 1}'],
                    'hook_events': [{'pid': 42, 'phase': phase, 'status': 0} for phase in sorted(hook.PHASES)] if mapped else [],
                    'hook_phase_contract': True, 'all_hooks_ok': True, 'file_events': events, 'file_event_contract': True,
                    'mapping_contract': True, 'unparsed_hook_event_lines': 0, 'unparsed_file_event_lines': 0})
        (self.root / policy.FIXTURE_RESULTS).write_text(json.dumps(results))
        self.save_nt()
        return results

    def save_nt(self, build=None, results=None):
        if build is None:
            build = {'schema_version': 1, 'profile': policy.NT_PROFILE, 'compiled': True,
                'artifacts': [self.ident(policy.NT_PROBE)],
                'runtime_inputs': [dict(self.ident(name), runtime_name=runtime) for name, runtime in policy.NT_INPUTS.items()],
                'source_evidence': [self.ident(name) for name in sorted(policy.NT_SOURCES)],
                'helper_sources': [self.ident(name) for name in sorted(policy.NT_HELPERS)],
                'core_build_evidence': self.ident(policy.BUILD_RECORD),
                'policy_build_evidence': self.ident(hook.POLICY_BUILD_RECORD),
                'cases': [{'location': loc, 'operation': op, 'mapped': mapped} for loc, op, mapped in policy.NT_CASES]}
        (self.root / policy.NT_BUILD_RECORD).write_text(json.dumps(build))
        if results is None:
            results = {'schema_version': 1, 'core_profile': policy.NT_PROFILE, 'core_sha256': policy.CORE_SHA256,
                'build_evidence_sha256': identity.sha(self.root / policy.NT_BUILD_RECORD), 'passed': True,
                'cleanup': [{'flag': '-k', 'exit': 0}, {'flag': '-w', 'exit': 0}], 'cases': []}
            for location, operation, mapped in policy.NT_CASES:
                bit = int(location == 'canonical')
                target = mapped and location == 'canonical'
                results['cases'].append({'location': location, 'operation': operation, 'mapped': mapped, 'exit': 0,
                    'metadata': [f'MAPPING_NT_POLICY_FIXTURE location={location} operation={operation} mapped={int(mapped)} '
                                 f'status=0x00000000 source_identity={int(not target)} target_identity={int(target)} '
                                 f'callback_count={int(target)} fixed_path_hits={int(target)}'],
                    'nt_contract': True, 'hook_phase_contract': True, 'file_event_contract': True,
                    'hook_events': [{'pid': 42, 'phase': phase, 'status': 0} for phase in sorted(hook.PHASES)] if mapped else [],
                    'file_events': [{'pid': 42, 'operation': operation, 'allowed': bit,
                                     'canonical_fragment': bit, 'folded_fragment': bit, 'nt_prefix': 1}] if mapped else [],
                    'unparsed_hook_event_lines': 0, 'unparsed_file_event_lines': 0})
        (self.root / policy.NT_RESULTS).write_text(json.dumps(results))
        self.nt_build, self.nt_results = build, results
        return results

    def test_complete_build_and_all_eight_runtime_contracts_pass(self):
        refs = policy.validate_evidence(self.root)
        self.assertIn({'path': policy.FIXTURE_RESULTS, 'sha256': identity.sha(self.root / policy.FIXTURE_RESULTS)}, refs)

    def test_file_event_contract_rejects_missing_or_forged_bits_and_private_fields(self):
        for defect in ('missing', 'wrong-gate', 'bool-bit', 'private-field', 'operation', 'baseline-event', 'unparsed', 'mapping-contract'):
            result = copy.deepcopy(self.results)
            case = result['cases'][3]
            if defect == 'missing': case['file_events'].clear()
            elif defect == 'wrong-gate': case['file_events'][0]['allowed'] = 1
            elif defect == 'bool-bit': case['file_events'][0]['allowed'] = False
            elif defect == 'private-field': case['file_events'][0]['path'] = 'PRIVATE'
            elif defect == 'operation': case['file_events'][0]['operation'] = 'read'
            elif defect == 'unparsed': case['unparsed_file_event_lines'] = 1
            elif defect == 'mapping-contract': case['mapping_contract'] = False
            else: result['cases'][0]['file_events'] = copy.deepcopy(case['file_events'])
            self.save(results=result)
            with self.subTest(defect=defect), self.assertRaises(RuntimeError):
                policy.validate_evidence(self.root)

    def test_early_canonical_loader_mapping_needs_direct_nt_positive_controls(self):
        result = copy.deepcopy(self.results)
        result['cases'][7]['file_events'] = []
        self.save(results=result)
        policy.validate_evidence(self.root)
        (self.root / policy.NT_RESULTS).unlink()
        with self.assertRaises(FileNotFoundError):
            policy.validate_evidence(self.root)

    def test_direct_nt_positive_identity_hook_and_file_contracts_are_required(self):
        baseline = copy.deepcopy(self.nt_results)
        for defect in ('missing-event', 'wrong-operation', 'wrong-prefix', 'wrong-identity', 'missing-hook', 'status', 'bool-mapped'):
            result = copy.deepcopy(baseline)
            case = result['cases'][5]
            if defect == 'missing-event': case['file_events'].clear()
            elif defect == 'wrong-operation': case['file_events'][0]['operation'] = 'create'
            elif defect == 'wrong-prefix': case['file_events'][0]['nt_prefix'] = 0
            elif defect == 'wrong-identity':
                case['metadata'][0] = case['metadata'][0].replace('source_identity=0 target_identity=1', 'source_identity=1 target_identity=0')
            elif defect == 'missing-hook': case['hook_events'].pop()
            elif defect == 'status': case['metadata'][0] = case['metadata'][0].replace('status=0x00000000', 'status=0xc0000001')
            else: case['mapped'] = 1
            self.save_nt(results=result)
            with self.subTest(defect=defect), self.assertRaises(RuntimeError):
                policy.validate_evidence(self.root)

    def test_direct_nt_dynamic_private_reference_refused_before_hash_or_open(self):
        build = copy.deepcopy(self.nt_build)
        build['helper_sources'][0]['path'] = 'prefixes/private/user.reg'
        self.save_nt(build=build)
        original_open = Path.open

        def no_private_open(path, *args, **kwargs):
            self.assertNotEqual(path, self.private)
            return original_open(path, *args, **kwargs)

        with mock.patch.object(Path, 'open', no_private_open), mock.patch.object(policy, 'sha', wraps=policy.sha) as hashed, \
                self.assertRaises(RuntimeError):
            policy.validate_evidence(self.root)
        self.assertNotIn(mock.call(self.private), hashed.call_args_list)

    def test_private_dynamic_inputs_refused_before_read_or_hash(self):
        original_open, original_sha = Path.open, policy.sha

        def no_private_open(path, *args, **kwargs):
            self.assertNotEqual(path, self.private)
            return original_open(path, *args, **kwargs)

        for group in ('source', 'overlay', 'runner', 'policy-runner', 'hook-runner', 'artifact', 'preserved', 'log'):
            build, fixture = copy.deepcopy(self.build), copy.deepcopy(self.fixture)
            private = 'prefixes/private/user.reg'
            if group == 'source': build['source_evidence'][0]['path'] = private
            elif group == 'overlay': build['generated_overlay'][0]['path'] = private
            elif group == 'runner': fixture['runner_source']['path'] = private
            elif group == 'policy-runner': fixture['policy_runner_source']['path'] = private
            elif group == 'hook-runner': fixture['hook_runner_source']['path'] = private
            elif group == 'artifact': fixture['artifacts'][0]['path'] = private
            elif group == 'log': build['header_and_overlay_tests']['log']['path'] = private
            else: build['preserved_original_and_v6_input_sha256'][private] = '0'*64
            self.save(build, fixture)
            with self.subTest(group=group), mock.patch.object(Path, 'open', no_private_open), \
                    mock.patch.object(policy, 'sha', wraps=original_sha) as hashed, self.assertRaises(RuntimeError):
                policy.validate_evidence(self.root)
            self.assertNotIn(mock.call(self.private), hashed.call_args_list)

    def test_noncanonical_unlisted_and_aliased_inputs_refused(self):
        with mock.patch.object(policy, 'sha') as hashed:
            for name in ('prefixes/private/user.reg', '/absolute/private', '../private',
                         'build/windows-core-file-policy-diagnostic/../windows-core-file-policy-diagnostic/CoreRT.dll'):
                with self.subTest(name=name), self.assertRaises(RuntimeError):
                    policy.allowed_input(self.root, name)
            path = self.root / policy.SOURCE
            path.unlink()
            for kind in ('symlink', 'hardlink', 'fifo'):
                if kind == 'symlink': path.symlink_to(self.private)
                elif kind == 'hardlink': os.link(self.private, path)
                else: os.mkfifo(path)
                with self.subTest(kind=kind), self.assertRaises(RuntimeError):
                    policy.allowed_input(self.root, policy.SOURCE)
                path.unlink()
            hashed.assert_not_called()

    def test_scope_claim_or_unreversible_overlay_rejected(self):
        build = copy.deepcopy(self.build)
        build['scope_proof']['mapping_filename_policy_changed'] = True
        self.save(build=build)
        with self.assertRaises(RuntimeError): policy.validate_evidence(self.root)
        self.save()
        overlay = self.root / 'build/windows-core-file-policy-diagnostic/overlay/FileMapping.Win32.cpp'
        overlay.write_bytes(overlay.read_bytes().replace(policy.PREDICATE, b'true', 1))
        with self.assertRaises(RuntimeError): policy.validate_evidence(self.root)


if __name__ == '__main__':
    unittest.main()
