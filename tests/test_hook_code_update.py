"""Own temporary code and metadata only; no Wine or real stage/prefix mutations."""
from contextlib import contextmanager, nullcontext
import copy
import hashlib
import importlib.util
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
import hook_diagnostic_identity as hook
import prepare_hook_diagnostic as update
import source_code_identity as identity


class HookCodeUpdateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.stage = self.root / 'build/windows-source-integration'
        self.stage.mkdir(parents=True)
        self.old_bytes, self.new_bytes = b'own previous v5 Core', b'own next v6 Core'
        self.old_sha = hashlib.sha256(self.old_bytes).hexdigest()
        self.new_sha = hashlib.sha256(self.new_bytes).hexdigest()
        source = self.root / hook.SOURCE
        source.parent.mkdir(parents=True)
        source.write_bytes(self.new_bytes)
        self.previous = {
            'at': 'own-v5', 'source_revision': identity.REVISION, 'developer_code_version': 5,
            'stage': 'build/windows-source-integration', 'prefix_is_account_free': False,
            'manual_login_user_confirmed': True, 'role': 'own source metadata fixture',
            'mapping_previous_manifest': 'research/own-v4.json',
            'mapping_previous_manifest_sha256': 'a'*64,
            'mapping_update_transaction': 'research/own-v5-transaction.json',
            'mapping_update_transaction_sha256': 'b'*64,
            'auth_confirmation_evidence': 'research/own-user-confirmation.json',
            'auth_confirmation_evidence_sha256': 'c'*64,
            'allowed_generated_subprocess_code': [],
            'files': [{'name': 'CoreRT.dll', 'bytes': len(self.old_bytes), 'sha256': self.old_sha, 'origin': 'own v5'},
                      {'name': 'FiveM.exe', 'bytes': 1, 'sha256': 'd'*64, 'origin': 'own MAIN'}]}
        self.write(hook.PREVIOUS_MANIFEST, self.previous)
        backup = self.root / hook.BACKUP
        backup.parent.mkdir(parents=True)
        backup.write_bytes(self.old_bytes)
        self.evidence = [{'path': hook.BUILD_RECORD, 'sha256': 'e'*64}]
        self.transaction = {
            'source_revision': identity.REVISION, 'developer_code_version': 6,
            'hook_previous_manifest': hook.PREVIOUS_MANIFEST,
            'hook_previous_manifest_sha256': identity.sha(self.root / hook.PREVIOUS_MANIFEST),
            'previous_sha256': self.old_sha, 'new_sha256': self.new_sha,
            'source': hook.SOURCE, 'target': 'build/windows-source-integration/CoreRT.dll',
            'previous_code_backup': hook.BACKUP, 'header_checks': {'passed': 5, 'exit': 0},
            'diagnostic_evidence': self.evidence, 'only_own_core_file_updated': True,
            'main_citigame_and_original_modules_unchanged': True,
            'original_conditions_returns_mapping_authentication_and_security_decisions_preserved': True,
            'profiles_sessions_tickets_read_copied_or_reset': False}
        self.write(hook.TRANSACTION, self.transaction)
        self.record = copy.deepcopy(self.previous)
        self.record.update(developer_code_version=6, hook_previous_manifest=hook.PREVIOUS_MANIFEST,
                           hook_previous_manifest_sha256=identity.sha(self.root / hook.PREVIOUS_MANIFEST),
                           hook_update_transaction=hook.TRANSACTION,
                           hook_update_transaction_sha256=identity.sha(self.root / hook.TRANSACTION))
        self.record['files'][0].update(sha256=self.new_sha, bytes=len(self.new_bytes), origin=hook.ORIGIN)
        self.patches = [mock.patch.object(hook, 'ROOT', self.root), mock.patch.object(update, 'ROOT', self.root),
                        mock.patch.object(update, 'STAGE', self.stage),
                        mock.patch.dict(identity.plain.__globals__, ROOT=self.root),
                        mock.patch.object(hook, 'CORE_SHA256', self.new_sha),
                        mock.patch.object(hook, 'PREVIOUS_CORE_SHA256', self.old_sha),
                        mock.patch.object(identity, 'validate_mapping_version'),
                        mock.patch.object(hook, 'validate_evidence', return_value=self.evidence)]
        self.active = [patch.start() for patch in self.patches]

    def tearDown(self):
        for patch in reversed(self.patches):
            patch.stop()
        self.temporary.cleanup()

    def write(self, relative, value):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))

    def test_exact_v5_predecessor_validated_and_only_core_delta_admitted(self):
        hook.validate_version(self.record)
        identity.validate_mapping_version.assert_called_once_with(self.previous)
        for change in ('role', 'noncore', 'order', 'reference', 'extra', 'core-origin'):
            invalid = copy.deepcopy(self.record)
            if change == 'role': invalid['role'] = 'different'
            elif change == 'noncore': invalid['files'][1]['sha256'] = '0'*64
            elif change == 'order': invalid['files'].reverse()
            elif change == 'reference': invalid['hook_previous_manifest'] = 'research/own-v4.json'
            elif change == 'extra': invalid['unapproved_flag'] = True
            else: invalid['files'][0]['origin'] = 'unbound build'
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                hook.validate_version(invalid)

    def test_predecessor_hash_backup_and_evidence_must_remain_bound(self):
        with mock.patch.object(hook, 'validate_evidence', return_value=[]), self.assertRaises(RuntimeError):
            hook.validate_version(self.record)
        (self.root / hook.BACKUP).write_bytes(b'own wrong Core')
        with self.assertRaises(RuntimeError):
            hook.validate_version(self.record)
        (self.root / hook.BACKUP).write_bytes(self.old_bytes)
        self.write(hook.PREVIOUS_MANIFEST, dict(self.previous, at='changed'))
        with self.assertRaises(RuntimeError):
            hook.validate_version(self.record)

    def test_private_metadata_redirect_is_rejected_without_open_or_hash(self):
        private = self.root / 'prefixes/private/user.reg'
        private.parent.mkdir(parents=True)
        private.write_text('OWN PRIVATE SENTINEL')
        original_open = Path.open

        def no_private_open(path, *args, **kwargs):
            self.assertNotEqual(path, private)
            return original_open(path, *args, **kwargs)

        invalid = copy.deepcopy(self.record)
        invalid['auth_confirmation_evidence'] = 'prefixes/private/user.reg'
        with mock.patch.object(Path, 'open', no_private_open), mock.patch.object(hook, 'sha', wraps=hook.sha) as hashed, \
                self.assertRaisesRegex(RuntimeError, 'v6 must preserve existing v5 role'):
            hook.validate_version(invalid)
        self.assertNotIn(mock.call(private), hashed.call_args_list)

    def reset_for_transaction(self):
        (self.root / hook.TRANSACTION).unlink()
        (self.root / hook.BACKUP).unlink()
        (self.stage / 'CoreRT.dll').write_bytes(self.old_bytes)

    def own_subprocess(self, command, **kwargs):
        if command[:2] == ['/bin/cp', '-c']:
            shutil.copyfile(command[2], command[3])
            return SimpleNamespace(returncode=0)
        self.assertEqual(command[1:4], ['-m', 'unittest', 'discover'])
        return SimpleNamespace(returncode=0, stderr='Ran 5 tests in 0.1s\n\nOK\n')

    def test_transaction_postcheck_failure_rolls_back_only_own_core_and_new_metadata(self):
        self.reset_for_transaction()
        import source_main_environment
        with mock.patch.object(source_main_environment, 'source_main_prefix', return_value=nullcontext()), \
                mock.patch.object(update, 'validate_code_inputs', side_effect=[self.previous, self.previous, RuntimeError('own postcheck')]), \
                mock.patch.object(update.subprocess, 'run', side_effect=self.own_subprocess), \
                self.assertRaisesRegex(RuntimeError, 'own postcheck'):
            update.main()
        self.assertEqual((self.stage / 'CoreRT.dll').read_bytes(), self.old_bytes)
        self.assertEqual((self.root / hook.BACKUP).read_bytes(), self.old_bytes)
        for path in (hook.MANIFEST, hook.TRANSACTION):
            self.assertFalse((self.root / path).exists())
        self.assertFalse(list(self.stage.glob('*.pending')))

    def test_successful_transaction_keeps_v5_metadata_and_changes_only_own_core(self):
        self.reset_for_transaction()
        previous_bytes = (self.root / hook.PREVIOUS_MANIFEST).read_bytes()
        import source_main_environment
        with mock.patch.object(source_main_environment, 'source_main_prefix', return_value=nullcontext()), \
                mock.patch.object(update, 'validate_code_inputs', side_effect=[self.previous, self.previous, self.record]), \
                mock.patch.object(update.subprocess, 'run', side_effect=self.own_subprocess):
            update.main()
        self.assertEqual((self.stage / 'CoreRT.dll').read_bytes(), self.new_bytes)
        self.assertEqual((self.root / hook.PREVIOUS_MANIFEST).read_bytes(), previous_bytes)
        record = json.loads((self.root / hook.MANIFEST).read_text())
        hook.validate_version(record)
        self.assertEqual(record['files'][1], self.previous['files'][1])

    def test_output_created_while_waiting_for_lock_refused_before_code_access(self):
        self.reset_for_transaction()

        @contextmanager
        def intervening_writer(*args, **kwargs):
            (self.root / hook.MANIFEST).write_text('own intervening transaction')
            yield

        import source_main_environment
        with mock.patch.object(source_main_environment, 'source_main_prefix', side_effect=intervening_writer), \
                mock.patch.object(update, 'validate_code_inputs') as validated, \
                mock.patch.object(update.subprocess, 'run') as process, self.assertRaises(RuntimeError):
            update.main()
        validated.assert_not_called()
        process.assert_not_called()
        self.assertEqual((self.root / hook.MANIFEST).read_text(), 'own intervening transaction')

    def test_missing_runtime_evidence_blocks_before_copy_or_backup(self):
        self.reset_for_transaction()
        import source_main_environment
        with mock.patch.object(source_main_environment, 'source_main_prefix', return_value=nullcontext()), \
                mock.patch.object(update, 'validate_code_inputs', return_value=self.previous), \
                mock.patch.object(hook, 'validate_evidence', side_effect=RuntimeError('own missing real fixture')), \
                mock.patch.object(update.subprocess, 'run') as process, self.assertRaises(RuntimeError):
            update.main()
        process.assert_not_called()
        self.assertFalse((self.root / hook.BACKUP).exists())


class HookInputScopeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        for name in hook.ALLOWED_INPUTS:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(('own inert input ' + name).encode())
        self.private = self.root / 'prefixes/private/user.reg'
        self.private.parent.mkdir(parents=True)
        self.private.write_text('OWN PRIVATE SENTINEL')
        for name in hook.PINNED_SOURCES:
            shutil.copyfile(PROJECT / name, self.root / name)
        (self.root / hook.HEADER_LOG).write_text('Ran 5 tests in 0.1s\n\nOK\n')
        self.build = {
            'compiled': True, 'source_revision': identity.REVISION,
            'artifact': self.ident(hook.SOURCE), 'tbb_artifact': self.ident(hook.TBB),
            'base_v5_build_record': self.ident(hook.V5_BUILD_RECORD),
            'source_evidence': [self.ident(name) for name in sorted(hook.EXPECTED_SOURCES)],
            'generated_overlay': [self.ident(name) for name in sorted(hook.EXPECTED_OVERLAY)],
            'build': {'directory': 'build/windows-core-hook-diagnostic', 'exit': 0, 'CFX_SOURCE_DIR': 'port/fivem',
                      'CFX_CORE_MAPPING_DIAGNOSTICS': 'ON', 'CFX_CORE_ACCOUNT_FREE_TESTS': 'OFF',
                      'runtime': '/MD', 'target': 'AMD64 Windows CoreRT',
                      **{key: self.ident(name) for key, name in hook.BUILD_FILES.items()}},
            'scope_proof': {'original_sources_pinned': hook.PINNED_SOURCES,
                'stripped_mapping_sha256': hook.PINNED_SOURCES['port/fivem/code/client/citicore/FileMapping.Win32.cpp'],
                'stripped_mapping_equals_exact_v5_bytes': True, 'stripped_cmake_equals_exact_v5_bytes': True,
                'create_hook_api_wrappers': 20, 'enable_all_wrappers': 1,
                'original_hook_expressions_unchanged_and_evaluated_once': True, 'status_controls_original_flow': False,
                'mapping_callback_filter_or_return_changed': False, 'additional_getmodulehandle_probes': False},
            'header_and_overlay_tests': {'exit': 0, 'log': self.ident(hook.HEADER_LOG)},
            'payload': {'fixed_prefix': 'CFX_MAPPING_HOOK', 'fields': ['pid', 'phase', 'status'],
                'phase_source': 'fixed enum only', 'status_range': [-1, 12], 'out_of_range_status_logged_as': -1,
                'paths_pointers_auth_or_profile_values_logged': False, 'last_error_preserved': True},
            'preserved_original_input_and_artifact_sha256': {name: self.ident(name)['sha256'] for name in hook.PRESERVED_INPUTS},
            'wine_client_or_game_started': False, 'stage_or_prefix_accessed': False,
            'existing_patch_queue_changed': False, 'runtime_tested': False}
        self.fixture = {'build_record': {'path': hook.BUILD_RECORD, 'sha256': '0'*64},
                        'runner_source': self.ident(hook.RUNNER_SOURCE),
                        'policy_runner_source': self.ident(hook.POLICY_RUNNER_SOURCE),
                        'policy_build_evidence': {'path': hook.POLICY_BUILD_RECORD, 'sha256': self.ident(hook.POLICY_BUILD_RECORD)['sha256']},
                        'diagnostic_core_input': self.ident(hook.SOURCE), 'tbb_input': self.ident(hook.ORDINARY_TBB),
                        'artifacts': [self.ident(name) for name in sorted(hook.EXPECTED_ARTIFACTS)],
                        'hook_phases': sorted(hook.PHASES)}
        self.patches = [mock.patch.dict(identity.plain.__globals__, ROOT=self.root),
                        mock.patch.object(hook, 'CORE_SHA256', self.ident(hook.SOURCE)['sha256']),
                        mock.patch.object(hook, 'TBB_SHA256', self.ident(hook.TBB)['sha256']),
                        mock.patch.object(hook, 'PREVIOUS_CORE_SHA256', self.ident(hook.PREVIOUS_CORE)['sha256']),
                        mock.patch.object(hook, 'ORDINARY_CORE_SHA256', self.ident(hook.ORDINARY_CORE)['sha256']),
                        mock.patch.object(hook, 'ORDINARY_TBB_SHA256', self.ident(hook.ORDINARY_TBB)['sha256'])]
        for patch in self.patches:
            patch.start()
        self.results = self.save_records()

    def tearDown(self):
        for patch in reversed(self.patches):
            patch.stop()
        self.temporary.cleanup()

    def ident(self, name):
        path = self.root / name
        return {'path': name, 'bytes': path.stat().st_size, 'sha256': identity.sha(path)}

    def save_records(self, build=None, fixture=None, results=None):
        build = copy.deepcopy(self.build if build is None else build)
        fixture = copy.deepcopy(self.fixture if fixture is None else fixture)
        (self.root / hook.BUILD_RECORD).write_text(json.dumps(build))
        fixture['build_record']['sha256'] = identity.sha(self.root / hook.BUILD_RECORD)
        (self.root / hook.FIXTURE_BUILD_RECORD).write_text(json.dumps(fixture))
        if results is None:
            results = {'passed': True, 'core_sha256': hook.CORE_SHA256,
                       'fixture_build_sha256': identity.sha(self.root / hook.FIXTURE_BUILD_RECORD),
                       'only_own_marker_dlls': True, 'client_started': False, 'real_rockstar_code_staged': False,
                       'cleanup': [{'flag': '-k', 'exit': 0}, {'flag': '-w', 'exit': 0}], 'cases': []}
            for location, mode in hook.CASES:
                mapped = mode.startswith('--mapped-')
                route = 'import' if mode.endswith('-import') else 'explicit'
                should_map = mapped and (route == 'explicit' or location == 'canonical')
                events = [{'pid': 42, 'phase': phase, 'status': 0} for phase in sorted(hook.PHASES)] if mapped else []
                results['cases'].append({'location': location, 'mode': mode, 'exit': 0, 'passed': True,
                    'metadata': [f'MAPPING_POLICY_FIXTURE location={location} route={route} mapped={int(mapped)} '
                                 f'preloaded_before=0 preloaded_after=0 callback_count={int(should_map)} '
                                 f'fixed_path_hits={int(should_map)} load_error=0 marker=0x4658523{2 if should_map else 1}'],
                    'hook_phase_contract': True, 'hook_events': events, 'all_hooks_ok': True})
        (self.root / hook.FIXTURE_RESULTS).write_text(json.dumps(results))
        return results

    def test_complete_own_build_and_eight_case_contract_passes(self):
        references = hook.validate_evidence(self.root)
        self.assertIn({'path': hook.FIXTURE_RESULTS, 'sha256': identity.sha(self.root / hook.FIXTURE_RESULTS)}, references)

    def test_status_errors_are_diagnostics_and_do_not_change_mapping_expectation(self):
        result = copy.deepcopy(self.results)
        case = result['cases'][1]
        case['hook_events'][0]['status'] = 12
        case['all_hooks_ok'] = False
        self.save_records(results=result)
        hook.validate_evidence(self.root)

    def test_bad_case_hook_status_phase_or_marker_is_rejected(self):
        for bad in ('missing-phase', 'unknown-phase', 'extra-field', 'bad-status', 'bool-status', 'wrong-marker', 'false-ok', 'baseline-event'):
            result = copy.deepcopy(self.results)
            case = result['cases'][1]
            if bad == 'missing-phase': case['hook_events'].pop()
            elif bad == 'unknown-phase': case['hook_events'][0]['phase'] = 'unknown'
            elif bad == 'extra-field': case['hook_events'][0]['private'] = 'PRIVATE'
            elif bad == 'bad-status': case['hook_events'][0]['status'] = 13
            elif bad == 'bool-status': case['hook_events'][0]['status'] = False
            elif bad == 'wrong-marker': case['metadata'][0] = case['metadata'][0].replace('0x46585232', '0x46585231')
            elif bad == 'false-ok': case['hook_events'][0]['status'] = 12
            else: result['cases'][0]['hook_events'] = copy.deepcopy(case['hook_events'])
            self.save_records(results=result)
            with self.subTest(bad=bad), self.assertRaises(RuntimeError):
                hook.validate_evidence(self.root)

    def test_misdirected_dynamic_paths_rejected_before_private_hash_or_read(self):
        original_open = Path.open
        original_sha = hook.sha

        def no_private_open(path, *args, **kwargs):
            self.assertNotEqual(path, self.private, 'Private content was opened')
            return original_open(path, *args, **kwargs)

        for group in ('source', 'overlay', 'artifact', 'tbb', 'log', 'preserved', 'policy-reference', 'runner', 'policy-runner'):
            build, fixture = copy.deepcopy(self.build), copy.deepcopy(self.fixture)
            private_name = 'prefixes/private/user.reg'
            if group == 'source': build['source_evidence'][0]['path'] = private_name
            elif group == 'overlay': build['generated_overlay'][0]['path'] = private_name
            elif group == 'artifact': fixture['artifacts'][0]['path'] = private_name
            elif group == 'tbb': fixture['tbb_input']['path'] = private_name
            elif group == 'log': build['header_and_overlay_tests']['log']['path'] = private_name
            elif group == 'runner': fixture['runner_source']['path'] = private_name
            elif group == 'policy-runner': fixture['policy_runner_source']['path'] = private_name
            elif group == 'preserved':
                build['preserved_original_input_and_artifact_sha256'][private_name] = '0'*64
            else: fixture['policy_build_evidence']['path'] = private_name
            self.save_records(build=build, fixture=fixture)
            with self.subTest(group=group), mock.patch.object(Path, 'open', no_private_open), \
                    mock.patch.object(hook, 'sha', wraps=original_sha) as hashed, self.assertRaises(RuntimeError):
                hook.validate_evidence(self.root)
            self.assertNotIn(mock.call(self.private), hashed.call_args_list)

    def test_unlisted_noncanonical_and_aliased_inputs_refused_without_hash(self):
        with mock.patch.object(hook, 'sha') as hashed:
            for name in ('prefixes/private/user.reg', '/absolute/private', '../private',
                         'build/windows-core-hook-diagnostic/../windows-core-hook-diagnostic/CoreRT.dll'):
                with self.subTest(name=name), self.assertRaises(RuntimeError):
                    hook.allowed_input(self.root, name)
            path = self.root / hook.SOURCE
            path.unlink()
            for kind in ('symlink', 'hardlink', 'fifo'):
                if kind == 'symlink': path.symlink_to(self.private)
                elif kind == 'hardlink': os.link(self.private, path)
                else: os.mkfifo(path)
                with self.subTest(kind=kind), self.assertRaises(RuntimeError):
                    hook.allowed_input(self.root, hook.SOURCE)
                path.unlink()
            hashed.assert_not_called()


if __name__ == '__main__':
    unittest.main()
