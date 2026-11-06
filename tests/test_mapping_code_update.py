"""Own temporary metadata/code fixtures; no Wine, real stage, prefix, or user data."""
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
import mapping_diagnostic_identity as mapping
import prepare_mapping_diagnostic as update
import run_source as runner
import source_code_identity as identity


class MappingCodeUpdateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.stage = self.root / 'build/windows-source-integration'
        self.stage.mkdir(parents=True)
        (self.root / 'research').mkdir()
        self.old_bytes, self.new_bytes = b'own-old-code', b'own-new-code'
        self.old_sha = hashlib.sha256(self.old_bytes).hexdigest()
        self.new_sha = hashlib.sha256(self.new_bytes).hexdigest()
        self.previous = {'at': 'old', 'source_revision': identity.REVISION, 'developer_code_version': 4,
                         'stage': 'build/windows-source-integration', 'prefix_is_account_free': False,
                         'phase_update_transaction': 'research/old-phase.json', 'phase_update_transaction_sha256': 'a'*64,
                         'previous_code_manifest': 'research/old-v3.json', 'previous_code_manifest_sha256': 'b'*64,
                         'auth_confirmation_evidence': 'research/own-user-confirmation.json',
                         'auth_confirmation_evidence_sha256': 'e'*64,
                         'allowed_generated_subprocess_code': [], 'manual_login_user_confirmed': True,
                         'files': [{'name': 'CoreRT.dll', 'sha256': self.old_sha, 'bytes': len(self.old_bytes)},
                                   {'name': 'FiveM.exe', 'sha256': 'c'*64, 'bytes': 1}]}
        self.write(mapping.PREVIOUS_MANIFEST, self.previous)
        backup = self.root / mapping.BACKUP
        backup.parent.mkdir(parents=True)
        backup.write_bytes(self.old_bytes)
        transaction = {'source_revision': identity.REVISION, 'developer_code_version': 5,
                       'mapping_previous_manifest': mapping.PREVIOUS_MANIFEST,
                       'mapping_previous_manifest_sha256': identity.sha(self.root / mapping.PREVIOUS_MANIFEST),
                       'previous_sha256': self.old_sha, 'new_sha256': self.new_sha,
                       'source': mapping.SOURCE, 'target': 'build/windows-source-integration/CoreRT.dll',
                       'previous_code_backup': mapping.BACKUP, 'header_checks': {'passed': 2, 'exit': 0},
                       'diagnostic_evidence': [{'path': 'own-evidence', 'sha256': 'd'*64}]}
        self.write(mapping.TRANSACTION, transaction)
        self.record = copy.deepcopy(self.previous)
        self.record.update(developer_code_version=5, mapping_previous_manifest=mapping.PREVIOUS_MANIFEST,
                           mapping_previous_manifest_sha256=identity.sha(self.root / mapping.PREVIOUS_MANIFEST),
                           mapping_update_transaction=mapping.TRANSACTION,
                           mapping_update_transaction_sha256=identity.sha(self.root / mapping.TRANSACTION))
        self.record['files'][0].update(sha256=self.new_sha, bytes=len(self.new_bytes))
        self.patches = [mock.patch.object(identity, 'ROOT', self.root), mock.patch.object(identity, 'STAGE', self.stage),
                        mock.patch.object(update, 'ROOT', self.root), mock.patch.object(update, 'STAGE', self.stage),
                        mock.patch.dict(identity.plain.__globals__, ROOT=self.root),
                        mock.patch.object(mapping, 'CORE_SHA256', self.new_sha),
                        mock.patch.object(mapping, 'PREVIOUS_CORE_SHA256', self.old_sha),
                        mock.patch.object(mapping, 'validate_evidence', return_value=transaction['diagnostic_evidence'])]
        for patch in self.patches:
            patch.start()

    def tearDown(self):
        for patch in reversed(self.patches):
            patch.stop()
        self.temporary.cleanup()

    def write(self, relative, value):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))

    def test_v5_preserves_v4_phase_provenance_and_accepts_only_own_core_delta(self):
        identity.validate_mapping_version(self.record)
        for change in ('phase', 'main-code', 'wrong-reference'):
            invalid = copy.deepcopy(self.record)
            if change == 'phase':
                invalid['previous_code_manifest_sha256'] = '0'*64
            elif change == 'main-code':
                invalid['files'][1]['sha256'] = '0'*64
            else:
                invalid['mapping_previous_manifest'] = 'research/old-v3.json'
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                identity.validate_mapping_version(invalid)

    def test_changed_bound_previous_manifest_or_fixture_evidence_is_rejected(self):
        with mock.patch.object(mapping, 'validate_evidence', return_value=[]), self.assertRaises(RuntimeError):
            identity.validate_mapping_version(self.record)
        self.write(mapping.PREVIOUS_MANIFEST, dict(self.previous, at='changed'))
        with self.assertRaises(RuntimeError):
            identity.validate_mapping_version(self.record)

    def test_v5_misdirected_auth_evidence_is_refused_before_common_hash_loop(self):
        private = self.root / 'prefixes/private/user.reg'
        private.parent.mkdir(parents=True)
        private.write_text('OWN PRIVATE SENTINEL; this fixture must never read it')
        invalid = copy.deepcopy(self.record)
        invalid['auth_confirmation_evidence'] = 'prefixes/private/user.reg'
        self.write(mapping.MANIFEST, invalid)
        original_open = Path.open

        def no_private_open(path, *args, **kwargs):
            self.assertNotEqual(path, private, 'Private content was read before v4 metadata admission')
            return original_open(path, *args, **kwargs)

        with mock.patch.object(Path, 'open', no_private_open), mock.patch.object(identity, 'sha', wraps=identity.sha) as hashed, \
                self.assertRaisesRegex(RuntimeError, 'v5 must preserve existing v4 role'):
            identity.validate_code_inputs(self.root / mapping.MANIFEST)
        self.assertNotIn(mock.call(private), hashed.call_args_list)

    def test_transaction_exception_restores_core_and_removes_only_own_new_metadata(self):
        (self.root / mapping.TRANSACTION).unlink()
        (self.root / mapping.BACKUP).unlink()
        (self.stage / 'CoreRT.dll').write_bytes(self.old_bytes)
        source = self.root / mapping.SOURCE
        source.parent.mkdir(parents=True)
        source.write_bytes(self.new_bytes)

        def own_subprocess(command, **kwargs):
            if command[:2] == ['/bin/cp', '-c']:
                shutil.copyfile(command[2], command[3])
                return SimpleNamespace(returncode=0)
            self.assertEqual(command[1:4], ['-m', 'unittest', 'discover'])
            return SimpleNamespace(returncode=0, stderr='Ran 2 tests in 0.1s\n\nOK\n')

        sys.path.insert(0, str(PROJECT / 'scripts'))
        import source_main_environment
        with mock.patch.object(source_main_environment, 'source_main_prefix', return_value=nullcontext()), \
                mock.patch.object(update, 'validate_code_inputs', side_effect=[self.previous, RuntimeError('postcheck failure')]), \
                mock.patch.object(update.subprocess, 'run', side_effect=own_subprocess), \
                self.assertRaisesRegex(RuntimeError, 'postcheck failure'):
            update.main()
        self.assertEqual((self.stage / 'CoreRT.dll').read_bytes(), self.old_bytes)
        self.assertEqual((self.root / mapping.BACKUP).read_bytes(), self.old_bytes)
        self.assertFalse((self.root / mapping.MANIFEST).exists())
        self.assertFalse((self.root / mapping.TRANSACTION).exists())
        self.assertFalse(list(self.stage.glob('*.pending')))

    def test_output_created_while_waiting_for_lock_is_refused_before_code_access(self):
        (self.root / mapping.TRANSACTION).unlink()
        (self.root / mapping.BACKUP).unlink()

        @contextmanager
        def intervening_writer(*args, **kwargs):
            (self.root / mapping.MANIFEST).write_text('own intervening transaction')
            yield

        sys.path.insert(0, str(PROJECT / 'scripts'))
        import source_main_environment
        with mock.patch.object(source_main_environment, 'source_main_prefix', side_effect=intervening_writer), \
                mock.patch.object(update, 'validate_code_inputs') as validate, \
                mock.patch.object(update.subprocess, 'run') as process, self.assertRaises(RuntimeError):
            update.main()
        validate.assert_not_called()
        process.assert_not_called()
        self.assertEqual((self.root / mapping.MANIFEST).read_text(), 'own intervening transaction')


class MappingInputScopeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        for name in mapping.ALLOWED_INPUTS:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'own inert metadata/code fixture')
        self.private = self.root / 'prefixes/private/user.reg'
        self.private.parent.mkdir(parents=True)
        self.private.write_text('OWN PRIVATE SENTINEL; never read by the evidence validator')
        stripped = b'own previous mapping implementation\n'
        code = b'#include "MappingDiagnostics.h"\n' + stripped + b'cfx::compat::TraceMappingProvider("own", true);\n'*8
        (self.root / 'port/fivem/code/client/citicore/FileMapping.Win32.cpp').write_bytes(code)
        artifact = {'path': mapping.SOURCE, 'bytes': (self.root / mapping.SOURCE).stat().st_size,
                    'sha256': identity.sha(self.root / mapping.SOURCE)}
        self.build = {'diagnostic_artifact': artifact, 'source_revision': identity.REVISION,
                      'build': {'exit': 0, 'CFX_CORE_MAPPING_DIAGNOSTICS': 'ON', 'CFX_CORE_ACCOUNT_FREE_TESTS': 'OFF'},
                      'source_evidence': [{'path': name, 'sha256': identity.sha(self.root / name)} for name in sorted(mapping.EXPECTED_SOURCES)],
                      'header_tests': {'passed': 2, 'source': mapping.HEADER_TEST,
                                       'source_sha256': identity.sha(self.root / mapping.HEADER_TEST)}}
        self.fixture = {'diagnostic_core_input': artifact,
                        'artifacts': [{'path': name, 'sha256': identity.sha(self.root / name),
                                       'bytes': (self.root / name).stat().st_size} for name in sorted(mapping.EXPECTED_ARTIFACTS)]}
        self.patches = [mock.patch.dict(identity.plain.__globals__, ROOT=self.root),
                        mock.patch.object(mapping, 'CORE_SHA256', artifact['sha256']),
                        mock.patch.object(mapping, 'PREVIOUS_CORE_SHA256', identity.sha(self.root / 'build/windows-core/CoreRT.dll')),
                        mock.patch.object(mapping, 'PRETRACE_SOURCE_SHA256', hashlib.sha256(stripped).hexdigest())]
        for patch in self.patches:
            patch.start()

    def tearDown(self):
        for patch in reversed(self.patches):
            patch.stop()
        self.temporary.cleanup()

    def save_records(self, build, fixture):
        (self.root / mapping.BUILD_RECORD).write_text(json.dumps(build))
        fixture['diagnostic_build_evidence'] = {'path': mapping.BUILD_RECORD, 'sha256': identity.sha(self.root / mapping.BUILD_RECORD)}
        (self.root / mapping.FIXTURE_BUILD_RECORD).write_text(json.dumps(fixture))
        results = {'passed': True, 'core_sha256': mapping.CORE_SHA256,
                   'fixture_build_sha256': identity.sha(self.root / mapping.FIXTURE_BUILD_RECORD),
                   'only_own_marker_dlls': True, 'client_started': False, 'real_rockstar_code_staged': False,
                   'cleanup': [{'flag': '-k', 'exit': 0}, {'flag': '-w', 'exit': 0}],
                   'cases': [{'mode': 'baseline', 'passed': True, 'exit': 0, 'diagnostic_phase_contract': True,
                              'own_fixture_metadata': ['marker=0x46585231 fixed_path_hits=0'], 'diagnostic_events': []},
                             {'mode': 'mapped', 'passed': True, 'exit': 0, 'diagnostic_phase_contract': True,
                              'own_fixture_metadata': ['marker=0x46585232 fixed_path_hits=1'],
                              'diagnostic_events': [{'phase': phase} for phase in sorted(mapping.PHASES)]}]}
        (self.root / mapping.FIXTURE_RESULTS).write_text(json.dumps(results))

    def test_misdirected_dynamic_groups_refuse_user_registry_before_hash_or_read(self):
        original_open = Path.open
        original_sha = mapping.sha

        def no_private_open(path, *args, **kwargs):
            self.assertNotEqual(path, self.private, 'Private content was accessed before refusal')
            return original_open(path, *args, **kwargs)

        for group in ('source', 'header', 'artifact'):
            build, fixture = copy.deepcopy(self.build), copy.deepcopy(self.fixture)
            if group == 'source':
                build['source_evidence'][0]['path'] = 'prefixes/private/user.reg'
            elif group == 'header':
                build['header_tests']['source'] = 'prefixes/private/user.reg'
            else:
                fixture['artifacts'][0]['path'] = 'prefixes/private/user.reg'
            self.save_records(build, fixture)
            with self.subTest(group=group), mock.patch.object(Path, 'open', no_private_open), \
                    mock.patch.object(mapping, 'sha', wraps=original_sha) as hashed, self.assertRaises(RuntimeError):
                mapping.validate_evidence(self.root)
            self.assertNotIn(mock.call(self.private), hashed.call_args_list)

    def test_noncanonical_unlisted_and_aliased_inputs_are_refused_before_hash(self):
        with mock.patch.object(mapping, 'sha') as hashed:
            for name in ('prefixes/private/user.reg', '/absolute/private', '../private',
                         'build/windows-core/../windows-core/CoreRT.dll'):
                with self.subTest(name=name), self.assertRaises(RuntimeError):
                    mapping.allowed_input(self.root, name)
            candidate = self.root / 'build/windows-mapping-diagnostics/socialclub.dll'
            candidate.unlink()
            for kind in ('symlink', 'hardlink', 'fifo'):
                if kind == 'symlink':
                    candidate.symlink_to(self.private)
                elif kind == 'hardlink':
                    os.link(self.private, candidate)
                else:
                    os.mkfifo(candidate)
                with self.subTest(kind=kind), self.assertRaises(RuntimeError):
                    mapping.allowed_input(self.root, str(candidate.relative_to(self.root)))
                candidate.unlink()
            hashed.assert_not_called()


class MappingControllerMetadataTests(unittest.TestCase):
    def test_debugstr_is_only_added_to_v5_and_no_new_role_variable_exists(self):
        self.assertEqual(runner.diagnostic_winedebug(4), '+loaddll,+seh')
        self.assertEqual(runner.diagnostic_winedebug(5), '+loaddll,+seh,+debugstr')
        self.assertEqual(runner.diagnostic_winedebug(5, True), '+loaddll,+seh,+debugstr,+process')

    def test_parser_rejects_arbitrary_payload_unknown_phase_and_extra_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'own.log'
            valid = '00d0:warn:debugstr:OutputDebugStringA "[CFX_MAPPING] pid=204 phase=provider.after provider_set=1 provider_called=1 return_changed=1\\n"\n'
            log.write_text(valid + valid.replace('provider.after', 'unknown.phase')
                           + valid.replace('return_changed=1', 'return_changed=1 path=PRIVATE')
                           + 'arbitrary private data\n')
            self.assertEqual(runner.mapping_metadata(log), [{'pid': 204, 'phase': 'provider.after',
                            'provider_set': 1, 'provider_called': 1, 'return_changed': 1}])


if __name__ == '__main__':
    unittest.main()
