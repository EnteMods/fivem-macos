"""A single vendor-update proof preserves old history and admits only its new SDK root."""
import copy
import datetime
import hashlib
import json
import os
from pathlib import Path
import unittest
from unittest import mock

import test_user_game_data_enrollment as fixtures
import source_main_environment as main
import rockstar_code_policy as policy
from probe_environment import ProbePrefixError


class UpdateOriginTests(unittest.TestCase):
    def write(self, relative, record):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(record, indent=2) + '\n')
        return {'path': relative, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}

    def setUp(self):
        self.fixture = fixtures.UserGameDataEnrollmentTests()
        self.fixture.setUp()
        self.root, self.prefix, self.user = self.fixture.root, self.fixture.prefix, self.fixture.user
        self.marker = self.prefix / main.MARKER_NAME
        self.manifest_path = self.prefix / policy.MANIFEST_NAME
        self.machine = self.prefix / policy.MACHINE_ROOT
        self.machine.mkdir(parents=True)
        machine_identity = {'device': self.machine.stat().st_dev, 'inode': self.machine.stat().st_ino}
        origin_ref = self.write('research/own-machine-origin.json', {
            'schema': 1, 'kind': 'fresh-rockstar-machine-runtime', 'prefix': 'prefixes/fivem-source-main',
            'copied_from_other_prefix': False, 'directory': machine_identity})
        old = json.loads(self.manifest_path.read_bytes())
        old['machine_runtime_policy'] = {'root': policy.MACHINE_ROOT, 'directory': machine_identity,
                                        'origin_evidence': origin_ref}
        old_ref = self.write(str(self.manifest_path.relative_to(self.root)), old)
        self.old_ref = {'path': policy.MANIFEST_NAME, 'sha256': old_ref['sha256']}
        identity = json.loads(self.marker.read_bytes())
        identity['rockstar_code_manifest'] = self.old_ref
        self.write(str(self.marker.relative_to(self.root)), identity)
        self.fixture.session['rockstar_code_manifest_sha256'] = self.old_ref['sha256']
        install_path = self.fixture.origin['user_install_session']['path']
        self.fixture.origin['user_install_session'] = self.write(install_path, self.fixture.session)
        self.fixture.origin['rockstar_code_manifest'] = self.old_ref
        self.fixture.refresh_origin()
        self.fixture.enroll()
        self.identity = json.loads(self.marker.read_bytes())
        self.history = {path: (self.root / path).read_bytes() for path in (
            'research/manual-user-login.json', self.fixture.origin_ref['path'], install_path)}
        backup = self.root / policy.UPDATE_PREVIOUS_BACKUP
        backup.parent.mkdir(parents=True)
        backup.write_bytes(self.manifest_path.read_bytes())
        self.old_patch = mock.patch.object(policy, 'UPDATE_PREVIOUS_SHA256', self.old_ref['sha256'])
        self.old_patch.start()
        self.sdk = self.prefix / policy.sdk_user_root(self.user)
        self.sdk.mkdir()
        self.sdk_private = self.sdk / 'opaque-own-fixture.dat'
        self.sdk_private.write_bytes(b'Own opaque data, never opened by the policy.')
        sdk_info = self.sdk.stat()
        birth = policy._birthtime_ns(sdk_info)
        self.x86 = self.prefix / policy.UPDATE_X86_CODE_ROOT
        self.x86.mkdir(parents=True)
        x86_files = []
        for name in sorted(policy.UPDATE_X86_BASENAMES):
            path = self.x86 / name
            path.write_bytes(b'Own inert 32-bit fixture code: ' + name.encode())
            x86_files.append({'path': path.relative_to(self.prefix).as_posix(), 'bytes': path.stat().st_size,
                              'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
        self.session = {
            'kind': 'one-off-user-authorized-original-rockstar-update-session',
            'at': datetime.datetime.fromtimestamp(birth / 1e9 - 1, datetime.timezone.utc).isoformat(),
            'controller_ended_at': datetime.datetime.fromtimestamp(birth / 1e9 + 1, datetime.timezone.utc).isoformat(),
            'prefix': 'prefixes/fivem-source-main',
            'prefix_identity': [self.prefix.stat().st_dev, self.prefix.stat().st_ino],
            'old_code_manifest_sha256': self.old_ref['sha256'], 'runtime_profile': 'parity',
            'runtime_manifest_sha256': 'e4fc3167813864102909da696cf3a03e89bd00a4a9abe26d8478c88316600f9c',
            'manual_user_login': self.identity['manual_user_login'], 'user_game_data_origin': self.identity['user_game_data_origin'],
            'original_security_authentication_or_update_decisions_changed': False,
            'code_binding_changed': False, 'five_m_or_installer_started': False, 'final_code_binding_pending': True,
            'cleanup_confirmed': True, 'failure_type': 'ProbePrefixError', 'status': 'stopped-or-detached-needs-review',
            'cleanup_reason': 'isolation-or-controller-failure', 'updater_success_claim': False, 'new_code_admitted': False,
            'cleanup': [{'flag': '-k', 'exit': 0, 'timed_out': False}, {'flag': '-w', 'exit': 0, 'timed_out': False}]}
        self.session_path = 'research/user-rockstar-official-update-20261103T120000000000Z.json'
        self.new_manifest = copy.deepcopy(old)
        self.new_manifest['roots'] = list(policy.UPDATED_CODE_ROOTS)
        self.new_manifest['files'].extend(x86_files)
        self.new_manifest['user_data_roots'] = list(policy.user_roots(self.user)) + [policy.sdk_user_root(self.user)]
        launcher = self.prefix / policy.CODE_ROOTS[0] / 'Launcher.exe'
        launcher.write_bytes(b'Own inert updated code, never executed.')
        entry = next(row for row in self.new_manifest['files'] if row['path'].endswith('/Launcher.exe'))
        entry.update(bytes=launcher.stat().st_size, sha256=hashlib.sha256(launcher.read_bytes()).hexdigest())
        self.proof = {
            'schema': 1, 'kind': 'user-authorized-rockstar-code-update-origin',
            'scope': 'same-source-prefix-code-update-metadata-only', 'prefix': 'prefixes/fivem-source-main',
            'prefix_device': self.prefix.stat().st_dev, 'prefix_inode': self.prefix.stat().st_ino, 'user': self.user,
            'previous_code_manifest': self.old_ref, 'current_code_manifest': {},
            'previous_manifest_backup': {'path': policy.UPDATE_PREVIOUS_BACKUP, 'sha256': self.old_ref['sha256']},
            'manual_user_login': self.identity['manual_user_login'], 'user_game_data_origin': self.identity['user_game_data_origin'],
            'update_session': {}, 'update_session_outcome': 'old-policy-rejected-new-sdk-user-root',
            'vendor_update_completed_observed': True, 'post_update_library_observed': True,
            'post_update_prefix_quiescent': True, 'copied_or_imported': False,
            'sdk_user_data': {'relative_root': policy.sdk_user_root(self.user), 'root_device': sdk_info.st_dev,
                'root_inode': sdk_info.st_ino, 'root_birthtime_ns': birth,
                'created_during_update': True, 'copied_or_imported': False},
            'machine_runtime': {'root': policy.MACHINE_ROOT, 'directory': machine_identity,
                                'unchanged_from_previous_binding': True}}
        self.proof['social_club_x86'] = {'root': policy.UPDATE_X86_CODE_ROOT,
            'created_during_update': True, 'copied_or_imported': False}
        for key, path in (('container', self.x86.parent), ('directory', self.x86)):
            value = path.stat()
            self.proof['social_club_x86'][key] = {'device': value.st_dev, 'inode': value.st_ino,
                                                  'birthtime_ns': policy._birthtime_ns(value)}
        self.refresh()

    def tearDown(self):
        self.old_patch.stop()
        self.fixture.tearDown()

    def refresh(self):
        self.proof['update_session'] = self.write(self.session_path, self.session)
        new = self.write(str(self.manifest_path.relative_to(self.root)), self.new_manifest)
        self.identity['rockstar_code_manifest'] = {'path': policy.MANIFEST_NAME, 'sha256': new['sha256']}
        self.proof['current_code_manifest'] = self.identity['rockstar_code_manifest']
        self.identity[policy.UPDATE_MARKER_KEY] = self.write(policy.UPDATE_EVIDENCE_PATH, self.proof)
        self.write(str(self.marker.relative_to(self.root)), self.identity)

    def assert_history_unchanged(self):
        self.assertEqual(self.history, {path: (self.root / path).read_bytes() for path in self.history})

    def refused(self):
        with self.assertRaises(ProbePrefixError):
            main.assert_source_main_prefix(self.prefix, root=self.root)
        self.assert_history_unchanged()

    def test_valid_forward_accepts_only_sdk_metadata_without_reading_or_rewriting_userdata(self):
        original_open, original_os_open = Path.open, os.open
        forbidden = (self.sdk, self.fixture.directory)
        def allowed(path):
            path = Path(path)
            if any(path == base or base in path.parents for base in forbidden):
                raise AssertionError('User-data contents must stay opaque.')
        def path_open(path, *args, **kwargs):
            allowed(path)
            return original_open(path, *args, **kwargs)
        def os_open(path, *args, **kwargs):
            allowed(path)
            return original_os_open(path, *args, **kwargs)
        with mock.patch.object(Path, 'open', path_open), mock.patch.object(os, 'open', os_open):
            main.assert_source_main_prefix(self.prefix, root=self.root)
            self.assertEqual(policy.validated_update_origin(self.prefix, self.root, self.identity, self.user), self.proof)
        self.assert_history_unchanged()

    def test_no_proof_keeps_default_old_binding_and_three_roots(self):
        with self.assertRaises(ProbePrefixError):
            policy._verify_code(self.new_manifest, self.prefix, self.root)
        self.identity.pop(policy.UPDATE_MARKER_KEY)
        self.write(str(self.marker.relative_to(self.root)), self.identity)
        self.assertIsNone(policy.validated_update_origin(self.prefix, self.root, self.identity, self.user))
        self.refused()

    def test_x86_origin_and_five_file_set_are_exact_not_a_generic_third_root(self):
        original = copy.deepcopy(self.proof)
        for part, field, value in (('directory', 'inode', 0), ('container', 'birthtime_ns', 0)):
            self.proof = copy.deepcopy(original)
            self.proof['social_club_x86'][part][field] = value
            self.refresh()
            with self.subTest(part=part, field=field):
                self.refused()
        self.proof = original
        self.new_manifest['files'].append({'path': policy.UPDATE_X86_CODE_ROOT + '/unapproved.dll',
                                          'bytes': 0, 'sha256': '0' * 64})
        self.refresh()
        self.refused()

    def test_wrong_history_current_code_or_unconfirmed_library_cannot_forward(self):
        original = copy.deepcopy(self.proof)
        for key, value in (('previous_code_manifest', {'path': policy.MANIFEST_NAME, 'sha256': '0' * 64}),
                           ('manual_user_login', {'path': 'research/other.json', 'sha256': '0' * 64}),
                           ('post_update_library_observed', False), ('post_update_prefix_quiescent', False)):
            self.proof = copy.deepcopy(original)
            self.proof[key] = value
            self.refresh()
            with self.subTest(key=key):
                self.refused()
        self.proof = original
        self.refresh()
        self.identity['rockstar_code_manifest']['sha256'] = '0' * 64
        self.write(str(self.marker.relative_to(self.root)), self.identity)
        self.refused()

    def test_sdk_relative_root_inode_birth_and_copy_flags_are_exact(self):
        original = copy.deepcopy(self.proof)
        for key, value in (('relative_root', policy.sdk_user_root(self.user) + '-other'),
                           ('root_inode', 0), ('root_birthtime_ns', 0), ('copied_or_imported', True)):
            self.proof = copy.deepcopy(original)
            self.proof['sdk_user_data'][key] = value
            self.refresh()
            with self.subTest(key=key):
                self.refused()

    def test_failed_cleanup_or_rewritten_update_success_is_not_accepted(self):
        original = copy.deepcopy(self.session)
        for key, value in (('failure_type', None), ('updater_success_claim', True), ('cleanup_confirmed', False)):
            self.session = copy.deepcopy(original)
            self.session[key] = value
            self.refresh()
            with self.subTest(key=key):
                self.refused()
        self.session = original
        self.session['at'] = self.session['controller_ended_at']
        self.refresh()
        self.refused()

    def test_machine_directory_and_old_policy_cannot_be_replaced(self):
        self.machine.rename(self.machine.with_name('preserved-original'))
        self.machine.mkdir()
        self.refused()
        self.machine.rmdir()
        self.machine.with_name('preserved-original').rename(self.machine)
        self.new_manifest['machine_runtime_policy']['directory']['inode'] = 0
        self.refresh()
        self.refused()

    def test_sdk_permission_does_not_admit_aliases_or_new_siblings(self):
        os.link(self.sdk_private, self.sdk / 'hardlink')
        self.refused()
        (self.sdk / 'hardlink').unlink()
        extra = self.sdk.with_name('SDK-other')
        extra.mkdir()
        self.refused()


if __name__ == '__main__':
    unittest.main()
