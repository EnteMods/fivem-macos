"""One explicit user-created GTA data root does not authorize auth files or copies."""
import getpass
import hashlib
import json
import os
from pathlib import Path
import shutil
import unittest
from unittest import mock

import test_rockstar_code_policy as code_fixtures
import source_main_environment as main
from probe_environment import ProbePrefixError, assert_account_free_prefix
from rockstar_code_policy import MANIFEST_NAME, user_roots
from source_preinit_environment import assert_source_preinit_prefix
from user_game_data_policy import EVIDENCE_PATH, INSTALL_SCOPE, MARKER_KEY, game_user_root, validated_game_root


class UserGameDataEnrollmentTests(unittest.TestCase):
    def setUp(self):
        self.fixture = code_fixtures.RockstarCodePolicyTests()
        self.fixture.setUp()
        self.root, self.prefix = self.fixture.root, self.fixture.prefix
        self.fixture.enrolled()
        self.user = getpass.getuser()
        self.marker = self.prefix / main.MARKER_NAME
        info = self.prefix.stat()
        login = {'schema': 1, 'kind': 'user-confirmed-manual-login',
                 'prefix': 'prefixes/fivem-source-main', 'prefix_device': info.st_dev,
                 'prefix_inode': info.st_ino, 'user': self.user, 'confirmed_by_user': True,
                 'scope': 'launcher-ui-only', 'account_data_copied': False}
        login_ref = self.reference('research/manual-user-login.json', login)
        with main.source_main_prefix(self.prefix, root=self.root):
            main.record_manual_user_login(self.prefix, login_ref, root=self.root)
        identity = json.loads(self.marker.read_text())
        self.directory = self.prefix / game_user_root(self.user)
        self.directory.mkdir()
        self.private = self.directory / 'Profiles/own-inert-fixture.dat'
        self.private.parent.mkdir()
        self.private.write_bytes(b'Own inert data; no actual account, credential or game save.')
        self.session = {'scope': INSTALL_SCOPE, 'prefix': 'prefixes/fivem-source-main',
                        'prefix_device': info.st_dev, 'prefix_inode': info.st_ino,
                        'rockstar_code_manifest_sha256': identity['rockstar_code_manifest']['sha256'],
                        'prefix_is_account_free': False, 'user_requested_leave_open': True,
                        'automatic_wineserver_kill': False,
                        'original_authentication_integrity_or_anticheat_modified': False}
        session_ref = self.reference('research/user-rockstar-install-20261101T204842084720Z.json', self.session)
        self.origin = {'schema': 1, 'kind': 'user-authorized-gta-v-data-origin',
                       'prefix': 'prefixes/fivem-source-main', 'prefix_device': info.st_dev,
                       'prefix_inode': info.st_ino, 'user': self.user,
                       'relative_root': game_user_root(self.user),
                       'root_device': self.directory.stat().st_dev, 'root_inode': self.directory.stat().st_ino,
                       'scope': 'gta-v-user-data-metadata-only',
                       'created_in_user_authorized_install_session': True, 'copied_or_imported': False,
                       'manual_user_login': identity['manual_user_login'],
                       'rockstar_code_manifest': identity['rockstar_code_manifest'],
                       'user_install_session': session_ref}
        self.refresh_origin()

    def tearDown(self):
        self.fixture.tearDown()

    def reference(self, path, value):
        target = self.root / path
        target.write_text(json.dumps(value, indent=2) + '\n')
        return {'path': path, 'sha256': hashlib.sha256(target.read_bytes()).hexdigest()}

    def refresh_origin(self):
        self.origin_ref = self.reference(EVIDENCE_PATH, self.origin)

    def enroll(self):
        return main.enroll_user_game_data(self.prefix, self.origin_ref, root=self.root)

    def refused(self):
        with self.assertRaises(ProbePrefixError):
            main.assert_source_main_prefix(self.prefix, root=self.root)

    def test_explicit_enrollment_is_metadata_only_inode_bound_and_idempotent(self):
        self.refused()
        code_before = (self.prefix / MANIFEST_NAME).read_bytes()
        data_before = self.private.read_bytes()
        original_read = Path.read_bytes

        def read_only_metadata(path):
            if path == self.directory or self.directory in path.parents:
                raise AssertionError('User data contents must never be opened by enrollment or guard.')
            return original_read(path)

        with mock.patch.object(Path, 'read_bytes', read_only_metadata):
            self.assertEqual(self.enroll(), self.origin_ref)
            main.assert_source_main_prefix(self.prefix, root=self.root)
            self.assertEqual(self.enroll(), self.origin_ref)
        self.assertEqual(code_before, (self.prefix / MANIFEST_NAME).read_bytes())
        self.assertEqual(data_before, self.private.read_bytes())
        self.assertEqual(json.loads(self.marker.read_text())[MARKER_KEY], self.origin_ref)

    def test_origin_scope_identity_or_install_provenance_mismatch_never_writes_marker(self):
        before = self.marker.read_bytes()
        changes = {'prefix': 'prefixes/other', 'prefix_inode': -1, 'root_inode': -1,
                   'user': 'another-user', 'relative_root': game_user_root(self.user) + ' Legacy',
                   'scope': 'server-connect', 'copied_or_imported': True,
                   'created_in_user_authorized_install_session': 1,
                   'manual_user_login': {}, 'rockstar_code_manifest': {},
                   'user_install_session': {'path': 'user.reg', 'sha256': '0' * 64}}
        original = dict(self.origin)
        for key, value in changes.items():
            with self.subTest(key=key):
                self.origin = dict(original, **{key: value})
                self.refresh_origin()
                with self.assertRaises(ProbePrefixError): self.enroll()
                self.assertEqual(before, self.marker.read_bytes())

    def test_manual_login_and_matching_user_install_evidence_are_required(self):
        before = self.marker.read_bytes()
        identity = json.loads(before)
        identity.pop('manual_user_login')
        self.marker.write_text(json.dumps(identity))
        without_login = self.marker.read_bytes()
        with self.assertRaises(ProbePrefixError): self.enroll()
        self.assertEqual(without_login, self.marker.read_bytes())
        self.marker.write_bytes(before)
        for changes in ({'prefix_inode': -1}, {'user_requested_leave_open': False},
                        {'automatic_wineserver_kill': True}, {'prefix_is_account_free': 0},
                        {'rockstar_code_manifest_sha256': '0' * 64}):
            with self.subTest(changes=changes):
                self.origin['user_install_session'] = self.reference(
                    'research/user-rockstar-install-20261101T204842084720Z.json', dict(self.session, **changes))
                self.refresh_origin()
                with self.assertRaises(ProbePrefixError): self.enroll()
                self.assertEqual(before, self.marker.read_bytes())

    def test_gta_metadata_permission_never_extends_original_auth_ticket_roots(self):
        self.enroll()
        legitimate = self.prefix / user_roots(self.user)[0] / 'ros_login.dat'
        legitimate.write_bytes(b'Own inert ticket-name fixture, not a credential.')
        main.assert_source_main_prefix(self.prefix, root=self.root)
        for name in ('cfxTicket2', 'ros_login.dat', 'ros_login.json'):
            with self.subTest(name=name):
                ticket = self.directory / 'Profiles' / name
                ticket.write_bytes(b'Own inert negative fixture.')
                self.refused()
                ticket.unlink()

    def test_symlinks_hardlinks_special_files_and_other_game_siblings_stay_forbidden(self):
        self.enroll()
        outside = self.root / 'outside'; outside.mkdir()
        link = self.directory / 'redirect'; link.symlink_to(outside, target_is_directory=True)
        self.refused(); link.unlink()
        hardlink = self.directory / 'hardlink'; os.link(self.private, hardlink)
        self.refused(); hardlink.unlink()
        pipe = self.directory / 'special'; os.mkfifo(pipe)
        self.refused(); pipe.unlink()
        sibling = self.directory.parent / 'GTA IV'; sibling.mkdir()
        self.refused(); sibling.rmdir()
        main.assert_source_main_prefix(self.prefix, root=self.root)

    def test_root_replacement_other_users_and_existing_origin_rebinding_are_rejected(self):
        self.enroll()
        saved = self.directory.with_name('GTA V.saved')
        self.directory.rename(saved)
        self.directory.mkdir()
        self.refused()
        self.directory.rmdir(); saved.rename(self.directory)
        foreign = self.prefix / 'drive_c/users/another-user/Documents/Rockstar Games/GTA V'
        foreign.mkdir(parents=True)
        self.refused(); shutil.rmtree(self.prefix / 'drive_c/users/another-user')
        before = self.marker.read_bytes()
        self.origin['unreviewed_extra'] = 'new evidence cannot replace the prior reference'
        self.refresh_origin()
        with self.assertRaises(ProbePrefixError): self.enroll()
        self.assertEqual(before, self.marker.read_bytes())

    def test_temporarily_absent_enrolled_root_still_requires_unchanged_valid_origin(self):
        self.enroll()
        before = self.marker.read_bytes()
        shutil.rmtree(self.directory)
        identity = json.loads(before)
        self.assertEqual(validated_game_root(self.prefix, self.root, identity, self.user), game_user_root(self.user))
        main.assert_source_main_prefix(self.prefix, root=self.root)
        self.assertFalse(self.directory.exists())
        self.assertEqual(before, self.marker.read_bytes())
        (self.root / EVIDENCE_PATH).write_text('{}')
        with self.assertRaisesRegex(ProbePrefixError, 'origin metadata evidence changed'):
            validated_game_root(self.prefix, self.root, identity, self.user)
        self.assertFalse(self.directory.exists())

    def test_absent_root_does_not_skip_install_reference_or_install_session_validation(self):
        self.enroll()
        shutil.rmtree(self.directory)
        identity = json.loads(self.marker.read_text())
        for reference in ({'path': 'user.reg', 'sha256': '0' * 64},
                          self.reference('research/user-rockstar-install-20261101T204842084720Z.json',
                                         dict(self.session, automatic_wineserver_kill=True))):
            with self.subTest(reference=reference['path']):
                self.origin['user_install_session'] = reference
                self.refresh_origin()
                candidate = dict(identity, **{MARKER_KEY: self.origin_ref})
                with self.assertRaises(ProbePrefixError):
                    validated_game_root(self.prefix, self.root, candidate, self.user)
                self.assertFalse(self.directory.exists())

    def test_enrollment_requires_the_exclusive_main_lock(self):
        before = self.marker.read_bytes()
        with main._source_main_file_lock(self.prefix):
            with self.assertRaises(ProbePrefixError): self.enroll()
        self.assertEqual(before, self.marker.read_bytes())

    def test_failed_final_validation_restores_marker_without_changing_existing_data(self):
        before = self.marker.read_bytes()
        data = self.private.read_bytes()
        code = (self.prefix / MANIFEST_NAME).read_bytes()
        def fail_after_marker_write(*args, **kwargs):
            self.assertEqual(json.loads(self.marker.read_text())[MARKER_KEY], self.origin_ref)
            raise ProbePrefixError('own injected failure after marker write')
        with mock.patch.object(main, 'assert_source_main_prefix', side_effect=fail_after_marker_write):
            with self.assertRaises(ProbePrefixError): self.enroll()
        self.assertEqual(before, self.marker.read_bytes())
        self.assertEqual(data, self.private.read_bytes())
        self.assertEqual(code, (self.prefix / MANIFEST_NAME).read_bytes())
        self.refused()

    def test_changed_evidence_and_generic_api_preinit_policies_do_not_gain_permission(self):
        self.enroll()
        with self.assertRaises(ProbePrefixError): assert_account_free_prefix(self.prefix, root=self.root)
        with self.assertRaises(ProbePrefixError): assert_source_preinit_prefix(self.prefix, root=self.root)
        (self.root / EVIDENCE_PATH).write_text('{}')
        self.refused()

    def test_explicit_bounded_regular_reference_is_required_before_marker_write(self):
        before = self.marker.read_bytes()
        for reference in (None, {}, {'path': '../elsewhere', 'sha256': '0' * 64},
                          {'path': EVIDENCE_PATH, 'sha256': True}):
            with self.subTest(reference=reference), self.assertRaises(ProbePrefixError):
                main.enroll_user_game_data(self.prefix, reference, root=self.root)
            self.assertEqual(before, self.marker.read_bytes())
        target = self.root / EVIDENCE_PATH
        copy = target.with_suffix('.fixture-copy')
        target.rename(copy); target.symlink_to(copy)
        with self.assertRaises(ProbePrefixError): self.enroll()
        self.assertEqual(before, self.marker.read_bytes())
