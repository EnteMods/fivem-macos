"""Code-only dependency enrollment never imports RGL user/account state."""
import getpass
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / 'scripts'))
from probe_environment import ProbePrefixError, assert_account_free_prefix
from source_main_environment import (MARKER_NAME, PREFIX_NAME, assert_source_main_prefix,
                                     source_main_prefix, bind_rockstar_code_manifest)
from source_preinit_environment import source_preinit_prefix, assert_source_preinit_prefix
from rockstar_code_policy import CODE_ROOTS, MANIFEST_NAME, user_roots


class RockstarCodePolicyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve() / 'project'
        self.prefix = self.root / 'prefixes' / PREFIX_NAME
        self.user = getpass.getuser()
        with source_main_prefix(self.prefix, root=self.root, create=True):
            pass
        self.evidence = self.root / 'research/rockstar-code-only-source.json'
        self.evidence.parent.mkdir()
        self.evidence.write_text('{"source":"own code-only fixture, never a vendor executable"}\n')

    def tearDown(self):
        self.temporary.cleanup()

    def code(self):
        files = []
        for relative in (CODE_ROOTS[0] + '/Launcher.exe', CODE_ROOTS[0] + '/api-ms-win-core-profile-l1-1-0.dll',
                         CODE_ROOTS[1] + '/socialclub.dll'):
            path = self.prefix / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'own inert fixture bytes: ' + relative.encode())
            files.append({'path': relative, 'bytes': path.stat().st_size,
                          'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
        return {'schema': 1, 'kind': 'rockstar-code-only', 'roots': list(CODE_ROOTS),
                'files': files, 'source_evidence': {'path': str(self.evidence.relative_to(self.root)),
                    'sha256': hashlib.sha256(self.evidence.read_bytes()).hexdigest()},
                'excluded_account_profiles_registry_sessions': True}

    def enrolled(self):
        with source_main_prefix(self.prefix, root=self.root):
            manifest = self.code()
            binding = bind_rockstar_code_manifest(self.prefix, manifest, root=self.root)
            assert_source_main_prefix(self.prefix, root=self.root)
        return manifest, binding

    def assert_refused(self):
        with self.assertRaises(ProbePrefixError):
            assert_source_main_prefix(self.prefix, root=self.root)

    def test_exact_code_enrollment_is_locked_inode_bound_and_does_not_touch_registry(self):
        registry = self.prefix / 'user.reg'
        registry.write_text('own fresh fixture registry\n')
        before = registry.read_bytes()
        manifest, binding = self.enrolled()
        self.assertEqual(before, registry.read_bytes())
        identity = json.loads((self.prefix / MARKER_NAME).read_text())
        self.assertEqual(identity['rockstar_code_manifest'], binding)
        stored = json.loads((self.prefix / MANIFEST_NAME).read_text())
        self.assertEqual(stored['prefix_binding']['prefix_inode'], self.prefix.stat().st_ino)
        self.assertEqual(stored['user_data_roots'], list(user_roots(self.user)))
        self.assertEqual(binding['sha256'], hashlib.sha256((self.prefix / MANIFEST_NAME).read_bytes()).hexdigest())
        for relative in user_roots(self.user):
            self.assertEqual(list((self.prefix / relative).iterdir()), [])
        with source_main_prefix(self.prefix, root=self.root):
            self.assertEqual(bind_rockstar_code_manifest(self.prefix, manifest, root=self.root), binding)

    def test_enrollment_outside_held_main_context_is_refused(self):
        with self.assertRaises(ProbePrefixError):
            bind_rockstar_code_manifest(self.prefix, {}, root=self.root)
        self.assertFalse((self.prefix / MANIFEST_NAME).exists())

    def test_unbound_code_or_unbound_manifest_never_grants_exception(self):
        with source_main_prefix(self.prefix, root=self.root):
            manifest = self.code()
            self.assert_refused()
            (self.prefix / MANIFEST_NAME).write_text(json.dumps(manifest))
            self.assert_refused()

    def test_manifest_cannot_extend_to_registry_hives_other_roots_or_case_aliases(self):
        with source_main_prefix(self.prefix, root=self.root):
            original = self.code()
            for path in ('user.reg', 'drive_c/ProgramData/Rockstar Games/state.dat',
                         CODE_ROOTS[0] + '/../account.dat', CODE_ROOTS[0] + '/user.reg'):
                with self.subTest(path=path):
                    manifest = json.loads(json.dumps(original))
                    manifest['files'].append({'path': path, 'bytes': 0, 'sha256': '0' * 64})
                    with self.assertRaises(ProbePrefixError):
                        bind_rockstar_code_manifest(self.prefix, manifest, root=self.root)
            manifest = json.loads(json.dumps(original))
            alias = dict(manifest['files'][0], path=manifest['files'][0]['path'].upper())
            manifest['files'].append(alias)
            with self.assertRaises(ProbePrefixError):
                bind_rockstar_code_manifest(self.prefix, manifest, root=self.root)
            manifest = json.loads(json.dumps(original)); manifest['roots'] = ['drive_c/Program Files']
            with self.assertRaises(ProbePrefixError):
                bind_rockstar_code_manifest(self.prefix, manifest, root=self.root)

    def test_existing_nonempty_userdata_is_not_adopted_or_deleted(self):
        with source_main_prefix(self.prefix, root=self.root):
            manifest = self.code()
            path = self.prefix / user_roots(self.user)[0] / 'webcache/Cookies'
            path.parent.mkdir(parents=True)
            path.write_bytes(b'inert preexisting fixture, must not be adopted')
            with self.assertRaises(ProbePrefixError):
                bind_rockstar_code_manifest(self.prefix, manifest, root=self.root)
            self.assertEqual(path.read_bytes(), b'inert preexisting fixture, must not be adopted')
            self.assertFalse((self.prefix / MANIFEST_NAME).exists())

    def test_runtime_file_disappearing_after_walk_snapshot_is_tolerated(self):
        import rockstar_code_policy as policy
        self.enrolled()
        for inside in (True, False):
            path = self.prefix / user_roots(self.user)[2] / 'own-volatile'
            if not inside:
                path = path.parent.parent / 'own-vanished-sibling'
            path.write_bytes(b'own volatile fixture')
            original_walk = os.walk
            def snapshot(*args, **kwargs):
                for base, folders, files in original_walk(*args, **kwargs):
                    if Path(base) == path.parent and path.name in files:
                        path.unlink()
                    yield base, folders, files
            with self.subTest(inside=inside), mock.patch.object(policy.os, 'walk', side_effect=snapshot):
                policy._verify_user_tree(self.prefix, user_roots(self.user))
            self.assertFalse(path.exists())

    def test_runtime_file_disappearing_after_plain_check_is_tolerated(self):
        import rockstar_code_policy as policy
        self.enrolled()
        path = self.prefix / user_roots(self.user)[2] / 'own-volatile'
        path.write_bytes(b'own volatile fixture')
        original_plain = policy._plain_path
        def plain(candidate, boundary):
            original_plain(candidate, boundary)
            if candidate == path:
                path.unlink()
        with mock.patch.object(policy, '_plain_path', side_effect=plain):
            policy._verify_user_tree(self.prefix, user_roots(self.user))
        self.assertFalse(path.exists())

    def test_runtime_leaf_uses_one_captured_stat_after_plain_check(self):
        import rockstar_code_policy as policy
        self.enrolled()
        path = self.prefix / user_roots(self.user)[2] / 'own-volatile'
        path.write_bytes(b'own volatile fixture')
        original_plain, original_lstat = policy._plain_path, Path.lstat
        armed, metadata_reads = False, 0
        def plain(candidate, boundary):
            nonlocal armed
            original_plain(candidate, boundary)
            if candidate == path:
                armed = True
        def lstat(candidate, *args, **kwargs):
            nonlocal armed, metadata_reads
            value = original_lstat(candidate, *args, **kwargs)
            if candidate == path and armed:
                armed = False
                metadata_reads += 1
                path.unlink()
            return value
        with mock.patch.object(policy, '_plain_path', side_effect=plain), mock.patch.object(Path, 'lstat', lstat):
            policy._verify_user_tree(self.prefix, user_roots(self.user))
        self.assertEqual(metadata_reads, 1)
        self.assertFalse(path.exists())

    def test_runtime_symlinks_special_files_and_multilinks_still_fail(self):
        import rockstar_code_policy as policy
        self.enrolled()
        path = self.prefix / user_roots(self.user)[2] / 'own-volatile'
        outside = self.root / 'own-runtime-source'
        outside.write_bytes(b'own inert fixture')
        path.symlink_to(outside)
        with self.assertRaises(ProbePrefixError): policy._verify_user_tree(self.prefix, user_roots(self.user))
        path.unlink()
        os.link(outside, path)
        with self.assertRaises(ProbePrefixError): policy._verify_user_tree(self.prefix, user_roots(self.user))
        path.unlink()
        os.mkfifo(path)
        with self.assertRaises(ProbePrefixError): policy._verify_user_tree(self.prefix, user_roots(self.user))
        path.unlink()

    def test_empty_userdata_can_be_seeded_and_fresh_runtime_ui_files_allowed(self):
        with source_main_prefix(self.prefix, root=self.root):
            manifest = self.code()
            empty = self.prefix / user_roots(self.user)[1] / 'Profiles'
            empty.mkdir(parents=True)
            bind_rockstar_code_manifest(self.prefix, manifest, root=self.root)
        for relative in ('launcher.log', 'settings.xml', 'webcache/Cookies'):
            path = self.prefix / user_roots(self.user)[2] / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'new inert runtime UI fixture')
        assert_source_main_prefix(self.prefix, root=self.root)

    def test_roaming_other_users_and_other_game_siblings_stay_forbidden(self):
        self.enrolled()
        for relative in ('drive_c/users/' + self.user + '/AppData/Roaming/Rockstar Games/Launcher',
                         'drive_c/users/other/Documents/Rockstar Games/Launcher',
                         'drive_c/users/' + self.user + '/Documents/Rockstar Games/GTA V',
                         'drive_c/Program Files/Rockstar Games/OtherGame'):
            path = self.prefix / relative
            path.mkdir(parents=True)
            self.assert_refused()
            shutil.rmtree(path)

    def test_login_and_cfx_ticket_names_stay_forbidden_after_enrollment(self):
        self.enrolled()
        for name in ('ros_login.dat', 'ROS_LOGIN.JSON', 'cfxTicket2', 'CFXTICKET-backup'):
            path = self.prefix / user_roots(self.user)[0] / name
            path.write_bytes(b'credential-name fixture, never an actual credential')
            self.assert_refused()
            path.unlink()

    def test_changed_missing_and_extra_program_files_fail_closed(self):
        manifest, _ = self.enrolled()
        path = self.prefix / manifest['files'][0]['path']
        data = path.read_bytes()
        path.write_bytes(data[:-1] + bytes([data[-1] ^ 1]))
        self.assert_refused()
        path.write_bytes(data)
        path.unlink()
        self.assert_refused()
        path.write_bytes(data)
        extra = self.prefix / CODE_ROOTS[0] / 'unrecorded.dll'
        extra.write_bytes(b'inert extra code fixture')
        self.assert_refused()

    def test_code_symlinks_hardlinks_and_profile_directory_are_rejected(self):
        manifest, _ = self.enrolled()
        path = self.prefix / manifest['files'][0]['path']
        data = path.read_bytes()
        external = self.root.parent / 'preserve.bin'; external.write_bytes(data)
        path.unlink(); path.symlink_to(external)
        self.assert_refused()
        path.unlink(); os.link(external, path)
        self.assert_refused()
        path.unlink(); path.write_bytes(data)
        (self.prefix / CODE_ROOTS[0] / 'Profiles').mkdir()
        self.assert_refused()
        self.assertEqual(external.read_bytes(), data)

    def test_manifest_source_evidence_and_marker_binding_tampering_are_rejected(self):
        _, binding = self.enrolled()
        manifest = self.prefix / MANIFEST_NAME
        original = manifest.read_bytes()
        manifest.write_bytes(original + b' ')
        self.assert_refused()
        manifest.write_bytes(original)
        source = self.evidence.read_bytes(); self.evidence.write_bytes(source + b' ')
        self.assert_refused()
        self.evidence.write_bytes(source)
        marker = self.prefix / MARKER_NAME
        identity = json.loads(marker.read_text()); identity['rockstar_code_manifest']['sha256'] = '0' * 64
        marker.write_text(json.dumps(identity))
        self.assert_refused()

    def test_copying_marked_installation_does_not_copy_prefix_identity(self):
        self.enrolled()
        original = self.prefix.parent / 'saved-main'
        self.prefix.rename(original)
        shutil.copytree(original, self.prefix)
        self.assert_refused()

    def test_metadata_cached_code_is_rehashed_after_same_size_write_and_restored_mtime(self):
        manifest, _ = self.enrolled()
        with mock.patch('rockstar_code_policy.hashlib.sha256', wraps=hashlib.sha256) as digest:
            assert_source_main_prefix(self.prefix, root=self.root)
            self.assertEqual(digest.call_count, 0, 'Unchanged large code should not be fully rehashed every 2 seconds')
            path = self.prefix / manifest['files'][0]['path']
            before = path.stat(); data = path.read_bytes()
            path.write_bytes(data[:-1] + bytes([data[-1] ^ 1]))
            os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
            self.assert_refused()
            self.assertGreater(digest.call_count, 0)

    def test_runtime_userdata_redirect_is_rejected_without_touching_external_folder(self):
        self.enrolled()
        path = self.prefix / user_roots(self.user)[0]
        path.rmdir()
        external = self.root.parent / 'external'; external.mkdir()
        (external / 'keep').write_text('preserve\n')
        path.symlink_to(external, target_is_directory=True)
        self.assert_refused()
        self.assertEqual((external / 'keep').read_text(), 'preserve\n')

    def test_failure_after_marker_write_restores_bytes_and_only_new_empty_directories(self):
        with source_main_prefix(self.prefix, root=self.root):
            existing = self.prefix / user_roots(self.user)[0] / 'ExistingEmptyFolder'
            existing.mkdir(parents=True)
            unrelated = self.prefix / 'drive_c/users' / self.user / 'Documents/keep.txt'
            unrelated.write_text('unrelated existing user fixture\n')
            marker = self.prefix / MARKER_NAME
            marker_before = marker.read_bytes()
            user_tree = self.prefix / 'drive_c/users'
            before = sorted(str(path.relative_to(user_tree)) for path in user_tree.rglob('*'))
            manifest = self.code()
            def fail_after_marker(prefix, root, identity, user):
                self.assertIn('rockstar_code_manifest', json.loads(marker.read_text()))
                self.assertTrue((prefix / MANIFEST_NAME).is_file())
                raise RuntimeError('injected final validation failure after marker write')
            with mock.patch('rockstar_code_policy.validate_binding', side_effect=fail_after_marker):
                with self.assertRaisesRegex(RuntimeError, 'injected final validation failure'):
                    bind_rockstar_code_manifest(self.prefix, manifest, root=self.root)
        self.assertEqual(marker.read_bytes(), marker_before)
        self.assertFalse((self.prefix / MANIFEST_NAME).exists())
        failed = list(self.prefix.glob('.source-main-rockstar-code.failed-*.json'))
        self.assertEqual(len(failed), 1)
        self.assertEqual(json.loads(failed[0].read_text())['kind'], 'rockstar-code-only')
        self.assertEqual(before, sorted(str(path.relative_to(user_tree)) for path in user_tree.rglob('*')))
        self.assertTrue(existing.is_dir())
        self.assertEqual(unrelated.read_text(), 'unrelated existing user fixture\n')

    def test_generic_api_and_preinit_guards_keep_rejecting_rockstar_code(self):
        for name in ('corert-regression', 'fivem-source-preinit'):
            prefix = self.prefix.parent / name
            if name == 'corert-regression':
                prefix.mkdir(); (prefix / '.account-free-probe').write_text('own fixture\n')
            else:
                with source_preinit_prefix(prefix, root=self.root, create=True): pass
            (prefix / CODE_ROOTS[0]).mkdir(parents=True)
            with self.assertRaises(ProbePrefixError):
                (assert_account_free_prefix if name == 'corert-regression' else assert_source_preinit_prefix)(prefix, root=self.root)


if __name__ == '__main__':
    unittest.main()
