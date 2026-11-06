"""Normal MAIN install/cache scope remains fresh and separate from API/PreInit probes."""
import getpass
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / 'scripts'))
from probe_environment import PERSONAL_FOLDERS, ProbePrefixError, assert_account_free_prefix
from source_preinit_environment import source_preinit_prefix, assert_source_preinit_prefix
from source_main_environment import (MARKER_NAME, PREFIX_NAME,
                                        assert_source_main_prefix, source_main_prefix)


class SourceMainEnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve() / 'project'
        self.prefix = self.root / 'prefixes' / PREFIX_NAME
        self.external = self.root.parent / 'external'
        self.external.mkdir()

    def tearDown(self):
        self.temporary.cleanup()

    def initialize(self):
        with source_main_prefix(self.prefix, root=self.root, create=True):
            pass

    def refuse(self):
        snapshot = sorted(str(p.relative_to(self.external)) for p in self.external.rglob('*'))
        with self.assertRaises(ProbePrefixError):
            with source_main_prefix(self.prefix, root=self.root, create=True):
                self.fail('Unsafe prefix reached the writable stage')
        self.assertEqual(snapshot, sorted(str(p.relative_to(self.external))
                                         for p in self.external.rglob('*')))

    def test_fresh_prefix_seeds_personal_folders_before_caller_can_boot_wine(self):
        self.assertFalse(self.prefix.exists())
        with source_main_prefix(self.prefix, root=self.root, create=True):
            marker = json.loads((self.prefix / MARKER_NAME).read_text())
            self.assertEqual(marker['prefix_inode'], self.prefix.stat().st_ino)
            self.assertTrue(marker['created_without_copy'])
            self.assertFalse((self.prefix / '.account-free-probe').exists())
            self.assertFalse((self.prefix / 'system.reg').exists())
            for user in (getpass.getuser(), 'Public'):
                for folder in PERSONAL_FOLDERS:
                    path = self.prefix / 'drive_c/users' / user / folder
                    self.assertTrue(path.is_dir())
                    self.assertFalse(path.is_symlink())

    def test_existing_unmarked_prefix_is_never_adopted(self):
        self.prefix.mkdir(parents=True)
        self.refuse()
        self.assertEqual(list(self.prefix.iterdir()), [])
        self.assertFalse((self.prefix.parent / ('.' + PREFIX_NAME + '.source-main.lock')).exists())

    def test_other_prefix_names_are_not_accepted(self):
        for name in ('corert-regression', 'fivem-legacy', 'rockstar-legacy'):
            with self.subTest(name=name), self.assertRaises(ProbePrefixError):
                with source_main_prefix(self.prefix.parent / name, root=self.root, create=True):
                    self.fail('A different prefix entered the source-MAIN scope')

    def test_redirected_prefix_and_parent_are_rejected_before_writes(self):
        self.prefix.parent.mkdir(parents=True)
        self.prefix.symlink_to(self.external, target_is_directory=True)
        self.refuse()
        self.prefix.unlink()
        self.prefix.parent.rmdir()
        self.prefix.parent.symlink_to(self.external, target_is_directory=True)
        self.refuse()

    def test_drive_users_user_and_known_folder_redirects_are_rejected(self):
        self.initialize()
        user = 'drive_c/users/' + getpass.getuser()
        for relative in ('drive_c', 'drive_c/users', user, user + '/Documents'):
            with self.subTest(relative=relative):
                path = self.prefix / relative
                shutil.rmtree(path)
                path.symlink_to(self.external, target_is_directory=True)
                self.refuse()
                path.unlink()
                path.mkdir(parents=True)
                self.initialize()

    def test_copying_a_marked_prefix_does_not_copy_its_fresh_identity(self):
        self.initialize()
        original = self.prefix.parent / 'saved-source-main'
        self.prefix.rename(original)
        shutil.copytree(original, self.prefix)
        self.refuse()

    def test_marker_link_and_generic_marker_are_rejected(self):
        self.initialize()
        marker = self.prefix / MARKER_NAME
        saved = self.external / 'marker.json'
        shutil.copy2(marker, saved)
        marker.unlink()
        marker.symlink_to(saved)
        self.refuse()
        marker.unlink()
        shutil.copy2(saved, marker)
        (self.prefix / '.account-free-probe').write_text('API marker is not a source marker\n')
        self.refuse()

    def test_main_owned_installation_and_cache_roots_are_allowed(self):
        self.initialize()
        user = self.prefix / 'drive_c/users' / getpass.getuser()
        for relative in ('AppData/Local/FiveM', 'AppData/Local/CitizenFX/cache',
                         'AppData/Roaming/CitizenFX/cache'):
            cache = user / relative
            cache.mkdir(parents=True)
            (cache / 'index').write_bytes(b'local bootstrap fixture')
        assert_source_main_prefix(self.prefix, root=self.root)

    def test_installation_and_cache_exceptions_do_not_expand_to_other_locations(self):
        self.initialize()
        for relative in (getpass.getuser() + '/Documents/CitizenFX',
                         getpass.getuser() + '/AppData/Roaming/FiveM',
                         'another-user/AppData/Local/FiveM',
                         'another-user/AppData/Local/CitizenFX'):
            path = self.prefix / 'drive_c/users' / relative
            path.mkdir(parents=True)
            self.refuse()
            shutil.rmtree(path)

    def test_exact_own_saved_games_root_and_gta5_descendants_are_directory_scope(self):
        import source_main_environment as policy
        self.initialize()
        user = self.prefix / 'drive_c/users' / getpass.getuser()
        saved = user / 'Saved Games/CitizenFX'
        target = saved / 'GTA5/own-progress'
        target.mkdir(parents=True)
        (target / 'save.dat').write_bytes(b'own inert save fixture')
        assert_source_main_prefix(self.prefix, root=self.root)
        self.assertTrue(policy._is_own_save_data(saved, self.prefix))
        self.assertTrue(policy._is_own_save_data(target, self.prefix))
        self.assertFalse(policy._is_own_save_data(saved / 'AnotherGame', self.prefix))
        self.assertFalse(policy._is_own_cache(saved, self.prefix))

    def test_saved_games_exception_rejects_other_users_roots_and_lookalikes(self):
        self.initialize()
        for relative in ('another-user/Saved Games/CitizenFX',
                         getpass.getuser() + '/Documents/CitizenFX',
                         getpass.getuser() + '/Saved Games/CitizenFX-backup',
                         getpass.getuser() + '/Saved Games/CitizenFX/GTA5-backup/CitizenFX'):
            path = self.prefix / 'drive_c/users' / relative
            path.mkdir(parents=True)
            self.refuse()
            shutil.rmtree(path)

    def test_saved_games_exception_does_not_authorize_tickets_even_after_manual_login(self):
        self.initialize()
        saved = self.prefix / 'drive_c/users' / getpass.getuser() / 'Saved Games/CitizenFX/GTA5'
        saved.mkdir(parents=True)
        for name in ('ros_login.dat', 'ROS_LOGIN.JSON', 'cfxTicket', 'CFXTICKET-backup'):
            path = saved / name
            path.write_bytes(b'own inert forbidden-name fixture')
            with mock.patch('source_main_environment._manual_login_authorized', return_value=True):
                self.refuse()
            self.assertEqual(path.read_bytes(), b'own inert forbidden-name fixture')
            path.unlink()

    def test_saved_games_exception_rejects_nested_vendor_account_directories(self):
        self.initialize()
        saved = self.prefix / 'drive_c/users' / getpass.getuser() / 'Saved Games/CitizenFX/GTA5'
        saved.mkdir(parents=True)
        for name in ('Rockstar Games', 'Social Club', 'socialclub'):
            path = saved / name
            path.mkdir()
            self.refuse()
            path.rmdir()

    def test_normal_wineboot_files_do_not_require_a_client_scope_exception(self):
        self.initialize()
        for relative in ('drive_c/windows/system32/kernel32.dll',
                         'drive_c/windows/temp/setup.log', 'drive_c/ProgramData/Microsoft/setup.log',
                         'drive_c/users/Public/Shared/setup.log'):
            path = self.prefix / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'ordinary setup fixture')
        for name in ('system.reg', 'user.reg', 'userdef.reg'):
            (self.prefix / name).write_text('ordinary fixture registry\n')
        devices = self.prefix / 'dosdevices'
        devices.mkdir()
        (devices / 'c:').symlink_to('../drive_c', target_is_directory=True)
        assert_source_main_prefix(self.prefix, root=self.root)

    def test_preinit_policy_does_not_acquire_main_install_permission(self):
        prefix = self.prefix.parent / 'fivem-source-preinit'
        with source_preinit_prefix(prefix, root=self.root, create=True):
            pass
        installation = prefix / 'drive_c/users' / getpass.getuser() / 'AppData/Local/FiveM'
        installation.mkdir(parents=True)
        with self.assertRaises(ProbePrefixError):
            assert_source_preinit_prefix(prefix, root=self.root)

    def test_strict_api_probe_policy_still_rejects_citizenfx_caches(self):
        api_prefix = self.prefix.parent / 'corert-regression'
        cache = api_prefix / 'drive_c/users' / getpass.getuser() / 'AppData/Local/CitizenFX'
        cache.mkdir(parents=True)
        (api_prefix / '.account-free-probe').write_text('own API probes\n')
        with self.assertRaises(ProbePrefixError):
            assert_account_free_prefix(api_prefix, root=self.root)

    def test_client_installations_and_login_artifacts_are_rejected(self):
        self.initialize()
        user = self.prefix / 'drive_c/users' / getpass.getuser()
        for relative in ('drive_c/FiveM', 'drive_c/Program Files/Rockstar Games',
                         'drive_c/ProgramData/CitizenFX'):
            path = self.prefix / relative
            path.mkdir(parents=True)
            self.refuse()
            shutil.rmtree(path)
        cache = user / 'AppData/Roaming/CitizenFX'
        cache.mkdir(parents=True)
        for name in ('cfxTicket', 'cfxTicket2', 'CFXTICKET-backup', 'ros_login.dat', 'ROS_LOGIN.JSON'):
            ticket = cache / name
            ticket.write_bytes(b'fixture, never an actual credential')
            self.refuse()
            self.assertTrue(ticket.is_file())
            ticket.unlink()

    def test_rockstar_directory_is_not_allowed_inside_the_cache_exception(self):
        self.initialize()
        path = self.prefix / 'drive_c/users' / getpass.getuser() / 'AppData/Local/CitizenFX/Rockstar Games'
        path.mkdir(parents=True)
        self.refuse()

    def test_shell_folder_host_drive_mapping_is_rejected(self):
        self.initialize()
        (self.prefix / 'user.reg').write_text(
            '[Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\Shell Folders]\n'
            '"Personal"="Z:\\\\Users\\\\someone\\\\Documents"\n')
        self.refuse()

    def test_external_c_drive_and_redirected_dosdevices_are_rejected(self):
        self.initialize()
        devices = self.prefix / 'dosdevices'
        devices.mkdir()
        mapping = devices / 'c:'
        mapping.symlink_to(self.external, target_is_directory=True)
        self.refuse()
        mapping.unlink()
        devices.rmdir()
        devices.symlink_to(self.external, target_is_directory=True)
        self.refuse()

    def test_mapping_is_optional_before_boot_and_required_after_boot(self):
        self.initialize()
        assert_source_main_prefix(self.prefix, root=self.root)
        (self.prefix / 'system.reg').write_text('fixture registry\n')
        with self.assertRaises(ProbePrefixError):
            assert_source_main_prefix(self.prefix, root=self.root)
        devices = self.prefix / 'dosdevices'
        devices.mkdir()
        (devices / 'c:').symlink_to('../drive_c', target_is_directory=True)
        assert_source_main_prefix(self.prefix, root=self.root)

    def test_post_boot_known_folder_mapping_is_detected(self):
        with source_main_prefix(self.prefix, root=self.root, create=True):
            documents = self.prefix / 'drive_c/users' / getpass.getuser() / 'Documents'
            documents.rmdir()
            documents.symlink_to(self.external, target_is_directory=True)
            with self.assertRaises(ProbePrefixError):
                assert_source_main_prefix(self.prefix, root=self.root)

    def test_invalid_username_cannot_seed_folders_outside_the_prefix(self):
        with mock.patch('getpass.getuser', return_value='../../external'):
            self.refuse()
        self.assertFalse(self.prefix.exists())

    def test_lock_redirects_and_hardlinks_do_not_modify_their_targets(self):
        self.initialize()
        lock = self.prefix.parent / ('.' + PREFIX_NAME + '.source-main.lock')
        target = self.external / 'preserve.txt'
        target.write_text('preserve this\n')
        lock.unlink()
        lock.symlink_to(target)
        self.refuse()
        self.assertEqual(target.read_text(), 'preserve this\n')
        lock.unlink()
        os.link(target, lock)
        self.refuse()
        self.assertEqual(target.read_text(), 'preserve this\n')

    def test_process_lock_blocks_overlap_and_releases_on_process_death(self):
        self.initialize()
        code = ('import sys; from pathlib import Path; sys.path.insert(0,sys.argv[1]); '
                'from source_main_environment import source_main_prefix; '
                'scope=source_main_prefix(Path(sys.argv[2]),root=Path(sys.argv[3])); '
                'scope.__enter__(); print("LOCKED",flush=True); sys.stdin.read()')
        child = subprocess.Popen([sys.executable, '-c', code, str(PROJECT / 'scripts'),
                                  str(self.prefix), str(self.root)], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.assertEqual(child.stdout.readline().strip(), 'LOCKED')
            with self.assertRaises(ProbePrefixError):
                with source_main_prefix(self.prefix, root=self.root):
                    self.fail('Concurrent MAIN process acquired the same prefix')
        finally:
            child.kill()
            child.communicate(timeout=5)
        with source_main_prefix(self.prefix, root=self.root):
            pass


if __name__ == '__main__':
    unittest.main()
