"""Account-free prefix guards reject redirects before writes or Wine execution."""
import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / 'scripts'))
from probe_environment import ProbePrefixError, assert_account_free_prefix, probe_prefix


class ProbeEnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve() / 'project'
        self.prefix = self.root / 'prefixes/corert-regression'
        self.user = self.prefix / 'drive_c/users/testuser'
        self.user.mkdir(parents=True)
        (self.prefix / '.account-free-probe').write_text('own probes only\n')
        self.external = self.root.parent / 'external'
        self.external.mkdir()

    def tearDown(self):
        self.temporary.cleanup()

    def refuse_before_writes(self):
        before = sorted(str(p.relative_to(self.external)) for p in self.external.rglob('*'))
        with self.assertRaises(ProbePrefixError):
            with probe_prefix(self.prefix, root=self.root, create=True):
                self.fail('An unsafe prefix reached its writable scope')
        after = sorted(str(p.relative_to(self.external)) for p in self.external.rglob('*'))
        self.assertEqual(before, after)
        self.assertFalse((self.root / 'prefixes/.corert-regression.probe.lock').exists())

    def test_current_regular_prefix_is_accepted(self):
        with probe_prefix(self.prefix, root=self.root):
            self.assertEqual(assert_account_free_prefix(self.prefix, root=self.root), self.prefix)

    def test_redirected_prefix_parent_is_rejected_before_writes(self):
        parent = self.prefix.parent
        shutil.move(str(parent), str(self.external / 'prefixes'))
        parent.symlink_to(self.external / 'prefixes', target_is_directory=True)
        self.refuse_before_writes()

    def test_prefix_aliases_to_original_or_account_copy_are_rejected(self):
        shutil.rmtree(self.prefix)
        for name in ('rockstar-legacy', 'fivem-legacy', 'unrelated-folder'):
            target = self.external / name
            target.mkdir()
            (target / '.account-free-probe').write_text('copied marker\n')
            self.prefix.symlink_to(target, target_is_directory=True)
            self.refuse_before_writes()
            self.prefix.unlink()

    def test_redirected_drive_users_user_and_known_folder_are_rejected(self):
        for relative in ('drive_c', 'drive_c/users', 'drive_c/users/testuser',
                         'drive_c/users/testuser/Documents'):
            with self.subTest(relative=relative):
                path = self.prefix / relative
                if path.exists():
                    shutil.rmtree(path)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.symlink_to(self.external, target_is_directory=True)
                self.refuse_before_writes()
                path.unlink()
                self.user.mkdir(parents=True, exist_ok=True)

    def test_existing_unmarked_prefix_is_not_initialized(self):
        marker = self.prefix / '.account-free-probe'
        marker.unlink()
        self.refuse_before_writes()
        self.assertFalse(marker.exists())

    def test_external_c_drive_and_redirected_dosdevices_are_rejected(self):
        devices = self.prefix / 'dosdevices'
        devices.mkdir()
        mapping = devices / 'c:'
        mapping.symlink_to(self.external, target_is_directory=True)
        self.refuse_before_writes()
        mapping.unlink()
        devices.rmdir()
        devices.symlink_to(self.external, target_is_directory=True)
        self.refuse_before_writes()

    def test_booted_prefix_requires_normal_c_drive_mapping(self):
        (self.prefix / 'system.reg').write_text('fixture registry\n')
        with self.assertRaises(ProbePrefixError):
            assert_account_free_prefix(self.prefix, root=self.root)
        devices = self.prefix / 'dosdevices'
        devices.mkdir()
        (devices / 'c:').symlink_to('../drive_c', target_is_directory=True)
        assert_account_free_prefix(self.prefix, root=self.root)

    def test_known_client_prefix_name_is_rejected_even_with_marker(self):
        copied = self.prefix.parent / 'fivem-legacy'
        copied.mkdir()
        (copied / '.account-free-probe').write_text('copied marker\n')
        with self.assertRaises(ProbePrefixError):
            assert_account_free_prefix(copied, root=self.root)

    def test_account_directories_are_rejected(self):
        for relative in ('drive_c/FiveM', 'drive_c/Program Files/Rockstar Games',
                         'drive_c/users/testuser/AppData/Local/CitizenFX',
                         'drive_c/users/testuser/Documents/Rockstar Games'):
            with self.subTest(relative=relative):
                path = self.prefix / relative
                path.mkdir(parents=True)
                self.refuse_before_writes()
                shutil.rmtree(path)

    def test_registry_host_mapping_and_parent_escape_are_rejected(self):
        for value in (r'Z:\\Users\\testuser\\Documents', r'C:\\users\\..\\..\\outside'):
            (self.prefix / 'user.reg').write_text(
                '[Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\Shell Folders]\n'
                '"Personal"="' + value + '"\n')
            self.refuse_before_writes()

    def test_registry_prefix_local_shell_folder_is_accepted(self):
        (self.prefix / 'user.reg').write_text(
            '[Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\Shell Folders]\n'
            '"Personal"="C:\\\\users\\\\testuser\\\\Documents"\n')
        assert_account_free_prefix(self.prefix, root=self.root)

    def test_post_boot_redirect_is_detected_without_reinitializing_prefix(self):
        with probe_prefix(self.prefix, root=self.root):
            (self.user / 'Documents').symlink_to(self.external, target_is_directory=True)
            with self.assertRaises(ProbePrefixError):
                assert_account_free_prefix(self.prefix, root=self.root)

    def test_missing_prefix_is_created_only_inside_the_locked_scope(self):
        shutil.rmtree(self.prefix)
        with probe_prefix(self.prefix, root=self.root, create=True):
            self.assertTrue((self.prefix / '.account-free-probe').is_file())

    def test_process_lock_blocks_overlap_and_releases_after_process_death(self):
        code = (
            'import sys; from pathlib import Path; '
            'sys.path.insert(0, sys.argv[1]); '
            'from probe_environment import probe_prefix; '
            'scope=probe_prefix(Path(sys.argv[2]), root=Path(sys.argv[3])); '
            'scope.__enter__(); print("LOCKED", flush=True); sys.stdin.read()'
        )
        child = subprocess.Popen([sys.executable, '-c', code, str(PROJECT / 'scripts'),
                                  str(self.prefix), str(self.root)], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.assertEqual(child.stdout.readline().strip(), 'LOCKED')
            with self.assertRaises(ProbePrefixError):
                with probe_prefix(self.prefix, root=self.root):
                    self.fail('Concurrent process acquired the same prefix')
        finally:
            child.kill()
            child.communicate(timeout=5)
        with probe_prefix(self.prefix, root=self.root):
            self.assertTrue((self.prefix.parent / '.corert-regression.probe.lock').is_file())

    def test_unsafe_regression_runner_does_not_import_runtime_or_write_marker(self):
        spec = importlib.util.spec_from_file_location('regression_scope_test', PROJECT / 'scripts/corert_regression.py')
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        build = self.root / 'build'
        build.mkdir()
        (build / 'corert-regression.exe').write_bytes(b'fixture, never executed')
        shutil.rmtree(self.prefix)
        (self.external / '.account-free-probe').write_text('copied marker\n')
        self.prefix.symlink_to(self.external, target_is_directory=True)
        with mock.patch.object(runner, 'ROOT', self.root), \
                mock.patch.object(runner, 'PREFIX', self.prefix), \
                mock.patch.object(runner, 'BUILD', build), \
                mock.patch('subprocess.run') as launch, \
                mock.patch('importlib.util.spec_from_file_location') as load_runtime:
            with self.assertRaises(ProbePrefixError):
                runner.test()
        launch.assert_not_called()
        load_runtime.assert_not_called()
        self.assertFalse((self.external / 'drive_c').exists())

    def test_full_dll_runner_rejects_redirect_before_runtime_import(self):
        spec = importlib.util.spec_from_file_location('core_scope_test', PROJECT / 'scripts/windows_core.py')
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        shutil.rmtree(self.prefix)
        (self.external / '.account-free-probe').write_text('copied marker\n')
        self.prefix.symlink_to(self.external, target_is_directory=True)
        with mock.patch.object(runner, 'ROOT', self.root), \
                mock.patch.object(runner, 'PREFIX', self.prefix), \
                mock.patch('subprocess.run') as launch, \
                mock.patch('importlib.util.spec_from_file_location') as load_runtime:
            with self.assertRaises(ProbePrefixError):
                runner.test()
        launch.assert_not_called()
        load_runtime.assert_not_called()

    def test_md_abi_runner_rejects_redirect_before_runtime_import(self):
        spec = importlib.util.spec_from_file_location('abi_scope_test', PROJECT / 'native/windows-abi/run.py')
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        shutil.rmtree(self.prefix)
        (self.external / '.account-free-probe').write_text('copied marker\n')
        self.prefix.symlink_to(self.external, target_is_directory=True)
        with mock.patch.object(runner, 'ROOT', self.root), \
                mock.patch.object(runner, 'PREFIX', self.prefix), \
                mock.patch.object(runner, 'BUILD', self.root / 'build'), \
                mock.patch('sys.argv', ['run.py', 'run']), \
                mock.patch('subprocess.run') as launch, \
                mock.patch('importlib.util.spec_from_file_location') as load_runtime:
            with self.assertRaises(ProbePrefixError):
                runner.main()
        launch.assert_not_called()
        load_runtime.assert_not_called()


if __name__ == '__main__':
    unittest.main()
