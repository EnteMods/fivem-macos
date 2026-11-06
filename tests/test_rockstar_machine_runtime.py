"""One observed machine-log root can migrate without adopting arbitrary account state."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import unittest
from unittest import mock

import test_rockstar_code_policy as code_fixtures
from probe_environment import ProbePrefixError, assert_account_free_prefix
from source_main_environment import (MARKER_NAME, assert_source_main_prefix, migrate_rockstar_machine_runtime,
                                     _source_main_file_lock)
from rockstar_code_policy import MACHINE_ROOT, MANIFEST_NAME


class RockstarMachineRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.fixture = code_fixtures.RockstarCodePolicyTests()
        self.fixture.setUp()
        self.root, self.prefix = self.fixture.root, self.fixture.prefix
        self.fixture.enrolled()
        before_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=1)
        self.before = {'at': before_time.isoformat(), 'prefix': str(self.prefix.relative_to(self.root)),
                       'passed': True, 'launcher_or_main_started': False,
                       'only_two_actual_installfolder_values_written': True,
                       'registry_hives_or_accounts_copied': False, 'prefix_cleanup': {'wait_exit': 0}}
        self.run = {'at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    'prefix': str(self.prefix.relative_to(self.root)), 'stage': 'build/windows-source-integration',
                    'resumed_from_exact_source_run_and_checkpoint': True, 'arguments': [],
                    'copied_account_or_profile_inputs': False, 'runtime_security_branches_modified': False,
                    'agent_issued_story_mode_gameplay_or_connect_arguments': False, 'runner_failure': None,
                    'isolation_guard_failure': {'type': 'ProbePrefixError',
                        'message': 'Refusing a client installation in the fresh source-MAIN prefix.'},
                    'prefix_cleanup': {'kill_exit': 0, 'wait_exit': 0, 'wait_timed_out': False},
                    'diagnostic': {'unhandled_c0000409': False}}
        self.directory = self.prefix / MACHINE_ROOT
        self.directory.mkdir(parents=True)
        for name in ('service_log.txt', 'svc_events.json'):
            (self.directory / name).write_bytes(b'inert fresh machine-diagnostic fixture, preserve IDs and bytes')
        self.origin = {'schema': 1, 'kind': 'fresh-rockstar-machine-runtime',
                       'prefix': str(self.prefix.relative_to(self.root)), 'copied_from_other_prefix': False,
                       'prior_marker_sha256': self.sha(self.prefix / MARKER_NAME),
                       'prior_code_manifest_sha256': self.sha(self.prefix / MANIFEST_NAME),
                       'directory': {'device': self.directory.stat().st_dev, 'inode': self.directory.stat().st_ino},
                       'files': [{'path': str(path.relative_to(self.prefix)), 'bytes': path.stat().st_size,
                                  'sha256': self.sha(path)} for path in sorted(self.directory.iterdir())]}
        self.refresh_evidence()

    def tearDown(self):
        self.fixture.tearDown()

    def sha(self, path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def reference(self, name, value):
        path = self.root / 'research' / name
        path.write_text(json.dumps(value, indent=2) + '\n')
        return {'path': str(path.relative_to(self.root)), 'sha256': self.sha(path)}

    def refresh_evidence(self):
        self.origin['strict_before'] = self.reference('strict-before.json', self.before)
        self.origin['source_run'] = self.reference('source-run.json', self.run)
        self.reference_value = self.reference('machine-origin.json', self.origin)

    def migrate(self):
        return migrate_rockstar_machine_runtime(self.prefix, self.reference_value, root=self.root)

    def test_one_time_migration_preserves_runtime_files_and_ids_then_allows_normal_log_growth(self):
        before = {p.name: (p.read_bytes(), p.stat().st_ino) for p in self.directory.iterdir()}
        inode = self.directory.stat().st_ino
        with self.assertRaises(ProbePrefixError): assert_source_main_prefix(self.prefix, root=self.root)
        binding = self.migrate()
        self.assertEqual(inode, self.directory.stat().st_ino)
        self.assertEqual(before, {p.name: (p.read_bytes(), p.stat().st_ino) for p in self.directory.iterdir()})
        assert_source_main_prefix(self.prefix, root=self.root)
        self.assertEqual(binding, self.migrate())
        (self.directory / 'service_log.txt').write_bytes(before['service_log.txt'][0] + b'\nnew fixture event\n')
        assert_source_main_prefix(self.prefix, root=self.root)

    def test_failed_or_wrong_order_strict_before_and_cleanup_cannot_adopt_data(self):
        marker = (self.prefix / MARKER_NAME).read_bytes()
        for field in ('before_failed', 'before_after_run', 'copied', 'cleanup_failed'):
            old_before, old_run, old_origin = dict(self.before), json.loads(json.dumps(self.run)), dict(self.origin)
            if field == 'before_failed': self.before['passed'] = False
            elif field == 'before_after_run': self.before['at'] = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)).isoformat()
            elif field == 'copied': self.origin['copied_from_other_prefix'] = True
            else: self.run['prefix_cleanup']['wait_exit'] = 1
            self.refresh_evidence()
            with self.subTest(field=field), self.assertRaises(ProbePrefixError): self.migrate()
            self.assertEqual(marker, (self.prefix / MARKER_NAME).read_bytes())
            self.before, self.run, self.origin = old_before, old_run, old_origin

    def test_marker_code_directory_and_file_origin_mismatches_fail_before_writes(self):
        before_marker, before_manifest = (self.prefix / MARKER_NAME).read_bytes(), (self.prefix / MANIFEST_NAME).read_bytes()
        for key in ('prior_marker_sha256', 'prior_code_manifest_sha256', 'directory', 'files'):
            saved = self.origin[key]
            if key == 'directory': self.origin[key] = {'device': 0, 'inode': 0}
            elif key == 'files': self.origin[key] = []
            else: self.origin[key] = '0' * 64
            self.refresh_evidence()
            with self.subTest(key=key), self.assertRaises(ProbePrefixError): self.migrate()
            self.assertEqual(before_marker, (self.prefix / MARKER_NAME).read_bytes())
            self.assertEqual(before_manifest, (self.prefix / MANIFEST_NAME).read_bytes())
            self.origin[key] = saved

    def test_pending_root_rejects_extra_diagnostic_files_and_programdata_siblings(self):
        extra = self.directory / 'unproven.txt'; extra.write_text('not in observed input\n')
        with self.assertRaises(ProbePrefixError): self.migrate()
        extra.unlink()
        sibling = self.directory.parent / 'Social Club'; sibling.mkdir()
        with self.assertRaises(ProbePrefixError): self.migrate()
        self.assertTrue(sibling.is_dir())

    def test_migrated_machine_root_still_rejects_tickets_symlinks_hardlinks_and_siblings(self):
        self.migrate()
        for name in ('cfxTicket2', 'ros_login.dat', 'ros_login.json'):
            path = self.directory / name; path.write_bytes(b'inert credential-name fixture')
            with self.assertRaises(ProbePrefixError): assert_source_main_prefix(self.prefix, root=self.root)
            path.unlink()
        external = self.root.parent / 'external.txt'; external.write_text('preserve\n')
        link = self.directory / 'redirect.txt'; link.symlink_to(external)
        with self.assertRaises(ProbePrefixError): assert_source_main_prefix(self.prefix, root=self.root)
        link.unlink(); os.link(external, link)
        with self.assertRaises(ProbePrefixError): assert_source_main_prefix(self.prefix, root=self.root)
        self.assertEqual(external.read_text(), 'preserve\n')
        link.unlink(); (self.directory.parent / 'AnotherProduct').mkdir()
        with self.assertRaises(ProbePrefixError): assert_source_main_prefix(self.prefix, root=self.root)

    def test_migration_uses_the_same_exclusive_main_lock(self):
        before = (self.prefix / MARKER_NAME).read_bytes()
        with _source_main_file_lock(self.prefix):
            with self.assertRaises(ProbePrefixError): self.migrate()
        self.assertEqual(before, (self.prefix / MARKER_NAME).read_bytes())

    def test_post_write_failure_restores_both_metadata_files_without_touching_runtime_data(self):
        marker, manifest = (self.prefix / MARKER_NAME).read_bytes(), (self.prefix / MANIFEST_NAME).read_bytes()
        data = {p.name: (p.read_bytes(), p.stat().st_ino) for p in self.directory.iterdir()}
        with mock.patch('source_main_environment.assert_source_main_prefix', side_effect=RuntimeError('injected final check failure')):
            with self.assertRaisesRegex(RuntimeError, 'injected final check failure'): self.migrate()
        self.assertEqual(marker, (self.prefix / MARKER_NAME).read_bytes())
        self.assertEqual(manifest, (self.prefix / MANIFEST_NAME).read_bytes())
        self.assertEqual(data, {p.name: (p.read_bytes(), p.stat().st_ino) for p in self.directory.iterdir()})

    def test_replaced_machine_directory_and_generic_api_exception_remain_forbidden(self):
        self.migrate()
        saved = self.directory.parent / 'saved'
        self.directory.rename(saved); shutil.copytree(saved, self.directory)
        with self.assertRaises(ProbePrefixError): assert_source_main_prefix(self.prefix, root=self.root)
        prefix = self.prefix.parent / 'corert-regression'; prefix.mkdir()
        (prefix / '.account-free-probe').write_text('own fixture\n')
        (prefix / MACHINE_ROOT).mkdir(parents=True)
        with self.assertRaises(ProbePrefixError): assert_account_free_prefix(prefix, root=self.root)


if __name__ == '__main__':
    unittest.main()
