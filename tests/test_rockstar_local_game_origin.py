"""Own temporary metadata only; no actual prefix or user-data reads."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / 'scripts'))
import rockstar_local_game_origin as policy
from probe_environment import ProbePrefixError


class LocalGameOriginTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.prefix = self.root / policy.PREFIX
        self.user = 'ownuser'
        self.relative = 'drive_c/users/ownuser/AppData/Local/Rockstar Games/GTA V'
        self.directory = self.prefix / self.relative
        self.directory.mkdir(parents=True)
        self.birth = 1793717547161508608
        self.result = {'at': '2026-11-03T14:52:29.262090+00:00', 'prefix': policy.PREFIX,
            'developer_code_version': 10, 'source_revision': policy.REVISION, 'runtime_engine_profile': 'parity',
            'isolation_guard_failure': copy.deepcopy(policy.FAILURE),
            'prefix_cleanup': {'kill_exit': 0, 'wait_exit': 0, 'wait_timed_out': False}}
        raw = json.dumps(self.result).encode()
        self.save_bytes(policy.SOURCE_RESULT, raw)
        self.sha, self.size = hashlib.sha256(raw).hexdigest(), len(raw)
        p, d = self.prefix.stat(), self.directory.stat()
        self.record = {'schema': 1, 'kind': 'rockstar-local-game-runtime-origin',
            'scope': 'runtime-directory-metadata-only', 'prefix': policy.PREFIX, 'user': self.user,
            'relative_root': self.relative, 'created_during_source_run': True, 'copied_or_imported': False,
            'source_result': {'path': policy.SOURCE_RESULT, 'bytes': self.size, 'sha256': self.sha},
            'prefix_device': p.st_dev, 'prefix_inode': p.st_ino, 'root_device': d.st_dev,
            'root_inode': d.st_ino, 'root_birthtime_ns': self.birth}
        self.patches = [mock.patch.object(policy, 'SOURCE_BYTES', self.size),
            mock.patch.object(policy, 'SOURCE_SHA256', self.sha),
            mock.patch.object(policy, '_birthtime_ns', return_value=self.birth)]
        for patch in self.patches:
            patch.start()
        self.save_record()

    def tearDown(self):
        for patch in reversed(self.patches):
            patch.stop()
        self.temp.cleanup()

    def save_bytes(self, name, raw):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)

    def save_record(self, record=None):
        self.save_bytes(policy.EVIDENCE_PATH, json.dumps(self.record if record is None else record).encode())

    def validate(self):
        return policy.validated_local_game_runtime_root(self.prefix, self.root, self.user)

    def test_exact_directory_admitted_without_listing_or_opening_user_data(self):
        private = self.directory / 'PRIVATE_SESSION_SENTINEL'
        private.write_bytes(b'OWN PRIVATE SENTINEL')
        original = policy.os.open
        opened = []
        def metadata_only(path, *args, **kwargs):
            opened.append(Path(path))
            self.assertIn(Path(path), [self.root / policy.EVIDENCE_PATH, self.root / policy.SOURCE_RESULT])
            return original(path, *args, **kwargs)
        with mock.patch.object(policy.os, 'open', side_effect=metadata_only), \
                mock.patch.object(policy.os, 'scandir', side_effect=AssertionError('must not enumerate user data')):
            self.assertEqual(self.validate(), self.relative)
        self.assertEqual(opened, [self.root / policy.EVIDENCE_PATH, self.root / policy.SOURCE_RESULT])
        self.assertEqual(private.read_bytes(), b'OWN PRIVATE SENTINEL')

    def test_absent_evidence_returns_none_without_prefix_or_result_reads(self):
        (self.root / policy.EVIDENCE_PATH).unlink()
        with mock.patch.object(policy, '_read_json', side_effect=AssertionError('absent origin must not read')):
            self.assertIsNone(self.validate())

    def test_other_root_or_user_or_result_reference_refused_before_result_read(self):
        for key, value in (('relative_root', self.relative + ' Enhanced'), ('user', 'another'),
            ('prefix', 'prefixes/rockstar-legacy'), ('copied_or_imported', True),
            ('source_result', {'path': 'prefixes/private/user.reg', 'bytes': 1, 'sha256': self.sha})):
            record = copy.deepcopy(self.record);record[key] = value;self.save_record(record)
            with self.subTest(key=key), mock.patch.object(policy, '_read_json', wraps=policy._read_json) as reads, \
                    self.assertRaises(ProbePrefixError):
                self.validate()
            self.assertEqual(len(reads.call_args_list), 1)

    def test_inode_creation_window_and_numeric_type_are_bound(self):
        for key, value in (('prefix_inode', self.record['prefix_inode'] + 1),
            ('root_inode', self.record['root_inode'] + 1), ('root_birthtime_ns', self.birth + 1),
            ('root_birthtime_ns', 0), ('root_birthtime_ns', 1793717550000000000),
            ('schema', True), ('prefix_device', float(self.record['prefix_device']))):
            record = copy.deepcopy(self.record);record[key] = value;self.save_record(record)
            with self.subTest(key=key, value=value), self.assertRaises(ProbePrefixError):
                self.validate()

    def test_result_hash_cleanup_and_source_role_are_required(self):
        self.save_bytes(policy.SOURCE_RESULT, b'changed own metadata')
        with self.assertRaises(ProbePrefixError): self.validate()
        for key, value in (('developer_code_version', 9), ('developer_code_version', 10.0),
            ('runtime_engine_profile', 'read'), ('isolation_guard_failure', None),
            ('prefix_cleanup', {'kill_exit': 1, 'wait_exit': 0, 'wait_timed_out': False}),
            ('prefix_cleanup', {'kill_exit': False, 'wait_exit': 0, 'wait_timed_out': False})):
            result = copy.deepcopy(self.result);result[key] = value;raw = json.dumps(result).encode()
            digest = hashlib.sha256(raw).hexdigest();record = copy.deepcopy(self.record)
            record['source_result'].update(bytes=len(raw), sha256=digest)
            self.save_bytes(policy.SOURCE_RESULT, raw);self.save_record(record)
            with self.subTest(key=key), mock.patch.object(policy, 'SOURCE_BYTES', len(raw)), \
                    mock.patch.object(policy, 'SOURCE_SHA256', digest), self.assertRaises(ProbePrefixError):
                self.validate()

    def test_symlink_directory_and_linked_metadata_are_refused(self):
        outside = self.root / 'own-outside';outside.mkdir()
        self.directory.rmdir();self.directory.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ProbePrefixError): self.validate()
        self.directory.unlink();self.directory.mkdir()
        evidence = self.root / policy.EVIDENCE_PATH
        policy.os.link(evidence, self.root / 'own-hardlink')
        with self.assertRaises(ProbePrefixError): self.validate()


class LocalGameFullGuardTests(unittest.TestCase):
    def setUp(self):
        import test_rockstar_code_policy as fixtures
        self.fixture = fixtures.RockstarCodePolicyTests('test_unbound_code_or_unbound_manifest_never_grants_exception')
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.root, self.prefix, self.user = self.fixture.root, self.fixture.prefix, self.fixture.user
        self.fixture.enrolled()
        self.relative = 'drive_c/users/' + self.user + '/AppData/Local/Rockstar Games/GTA V'
        self.directory = self.prefix / self.relative
        self.directory.mkdir()
        self.birth = 1793717547161508608
        self.result = {'at': '2026-11-03T14:52:29.262090+00:00', 'prefix': policy.PREFIX,
            'developer_code_version': 10, 'source_revision': policy.REVISION, 'runtime_engine_profile': 'parity',
            'isolation_guard_failure': policy.FAILURE,
            'prefix_cleanup': {'kill_exit': 0, 'wait_exit': 0, 'wait_timed_out': False}}
        raw = json.dumps(self.result).encode()
        result = self.root / policy.SOURCE_RESULT
        result.write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()
        p, d = self.prefix.stat(), self.directory.stat()
        record = {'schema': 1, 'kind': 'rockstar-local-game-runtime-origin',
            'scope': 'runtime-directory-metadata-only', 'prefix': policy.PREFIX, 'user': self.user,
            'relative_root': self.relative, 'created_during_source_run': True, 'copied_or_imported': False,
            'source_result': {'path': policy.SOURCE_RESULT, 'bytes': len(raw), 'sha256': digest},
            'prefix_device': p.st_dev, 'prefix_inode': p.st_ino, 'root_device': d.st_dev,
            'root_inode': d.st_ino, 'root_birthtime_ns': self.birth}
        (self.root / policy.EVIDENCE_PATH).write_text(json.dumps(record))
        self.original_birthtime = policy._birthtime_ns
        self.patches = [mock.patch.object(policy, 'SOURCE_BYTES', len(raw)),
            mock.patch.object(policy, 'SOURCE_SHA256', digest),
            mock.patch.object(policy, '_birthtime_ns', return_value=self.birth)]
        for patch in self.patches:
            patch.start()
            self.addCleanup(patch.stop)

    def test_full_guard_allows_only_runtime_overlay_without_changing_bound_metadata(self):
        import rockstar_code_policy as rockstar
        import source_main_environment as main
        manifest, marker = self.prefix / rockstar.MANIFEST_NAME, self.prefix / main.MARKER_NAME
        before_manifest, before_marker = manifest.read_bytes(), marker.read_bytes()
        main.assert_source_main_prefix(self.prefix, root=self.root)
        identity = json.loads(before_marker)
        admitted = rockstar.validate_binding(self.prefix, self.root, identity, self.user)
        self.assertEqual(admitted['local_game_runtime_root'], self.relative)
        self.assertTrue(rockstar.user_path_allowed(self.directory, self.prefix, admitted))
        self.assertTrue(rockstar.user_path_allowed(self.directory / 'own-runtime-file', self.prefix, admitted))
        self.assertEqual(manifest.read_bytes(), before_manifest)
        self.assertEqual(marker.read_bytes(), before_marker)
        self.assertNotIn('local_game_runtime_root', json.loads(before_manifest))

    def test_full_guard_refuses_other_gta_sibling_even_with_exact_root_admitted(self):
        import rockstar_code_policy as rockstar
        import source_main_environment as main
        manifest = self.prefix / rockstar.MANIFEST_NAME
        before = manifest.read_bytes()
        identity = json.loads((self.prefix / main.MARKER_NAME).read_bytes())
        admitted = rockstar.validate_binding(self.prefix, self.root, identity, self.user)
        sibling = self.directory.with_name('GTA V Enhanced')
        self.assertFalse(rockstar.user_path_allowed(sibling, self.prefix, admitted))
        sibling.mkdir()
        with self.assertRaises(ProbePrefixError):
            main.assert_source_main_prefix(self.prefix, root=self.root)
        self.assertEqual(manifest.read_bytes(), before)

    def test_nanosecond_creation_attribute_has_precedence(self):
        self.assertEqual(self.original_birthtime(SimpleNamespace(st_birthtime_ns=123, st_birthtime=9.0)), 123)


if __name__ == '__main__':
    unittest.main()
