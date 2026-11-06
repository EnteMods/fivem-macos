"""Inert checks for the separate one-DLL engine preparation and verification."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'native/wine-session-proxy-runtime' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


env = load('test_session_proxy_environment', 'environment.py')
prep = load('test_session_proxy_prepare', 'prepare.py')


class CandidateTests(unittest.TestCase):
    def entries(self):
        return [{'path': 'bin/wine', 'bytes': 1, 'sha256': 'a'*64, 'kind': 'mach_o_x86_64', 'executable': True},
                {'path': env.REPLACED, 'bytes': 1, 'sha256': 'b'*64, 'kind': 'pe_amd64', 'executable': False}]

    def test_manifest_comes_from_baseline_with_exactly_one_delta(self):
        original = {'entries': self.entries()}
        snapshot = copy.deepcopy(original)
        report = {'baseline_manifest': {'path': 'baseline', 'sha256': 'c'*64, 'bytes': 1},
                  'artifact': {'path': str(env.ARTIFACT.relative_to(env.ROOT)), 'bytes': 2647381, 'sha256': env.ARTIFACT_SHA}}
        with patch.object(env, 'ENTRY_COUNT', 2):
            value = env.expected_manifest(original, report)
        self.assertEqual(original, snapshot)
        self.assertEqual(value['changed_files'], [env.REPLACED])
        self.assertEqual(value['entries'][0], dict(snapshot['entries'][0], mode=0o755))
        self.assertEqual(value['entries'][1]['sha256'], env.ARTIFACT_SHA)
        self.assertEqual(value['entries'][1]['mode'], 0o644)
        self.assertEqual(value['prefix'], 'prefixes/wine-session-proxy-regression')

    def test_missing_replacement_or_wrong_count_rejected(self):
        with patch.object(env, 'ENTRY_COUNT', 1):
            with self.assertRaises(RuntimeError):
                env.expected_manifest({'entries': self.entries()[:1]}, {})

    def test_environment_changes_exactly_three_baseline_keys(self):
        baseline = {'WINEPREFIX': 'old', 'WINELOADER': 'old-loader', 'WINESERVER': 'old-server',
                    'DYLD_LIBRARY_PATH': 'unchanged-original-deps', 'WINEDEBUG': '-all,err+all', 'SAFE': 'kept'}
        fake = types.SimpleNamespace(environment=Mock(return_value=dict(baseline)))
        verified = {'manifest_sha256': 'e'*64, 'profile': env.ROLE, 'protocol_version': 1810,
                    'engine': str(env.ENGINE.relative_to(env.ROOT)), 'prefix': str(env.PREFIX.relative_to(env.ROOT)),
                    'baseline_verification': {'manifest_sha256': 'baseline'}}
        with patch.object(env, 'BASE', fake), patch.object(env, 'MANIFEST_SHA', 'e'*64):
            result = env.environment(verified, inherited={'OTHER': 'given'})
        self.assertEqual({k for k in result if result[k] != baseline[k]}, {'WINEPREFIX', 'WINELOADER', 'WINESERVER'})
        self.assertEqual(set(result), set(baseline))
        fake.environment.assert_called_once_with(verified['baseline_verification'], inherited={'OTHER': 'given'})

    def test_environment_requires_current_successful_candidate_verification(self):
        with patch.object(env, 'MANIFEST_SHA', None):
            with self.assertRaises(RuntimeError):
                env.environment({'manifest_sha256': None})

    def test_all_report_paths_admitted_before_preparation_selected_read(self):
        report = json.loads(env.BUILD_REPORT.read_bytes())
        report['build']['log']['path'] = 'research/unreviewed.log'
        raw = json.dumps(report).encode()
        bound = Mock(side_effect=AssertionError('No selected build member may be read'))
        with patch.object(env, 'read_regular', return_value=raw), patch.object(env, 'BUILD_REPORT_SHA', hashlib.sha256(raw).hexdigest()), patch.object(env, '_bound', bound):
            # Preserve the fixed Root report length admission while changing only a path role.
            if len(raw) != 3875:
                raw = json.dumps(report, indent=2).encode() + b'\n'
            raw = raw + b' ' * (3875-len(raw)) if len(raw) <= 3875 else raw
            with patch.object(env, 'read_regular', return_value=raw), patch.object(env, 'BUILD_REPORT_SHA', hashlib.sha256(raw).hexdigest()):
                with self.assertRaisesRegex(RuntimeError, 'Unexpected build identity role'):
                    env.verify_build()
        bound.assert_not_called()

    def test_pe_header_rejects_non_pe_without_claiming_artifact_success(self):
        with self.assertRaises(RuntimeError):
            env.pe_header(b'not a PE' * 100)

    def test_tree_requires_exact_set_and_direct_single_link_files(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            engine = root/'engine'
            engine.mkdir()
            (engine/'bin').mkdir()
            binary = engine/'bin/wine'
            binary.write_bytes(b'own')
            with patch.object(env, 'ROOT', root), patch.object(env, 'canonical', side_effect=lambda p, boundary: p):
                env._tree_paths(engine, [{'path': 'bin/wine'}])
                (engine/'extra').mkdir()
                with self.assertRaises(RuntimeError):
                    env._tree_paths(engine, [{'path': 'bin/wine'}])
                (engine/'extra').rmdir()
                (engine/'bin/alias').symlink_to(binary)
                with self.assertRaises(RuntimeError):
                    env._tree_paths(engine, [{'path': 'bin/wine'}])

    def test_hardlink_is_not_a_cow_clone(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            engine = root/'engine'
            engine.mkdir()
            (root/'original').write_bytes(b'own')
            os.link(root/'original', engine/'wine')
            with patch.object(env, 'ROOT', root), patch.object(env, 'canonical', side_effect=lambda p, boundary: p):
                with self.assertRaises(RuntimeError):
                    env._tree_paths(engine, [{'path': 'wine'}])

    def test_full_baseline_mode_is_checked(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            binary = root/'wine'
            binary.write_bytes(b'own')
            binary.chmod(0o755)
            with patch.object(env, 'BASE', types.SimpleNamespace(ENGINE=root)), patch.object(env, 'canonical', side_effect=lambda p, boundary: p):
                env.verify_baseline_modes([{'path': 'wine', 'executable': True}])
                binary.chmod(0o775)
                with self.assertRaises(RuntimeError):
                    env.verify_baseline_modes([{'path': 'wine', 'executable': True}])

    def test_existing_install_refused_before_baseline_read_or_prefix_activity(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            fake = types.SimpleNamespace(WORK=root, ROOT=root, canonical=lambda p, boundary: p,
                                         BASE=types.SimpleNamespace(verify_runtime=Mock()))
            with patch.object(prep, 'runtime', fake):
                with self.assertRaises(RuntimeError):
                    prep.prepare()
            fake.BASE.verify_runtime.assert_not_called()


if __name__ == '__main__':
    unittest.main()
