"""Keep retired account prefixes inactive and SDK payloads out of Git."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


class RetiredRetestTests(unittest.TestCase):
    def test_entrypoint_refuses_without_starting_a_process(self):
        output = io.StringIO()
        with mock.patch('subprocess.run') as launch, contextlib.redirect_stderr(output):
            with self.assertRaises(SystemExit) as exit_result:
                runpy.run_path(str(ROOT / 'scripts/retest_legacy.py'), run_name='__main__')
        self.assertEqual(exit_result.exception.code, 2)
        launch.assert_not_called()
        self.assertIn('fivem-legacy', output.getvalue())
        self.assertIn('fivem-enhanced-probe', output.getvalue())
        self.assertIn('scripts/corert_regression.py all', output.getvalue())

    def test_legacy_force_argument_does_not_authorize_a_launch(self):
        with mock.patch('sys.argv', ['retest_legacy.py', '--force']), \
                mock.patch('subprocess.run') as launch, \
                contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as exit_result:
                runpy.run_path(str(ROOT / 'scripts/retest_legacy.py'), run_name='__main__')
        self.assertEqual(exit_result.exception.code, 2)
        launch.assert_not_called()


class ToolchainGitScopeTests(unittest.TestCase):
    def ignored(self, path):
        return subprocess.run(['git', 'check-ignore', '--no-index', '--quiet', path],
                              cwd=ROOT, check=False).returncode == 0

    def test_sdk_cache_manifests_and_binaries_stay_ignored(self):
        for path in ('toolchains/msvc-2022/VC/test.h', 'toolchains/cache/test.vsix',
                     'toolchains/helpers/msvc-wine/vsdownload.py',
                     'toolchains/metadata/vs17-manifest.json',
                     'toolchains/metadata/vs17-channel.json',
                     'toolchains/metadata/future-unreviewed.json',
                     'toolchains/smoke/msvc-abi-smoke.exe',
                     'toolchains/smoke/msvc-abi-smoke.obj'):
            with self.subTest(path=path):
                self.assertTrue(self.ignored(path))

    def test_only_reviewed_sources_and_small_evidence_are_allowed(self):
        paths = ('toolchains/msvc.cmake',
                 'toolchains/metadata/acquisition-plan.json',
                 'toolchains/metadata/acquisition-wave-01-core.json',
                 'toolchains/metadata/atl-acquisition.json',
                 'toolchains/metadata/atl-payload-verification.json',
                 'toolchains/metadata/atl-installed-files.json',
                 'toolchains/metadata/authorization-and-invocation.json',
                 'toolchains/metadata/full-toolchain-invocation.json',
                 'toolchains/metadata/manifest-transport-verification.json',
                 'toolchains/metadata/minimal-package-selection.json',
                 'toolchains/metadata/payload-verification.json',
                 'toolchains/smoke/msvc-abi-smoke.cpp',
                 'toolchains/smoke/run-smoke.py',
                 'toolchains/smoke/build-commands.json',
                 'toolchains/smoke/result.json',
                 'toolchains/smoke/pe-imports.txt')
        for relative in paths:
            with self.subTest(path=relative):
                self.assertFalse(self.ignored(relative))
                path = ROOT / relative
                if path.is_file():
                    self.assertLess(path.stat().st_size, 256 * 1024)


class BootstrapPinningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('bootstrap_under_test', ROOT / 'scripts/bootstrap-msvc.py')
        cls.bootstrap = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.bootstrap)

    def test_no_authorization_means_no_download(self):
        with mock.patch('sys.argv', ['bootstrap-msvc.py']), \
                mock.patch('urllib.request.urlopen') as download, \
                contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as exit_result:
                self.bootstrap.main()
        self.assertEqual(exit_result.exception.code, 2)
        download.assert_not_called()

    def test_unexpected_download_is_not_written_or_executed(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'helper.py'
            with mock.patch('urllib.request.urlopen') as download:
                download.return_value.__enter__.return_value.read.return_value = b'unexpected bytes'
                with self.assertRaises(SystemExit):
                    self.bootstrap.ensure_pinned_file(path, 'https://example.invalid/helper.py', '0' * 64)
            self.assertFalse(path.exists())

    def test_existing_changed_helper_is_not_replaced(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'helper.py'
            path.write_bytes(b'local changed bytes')
            expected = hashlib.sha256(b'original reviewed bytes').hexdigest()
            with mock.patch('urllib.request.urlopen') as download:
                with self.assertRaises(SystemExit):
                    self.bootstrap.ensure_pinned_file(path, 'https://example.invalid/helper.py', expected)
            download.assert_not_called()
            self.assertEqual(path.read_bytes(), b'local changed bytes')

    def test_atl_only_selects_original_x64_packages_without_sdk(self):
        with tempfile.TemporaryDirectory() as folder:
            metadata = Path(folder)
            metadata.joinpath('acquisition-plan.json').write_bytes(
                (ROOT / 'toolchains/metadata/acquisition-plan.json').read_bytes())
            with mock.patch.object(self.bootstrap, 'META', metadata), \
                    mock.patch.object(self.bootstrap, 'ensure_pinned_file'), \
                    mock.patch('sys.argv', ['bootstrap-msvc.py', '--authorized-20261101', '--atl-only']), \
                    mock.patch('subprocess.run') as invoke:
                invoke.return_value.returncode = 0
                self.assertEqual(self.bootstrap.main(), 0)
            command = invoke.call_args.args[0]
            self.assertEqual(command[command.index('--with-sdk') + 1], 'no')
            selected = [arg for arg in command if arg.startswith('Microsoft.VC.')]
            self.assertEqual(selected, ['Microsoft.VC.14.44.17.14.ATL.Headers.base',
                                        'Microsoft.VC.14.44.17.14.ATL.X64.base'])
            self.assertTrue((metadata / 'atl-acquisition.json').is_file())
            self.assertFalse((metadata / 'authorization-and-invocation.json').exists())


class AcquisitionHistoryTests(unittest.TestCase):
    def test_original_six_package_wave_remains_byte_identical(self):
        metadata = ROOT / 'toolchains/metadata'
        plan = json.loads((metadata / 'acquisition-plan.json').read_text())
        first = plan['acquisition_waves'][0]
        for filename_key, digest_key in (('plan_snapshot', 'plan_snapshot_sha256'),
                                         ('payload_audit', 'payload_audit_sha256'),
                                         ('invocation', 'invocation_sha256')):
            self.assertEqual(hashlib.sha256((ROOT / first[filename_key]).read_bytes()).hexdigest(),
                             first[digest_key])
        original = json.loads((ROOT / first['plan_snapshot']).read_text())
        self.assertEqual(len(original['selected_packages']), 6)
        self.assertEqual(original['payload_count_verified'], 234)

    def test_aggregate_selection_equals_disjoint_acquisition_waves(self):
        metadata = ROOT / 'toolchains/metadata'
        plan = json.loads((metadata / 'acquisition-plan.json').read_text())
        original = json.loads((metadata / 'acquisition-wave-01-core.json').read_text())
        atl = json.loads((metadata / 'atl-payload-verification.json').read_text())
        original_ids = {p['id'] for p in original['selected_packages']}
        atl_ids = {p['package_id'] for p in atl['payloads']}
        self.assertFalse(original_ids & atl_ids)
        self.assertEqual(len(atl_ids), 4)
        self.assertEqual({p['id'] for p in plan['selected_packages']}, original_ids | atl_ids)
        self.assertEqual(len(plan['selected_packages']), 10)
        self.assertEqual(sum(p['payload_count'] for p in plan['selected_packages']), 238)
        self.assertEqual(plan['payload_count_verified'], 234 + atl['new_payload_count'])
        self.assertEqual(plan['payload_bytes_verified_actual'],
                         original['payload_bytes_verified_actual'] + atl['new_payload_bytes_actual'])
        self.assertTrue(all(p['hash_verified'] and p['sha256_expected'] == p['sha256_actual']
                            for p in atl['payloads']))

    def test_installed_atl_files_match_recorded_original_archive_bytes(self):
        metadata = ROOT / 'toolchains/metadata'
        installed = json.loads((metadata / 'atl-installed-files.json').read_text())
        if not (ROOT / installed['files'][0]['path']).exists():
            self.skipTest('Original Microsoft files are acquired locally and excluded from Git.')
        self.assertEqual(installed['file_count'], len(installed['files']))
        for entry in installed['files']:
            with self.subTest(path=entry['path']):
                self.assertTrue(entry['byte_identical_to_original_archive'])
                self.assertEqual(hashlib.sha256((ROOT / entry['path']).read_bytes()).hexdigest(),
                                 entry['sha256'])


if __name__ == '__main__':
    unittest.main()
