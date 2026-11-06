"""Inert scope, prerequisite and environment checks for the opt-in Source profile."""
import copy
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
path = ROOT / 'native/windows-client/session_proxy_runtime_profile.py'
spec = importlib.util.spec_from_file_location('test_session_proxy_source', path)
profile = importlib.util.module_from_spec(spec)
spec.loader.exec_module(profile)


class SourceProfileTests(unittest.TestCase):
    def record(self):
        return json.loads(profile.CONTROL_PATH.read_bytes())

    def test_another_source_prefix_rejected_before_baseline_selection(self):
        original = Mock()
        with patch.object(profile, 'parity', SimpleNamespace(select_runtime=original)):
            with self.assertRaises(RuntimeError):
                profile.select_runtime(object(), ROOT / 'prefixes/not-source')
        original.assert_not_called()

    def test_source_environment_changes_only_loader_and_server(self):
        original = {'WINEPREFIX': str(profile.SOURCE_PREFIX), 'WINESERVER': 'old-server',
                    'DYLD_LIBRARY_PATH': 'exact-original-unix-and-dependencies',
                    'DYLD_FALLBACK_LIBRARY_PATH': 'exact-original-unix-and-dependencies',
                    'PATH': 'original-parity-path', 'WINEDLLOVERRIDES': 'dxgi,d3d11,d3d10core,winemetal=b',
                    'WINEDLLPATH_PREPEND': 'original-dxmt', 'DXMT_ALLOW_CROSS_PROCESS_SWAPCHAIN': '1'}
        source_env = Mock(return_value=dict(original))
        matched = object()
        with patch.object(profile, 'parity', SimpleNamespace(source_environment=source_env)):
            actual = profile.source_environment(matched, profile.SOURCE_PREFIX)
        self.assertEqual({key for key in actual if actual[key] != original.get(key)}, {'WINELOADER', 'WINESERVER'})
        self.assertEqual(actual['WINEPREFIX'], original['WINEPREFIX'])
        self.assertEqual(actual['WINEDLLOVERRIDES'], original['WINEDLLOVERRIDES'])
        source_env.assert_called_once_with(matched, profile.SOURCE_PREFIX)
        self.assertNotIn('mscoree', actual['WINEDLLOVERRIDES'])
        self.assertNotIn('mshtml', actual['WINEDLLOVERRIDES'])

    def test_selection_reuses_original_guard_then_reverifies_before_spawn(self):
        matched = object()
        original = SimpleNamespace(PREFIX=ROOT.parent/'GTA-V-macOS/prefixes/rockstar-legacy',
                                   source_runtime_profile={'profile': 'parity', 'proof': 'unchanged'})
        select = Mock(return_value=original)
        context = {'profile': 'session-proxy', 'frozen': 'one'}
        verify = Mock(return_value=context)
        with patch.object(profile, 'parity', SimpleNamespace(select_runtime=select)), patch.object(profile, 'verify_profile', verify):
            value = profile.select_runtime(matched)
            self.assertEqual(value.ENGINE, profile.ENGINE)
            self.assertEqual(value.WINE, profile.ENGINE/'bin/wine')
            self.assertEqual(value.PREFIX, original.PREFIX)
            self.assertEqual(value.source_runtime_profile, context)
            value.before_source_spawn()
            self.assertEqual(select.call_count, 2)
            self.assertEqual(verify.call_count, 2)
            select.assert_called_with(matched, profile.SOURCE_PREFIX)
            verify.return_value = {'profile': 'session-proxy', 'frozen': 'changed'}
            with self.assertRaises(RuntimeError):
                value.before_source_spawn()

    def test_exact_own_report_metadata_accepts_current_three_case_success(self):
        record = self.record()
        profile._check_control_record(record, copy.deepcopy(record['runtime_verification']))
        profile._check_engine(record['runtime_verification'])

    def test_own_record_rejects_missing_case_failure_and_unclean_cleanup(self):
        original = self.record()
        for change in ('missing', 'state-failure', 'direct-failure', 'cleanup', 'foreign-prefix', 'bool-exit'):
            record = copy.deepcopy(original)
            if change == 'missing':
                record['runs'].pop()
            elif change == 'state-failure':
                record['runs'][0]['summary']['failed_cases'] = 1
            elif change == 'direct-failure':
                record['runs'][1]['direct_setup_passed'] = False
            elif change == 'cleanup':
                record['cleanup'][1]['exit'] = 1
            elif change == 'foreign-prefix':
                record['prefix'] = 'prefixes/fivem-source-main'
            else:
                record['runs'][0]['exit'] = False
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                profile._check_control_record(record, original['runtime_verification'])

    def test_engine_rejects_another_manifest_build_or_prefix(self):
        original = self.record()['runtime_verification']
        for field, value in (('manifest_sha256', '0'*64), ('prefix', 'prefixes/fivem-source-main'),
                             ('selective_build_report', {'sha256': '0'*64})):
            engine = copy.deepcopy(original)
            engine[field] = value
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                profile._check_engine(engine)

    def test_changed_actual_report_rejected_before_loading_control_code(self):
        load = Mock(side_effect=AssertionError('Cannot load control code after report mismatch'))
        with patch.object(profile, '_read_direct', return_value=b'{}'), patch.object(profile, '_load_frozen', load):
            with self.assertRaises(RuntimeError):
                profile.verify_own_control({})
        load.assert_not_called()

    def test_changed_runner_rejected_before_control_execution(self):
        record_raw = profile.CONTROL_PATH.read_bytes()
        record = json.loads(record_raw)
        load = Mock(side_effect=AssertionError('Changed own runner must stop before execution'))
        def read(path):
            return record_raw if path == profile.CONTROL_PATH else b'changed'
        with patch.object(profile, '_read_direct', side_effect=read), patch.object(profile, '_load_frozen', load):
            with self.assertRaises(RuntimeError):
                profile.verify_own_control(record['runtime_verification'])
        load.assert_not_called()

    def test_reuse_module_digest_checked_before_exec(self):
        with patch.object(profile, '_read_direct', return_value=b'raise AssertionError("must not execute")'):
            with self.assertRaisesRegex(RuntimeError, 'before execution'):
                profile._load_frozen(profile.VERIFIER_PATH, '0'*64, 'forbidden')


if __name__ == '__main__':
    unittest.main()
