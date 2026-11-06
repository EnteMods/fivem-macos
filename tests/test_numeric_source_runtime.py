"""Numeric source selection must wait for separately proven account-free regressions."""
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'native/windows-client'))
import numeric_runtime_profile as profile
import run_source


class NumericSourceTests(unittest.TestCase):
    def setUp(self):
        self.engine = {'manifest_sha256': 'a' * 64, 'protocol_version': 1810}
        self.files = {}
        checks = []
        for mode in sorted(profile.MODES):
            name = 'research/wine-parity-numeric-' + mode + '-20261102T120000000000Z-results.json'
            report = {'passed': True, 'runtime_started': True, 'profile': 'wine-numeric-api-probes',
                'protocol_version': 1810, 'probe_role': 'numeric-' + mode, 'prefix': 'prefixes/wine-numeric-regression',
                'runtime_verification': self.engine, 'cleanup': [{'flag': '-k', 'exit': 0}, {'flag': '-w', 'exit': 0}],
                'quarantine_cleared_after_confirmed_cleanup': True, 'only_own_fixtures_and_builtin_initialization': True,
                'client_cef_rockstar_game_or_account_code_started': False, 'runs': [{'passed': True, 'exit': 0}]}
            raw = json.dumps(report).encode()
            self.files[ROOT / name] = raw
            checks.append({'mode': mode, 'path': name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
        self.ready = {'schema_version': 1, 'profile': 'wine-numeric-source-prerequisites',
            'engine_manifest_sha256': self.engine['manifest_sha256'], 'source_stage_modified': False,
            'kernel_behavior_equal_on_off': True, 'wininet_behavior_equal_on_off': True, 'checks': checks}
        self.candidate = SimpleNamespace(read_regular=lambda path: self.files[path])

    def check(self):
        self.files[profile.READY] = json.dumps(self.ready).encode()
        return profile.verify_prerequisites(self.candidate, self.engine)

    def test_all_modes_are_bound_without_reading_api_prefix(self):
        result = self.check()
        self.assertEqual(len(result['checked_result_identities']), 8)
        self.assertFalse(result['api_prefix_or_account_storage_read'])

    def test_missing_or_duplicate_role_and_failed_comparison_are_refused(self):
        for field in ('kernel_behavior_equal_on_off', 'wininet_behavior_equal_on_off'):
            with self.subTest(field=field):
                self.ready[field] = False
                with self.assertRaises(RuntimeError): self.check()
                self.ready[field] = True
        self.ready['checks'][-1] = self.ready['checks'][0]
        with self.assertRaises(RuntimeError): self.check()

    def test_unreviewed_result_path_is_rejected_before_read(self):
        self.ready['checks'][-1]['path'] = 'prefixes/fivem-source-main/user.reg'
        self.files[profile.READY] = json.dumps(self.ready).encode()
        reads = []
        candidate = SimpleNamespace(read_regular=lambda path: reads.append(path) or self.files[path])
        with self.assertRaises(RuntimeError): profile.verify_prerequisites(candidate, self.engine)
        self.assertEqual(reads, [profile.READY])

    def test_stale_result_or_uncertain_cleanup_cannot_authorize_source(self):
        item = self.ready['checks'][0]
        self.files[ROOT / item['path']] += b' '
        with self.assertRaises(RuntimeError): self.check()
        report = json.loads(self.files[ROOT / item['path']])
        report['cleanup'][0]['exit'] = 1
        raw = json.dumps(report).encode()
        self.files[ROOT / item['path']] = raw
        item.update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        with self.assertRaises(RuntimeError): self.check()

    def test_source_environment_uses_source_flags_not_api_flags(self):
        candidate = SimpleNamespace(MOLTENVK=Path('/own/mvk/lib.dylib'), FRAMEWORKS=Path('/own/frameworks'), GST_LIB=Path('/own/gst'))
        env = {'WINEPREFIX': str(profile.SOURCE_PREFIX), 'WINEDLLOVERRIDES': 'dxgi,d3d11,d3d10core,winemetal=b'}
        with mock.patch.object(profile.baseline, 'source_environment', return_value=env):
            selected = profile.source_environment(None, profile.SOURCE_PREFIX, candidate)
        self.assertEqual(selected['WINEPREFIX'], str(profile.SOURCE_PREFIX))
        self.assertEqual(selected['WINEDEBUG'], '-all,+cfxnum')
        self.assertNotIn('mscoree', selected['WINEDLLOVERRIDES'])
        self.assertTrue(selected['DYLD_LIBRARY_PATH'].startswith(str(profile.ENGINE)))
        with self.assertRaises(RuntimeError): profile.source_environment(None, ROOT / 'prefixes/wine-numeric-regression', candidate)

    def test_numeric_debug_is_fixed_and_disallows_other_channels(self):
        runtime = SimpleNamespace(ENGINE=profile.ENGINE, source_winedebug=profile.DEBUG, environment=lambda: {})
        env = run_source.source_runtime_environment(runtime, 8)
        self.assertEqual(env['WINEDEBUG'], profile.DEBUG)
        self.assertEqual(env['CitizenFX_NoTenUI'], '1')
        with self.assertRaises(RuntimeError): run_source.source_runtime_environment(runtime, 8, True)
        runtime.source_winedebug = '+relay'
        with self.assertRaises(RuntimeError): run_source.source_runtime_environment(runtime, 8)


if __name__ == '__main__':
    unittest.main()
