"""Own inert read-source admission/selection tests; no Wine, prefix or client starts."""
import copy
from contextlib import ExitStack, nullcontext, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'native/windows-client'))
import read_runtime_profile as profile
import run_source


class ReadSourcePrerequisiteTests(unittest.TestCase):
    def setUp(self):
        self.engine = {'manifest_sha256': 'a' * 64, 'protocol_version': 1810}
        self.files = {}
        checks = []
        for mode in sorted(profile.MODES):
            name = 'research/wine-parity-numeric-' + mode + '-20261102T120000000000Z-results.json'
            report = {'passed': True, 'runtime_started': True, 'profile': 'wine-read-api-probes',
                'protocol_version': 1810, 'probe_role': 'numeric-' + mode, 'prefix': 'prefixes/wine-read-regression',
                'runtime_verification': self.engine, 'cleanup': copy.deepcopy(profile.CLEANUP),
                'quarantine_cleared_after_confirmed_cleanup': True, 'only_own_fixtures_and_builtin_initialization': True,
                'client_cef_rockstar_game_or_account_code_started': False, 'runs': [{'passed': True, 'exit': 0}]}
            raw = json.dumps(report).encode()
            self.files[ROOT / name] = raw
            checks.append({'mode': mode, 'path': name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
        self.ready = {'schema_version': 1, 'profile': 'wine-read-source-prerequisites',
            'engine_manifest_sha256': self.engine['manifest_sha256'], 'source_stage_modified': False,
            'kernel_behavior_equal_on_off': True, 'wininet_behavior_equal_on_off': True,
            'pipe_behavior_equal_on_off': True, 'checks': checks}
        self.reads = []
        self.candidate = SimpleNamespace(read_regular=lambda path: self.reads.append(path) or self.files[path])

    def check(self):
        self.files[profile.READY] = json.dumps(self.ready).encode()
        return profile.verify_prerequisites(self.candidate, self.engine)

    def alter_report(self, mode, change):
        item = next(item for item in self.ready['checks'] if item['mode'] == mode)
        record = json.loads(self.files[ROOT / item['path']])
        change(record)
        raw = json.dumps(record).encode()
        self.files[ROOT / item['path']] = raw
        item.update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())

    def test_all_ten_fixed_results_are_bound_without_prefix_or_log_reads(self):
        result = self.check()
        self.assertEqual(len(result['checked_result_identities']), 10)
        self.assertFalse(result['api_prefix_or_account_storage_read'])
        self.assertEqual(set(self.reads), {profile.READY, *self.files.keys()})
        self.assertTrue(all(path.parent == ROOT / 'research' for path in self.reads))

    def test_all_ten_path_and_identity_shapes_precede_first_selected_result_read(self):
        original = copy.deepcopy(self.ready)
        for field, invalid in (('path', 'prefixes/fivem-source-main/user.reg'), ('bytes', True),
                               ('bytes', 0), ('sha256', 'a' * 63), ('sha256', 'A' * 64)):
            self.ready = copy.deepcopy(original)
            self.ready['checks'][-1][field] = invalid
            self.reads.clear()
            with self.subTest(field=field, invalid=invalid), self.assertRaises(RuntimeError): self.check()
            self.assertEqual(self.reads, [profile.READY])

    def test_missing_duplicate_mode_or_any_failed_behavior_comparison_is_refused(self):
        for family in ('kernel', 'wininet', 'pipe'):
            field = family + '_behavior_equal_on_off'
            self.ready[field] = False
            with self.subTest(field=field), self.assertRaises(RuntimeError): self.check()
            self.ready[field] = True
        self.ready['checks'][-1] = self.ready['checks'][0]
        with self.assertRaises(RuntimeError): self.check()
        self.assertEqual(self.reads, [profile.READY] * 4)

    def test_stale_identity_foreign_profile_prefix_or_manifest_cannot_pass(self):
        original = copy.deepcopy(self.files)
        item = self.ready['checks'][0]
        self.files[ROOT / item['path']] += b' '
        with self.assertRaises(RuntimeError): self.check()
        for field, invalid in (('profile', 'wine-numeric-api-probes'), ('prefix', 'prefixes/fivem-source-main'),
                               ('probe_role', 'numeric-pipe-off'), ('protocol_version', 1811),
                               ('runtime_verification', {'manifest_sha256': 'b' * 64})):
            self.files = copy.deepcopy(original)
            self.alter_report(item['mode'], lambda record: record.update({field: invalid}))
            with self.subTest(field=field), self.assertRaises(RuntimeError): self.check()

    def test_failed_or_boolean_exit_uncertain_cleanup_and_client_code_are_refused(self):
        original_files, original_ready = copy.deepcopy(self.files), copy.deepcopy(self.ready)
        alterations = [lambda record: record.update(passed=False),
            lambda record: record['runs'][0].update(exit=False),
            lambda record: record['runs'][0].update(exit=1),
            lambda record: record.update(runs=[]),
            lambda record: record['cleanup'][0].update(exit=False),
            lambda record: record['cleanup'][1].update(exit=1),
            lambda record: record.update(quarantine_cleared_after_confirmed_cleanup=False),
            lambda record: record.update(client_cef_rockstar_game_or_account_code_started=True),
            lambda record: record.update(post_run_guard_failure={})]
        for change in alterations:
            self.files, self.ready = copy.deepcopy(original_files), copy.deepcopy(original_ready)
            self.alter_report('pipe-on', change)
            with self.assertRaises(RuntimeError): self.check()


class ReadVerifierBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.raw = b'own_marker = 17\n'
        self.pin = {'schema_version': 1, 'profile': 'wine-read-api-probes', 'protocol_version': 1810,
            'verifier': {'path': str(profile.VERIFIER.relative_to(ROOT)), 'bytes': len(self.raw),
                         'sha256': hashlib.sha256(self.raw).hexdigest()}}
        self.reads = []

    def load(self):
        def read(path):
            self.reads.append(path)
            return json.dumps(self.pin).encode() if path == profile.ROOT_PIN else self.raw
        with mock.patch.object(profile, 'bootstrap_read', side_effect=read):
            return profile.candidate_module()

    def test_fixed_verifier_identity_is_checked_before_captured_byte_execution(self):
        loaded = self.load()
        self.assertEqual(loaded.own_marker, 17)
        self.assertEqual(self.reads, [profile.ROOT_PIN, profile.VERIFIER])
        self.assertTrue(loaded.source_verifier_admission['verified_before_code_execution'])
        self.assertEqual(loaded.source_verifier_admission['verifier'], self.pin['verifier'])

    def test_foreign_path_or_bad_identity_rejects_before_verifier_read(self):
        original = copy.deepcopy(self.pin)
        for key, invalid in (('path', 'prefixes/fivem-source-main/private.py'), ('bytes', True),
                              ('sha256', 'z' * 64)):
            self.pin = copy.deepcopy(original)
            self.pin['verifier'][key] = invalid
            self.reads.clear()
            with self.assertRaises(RuntimeError): self.load()
            self.assertEqual(self.reads, [profile.ROOT_PIN])

    def test_changed_verifier_is_not_executed(self):
        self.raw = b'raise AssertionError("unbound code executed")\n'
        with self.assertRaisesRegex(RuntimeError, 'code changed before loading'): self.load()

    def test_bootstrap_refuses_foreign_symlink_and_hardlinked_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            code, pin, private = root / 'own.py', root / 'pin.json', root / 'private.py'
            code.write_bytes(b'own'); pin.write_bytes(b'{}'); private.write_bytes(b'PRIVATE')
            with mock.patch.multiple(profile, ROOT=root, VERIFIER=code, ROOT_PIN=pin):
                with self.assertRaises(RuntimeError): profile.bootstrap_read(private)
                code.unlink(); code.symlink_to(private)
                with self.assertRaises(RuntimeError): profile.bootstrap_read(code)
                code.unlink(); os.link(private, code)
                with self.assertRaises(RuntimeError): profile.bootstrap_read(code)


class ReadSourceEnvironmentTests(unittest.TestCase):
    def setUp(self):
        sibling = ROOT.parent / 'GTA-V-macOS'
        self.inherited = {}
        engine = sibling / 'runtime/matched-wine11-r29/engine'
        self.matched = SimpleNamespace(ENGINE=engine, WINE=engine / 'bin/wine',
            PREFIX=sibling / 'prefixes/rockstar-legacy', environment=lambda: dict(self.inherited))
        self.candidate = SimpleNamespace(MOLTENVK=Path('/own/mvk/lib.dylib'),
            FRAMEWORKS=Path('/own/frameworks'), GST_LIB=Path('/own/gst'))
        self.context = {'profile': 'read', 'engine': {'manifest_sha256': 'a' * 64}}

    def select(self):
        with mock.patch.object(profile, 'verify_profile', return_value=self.context), \
                mock.patch.object(profile, 'candidate_module', return_value=self.candidate):
            return profile.select_runtime(self.matched, profile.SOURCE_PREFIX)

    def test_source_flags_are_derived_from_source_environment_not_api_initializer(self):
        env = {'WINEDLLOVERRIDES': 'dxgi,d3d11,d3d10core,winemetal=b', 'SOURCE_SENTINEL': 'retained'}
        with mock.patch.object(profile.baseline, 'source_environment', return_value=env):
            actual = profile.source_environment(self.matched, profile.SOURCE_PREFIX, self.candidate)
        self.assertEqual(actual['WINEPREFIX'], str(profile.SOURCE_PREFIX))
        self.assertEqual(actual['WINESERVER'], str(profile.ENGINE / 'bin/wineserver'))
        self.assertEqual(actual['WINEDEBUG'], '-all,+cfxnum')
        self.assertTrue(actual['DYLD_LIBRARY_PATH'].startswith(str(profile.ENGINE)))
        self.assertEqual(actual['SOURCE_SENTINEL'], 'retained')
        self.assertNotIn('mscoree', actual['WINEDLLOVERRIDES'])
        self.assertNotIn('mshtml', actual['WINEDLLOVERRIDES'])

    def test_foreign_prefix_or_provider_rejects_before_profile_or_code_reads(self):
        with mock.patch.object(profile, 'verify_profile') as verify, mock.patch.object(profile, 'candidate_module') as load:
            for prefix in (self.matched.PREFIX, ROOT / 'prefixes/wine-read-regression'):
                with self.assertRaises(RuntimeError): profile.select_runtime(self.matched, prefix)
            wrong = copy.copy(self.matched); wrong.ENGINE = ROOT / 'unreviewed-engine'
            with self.assertRaises(RuntimeError): profile.select_runtime(wrong, profile.SOURCE_PREFIX)
        verify.assert_not_called(); load.assert_not_called()

    def test_inherited_citizenfx_roles_are_refused_before_cleanup_or_verification(self):
        with mock.patch.object(profile, 'verify_profile') as verify:
            for key in ('CitizenFX_NoTenUI', 'citizenfx_tool_mode', 'CITIZENFX_EMPTY'):
                self.inherited[key] = ''
                with self.assertRaises(RuntimeError): profile.select_runtime(self.matched, profile.SOURCE_PREFIX)
                del self.inherited[key]
        verify.assert_not_called()

    def test_pre_spawn_rechecks_context_and_new_inherited_roles(self):
        selected = self.select()
        with mock.patch.object(profile, 'verify_profile', return_value=self.context) as verify:
            selected.before_source_spawn(); verify.assert_called_once_with()
        with mock.patch.object(profile, 'verify_profile', return_value={'profile': 'changed'}):
            with self.assertRaises(RuntimeError): selected.before_source_spawn()
        self.inherited['CITIZENFX_NEW'] = ''
        with mock.patch.object(profile, 'verify_profile') as verify:
            with self.assertRaises(RuntimeError): selected.before_source_spawn()
            verify.assert_not_called()
        with self.assertRaises(RuntimeError): selected.environment()

    def test_full_profile_reuses_only_known_two_source_bridge_code_inputs(self):
        admission = {'code_pin': {'path': str(profile.ROOT_PIN.relative_to(ROOT)), 'bytes': 10, 'sha256': 'a' * 64},
                     'verifier': {'path': str(profile.VERIFIER.relative_to(ROOT)), 'bytes': 10, 'sha256': 'b' * 64}}
        engine = self.context['engine'] | {'protocol_version': 1810, 'root_pin': admission['code_pin'],
                    'verifier_source': dict(admission['verifier'], path=str(profile.VERIFIER))}
        candidate = SimpleNamespace(verify_runtime=lambda: engine, source_verifier_admission=admission)
        bridges = [{'path': name} for name in profile.baseline.SOURCE_BRIDGES]
        with mock.patch.object(profile, 'candidate_module', return_value=candidate), \
                mock.patch.object(profile.baseline.graphics, 'verify_renderer', return_value={'own': True}), \
                mock.patch.object(profile.baseline, 'verify_source_bridge_code', return_value=bridges) as bridge_read, \
                mock.patch.object(profile, 'verify_prerequisites', return_value={'own': True}):
            value = profile.verify_profile()
        bridge_read.assert_called_once_with()
        self.assertEqual(len(value['source_bridge_code']), 2)
        self.assertFalse(value['source_stage_update_performed'])
        self.assertFalse(value['authentication_security_or_integrity_decisions_modified'])

    def test_root_pin_or_verifier_code_race_is_refused_before_source_bridge_reads(self):
        admission = {'code_pin': {'path': str(profile.ROOT_PIN.relative_to(ROOT)), 'bytes': 10, 'sha256': 'a' * 64},
                     'verifier': {'path': str(profile.VERIFIER.relative_to(ROOT)), 'bytes': 10, 'sha256': 'b' * 64}}
        engine = self.context['engine'] | {'protocol_version': 1810, 'root_pin': admission['code_pin'],
                    'verifier_source': dict(admission['verifier'], path=str(profile.VERIFIER))}
        for field in ('root_pin', 'verifier_source'):
            changed = copy.deepcopy(engine); changed[field]['sha256'] = 'c' * 64
            candidate = SimpleNamespace(verify_runtime=lambda: changed, source_verifier_admission=admission)
            with mock.patch.object(profile, 'candidate_module', return_value=candidate), \
                    mock.patch.object(profile.baseline, 'verify_source_bridge_code') as read:
                with self.assertRaisesRegex(RuntimeError, 'changed between admission'): profile.verify_profile()
                read.assert_not_called()


class ReadSourceControllerTests(unittest.TestCase):
    def test_cli_keeps_matched_default_and_all_profiles_require_explicit_selection(self):
        for name in (None, 'matched', 'parity', 'numeric', 'read'):
            args = [] if name is None else ['--runtime', name]
            with mock.patch.object(run_source, 'run', return_value=0) as run, \
                    mock.patch.object(sys, 'argv', ['run_source.py', 'resume', *args]):
                self.assertEqual(run_source.main(), 0)
            expected = dict(resume=True, process_trace=False, observe_rockstar_processes=False)
            if name not in (None, 'matched'): expected['runtime_profile'] = name
            run.assert_called_once_with(3600, **expected)

    def test_selector_dispatches_read_only_on_explicit_name(self):
        matched = SimpleNamespace(PREFIX=Path('/own/productive-prefix'), ENGINE=Path('/own/matched-engine'))
        selected = SimpleNamespace(source_runtime_profile={'profile': 'read'})
        spec = SimpleNamespace(loader=SimpleNamespace(exec_module=lambda module: None))
        with mock.patch.object(run_source.importlib.util, 'spec_from_file_location', return_value=spec), \
                mock.patch.object(run_source.importlib.util, 'module_from_spec', return_value=matched), \
                mock.patch.object(profile, 'select_runtime', return_value=selected) as select:
            actual, context = run_source.select_runtime_profile('read')
            self.assertIs(actual, selected); self.assertEqual(context['profile'], 'read')
            select.assert_called_once_with(matched, run_source.PREFIX)
            select.reset_mock()
            actual, context = run_source.select_runtime_profile('matched')
            self.assertIs(actual, matched); self.assertEqual(context['profile'], 'matched')
            select.assert_not_called()

    def test_controller_guards_before_observer_and_after_ready_before_main(self):
        import source_main_environment
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); (root / 'logs').mkdir(); (root / 'research').mkdir()
            events = []
            runtime = SimpleNamespace(ENGINE=root / 'own-engine', WINE=root / 'own-engine/bin/wine',
                environment=lambda: {}, source_winedebug=profile.DEBUG,
                before_source_spawn=lambda: events.append('runtime-guard'))

            class Observer:
                def __init__(self, *args, **kwargs): events.append('observer-start')
                def wait_ready(self): events.append('observer-ready')
                def finish_after_wineserver_cleanup(self): return {'own_fixture': True}

            def spawn(*args, **kwargs):
                events.append('main-start')
                return SimpleNamespace(pid=42, poll=lambda: 0, wait=lambda **kw: 0)

            replacements = {'ROOT': root, 'PREFIX': root / 'prefixes/fivem-source-main',
                'STAGE': root / 'build/windows-source-integration', 'MANIFEST': root / 'research/own-v8.json',
                'INITIAL_MANIFEST': root / 'research/own-initial.json', 'USER_LOGIN': root / 'research/own-context.json',
                'PREFLIGHT': root / 'research/own-preflight.json'}
            with ExitStack() as stack:
                for name, value in replacements.items(): stack.enter_context(mock.patch.object(run_source, name, value))
                for module, name, kwargs in (
                    (run_source, 'check_inputs', {'return_value': {'developer_code_version': 8, 'files': []}}),
                    (run_source, 'game_mapping', {}),
                    (run_source, 'select_runtime_profile', {'return_value': (runtime, {'profile': 'read'})}),
                    (run_source, 'ProcessObserver', {'side_effect': Observer}), (run_source, 'sha', {'return_value': 'a' * 64}),
                    (run_source, 'code_only_snapshot', {'return_value': []}),
                    (source_main_environment, 'source_main_prefix', {'return_value': nullcontext()}),
                    (source_main_environment, 'assert_source_main_prefix', {}),
                    (run_source.subprocess, 'Popen', {'side_effect': spawn}),
                    (run_source.subprocess, 'run', {'return_value': SimpleNamespace(returncode=0)}),
                    (run_source.time, 'monotonic', {'side_effect': [100, 102, 103]})):
                    stack.enter_context(mock.patch.object(module, name, **kwargs))
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(run_source.run(1, resume=True, runtime_profile='read'), 0)
            self.assertEqual(events, ['runtime-guard', 'observer-start', 'observer-ready', 'runtime-guard', 'main-start'])
            metadata = json.loads(next((root / 'research').glob('*-results.json')).read_bytes())
            self.assertEqual(metadata['runtime_engine_profile'], 'read')
            self.assertFalse(metadata['launcher_ui_reached'])


if __name__ == '__main__':
    unittest.main()
