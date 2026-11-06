"""Parity Source selection and fixed own-probe evidence; no runtime/user state starts."""
import copy
from contextlib import ExitStack, nullcontext, redirect_stdout
import hashlib
import io
import os
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT/'native/windows-client'))
import parity_runtime_profile as profile
import run_source


class PrerequisiteEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()/'project'
        for name, (size, digest) in profile.PINS.items():
            source = PROJECT/name
            raw = source.read_bytes()
            self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), (size, digest))
            target = self.root/name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        patch = mock.patch.object(profile, 'ROOT', self.root)
        patch.start()
        self.addCleanup(patch.stop)

    def test_actual_fixed_reports_and_raw_logs_reparse_all_four_capabilities(self):
        result = profile._verify_prerequisites()
        self.assertEqual(result['job_event_counts'], [79, 170])
        self.assertEqual(result['probe_summaries']['winhttp']['http_status'], 200)
        self.assertEqual(result['probe_summaries']['graphics-dxmt']['feature_level'], 0xb000)
        self.assertTrue(result['historical_probe_runner_hashes_are_not_simultaneous_live_runner_claims'])

    def test_missing_or_changed_result_cannot_become_a_positive_prerequisite(self):
        path = self.root/profile.REASSESS
        original = path.read_bytes()
        path.unlink()
        with self.assertRaises(FileNotFoundError): profile._verify_prerequisites()
        path.write_bytes(b'{"passed":true}')
        with self.assertRaises(RuntimeError): profile._verify_prerequisites()
        path.write_bytes(original)
        raw = self.root/next(name for name in profile.PINS if name.endswith('-font.ndjson'))
        raw.write_bytes(raw.read_bytes().replace(b'after_ink=863', b'after_ink=000'))
        with self.assertRaises(RuntimeError): profile._verify_prerequisites()

    def test_unknown_private_path_is_rejected_before_any_selected_read(self):
        with mock.patch.object(profile.verifier, 'read_regular') as read, self.assertRaises(RuntimeError):
            profile._read('prefixes/fivem-source-main/user.reg')
        read.assert_not_called()

    def test_aliased_prerequisite_is_rejected_before_content_read(self):
        path = self.root/profile.REASSESS
        other = self.root/'own-sentinel'
        other.write_bytes(path.read_bytes())
        path.unlink()
        os.link(other, path)
        with self.assertRaises(RuntimeError): profile._verify_prerequisites()


class SourceProfileEnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()/'project'
        self.prefix = self.root/'prefixes/fivem-source-main'
        self.engine = self.root/'runtime/wine-job-query-parity/engine'
        sibling = self.root.parent/'GTA-V-macOS'
        matched_engine = sibling/'runtime/matched-wine11-r29/engine'
        self.inherited = {'WINEPREFIX': 'old-gta', 'WINESERVER': 'old-server', 'WINESERVERSOCKET': 'old-socket',
            'WINELOADER': 'old-loader', '__WINE_SERVER_DIR': 'old-dir', 'DYLD_INSERT_LIBRARIES': 'old-inject',
            'DYLD_LIBRARY_PATH': 'old-libs', 'WINEDLLOVERRIDES': 'mscoree,mshtml=d',
            'GST_PLUGIN_PATH': 'unbound-plugins', 'HOME': '/own-home', 'LANG': 'de_DE.UTF-8'}
        self.matched = SimpleNamespace(ENGINE=matched_engine, WINE=matched_engine/'bin/wine',
            PREFIX=sibling/'prefixes/rockstar-legacy', environment=lambda: dict(self.inherited))
        self.context = {'profile': 'parity', 'proof': 'own fixed evidence'}
        self.patches = [mock.patch.object(profile, 'ROOT', self.root), mock.patch.object(profile, 'SOURCE_PREFIX', self.prefix),
                        mock.patch.object(profile, 'ENGINE', self.engine), mock.patch.object(run_source, 'PREFIX', self.prefix),
                        mock.patch.object(profile, 'verify_profile', return_value=self.context)]
        for patch in self.patches:
            patch.start()
            self.addCleanup(patch.stop)

    def test_parity_keeps_source_role_and_rebinds_engine_without_api_initializer_overrides(self):
        selected = profile.select_runtime(self.matched, self.prefix)
        env = run_source.source_runtime_environment(selected, 7, True)
        self.assertEqual(selected.ENGINE, self.engine)
        self.assertEqual(selected.WINE, self.engine/'bin/wine')
        self.assertEqual(selected.PREFIX, self.matched.PREFIX)
        self.assertEqual(env['WINEPREFIX'], str(self.prefix))
        self.assertEqual(env['WINESERVER'], str(self.engine/'bin/wineserver'))
        self.assertEqual(env['CitizenFX_NoTenUI'], '1')
        self.assertEqual(env['WINEDEBUG'], '+loaddll,+seh,+debugstr,+process')
        self.assertEqual(env['WINEDLLOVERRIDES'], 'dxgi,d3d11,d3d10core,winemetal=b')
        self.assertNotIn('mscoree', env['WINEDLLOVERRIDES'])
        self.assertNotIn('mshtml', env['WINEDLLOVERRIDES'])
        self.assertEqual(env['DYLD_LIBRARY_PATH'].split(os.pathsep)[0], str(self.engine/'lib/wine/x86_64-unix'))
        for key in ('WINESERVERSOCKET', 'WINELOADER', '__WINE_SERVER_DIR', 'DYLD_INSERT_LIBRARIES'):
            self.assertNotIn(key, env)
        for key in ('GST_PLUGIN_PATH', 'GST_PLUGIN_PATH_1_0', 'GST_PLUGIN_SYSTEM_PATH', 'GST_PLUGIN_SYSTEM_PATH_1_0'):
            self.assertEqual(env[key], '')
        self.assertEqual(env['HOME'], self.inherited['HOME'])
        self.assertEqual(env['LANG'], self.inherited['LANG'])
        self.assertEqual(self.inherited['WINESERVER'], 'old-server')

    def test_all_inherited_citizenfx_variables_are_refused_before_cleanup_or_verification(self):
        for key in ('CitizenFX_NoTenUI', 'citizenfx_tool_mode', 'CITIZENFX_EMPTY'):
            self.inherited[key] = ''
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                profile.select_runtime(self.matched, self.prefix)
            profile.verify_profile.assert_not_called()
            del self.inherited[key]

    def test_new_inherited_role_after_selection_is_not_silently_removed(self):
        selected = profile.select_runtime(self.matched, self.prefix)
        self.inherited['CitizenFX_ToolMode'] = '1'
        with self.assertRaises(RuntimeError): selected.environment()

    def test_other_source_prefix_or_matched_provider_is_refused(self):
        with self.assertRaises(RuntimeError): profile.select_runtime(self.matched, self.matched.PREFIX)
        wrong = copy.copy(self.matched)
        wrong.ENGINE = self.root/'unreviewed-engine'
        with self.assertRaises(RuntimeError): profile.select_runtime(wrong, self.prefix)

    def test_pre_spawn_guard_refuses_changed_proof_without_starting_any_process(self):
        selected = profile.select_runtime(self.matched, self.prefix)
        selected.before_source_spawn()
        profile.verify_profile.return_value = {'profile': 'parity', 'proof': 'changed'}
        with self.assertRaises(RuntimeError): selected.before_source_spawn()


class SourceBridgeScopeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()/'project'
        self.prefix = self.root/'prefixes/fivem-source-main'
        own = b'own inert bridge fixture'
        pins = {}
        for name in profile.SOURCE_BRIDGES:
            path = self.prefix/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(own)
            pins[name] = (len(own), hashlib.sha256(own).hexdigest())
        self.patches = [mock.patch.object(profile, 'ROOT', self.root), mock.patch.object(profile, 'SOURCE_PREFIX', self.prefix),
                        mock.patch.object(profile, 'SOURCE_BRIDGES', pins)]
        for patch in self.patches:
            patch.start()
            self.addCleanup(patch.stop)

    def test_only_two_explicit_code_files_are_read_not_registry_or_profiles(self):
        private = self.prefix/'user.reg'
        private.write_text('OWN PRIVATE SENTINEL')
        with mock.patch.object(profile.verifier, 'read_regular', wraps=profile.verifier.read_regular) as read:
            result = profile.verify_source_bridge_code()
        self.assertEqual(len(result), 2)
        self.assertEqual({call.args[0] for call in read.call_args_list}, {self.prefix/name for name in profile.SOURCE_BRIDGES})
        self.assertFalse(any(call.args[0] == private for call in read.call_args_list))

    def test_bridge_mismatch_refuses_without_implicit_repair(self):
        path = self.prefix/next(iter(profile.SOURCE_BRIDGES))
        path.write_bytes(b'own mismatching code')
        before = path.read_bytes()
        with self.assertRaises(RuntimeError): profile.verify_source_bridge_code()
        self.assertEqual(path.read_bytes(), before)


class SourceProfileCliTests(unittest.TestCase):
    def test_matched_remains_default_and_parity_needs_explicit_flag(self):
        for args, selected in (([], False), (['--runtime', 'matched'], False), (['--runtime', 'parity'], True)):
            with self.subTest(args=args), mock.patch.object(run_source, 'run', return_value=0) as run, \
                    mock.patch.object(sys, 'argv', ['run_source.py', 'resume', *args]):
                self.assertEqual(run_source.main(), 0)
            expected = dict(resume=True, process_trace=False, observe_rockstar_processes=False)
            if selected: expected['runtime_profile'] = 'parity'
            run.assert_called_once_with(3600, **expected)

    def test_matched_selector_never_invokes_parity_verification(self):
        matched = SimpleNamespace(ENGINE=Path('/own/matched-engine'), PREFIX=Path('/own/production-prefix'))
        spec = SimpleNamespace(loader=SimpleNamespace(exec_module=lambda module: None))
        with mock.patch.object(run_source.importlib.util, 'spec_from_file_location', return_value=spec), \
                mock.patch.object(run_source.importlib.util, 'module_from_spec', return_value=matched), \
                mock.patch.object(profile, 'verify_profile') as verify:
            selected, context = run_source.select_runtime_profile('matched')
        self.assertIs(selected, matched)
        self.assertEqual(context['profile'], 'matched')
        verify.assert_not_called()

    def test_controller_rechecks_runtime_before_observer_and_after_ready_before_main(self):
        import source_main_environment
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root/'logs').mkdir()
            (root/'research').mkdir()
            events = []
            runtime = SimpleNamespace(ENGINE=root/'own-engine', WINE=root/'own-engine/bin/wine',
                environment=lambda: {}, before_source_spawn=lambda: events.append('runtime-guard'))

            class Observer:
                def __init__(self, *args, **kwargs): events.append('observer-start')
                def wait_ready(self): events.append('observer-ready')
                def finish_after_wineserver_cleanup(self): return {'own_fixture': True}

            def spawn(*args, **kwargs):
                events.append('main-start')
                return SimpleNamespace(pid=42, poll=lambda: 0, wait=lambda **kw: 0)

            replacements = {'ROOT': root, 'PREFIX': root/'prefixes/fivem-source-main',
                'STAGE': root/'build/windows-source-integration', 'MANIFEST': root/'research/own-v7.json',
                'INITIAL_MANIFEST': root/'research/own-initial.json', 'USER_LOGIN': root/'research/own-context.json',
                'PREFLIGHT': root/'research/own-preflight.json'}
            with ExitStack() as stack:
                for name, value in replacements.items(): stack.enter_context(mock.patch.object(run_source, name, value))
                for module, name, kwargs in (
                    (run_source, 'check_inputs', {'return_value': {'developer_code_version': 7, 'files': []}}),
                    (run_source, 'game_mapping', {}),
                    (run_source, 'select_runtime_profile', {'return_value': (runtime, {'profile': 'parity'})}),
                    (run_source, 'ProcessObserver', {'side_effect': Observer}),
                    (run_source, 'sha', {'return_value': 'a'*64}),
                    (run_source, 'code_only_snapshot', {'return_value': []}),
                    (source_main_environment, 'source_main_prefix', {'return_value': nullcontext()}),
                    (source_main_environment, 'assert_source_main_prefix', {}),
                    (run_source.subprocess, 'Popen', {'side_effect': spawn}),
                    (run_source.subprocess, 'run', {'return_value': SimpleNamespace(returncode=0)}),
                    (run_source.time, 'monotonic', {'side_effect': [100, 102, 103]})):
                    stack.enter_context(mock.patch.object(module, name, **kwargs))
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(run_source.run(1, resume=True, runtime_profile='parity'), 0)
            self.assertEqual(events, ['runtime-guard', 'observer-start', 'observer-ready', 'runtime-guard', 'main-start'])
            result = next((root/'research').glob('*-results.json'))
            import json
            metadata = json.loads(result.read_text())
            self.assertEqual(metadata['runtime_engine_profile'], 'parity')
            self.assertFalse(metadata['launcher_ui_reached'])


if __name__ == '__main__':
    unittest.main()
