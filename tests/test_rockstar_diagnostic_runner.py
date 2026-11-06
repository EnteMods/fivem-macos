"""Standalone RGL preparation and mocked process ownership; never execute Wine or RGL."""
from contextlib import contextmanager, redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / 'native/windows-client'))
spec = importlib.util.spec_from_file_location('rgl_diagnostic_scope_test', PROJECT / 'native/windows-client/run_rockstar_diagnostic.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class RockstarDiagnosticRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve() / 'project'
        self.prefix = self.root / 'prefixes/fivem-source-main'
        for name in ('logs', 'research'):
            (self.root / name).mkdir(parents=True)
        self.patches = [mock.patch.object(runner, 'ROOT', self.root), mock.patch.object(runner, 'PREFIX', self.prefix),
                        mock.patch.dict(runner.plain.__globals__, ROOT=self.root)]
        for patch in self.patches:
            patch.start()

    def tearDown(self):
        for patch in reversed(self.patches):
            patch.stop()
        self.temporary.cleanup()

    def result(self):
        files = list((self.root / 'research').glob('*-results.json'))
        self.assertEqual(len(files), 1)
        return json.loads(files[0].read_text())

    def argument_fixture(self, arguments=None):
        path = self.root / runner.ARGUMENT_EVIDENCE
        path.write_text(json.dumps({'startup_metadata': [{'startup_commands': [{
            'local_time': '2026-11-01 20:34:41.161', 'executable_basename': 'Launcher.exe',
            'flag_names_only': list(runner.OBSERVED_FIVEM_ARGUMENTS) if arguments is None else arguments}]}]}))

    def test_observed_variant_is_fixed_and_requires_exact_origin(self):
        self.argument_fixture()
        with mock.patch.object(runner, 'load_runtime') as runtime, mock.patch.object(runner.subprocess, 'Popen') as start:
            plan = runner.plan(180, True)
            self.assertEqual(plan['arguments'], ['-skipPatcherCheck', '-fivem'])
            self.assertEqual(plan['maximum_observe_seconds'], 180)
            self.assertFalse(plan['fivem_legitimacy_callback_success_claim'])
            for duration, variant in ((181, True), (3601, False), (1, '-other-option')):
                with self.assertRaises(ValueError):
                    runner.run(duration, variant)
            self.argument_fixture(['-skipPatcherCheck', '-fivem', '--parent_pid'])
            with self.assertRaises(ValueError):
                runner.run(1, True)
            runtime.assert_not_called()
            start.assert_not_called()

    def test_prepare_and_invalid_duration_cannot_import_or_start_runtime(self):
        with mock.patch.object(runner, 'load_runtime') as runtime, mock.patch.object(runner.subprocess, 'Popen') as start:
            plan = runner.plan()
            self.assertEqual(plan['arguments'], [])
            self.assertEqual(plan['observe_seconds'], 90)
            self.assertEqual(plan['wine_debug'], '-all,err+all')
            self.assertFalse(plan['module_trace'])
            self.assertFalse(plan['UI_success_claim'])
            traced = runner.plan(module_trace=True)
            self.assertEqual(traced['arguments'], [])
            self.assertEqual(traced['wine_debug'], '+loaddll,+seh')
            with self.assertRaises(ValueError):
                runner.run(module_trace='+process')
            for invalid in (0, 3601):
                with self.assertRaises(ValueError):
                    runner.run(invalid)
            runtime.assert_not_called()
            start.assert_not_called()
        self.assertFalse(self.prefix.exists())

    def test_real_shared_guard_rejects_missing_prefix_before_runtime_import(self):
        with mock.patch.object(runner, 'load_runtime') as runtime, mock.patch.object(runner.subprocess, 'Popen') as start, redirect_stdout(io.StringIO()):
            code = runner.run(1)
        self.assertEqual(code, 1)
        runtime.assert_not_called()
        start.assert_not_called()
        result = self.result()
        self.assertTrue(result['guard_failure'])
        self.assertFalse(result['launcher_started'])
        self.assertFalse(result['cleanup']['performed'])
        self.assertFalse(self.prefix.exists())

    def test_post_start_guard_failure_cleans_only_source_prefix_while_lock_is_held(self):
        self._assert_post_start_guard_cleanup(False)

    def test_fixed_argument_variant_preserves_same_locked_prefix_cleanup(self):
        self.argument_fixture()
        self._assert_post_start_guard_cleanup(True)

    def test_module_trace_changes_only_the_child_environment(self):
        inherited_debug = runner.os.environ.get('WINEDEBUG')
        self._assert_post_start_guard_cleanup(False, module_trace=True)
        self.assertEqual(runner.os.environ.get('WINEDEBUG'), inherited_debug)

    def test_observer_ready_precedes_rgl_and_both_clean_up_under_same_lock(self):
        self._assert_observer_order(False)

    def test_observer_readiness_failure_blocks_rgl_and_still_cleans_held_prefix(self):
        self._assert_observer_order(True)

    def _assert_observer_order(self, fail_ready):
        held = False
        actions = []
        ready_event = {'event': 'ready', 'time_ms': 1, 'pid': 32, 'parent_pid': 0,
                       'basename': 'process_observer.exe', 'exit_hex': None}

        @contextmanager
        def context(prefix, root):
            nonlocal held
            self.assertEqual((prefix, root), (self.prefix, self.root))
            held = True
            try:
                yield prefix
            finally:
                held = False
                actions.append('unlock')

        owner = self

        class Observer:
            def __init__(self, runtime, environment, stage, label, duration, *, rockstar_scope):
                owner.assertTrue(held)
                owner.assertTrue(rockstar_scope)
                owner.assertEqual(environment['WINEPREFIX'], str(owner.prefix))
                owner.assertEqual(duration, 31)
                actions.append('observer-start')

            def wait_ready(self):
                actions.append('ready')
                if fail_ready:
                    raise RuntimeError('Own synthetic readiness failure')

            def finish_after_wineserver_cleanup(self):
                owner.assertTrue(held)
                owner.assertEqual(actions[-1], '-w')
                actions.append('observer-finish')
                return {'reader_completed_without_error': True, 'events': [ready_event]}

        runtime = SimpleNamespace(WINE=self.root / 'wine', ENGINE=self.root / 'engine', environment=lambda: {})

        def start(command, **options):
            self.assertTrue(held)
            self.assertEqual(actions[-1], 'ready')
            self.assertEqual(command, [str(runtime.WINE), str(self.prefix / runner.LAUNCHER_RELATIVE)])
            actions.append('rgl-start')
            return SimpleNamespace(pid=12345, poll=lambda: None, wait=lambda timeout: 0)

        def cleanup(command, **options):
            self.assertTrue(held)
            self.assertEqual(options['env']['WINEPREFIX'], str(self.prefix))
            actions.append(command[-1])
            return SimpleNamespace(returncode=0)

        def guard(prefix, root):
            self.assertTrue(held)
            raise runner.ProbePrefixError('Own guard failure after mock RGL start')

        with mock.patch.object(runner, 'source_main_prefix', context), \
                mock.patch.object(runner, 'code_identity', return_value={'code_files': 142}) as identity, \
                mock.patch.object(runner, 'load_runtime', return_value=runtime), \
                mock.patch.object(runner, 'ProcessObserver', Observer), \
                mock.patch.object(runner, 'assert_source_main_prefix', guard), \
                mock.patch.object(runner.subprocess, 'Popen', start) as launch, \
                mock.patch.object(runner.subprocess, 'run', cleanup), redirect_stdout(io.StringIO()):
            code = runner.run(1, observe_code_processes=True)
        self.assertEqual(code, 1)
        identity.assert_called_once_with(True)
        self.assertEqual(actions, ['observer-start', 'ready'] + ([] if fail_ready else ['rgl-start']) +
                         ['-k', '-w', 'observer-finish', 'unlock'])
        result = self.result()
        self.assertEqual(result['launcher_started'], not fail_ready)
        self.assertEqual(result['read_only_code_process_observer']['events'], [ready_event])
        self.assertFalse(result['UI_success_claim'])

    def _assert_post_start_guard_cleanup(self, observed_fivem_arguments, module_trace=False):
        held = False
        launched = False
        commands = []

        @contextmanager
        def context(prefix, root):
            nonlocal held
            self.assertEqual(prefix, self.prefix)
            self.assertEqual(root, self.root)
            held = True
            try:
                yield prefix
            finally:
                held = False

        runtime = SimpleNamespace(WINE=self.root / 'engine/bin/wine', ENGINE=self.root / 'engine',
                                  environment=lambda: {'WINEPREFIX': '/forbidden-original-prefix', 'WINEDEBUG': '+process'})
        parent = SimpleNamespace(pid=12345, poll=lambda: None, wait=lambda timeout: 0)

        def start(command, **options):
            nonlocal launched
            self.assertTrue(held)
            arguments = list(runner.OBSERVED_FIVEM_ARGUMENTS) if observed_fivem_arguments else []
            self.assertEqual(command, [str(runtime.WINE), str(self.prefix / runner.LAUNCHER_RELATIVE), *arguments])
            self.assertEqual(options['env']['WINEPREFIX'], str(self.prefix))
            self.assertEqual(options['env']['WINEDEBUG'], '+loaddll,+seh' if module_trace else '-all,err+all')
            self.assertEqual(options['stdout'], runner.subprocess.DEVNULL)
            launched = True
            return parent

        def guard(prefix, root):
            self.assertTrue(held)
            if launched:
                raise runner.ProbePrefixError('Synthetic guard failure, no real profile')

        def cleanup(command, **options):
            self.assertTrue(held)
            self.assertEqual(options['env']['WINEPREFIX'], str(self.prefix))
            commands.append(command)
            return SimpleNamespace(returncode=0)

        with mock.patch.object(runner, 'source_main_prefix', context), \
                mock.patch.object(runner, 'code_identity', return_value={'code_files': 142}), \
                mock.patch.object(runner, 'load_runtime', return_value=runtime), \
                mock.patch.object(runner, 'assert_source_main_prefix', guard), \
                mock.patch.object(runner.subprocess, 'Popen', start), \
                mock.patch.object(runner.subprocess, 'run', cleanup), redirect_stdout(io.StringIO()):
            code = runner.run(1, observed_fivem_arguments, module_trace)
        self.assertEqual(code, 1)
        self.assertFalse(held)
        self.assertEqual(commands, [[str(runtime.ENGINE / 'bin/wineserver'), '-k'],
                                    [str(runtime.ENGINE / 'bin/wineserver'), '-w']])
        result = self.result()
        self.assertTrue(result['guard_failure'])
        self.assertEqual(result['cleanup']['wait_exit'], 0)
        self.assertIsNone(result['native_wine_parent_exit_before_cleanup'])
        self.assertEqual(result['launcher_UI_status'], 'unknown_requires_Root_current_PID_window_inspection')
        self.assertFalse(result['UI_success_claim'])
        self.assertFalse(result['private_log_contents_read_hashed_or_copied'])


if __name__ == '__main__':
    unittest.main()
