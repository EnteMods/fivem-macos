from contextlib import ExitStack, nullcontext, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'native/windows-client'))
import graphics_blit_launch as launch
import graphics_blit_metadata
import run_source
import source_main_environment
from source_main_environment import _ACTIVE_MAIN_LOCKS


def pin(data):
    return len(data), hashlib.sha256(data).hexdigest()


class GraphicsBlitLaunchTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        stage = self.root / 'stage'
        stage.mkdir()
        self.target = stage / 'rage-graphics-five.dll'
        self.checkpoint = stage / '.rage-graphics-five.dll.blit-v12.previous'
        self.target.write_bytes(b'baseline')
        self.manifest = self.root / 'manifest.json'
        self.manifest.write_bytes(b'{}')
        candidate = self.root / 'candidate.dll'
        candidate.write_bytes(b'candidate')
        report = self.root / 'report.json'
        report.write_text(json.dumps({'source_revision': launch.REVISION, 'compiled': True,
            'stage_or_prefix_modified': False, 'exports_match_v12': 80, 'import_symbols_match_v12': True,
            'artifact': {'path': 'candidate.dll', 'bytes': pin(b'candidate')[0], 'sha256': pin(b'candidate')[1]}}))
        self.prefix = self.root / 'source-prefix'
        self.prefix.mkdir()
        self.runtime = SimpleNamespace(ENGINE=self.root / 'engine')
        self.env = {'WINEPREFIX': str(self.prefix), 'WINESERVER': str(self.runtime.ENGINE / 'bin/wineserver')}
        self.commands = []
        for key, value in dict(ROOT=self.root, STAGE=stage, TARGET=self.target, CHECKPOINT=self.checkpoint,
                SOURCE=candidate, REPORT=report, MANIFEST=self.manifest, PREFIX=self.prefix,
                REPORT_PIN=pin(report.read_bytes()), MANIFEST_PIN=pin(b'{}'), BASELINE_PIN=pin(b'baseline'),
                CANDIDATE_PIN=pin(b'candidate')).items():
            patch = mock.patch.object(launch, key, value)
            patch.start()
            self.addCleanup(patch.stop)
        for patch in (mock.patch('run_main.ROOT', self.root),
                      mock.patch.dict(_ACTIVE_MAIN_LOCKS, {str(self.prefix): (os.getpid(), 1)}),
                      mock.patch.object(launch.subprocess, 'run', side_effect=self.command)):
            patch.start()
            self.addCleanup(patch.stop)

    def command(self, command, **options):
        self.commands.append(command)
        if command[-1] == '-w':
            return SimpleNamespace(returncode=0)
        self.assertEqual(command[:3], ['/bin/cp', '-c', '-n'])
        self.assertFalse(Path(command[4]).exists())
        shutil.copyfile(command[3], command[4])
        return SimpleNamespace(returncode=0)

    def activate(self):
        return launch.activate(self.manifest, self.runtime, self.env)

    def test_candidate_and_baseline_are_separate_then_restored(self):
        evidence = self.activate()
        self.assertEqual(evidence['artifact']['sha256'], pin(b'candidate')[1])
        self.assertEqual(self.commands[0][-1], '-w')
        self.assertEqual(self.target.read_bytes(), b'candidate')
        self.assertEqual(self.checkpoint.read_bytes(), b'baseline')
        self.assertNotEqual(self.target.stat().st_ino, self.checkpoint.stat().st_ino)
        launch.restore_locked()
        self.assertEqual(self.target.read_bytes(), b'baseline')
        self.assertEqual(self.manifest.read_bytes(), b'{}')
        self.assertFalse(self.checkpoint.exists())

    def test_gate_candidate_uses_same_checkpoint_and_recovery(self):
        gate_source = self.root / 'gate.dll'
        gate_source.write_bytes(b'gate candidate')
        gate_pin = pin(gate_source.read_bytes())
        gate_report = self.root / 'gate.json'
        gate_report.write_text(json.dumps({'source_revision': launch.REVISION, 'compiled': True,
            'stage_or_prefix_modified': False, 'exports_match_blit': 80, 'import_symbols_match_blit': True,
            'artifact': launch.artifact(gate_source, gate_pin),
            'baseline_report': launch.artifact(launch.REPORT, launch.REPORT_PIN),
            'baseline_artifact': launch.artifact(launch.SOURCE, launch.CANDIDATE_PIN)}))
        with mock.patch.multiple(launch, GATE_SOURCE=gate_source, GATE_CANDIDATE_PIN=gate_pin,
                                 GATE_REPORT=gate_report, GATE_REPORT_PIN=pin(gate_report.read_bytes())):
            evidence = launch.activate(self.manifest, self.runtime, self.env, gate_census=True)
            self.assertEqual(evidence['artifact']['sha256'], gate_pin[1])
            self.assertEqual(self.target.read_bytes(), b'gate candidate')
            self.assertEqual(self.checkpoint.read_bytes(), b'baseline')
            launch.restore_locked()
        self.assertEqual(self.target.read_bytes(), b'baseline')
        self.assertFalse(self.checkpoint.exists())

    def test_missing_lock_or_busy_wine_refuses_before_copy(self):
        with mock.patch.dict(_ACTIVE_MAIN_LOCKS, clear=True):
            with self.assertRaisesRegex(RuntimeError, 'lock'):
                self.activate()
        with mock.patch.object(launch.subprocess, 'run', side_effect=subprocess.TimeoutExpired('wine', 3)):
            with self.assertRaisesRegex(RuntimeError, 'previous Wine session'):
                self.activate()
        self.assertEqual(self.target.read_bytes(), b'baseline')
        self.assertFalse(self.checkpoint.exists())
        self.assertFalse(self.commands)

    def test_failed_postswap_verification_rolls_back_before_start(self):
        original = launch.require
        injected = False
        def check(path, expected):
            nonlocal injected
            if path == self.target and expected == launch.CANDIDATE_PIN and not injected:
                injected = True
                raise RuntimeError('postswap failure')
            return original(path, expected)
        with mock.patch.object(launch, 'require', side_effect=check):
            with self.assertRaisesRegex(RuntimeError, 'postswap failure'):
                self.activate()
        self.assertEqual(self.target.read_bytes(), b'baseline')
        self.assertFalse(self.checkpoint.exists())

    def test_interrupted_run_and_unexpected_bytes_preserve_checkpoint(self):
        self.activate()
        with self.assertRaisesRegex(RuntimeError, 'explicit recovery'):
            self.activate()
        self.target.write_bytes(b'unexpected')
        with self.assertRaisesRegex(RuntimeError, 'Unexpected graphics DLL'):
            launch.restore_locked()
        self.assertEqual(self.target.read_bytes(), b'unexpected')
        self.assertEqual(self.checkpoint.read_bytes(), b'baseline')

    def test_other_baseline_failure_keeps_checkpoint_after_dll_restore(self):
        self.activate()
        validate = mock.Mock(side_effect=RuntimeError('different immutable client file'))
        with self.assertRaisesRegex(RuntimeError, 'different immutable client file'):
            launch.restore_locked(validate)
        self.assertEqual(self.target.read_bytes(), b'baseline')
        self.assertEqual(self.checkpoint.read_bytes(), b'baseline')
        launch.restore_locked(mock.Mock())
        self.assertFalse(self.checkpoint.exists())

    def test_requires_exact_opt_in_runtime(self):
        for runtime, search, relay in [('matched', True, False), ('parity', False, False), ('parity', True, True)]:
            with self.subTest(runtime=runtime, search=search, relay=relay), self.assertRaises(ValueError):
                run_source.validate_graphics_blit_selection(True, runtime, search, relay)
        run_source.validate_graphics_blit_selection(True, 'parity', True, False)
        run_source.validate_graphics_blit_selection(False, 'matched', False, False)
        with self.assertRaisesRegex(ValueError, 'requires --trace-graphics-blit'):
            run_source.validate_graphics_blit_selection(False, 'parity', True, False, gate_census=True)

    def test_cli_passes_blit_only_for_explicit_flag(self):
        args = ['run_source.py', 'resume', '--runtime', 'parity', '--system-dyld-search']
        for enabled in (False, True):
            with self.subTest(enabled=enabled), mock.patch.object(sys, 'argv', args + (
                    ['--trace-graphics-blit'] if enabled else [])), mock.patch.object(run_source, 'run', return_value=0) as run:
                self.assertEqual(run_source.main(), 0)
                self.assertEqual(run.call_args.kwargs.get('trace_graphics_blit', False), enabled)
        with mock.patch.object(sys, 'argv', args + ['--trace-graphics-blit', '--blit-gate-census']), \
                mock.patch.object(run_source, 'run', return_value=0) as run:
            self.assertEqual(run_source.main(), 0)
            self.assertTrue(run.call_args.kwargs['blit_gate_census'])

    def test_alignment_is_explicit_and_excludes_y_probe(self):
        args = ['run_source.py', 'resume', '--runtime', 'parity', '--system-dyld-search',
                '--trace-graphics-blit', '--blit-gate-census', '--blit-vertices', '--blit-projection-ab']
        with mock.patch.object(sys, 'argv', args + ['--blit-projection-align']), \
                mock.patch.object(run_source, 'run', return_value=0) as run:
            self.assertEqual(run_source.main(), 0)
            self.assertTrue(run.call_args.kwargs['blit_projection_align'])
            self.assertFalse(run.call_args.kwargs.get('blit_y_probe', False))
        with self.assertRaisesRegex(ValueError, 'Choose one Y variant'):
            run_source.validate_graphics_blit_selection(True, 'parity', True, False, gate_census=True,
                                                         vertices=True, projection=True, y_probe=True, aligned=True)

    def test_sharpness_measurement_requires_aligned_projection(self):
        with self.assertRaisesRegex(ValueError, 'requires --blit-projection-align'):
            run_source.validate_graphics_blit_selection(True, 'parity', True, False, gate_census=True,
                                                         vertices=True, projection=True, sharpness=True)
        run_source.validate_graphics_blit_selection(True, 'parity', True, False, gate_census=True,
                                                    vertices=True, projection=True, aligned=True, sharpness=True)

    def test_native_extents_requires_an_admitted_sharpness_build_and_restores(self):
        with self.assertRaisesRegex(ValueError, 'requires? sharpness measurement'):
            launch.verify_candidate(self.manifest, native_extents=True)
        native = self.root / 'native.dll'
        native.write_bytes(b'native menu extents')
        native_pin = pin(native.read_bytes())
        report = self.root / 'native.json'
        evidence = {
            'source_revision': launch.REVISION, 'compiled': True, 'stage_or_prefix_modified': False,
            'exports_match_blit': 80, 'import_symbols_match_blit': True,
            'artifact': launch.artifact(native, native_pin),
            'baseline_report': launch.artifact(launch.REPORT, launch.REPORT_PIN),
            'baseline_artifact': launch.artifact(launch.SOURCE, launch.CANDIDATE_PIN),
            'vertex_measurement_enabled': True, 'projection_ab_candidate': True,
            'projection_y_alignment': 'target_height_minus_reference_height',
            'sharpness_texture_measurement': True, 'native_extents_projection': True,
        }
        report.write_text(json.dumps(evidence))
        with mock.patch.multiple(launch, NATIVE_EXTENTS_SOURCE=native, NATIVE_EXTENTS_CANDIDATE_PIN=native_pin,
                                 NATIVE_EXTENTS_REPORT=report, NATIVE_EXTENTS_REPORT_PIN=pin(report.read_bytes())):
            launch.activate(self.manifest, self.runtime, self.env, gate_census=True, vertices=True,
                            projection=True, aligned=True, sharpness=True, native_extents=True)
            self.assertEqual(self.target.read_bytes(), native.read_bytes())
            launch.restore_locked()
        self.assertEqual(self.target.read_bytes(), b'baseline')
        self.assertFalse(self.checkpoint.exists())

    def exercise_controller(self, wait_timeout=False, replace_prefix=False, natural_exit=False):
        for name in ('logs', 'research'):
            (self.root / name).mkdir()
        self.runtime.WINE = self.runtime.ENGINE / 'bin/wine'
        events = []
        idle_checked = False

        def command(args, **options):
            nonlocal idle_checked
            if args[-1] == '-w':
                if idle_checked:
                    if natural_exit:
                        events.append('idle-probe')
                        if events.count('idle-probe') == 1:
                            raise subprocess.TimeoutExpired(args, options['timeout'])
                        return SimpleNamespace(returncode=0)
                    events.append('cleanup-wait')
                    if wait_timeout:
                        raise subprocess.TimeoutExpired(args, options['timeout'])
                idle_checked = True
            if args[-1] == '-k':
                events.append('cleanup-kill')
                return SimpleNamespace(returncode=0)
            return self.command(args, **options)

        def check_inputs(**options):
            self.assertEqual(self.target.read_bytes(), b'baseline')
            return {'developer_code_version': 12, 'files': []}

        def observe(*args, **options):
            self.assertEqual(self.target.read_bytes(), b'candidate')
            self.assertEqual(self.checkpoint.read_bytes(), b'baseline')
            events.append('observe')
            return SimpleNamespace(wait_ready=lambda: None, finish_after_wineserver_cleanup=lambda: {})

        def spawn(args, **options):
            self.assertEqual(self.target.read_bytes(), b'candidate')
            events.append('spawn')
            options['stdout'].write('[CFX_GRAPHICS_BLIT] pid=32 tid=36 quad_w=1512 quad_h=982 vp_count=1 '
                'vp_valid=1 vp_x16=0 vp_y16=0 vp_w16=24192 vp_h16=15712 rt_w=1512 rt_h=982\n')
            if replace_prefix:
                self.prefix.rename(self.root / 'previous-prefix')
                self.prefix.mkdir()
            return SimpleNamespace(pid=42, poll=lambda: 0, wait=lambda **kwargs: events.append('parent-settled'))

        paths = dict(ROOT=self.root, STAGE=self.target.parent, PREFIX=self.prefix, MANIFEST=self.manifest,
            **{key: self.root / (key + '.json') for key in ('INITIAL_MANIFEST', 'USER_LOGIN', 'PREFLIGHT')})
        env = {**self.env, 'WINEDEBUG': '-all', 'DYLD_LIBRARY_PATH': '/own', 'DYLD_FALLBACK_LIBRARY_PATH': '/own'}
        ticks = [100, 101, 101, 105, 105, 106] if natural_exit else [100, 102, 103]
        with ExitStack() as stack:
            for name, value in paths.items():
                stack.enter_context(mock.patch.object(run_source, name, value))
            for module, name, options in (
                    (run_source, 'check_inputs', {'side_effect': check_inputs}),
                    (run_source, 'game_mapping', {}),
                    (run_source, 'select_runtime_profile', {'return_value': (self.runtime, {})}),
                    (run_source, 'source_runtime_environment', {'return_value': env}),
                    (run_source, 'ProcessObserver', {'side_effect': observe}),
                    (run_source, 'code_only_snapshot', {'side_effect': lambda _: {'baseline': self.target.read_bytes() == b'baseline'}}),
                    (run_source, 'sha', {'return_value': 'a' * 64}),
                    (run_source.subprocess, 'run', {'side_effect': command}),
                    (run_source.subprocess, 'Popen', {'side_effect': spawn}),
                    (run_source.time, 'monotonic', {'side_effect': ticks}),
                    (run_source.time, 'sleep', {}),
                    (source_main_environment, 'source_main_prefix', {'return_value': nullcontext()}),
                    (source_main_environment, 'assert_source_main_prefix', {})):
                stack.enter_context(mock.patch.object(module, name, **options))
            stack.enter_context(mock.patch.object(graphics_blit_metadata, 'ROOT', self.root))
            stack.enter_context(redirect_stdout(io.StringIO()))
            status = run_source.run(1, resume=True, runtime_profile='parity', system_dyld_search=True,
                                    trace_graphics_blit=True, keep_open=natural_exit)
        report = json.loads(next((self.root / 'research').glob('*-results.json')).read_text())
        expected = ['observe', 'spawn']
        if natural_exit:
            expected += ['idle-probe', 'idle-probe', 'parent-settled']
            self.assertTrue(report['prefix_cleanup']['natural_wine_idle_observed'])
        elif not replace_prefix:
            expected += ['cleanup-kill', 'cleanup-wait', 'parent-settled']
        self.assertEqual(events, expected)
        self.assertEqual(report['graphics_blit_diagnostics']['measurement']['accepted'], 1)
        pending = wait_timeout or replace_prefix
        self.assertEqual(report['graphics_blit_diagnostics']['baseline_restored'], not pending)
        self.assertEqual(status, 1 if pending else 0)
        self.assertEqual(self.checkpoint.exists(), pending)
        self.assertEqual(self.target.read_bytes(), b'candidate' if pending else b'baseline')
        if replace_prefix:
            self.assertEqual(report['prefix_cleanup']['failure_type'], 'RuntimeError')

    def test_controller_restores_after_verified_shutdown(self):
        self.exercise_controller(wait_timeout=False)

    def test_controller_preserves_checkpoint_if_shutdown_timed_out(self):
        self.exercise_controller(wait_timeout=True)

    def test_controller_preserves_checkpoint_and_avoids_replaced_prefix(self):
        self.exercise_controller(replace_prefix=True)

    def test_keep_open_waits_for_children_then_restores_without_kill(self):
        self.exercise_controller(natural_exit=True)
