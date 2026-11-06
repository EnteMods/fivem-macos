from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'native/windows-client'))
import nui_resize_launch as launch
from source_main_environment import _ACTIVE_MAIN_LOCKS


def pin(path):
    data = path.read_bytes()
    return len(data), hashlib.sha256(data).hexdigest()


class NuiResizeLaunchTests(unittest.TestCase):
    def setUp(self):
        scope = ExitStack()
        self.addCleanup(scope.close)
        root = Path(scope.enter_context(tempfile.TemporaryDirectory())).resolve()
        stage = root / 'stage'
        stage.mkdir()
        self.target = stage / 'nui-core.dll'
        self.target.write_bytes(b'original V12')
        self.checkpoint = stage / '.previous'
        self.prefix = root / 'prefix'
        self.prefix.mkdir()
        self.runtime = SimpleNamespace(ENGINE=root / 'engine')
        self.environment = {'WINEPREFIX': str(self.prefix),
                            'WINESERVER': str(self.runtime.ENGINE / 'bin/wineserver')}
        manifest = root / 'manifest.json'
        manifest.write_text('{}')
        self.candidate = root / 'candidate.dll'
        self.candidate.write_bytes(b'resize candidate')
        build_inputs = root / 'inputs.json'
        build_inputs.write_text(json.dumps({'source_revision': launch.SOURCE_REVISION, 'resize_overlay': True}))
        self.report = root / 'result.json'
        self.report.write_text(json.dumps({
            'candidate': {'path': str(self.candidate), 'bytes': pin(self.candidate)[0],
                          'sha256': pin(self.candidate)[1]},
            'passed': True, 'boot': 0, 'exit': 0, 'cleanup': [0, 0], 'probe_timed_out': False,
            'markers': ['NUI_CEF_API_MATCH version=103 hash=fixture', 'NUI_LOAD_PROBE_OK fixture'],
        }))
        scope.enter_context(mock.patch.multiple(
            launch, ROOT=root, STAGE=stage, TARGET=self.target, CHECKPOINT=self.checkpoint,
            BASELINE_PIN=pin(self.target), CANDIDATE=self.candidate, CANDIDATE_PIN=pin(self.candidate),
            BUILD_INPUTS=build_inputs, BUILD_INPUTS_PIN=pin(build_inputs),
            LOAD_REPORT=self.report, LOAD_REPORT_PIN=pin(self.report),
        ))
        scope.enter_context(mock.patch.multiple(
            launch.graphics, ROOT=root, PREFIX=self.prefix, MANIFEST=manifest, MANIFEST_PIN=pin(manifest),
        ))
        scope.enter_context(mock.patch('run_main.ROOT', root))
        scope.enter_context(mock.patch.dict(_ACTIVE_MAIN_LOCKS, {str(self.prefix): (os.getpid(), 1)}))
        scope.enter_context(mock.patch.object(launch.graphics.subprocess, 'run', side_effect=self.command))

    def command(self, args, **options):
        if args[-1] != '-w':
            self.assertEqual(args[:3], ['/bin/cp', '-c', '-n'])
            self.assertFalse(Path(args[4]).exists())
            shutil.copyfile(args[3], args[4])
        return SimpleNamespace(returncode=0)

    def activate(self):
        return launch.activate(self.report, self.runtime, self.environment)

    def test_running_candidate_keeps_stock_backup_until_restore(self):
        evidence = self.activate()
        launch.require_active(evidence)
        self.assertEqual(self.target.read_bytes(), b'resize candidate')
        self.assertEqual((self.checkpoint / self.target.name).read_bytes(), b'original V12')
        with self.assertRaisesRegex(RuntimeError, 'explicit recovery'):
            self.activate()
        launch.restore_locked(evidence)
        self.assertEqual(self.target.read_bytes(), b'original V12')
        self.assertFalse(self.checkpoint.exists())

    def test_timing_candidate_uses_its_own_pin_for_restore(self):
        timing = self.candidate.with_name('timing.dll')
        timing.write_bytes(b'timing candidate')
        inputs = timing.with_suffix('.json')
        inputs.write_text(json.dumps({'source_revision': launch.SOURCE_REVISION, 'resize_overlay': True,
                                      'menu_timing_overlay': True}))
        report = timing.with_name('timing-result.json')
        result = json.loads(self.report.read_text())
        size, digest = pin(timing)
        result['candidate'] = {'path': str(timing), 'bytes': size, 'sha256': digest}
        report.write_text(json.dumps(result))
        with mock.patch.multiple(launch, TIMING_CANDIDATE=timing, TIMING_CANDIDATE_PIN=pin(timing),
                                 TIMING_BUILD_INPUTS=inputs, TIMING_BUILD_INPUTS_PIN=pin(inputs),
                                 TIMING_LOAD_REPORT=report, TIMING_LOAD_REPORT_PIN=pin(report)):
            evidence = launch.activate(report, self.runtime, self.environment)
            self.assertTrue(evidence['timing_diagnostics'])
            launch.require_active(evidence)
            self.assertEqual(self.target.read_bytes(), b'timing candidate')
            launch.restore_locked(evidence)
        self.assertEqual(self.target.read_bytes(), b'original V12')
        self.assertFalse(self.checkpoint.exists())

    def test_interrupt_before_dll_rename_retires_the_checkpoint(self):
        replace = os.replace

        def interrupt_swap(source, destination):
            if destination == self.target:
                raise KeyboardInterrupt
            replace(source, destination)

        with mock.patch.object(launch.os, 'replace', side_effect=interrupt_swap):
            with self.assertRaises(KeyboardInterrupt):
                self.activate()
        self.assertEqual(self.target.read_bytes(), b'original V12')
        self.assertFalse(self.checkpoint.exists())

    def test_unknown_dll_or_replaced_prefix_preserves_backup(self):
        evidence = self.activate()
        with mock.patch.object(launch.graphics, 'prefix_identity', return_value=[123, 456]):
            with self.assertRaisesRegex(RuntimeError, 'prefix changed'):
                launch.restore_locked(evidence)
        self.target.write_bytes(b'unknown')
        with self.assertRaisesRegex(RuntimeError, 'Unexpected NUI DLL'):
            launch.restore_locked(evidence)
        self.assertEqual(self.target.read_bytes(), b'unknown')
        self.assertEqual((self.checkpoint / self.target.name).read_bytes(), b'original V12')
