import contextlib
import importlib.util
import io
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import json

spec = importlib.util.spec_from_file_location('handoff_contract', Path(__file__).with_name('handoff_current.py'))
handoff = importlib.util.module_from_spec(spec)
spec.loader.exec_module(handoff)


class UriContractTests(unittest.TestCase):
    def test_candidate_is_loaded_through_current_pinned_runner(self):
        candidate = object()
        current = SimpleNamespace(load_helper=Mock(return_value=candidate))
        with patch.object(handoff, 'load_current', return_value=current):
            self.assertIs(handoff.load_candidate(), candidate)
        current.load_helper.assert_called_once_with()

    def test_preserves_normal_opaque_return(self):
        for value in (b'fivem://accept-auth?payload=fixture%2Bdata%3D',
                      b'fivem://accept-auth?payload=fixture'):
            self.assertTrue(handoff.valid_uri(value))

    def test_rejects_wrong_route_and_ambiguous_input(self):
        for value in (b'', b'https://accept-auth?payload=x', b'fivem://connect/x?payload=x',
                      b'fivem://user@accept-auth?payload=x', b'fivem://accept-auth:80?payload=x',
                      b'fivem://accept-auth/path?payload=x', b'fivem://accept-auth?payload=x#fragment',
                      b'fivem://accept-auth/?payload=x', b'fivem://accept-auth?payload=%ZZ',
                      b'fivem://accept-auth?payload=', b'fivem://accept-auth?other=x',
                      b'fivem://accept-auth?payload=x&payload=y',
                      b'fivem://accept-auth?payload=x&other=y', b'fivem://accept-auth?payload=x\n',
                      b'fivem://accept-auth?payload=' + b'x' * 4096,
                      b'fivem://accept-auth?payload=\x00', b'\xff', b'x' * (handoff.MAX_BYTES + 1)):
            with self.subTest(value_length=len(value)):
                self.assertFalse(handoff.valid_uri(value))

    def test_invalid_uri_never_loads_or_launches_candidate(self):
        with patch.object(handoff, 'load_candidate') as load:
            self.assertEqual(handoff.dispatch(b'fivem://connect/fixture'), 2)
            load.assert_not_called()

    def test_inactive_client_does_not_launch(self):
        with patch.object(handoff, 'load_candidate'), patch.object(handoff, 'active_candidate', return_value=False), \
                patch.object(handoff.subprocess, 'Popen') as launch:
            self.assertEqual(handoff.dispatch(b'fivem://accept-auth?payload=fixture'), 3)
            launch.assert_not_called()

    def test_exception_does_not_expose_argument_or_payload(self):
        output = io.StringIO()
        with patch.object(handoff.sys, 'argv', ['handoff.py', '--check']), \
                patch.object(handoff, 'load_candidate', side_effect=ValueError('fixture-sensitive-value')), \
                contextlib.redirect_stdout(output):
            self.assertEqual(handoff.main(), 4)
        self.assertEqual(output.getvalue(), 'CFX_PROTOCOL_HANDOFF code=4\n')

    def test_only_client_processes_admit_normal_handoff(self):
        for name in (r'C:\source-update-game-client\FiveM.exe',
                     r'C:\source-update-game-client\data\cache\subprocess\FiveM_b3889_GameProcess.exe'):
            self.assertIsNotNone(handoff.GAME_PROCESS.fullmatch(name))
        for name in (r'C:\source-update-game-client\data\cache\subprocess\FiveM_DumpServer',
                     r'C:\unrelated\FiveM.exe', 'python3'):
            self.assertIsNone(handoff.GAME_PROCESS.fullmatch(name))


class DispatchOutcomeTests(unittest.TestCase):
    def dispatch_with_process(self, wait_result=None, wait_error=None):
        process = Mock()
        process.wait.return_value = wait_result
        process.wait.side_effect = wait_error
        engine = Path('/fixture/engine')
        graphics = SimpleNamespace(runtime=SimpleNamespace(ENGINE=engine))
        game = SimpleNamespace(first=SimpleNamespace(configure=Mock(return_value=(graphics, None, None, {}))),
                               WINDOWS_ENTRYPOINT='fixture.exe', STAGE=Path('/fixture/stage'))
        candidate = SimpleNamespace(game=game)
        with patch.object(handoff, 'load_candidate', return_value=candidate), \
                patch.object(handoff, 'active_candidate', return_value=True), \
                patch.object(handoff.subprocess, 'Popen', return_value=process) as launch:
            result = handoff.dispatch(b'fivem://accept-auth?payload=synthetic')
        self.assertEqual(launch.call_args.kwargs['stdout'], handoff.subprocess.DEVNULL)
        self.assertEqual(launch.call_args.kwargs['stderr'], handoff.subprocess.DEVNULL)
        return result, process

    def test_only_normal_zero_exit_is_confirmed(self):
        self.assertEqual(self.dispatch_with_process(wait_result=0)[0], 0)
        self.assertEqual(self.dispatch_with_process(wait_result=1)[0], 5)

    def test_timeout_is_pending_and_does_not_stop_client(self):
        result, process = self.dispatch_with_process(
            wait_error=handoff.subprocess.TimeoutExpired('fixture', 30))
        self.assertEqual(result, 6)
        process.wait.assert_called_once_with(timeout=30)
        process.terminate.assert_not_called()
        process.kill.assert_not_called()

    def test_pending_status_prints_only_code(self):
        output = io.StringIO()
        fake_input = SimpleNamespace(buffer=io.BytesIO(b'fivem://accept-auth?payload=synthetic'))
        with patch.object(handoff.sys, 'argv', ['handoff.py']), \
                patch.object(handoff.sys, 'stdin', fake_input), \
                patch.object(handoff, 'dispatch', return_value=6), contextlib.redirect_stdout(output):
            self.assertEqual(handoff.main(), 6)
        self.assertEqual(output.getvalue(), 'CFX_PROTOCOL_HANDOFF code=6\n')


class ActiveBindingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.prefix = self.root / 'prefixes/client'
        self.prefix.mkdir(parents=True)
        self.stage = self.prefix / 'drive_c/source-update-game-client'
        self.stage.mkdir(parents=True)
        self.lock = self.prefix.parent / '.client.probe.lock'
        self.lock.write_bytes(b'')
        self.helper = self.root / 'build/candidate/resume-candidate.py'
        sessions = self.helper.parent / 'sessions/20261106T123456123456Z'
        sessions.mkdir(parents=True)
        self.status = sessions / 'status.json'
        self.record = {'phase': 'parent-exited-awaiting-scoped-observation',
                       'stage': str(self.stage.relative_to(self.root)),
                       'prefix': str(self.prefix.relative_to(self.root)),
                       'controller_pid': 12345}
        self.write_status()
        self.game = SimpleNamespace(PREFIX=self.prefix, STAGE=self.stage,
                                    verify_finished_prelogin=Mock(side_effect=AssertionError('old marker used')))
        self.candidate = SimpleNamespace(game=self.game)
        self.current = SimpleNamespace(HELPER=self.helper, check_binding=Mock(return_value={}))

    def write_status(self):
        self.status.write_text(json.dumps(self.record))

    def active(self, *, pid_alive=True, process=True):
        def kill(_pid, _signal):
            if not pid_alive:
                raise ProcessLookupError()
        lines = r'C:\source-update-game-client\FiveM.exe' if process else 'python3'
        with patch.object(handoff, 'ROOT', self.root), \
                patch.object(handoff, 'load_current', return_value=self.current), \
                patch.object(handoff.fcntl, 'flock', side_effect=BlockingIOError()), \
                patch.object(handoff.os, 'kill', side_effect=kill), \
                patch.object(handoff.subprocess, 'run', return_value=SimpleNamespace(stdout=lines + '\n')):
            return handoff.active_candidate(self.candidate)

    def test_current_binding_and_live_prefix_admit_handoff_without_old_identity(self):
        self.assertTrue(self.active())
        self.current.check_binding.assert_called_once_with(self.candidate)
        self.game.verify_finished_prelogin.assert_not_called()

    def test_stale_controller_or_missing_client_process_is_inactive(self):
        self.assertFalse(self.active(pid_alive=False))
        self.assertFalse(self.active(process=False))

    def test_invalid_controller_pid_cannot_select_process_group(self):
        self.record['controller_pid'] = 0
        self.write_status()
        self.assertFalse(self.active())
        self.record['controller_pid'] = True
        self.write_status()
        self.assertFalse(self.active())

    def test_failed_current_binding_stays_private_and_never_launches(self):
        self.current.check_binding.side_effect = RuntimeError('fixture-sensitive-account-data')
        output = io.StringIO()
        with patch.object(handoff.sys, 'argv', ['handoff.py', '--check']), \
                patch.object(handoff, 'ROOT', self.root), \
                patch.object(handoff, 'load_current', return_value=self.current), \
                patch.object(handoff, 'load_candidate', return_value=self.candidate), \
                patch.object(handoff.subprocess, 'Popen') as launch, \
                contextlib.redirect_stdout(output):
            self.assertEqual(handoff.main(), 4)
        self.assertEqual(output.getvalue(), 'CFX_PROTOCOL_HANDOFF code=4\n')
        launch.assert_not_called()


if __name__ == '__main__':
    unittest.main()
