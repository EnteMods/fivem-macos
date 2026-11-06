"""Exercise the optional ROS window observer's CLI and failure cleanup without Wine."""
from contextlib import contextmanager, redirect_stderr
import io
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'native/windows-client'))
import run_source
import source_desktop_metadata as bridge
import test_source_exit_relay as exit_cases


class SourceRosWindowIntegrationTests(unittest.TestCase):
    def test_invalid_combinations_are_rejected_before_client_inputs(self):
        for args in (['resume', '--observe-ros-windows'],
                     ['resume', '--runtime', 'parity', '--observe-ros-windows'],
                     ['resume', '--runtime', 'read', '--exit-relay', '--observe-ros-windows']):
            with self.subTest(args=args), mock.patch.object(sys, 'argv', ['run_source.py', *args]), \
                    mock.patch.object(run_source, 'check_inputs') as inputs, redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    run_source.main()
                inputs.assert_not_called()

    def test_option_is_explicit_and_existing_default_stays_off(self):
        for enabled in (False, True):
            args = ['run_source.py', 'resume', '--runtime', 'parity', '--exit-relay']
            if enabled:
                args.append('--observe-ros-windows')
                args.append('--keep-open')
            with mock.patch.object(sys, 'argv', args), mock.patch.object(run_source, 'run', return_value=0) as run:
                self.assertEqual(run_source.main(), 0)
            self.assertEqual(run.call_args.kwargs.get('observe_ros_windows', False), enabled)
            self.assertEqual(run.call_args.kwargs.get('keep_open', False), enabled)

    def test_inspection_validates_pid_binding_without_constructing_runtime_observer(self):
        args = ['run_source.py', 'inspect-resume', '--runtime', 'parity', '--exit-relay', '--observe-ros-windows']
        proof = {'live_components': {'engine': {'manifest_sha256': 'own-inert-proof'}}}
        with mock.patch.object(sys, 'argv', args), \
                mock.patch.object(run_source, 'check_inputs', return_value={'files': [], 'developer_code_version': 8}), \
                mock.patch('source_main_environment.assert_source_main_prefix'), \
                mock.patch.object(run_source, 'select_runtime_profile', return_value=(object(), proof)), \
                mock.patch.object(run_source, 'source_runtime_environment'), \
                mock.patch('source_exit_relay.load_helpers'), \
                mock.patch.object(bridge, 'load_binding') as binding, \
                mock.patch.object(bridge, 'SourceDesktopMetadata') as observer, \
                mock.patch('builtins.print'):
            self.assertEqual(run_source.main(), 0)
        binding.assert_called_once_with()
        observer.assert_not_called()

    def test_main_spawn_failure_still_finishes_prepared_pid_observer(self):
        events = []
        @contextmanager
        def finishing():
            try:
                yield
            finally:
                events.append('pid-finish')
        observer = SimpleNamespace(start=lambda: events.append('pid-start'),
            wait_ready=lambda: events.append('pid-ready'), finishing_after_cleanup=finishing,
            result=lambda: {'enabled': True, 'window_metadata': []}, reader_error=None,
            lifecycle_error=None, start_error=None)
        original_run = run_source.run
        def pid_run(*args, **kwargs):
            return original_run(*args, **dict(kwargs, observe_ros_windows=True))
        fixture = exit_cases.SourceExitControllerTests('test_sink_remains_open_through_server_cleanup_and_pump_finish')
        with mock.patch.object(run_source, 'run', side_effect=pid_run), \
                mock.patch.object(bridge, 'SourceDesktopMetadata', return_value=observer):
            lifecycle = fixture.exercise(thread_start_failure=True)
        self.assertIn('main', lifecycle)
        self.assertEqual(events, ['pid-start', 'pid-ready', 'pid-finish'])


if __name__ == '__main__':
    unittest.main()
