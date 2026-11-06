"""Source-controller observer duration/CLI fixtures; no Wine or prefix access."""
from contextlib import redirect_stderr
import importlib.util
import io
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'native/windows-client'))
spec = importlib.util.spec_from_file_location('source_observer_configuration_test', ROOT / 'native/windows-client/run_source.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class SourceObserverConfigurationTests(unittest.TestCase):
    def test_default_duration_and_bounded_rockstar_window_are_separate(self):
        ordinary = runner.observer_configuration(3600)
        self.assertEqual(ordinary['observer_requested_duration_seconds'], 3600)
        self.assertEqual(ordinary['poll_ms'], 100)
        selected = runner.observer_configuration(3600, True)
        self.assertEqual(selected['controller_duration_seconds'], 3600)
        self.assertEqual(selected['observer_requested_duration_seconds'], 600)
        self.assertEqual(selected['poll_ms'], 10)
        self.assertTrue(selected['observer_completion_does_not_end_client_or_controller'])
        self.assertEqual(runner.observer_configuration(30, True)['observer_requested_duration_seconds'], 30)
        self.assertEqual(runner.observer_configuration(300, True)['observer_requested_duration_seconds'], 300)

    def test_invalid_values_are_rejected_before_source_input_or_runtime_access(self):
        with mock.patch.object(runner, 'check_inputs') as inputs:
            for duration, scope in ((0, False), (3601, True), (3600, '-other'), (True, False)):
                with self.assertRaises(ValueError):
                    runner.run(duration, observe_rockstar_processes=scope)
            inputs.assert_not_called()

    def test_cli_opt_in_and_limit_do_not_start_a_runtime_in_this_fixture(self):
        with mock.patch.object(runner, 'run', return_value=0) as run:
            with mock.patch.object(sys, 'argv', ['run_source.py', 'resume', '--observe-rockstar-processes']):
                self.assertEqual(runner.main(), 0)
            run.assert_called_once_with(3600, resume=True, process_trace=False, observe_rockstar_processes=True)
            run.reset_mock()
            with mock.patch.object(sys, 'argv', ['run_source.py', 'resume', '--observe-seconds', '3601']), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    runner.main()
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
