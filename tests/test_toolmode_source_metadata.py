"""Fixed ToolMode metadata only; no stage, Wine, private logs or prefix reads."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'native/windows-client'))
import run_source
from toolmode_diagnostic_identity import PHASES


class ToolModeSourceMetadataTests(unittest.TestCase):
    def test_v8_keeps_all_normal_source_diagnostic_channels(self):
        self.assertEqual(run_source.diagnostic_winedebug(8), '+loaddll,+seh,+debugstr')
        self.assertEqual(run_source.diagnostic_winedebug(8, True), '+loaddll,+seh,+debugstr,+process')

    def test_every_fixed_phase_both_wine_channels_and_bound_values(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'own.log'
            lines, expected = [], []
            for channel in ('debugstr:OutputDebugStringA', 'seh:dispatch_exception'):
                for index, phase in enumerate(PHASES):
                    value = index % 2
                    lines.append(f'00d0:warn:{channel} "[CFX_TOOLMODE] pid=204 phase={phase} value={value}\\n"\n')
                    expected.append({'pid': 204, 'phase': phase, 'value': value})
            path.write_text(''.join(lines))
            report = run_source.toolmode_diagnostic_report(path)
            self.assertEqual(report['events'], expected)
            self.assertEqual(report['marker_lines'], 54)
            self.assertEqual(report['accepted_events'], 54)
            self.assertEqual(report['rejected_marker_lines'], 0)
            self.assertEqual(report['channels'], {'debugstr': 27, 'seh': 27})
            self.assertTrue(report['scanned'])

    def test_private_or_invalid_payloads_only_increment_rejected_count(self):
        line = '00d0:warn:debugstr:OutputDebugStringA "[CFX_TOOLMODE] pid=204 phase=invoke.before value=0\\n"\n'
        invalid = [line.replace('pid=204', 'pid=0'), line.replace('pid=204', 'pid=4294967296'),
                   line.replace('phase=invoke.before', 'phase=PRIVATE'),
                   line.replace('phase=invoke.before', 'phase=unknown.phase'), line.replace('value=0', 'value=2'),
                   line.replace('value=0', 'value=0 command=PRIVATE'),
                   line.replace('debugstr:OutputDebugStringA', 'process:CreateProcess'),
                   line.replace('warn:', 'trace:'), 'PRIVATE [CFX_TOOLMODE] AUTH_PAYLOAD\n']
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'own.log'
            path.write_text(line + ''.join(invalid) + 'OWN UNRELATED PRIVATE SENTINEL\n')
            report = run_source.toolmode_diagnostic_report(path)
            self.assertEqual(report['events'], [{'pid': 204, 'phase': 'invoke.before', 'value': 0}])
            self.assertEqual(report['marker_lines'], 10)
            self.assertEqual(report['rejected_marker_lines'], 9)
            self.assertNotIn('PRIVATE', repr(report))

    def test_disabled_diagnostic_never_reads_log_and_absence_is_not_success(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'own.log'
            path.write_text('OWN PRIVATE SENTINEL')
            with mock.patch.object(Path, 'open', side_effect=AssertionError('must remain opaque')):
                disabled = run_source.toolmode_diagnostic_report(path, enabled=False)
            self.assertFalse(disabled['enabled'])
            self.assertFalse(disabled['scanned'])
            self.assertEqual(disabled['events'], [])
            missing = run_source.toolmode_diagnostic_report(Path(temp) / 'missing.log')
            self.assertTrue(missing['enabled'])
            self.assertFalse(missing['scanned'])
            self.assertEqual(missing['events'], [])


if __name__ == '__main__':
    unittest.main()
