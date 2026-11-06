"""Synthetic lifecycle diagnostics and version dispatch; no Wine or source-prefix access."""
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'native/windows-client'))
import run_source
import source_code_identity as identity


class LifecycleSourceMetadataTests(unittest.TestCase):
    @staticmethod
    def line(phase=1, valid=0, status=-1, channel='debugstr:OutputDebugStringA',
             pid=204, tid=208, prefix='00d0:'):
        return (f'{prefix}warn:{channel} "[CFX_CORE_MH] pid={pid} tid={tid} phase={phase} '
                f'status_valid={valid} status={status}\\n"\n')

    def parse(self, lines):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'own.log'
            path.write_text(''.join(lines))
            return run_source.lifecycle_diagnostic_report(path)

    def test_all_phases_channels_and_status_endpoints_preserve_numeric_values(self):
        lines, expected = [], []
        for channel in ('debugstr:OutputDebugStringA', 'seh:dispatch_exception'):
            for phase in range(1, 5):
                statuses = (-1,) if phase in (1, 3) else range(-1, 13)
                for status in statuses:
                    valid = int(phase in (2, 4))
                    lines.append(self.line(phase, valid, status, channel, 0xffffffff, 1, '00cc:00d0:'))
                    expected.append({'pid': 0xffffffff, 'tid': 1, 'phase': phase,
                                     'status_valid': valid, 'status': status})
        report = self.parse(lines)
        self.assertEqual(report['events'], expected)
        self.assertEqual(report['channels'], {'debugstr': 30, 'seh': 30})
        self.assertEqual(report['accepted_events'], 60)
        self.assertEqual(report['rejected_marker_lines'], 0)
        self.assertTrue(report['scanned'])

    def test_rejects_extra_payload_invalid_bounds_and_inconsistent_phase_status(self):
        good = self.line()
        invalid = [self.line(pid=0), self.line(tid=0), self.line(pid=4294967296),
                   self.line(tid=4294967296), self.line(pid=12345678901234567890),
                   self.line(phase=0), self.line(phase=5), self.line(phase='1.0'),
                   self.line(valid=1), self.line(status=0), self.line(phase=2, valid=0),
                   self.line(phase=4, valid=1, status=13), self.line(phase=2, valid=1, status=-2),
                   self.line(phase=2, valid=1, status='0.0'), self.line(valid=2),
                   self.line(channel='process:CreateProcess'), good.replace('warn:', 'trace:'),
                   good.replace('status=-1', 'status=-1 address=PRIVATE'),
                   good.replace('tid=208 phase=1', 'phase=1 tid=208'),
                   good.replace('pid=204', 'pid=204 pid=PRIVATE'),
                   'PRIVATE [CFX_CORE_MH] AUTH_SENTINEL\n']
        report = self.parse([good, *invalid, 'OWN UNRELATED PRIVATE SENTINEL\n'])
        self.assertEqual(report['events'], [{'pid': 204, 'tid': 208, 'phase': 1,
                                             'status_valid': 0, 'status': -1}])
        self.assertEqual(report['marker_lines'], len(invalid) + 1)
        self.assertEqual(report['rejected_marker_lines'], len(invalid))
        self.assertNotIn('PRIVATE', repr(report))
        self.assertNotIn('AUTH_SENTINEL', repr(report))

    def test_disabled_and_absent_do_not_claim_capture(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'own.log'
            path.write_text('OWN PRIVATE SENTINEL')
            with mock.patch.object(Path, 'open', side_effect=AssertionError('disabled must not read')):
                disabled = run_source.lifecycle_diagnostic_report(path, False)
            self.assertFalse(disabled['enabled'])
            self.assertFalse(disabled['scanned'])
            self.assertEqual(disabled['events'], [])
            missing = run_source.lifecycle_diagnostic_report(Path(temp) / 'absent.log')
            self.assertTrue(missing['enabled'])
            self.assertFalse(missing['scanned'])
            self.assertEqual(missing['events'], [])

    def test_v9_retains_existing_channels_and_v8_behavior(self):
        for version in (8, 9):
            self.assertEqual(run_source.diagnostic_winedebug(version), '+loaddll,+seh,+debugstr')
            self.assertEqual(run_source.diagnostic_winedebug(version, True), '+loaddll,+seh,+debugstr,+process')

    def test_v9_dispatches_exact_admission_before_any_further_evidence_access(self):
        record = {'source_revision': identity.REVISION, 'stage': str(identity.STAGE.relative_to(identity.ROOT)),
                  'developer_code_version': 9, 'manual_login_user_confirmed': True,
                  'prefix_is_account_free': False}
        validator = mock.Mock(side_effect=RuntimeError('own admission stop'))
        policy = SimpleNamespace(validate_version=validator)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'own.json'
            path.write_text(json.dumps(record))
            with mock.patch.object(identity, 'plain'), mock.patch.object(identity, 'sha') as hashed, \
                    mock.patch.dict(sys.modules, {'lifecycle_diagnostic_identity': policy}), \
                    self.assertRaisesRegex(RuntimeError, 'own admission stop'):
                identity.validate_code_inputs(path)
        validator.assert_called_once_with(record)
        hashed.assert_not_called()

    def test_unknown_version_still_fails_before_v9_validator(self):
        record = {'source_revision': identity.REVISION, 'stage': str(identity.STAGE.relative_to(identity.ROOT)),
                  'developer_code_version': -1, 'manual_login_user_confirmed': True,
                  'prefix_is_account_free': False}
        validator = mock.Mock()
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'own.json'
            path.write_text(json.dumps(record))
            with mock.patch.object(identity, 'plain'), \
                    mock.patch.dict(sys.modules, {'lifecycle_diagnostic_identity': SimpleNamespace(validate_version=validator)}), \
                    self.assertRaisesRegex(RuntimeError, 'Unexpected source code/session role'):
                identity.validate_code_inputs(path)
        validator.assert_not_called()


if __name__ == '__main__':
    unittest.main()
