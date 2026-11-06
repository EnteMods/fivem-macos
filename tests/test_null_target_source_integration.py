"""Version-ten dispatch and diagnostic continuity without Wine or a source prefix."""
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


class NullTargetSourceIntegrationTests(unittest.TestCase):
    def test_v10_admission_runs_before_further_evidence_reads(self):
        record = {'source_revision': identity.REVISION, 'stage': str(identity.STAGE.relative_to(identity.ROOT)),
            'developer_code_version': 10, 'manual_login_user_confirmed': True, 'prefix_is_account_free': False}
        validator = mock.Mock(side_effect=RuntimeError('own admission stop'))
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'own.json'
            path.write_text(json.dumps(record))
            with mock.patch.object(identity, 'plain'), mock.patch.object(identity, 'sha') as hashed, \
                    mock.patch.dict(sys.modules, {'null_target_fix_identity': SimpleNamespace(validate_version=validator)}), \
                    self.assertRaisesRegex(RuntimeError, 'own admission stop'):
                identity.validate_code_inputs(path)
        validator.assert_called_once_with(record)
        hashed.assert_not_called()

    def test_v10_keeps_diagnostic_channels(self):
        self.assertEqual(run_source.diagnostic_winedebug(10), run_source.diagnostic_winedebug(9))
        self.assertEqual(run_source.diagnostic_winedebug(10, True), '+loaddll,+seh,+debugstr,+process')

    def test_unknown_v13_remains_rejected_before_v10_policy(self):
        record = {'source_revision': identity.REVISION, 'stage': str(identity.STAGE.relative_to(identity.ROOT)),
            'developer_code_version': 13, 'manual_login_user_confirmed': True, 'prefix_is_account_free': False}
        validator = mock.Mock()
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'own.json'
            path.write_text(json.dumps(record))
            with mock.patch.object(identity, 'plain'), \
                    mock.patch.dict(sys.modules, {'null_target_fix_identity': SimpleNamespace(validate_version=validator)}), \
                    self.assertRaisesRegex(RuntimeError, 'Unexpected source code/session role'):
                identity.validate_code_inputs(path)
        validator.assert_not_called()


if __name__ == '__main__':
    unittest.main()
