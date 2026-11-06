import getpass
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / 'scripts'))
from source_main_environment import (source_main_prefix, assert_source_main_prefix,
                                     record_manual_user_login, ProbePrefixError)


class ManualUserLoginTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve() / 'project'
        self.prefix = self.root / 'prefixes/fivem-source-main'
        with source_main_prefix(self.prefix, root=self.root, create=True):
            pass

    def tearDown(self):
        self.temporary.cleanup()

    def evidence(self, **changes):
        info = self.prefix.stat()
        value = {'schema': 1, 'kind': 'user-confirmed-manual-login',
                 'prefix': 'prefixes/fivem-source-main', 'prefix_device': info.st_dev,
                 'prefix_inode': info.st_ino, 'user': getpass.getuser(),
                 'confirmed_by_user': True, 'scope': 'launcher-ui-only', 'account_data_copied': False}
        value.update(changes)
        path = self.root / 'research/manual-user-login.json'
        path.parent.mkdir(exist_ok=True)
        path.write_text(json.dumps(value))
        return {'path': 'research/manual-user-login.json', 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}

    def ticket(self, relative):
        path = self.prefix / 'drive_c/users' / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'Synthetic fixture only; never an actual credential.')
        return path

    def test_ticket_without_user_login_remains_rejected(self):
        self.ticket(getpass.getuser() + '/AppData/Roaming/CitizenFX/cfxTicket2')
        with self.assertRaises(ProbePrefixError):
            assert_source_main_prefix(self.prefix, root=self.root)

    def test_authorized_own_data_is_preserved_but_other_user_and_hardlink_are_rejected(self):
        reference = self.evidence()
        with source_main_prefix(self.prefix, root=self.root):
            record_manual_user_login(self.prefix, reference, root=self.root)
            path = self.ticket(getpass.getuser() + '/AppData/Roaming/CitizenFX/cfxTicket2')
            before = path.read_bytes()
            assert_source_main_prefix(self.prefix, root=self.root)
            self.assertEqual(path.read_bytes(), before)
            linked = self.root / 'linked-fixture'
            os.link(path, linked)
            with self.assertRaises(ProbePrefixError):
                assert_source_main_prefix(self.prefix, root=self.root)
            linked.unlink()
            self.ticket('another-user/Documents/cfxTicket2')
            with self.assertRaises(ProbePrefixError):
                assert_source_main_prefix(self.prefix, root=self.root)

    def test_evidence_scope_identity_and_lock_are_required(self):
        for changes in ({'scope': 'server-connect'}, {'confirmed_by_user': False}, {'prefix_inode': -1}):
            reference = self.evidence(**changes)
            marker = self.prefix / '.source-main-probe'
            before = marker.read_bytes()
            with source_main_prefix(self.prefix, root=self.root):
                with self.assertRaises(ProbePrefixError):
                    record_manual_user_login(self.prefix, reference, root=self.root)
            self.assertEqual(marker.read_bytes(), before)
        with self.assertRaises(ProbePrefixError):
            record_manual_user_login(self.prefix, self.evidence(), root=self.root)

    def test_changed_evidence_does_not_authorize_future_files(self):
        reference = self.evidence()
        with source_main_prefix(self.prefix, root=self.root):
            record_manual_user_login(self.prefix, reference, root=self.root)
        (self.root / reference['path']).write_text('{}')
        with self.assertRaises(ProbePrefixError):
            assert_source_main_prefix(self.prefix, root=self.root)


if __name__ == '__main__':
    unittest.main()
