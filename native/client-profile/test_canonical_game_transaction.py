import json
from contextlib import nullcontext
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import canonical_game_transaction as transaction
import doctor


class TransactionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.prefix = self.root / 'prefix'
        (self.prefix / 'dosdevices').mkdir(parents=True)
        (self.prefix / 'dosdevices/g:').symlink_to('old-game')
        self.targets = {key: self.root / key for key in ('profile', 'binding', 'launcher')}
        self.old = {'profile': transaction.document({'schema': 1, 'game': doctor.GAME,
                    'prefix_identity': {'device': self.prefix.stat().st_dev, 'inode': self.prefix.stat().st_ino}}),
                    'binding': transaction.document({'schema': 1})}
        self.old['launcher'] = ("PROFILE_SHA = '" + transaction.digest(self.old['profile']) + "'\n"
                                "BINDING_SHA = '" + transaction.digest(self.old['binding']) + "'\n").encode()
        self.new = transaction.proposed(self.old['profile'], self.old['binding'], self.old['launcher'], 'a'*64)
        for key, path in self.targets.items(): path.write_bytes(self.old[key])
        self.plan = {'comparison_sha256': 'a'*64, 'prefix_identity': json.loads(self.old['profile'])['prefix_identity'], 'old_g': 'old-game',
                     'new_g': 'new-game', 'files': {key: {'old': transaction.encoded(self.old[key]),
                     'new': transaction.encoded(self.new[key]), 'old_sha256': transaction.digest(self.old[key]),
                     'new_sha256': transaction.digest(self.new[key])} for key in self.targets}}
        self.patches = [patch.object(transaction, 'ROOT', self.root), patch.object(transaction, 'TARGETS', self.targets),
                        patch.object(transaction.run_current, 'load_helper'), patch.object(transaction.run_current, 'check_binding')]
        for item in self.patches: item.start()
    def tearDown(self):
        for item in reversed(self.patches): item.stop()
        self.tmp.cleanup()
    def test_proposal_preserves_other_fields_and_pins_real_new_bytes(self):
        profile = json.loads(self.new['profile']); binding = json.loads(self.new['binding'])
        self.assertEqual(profile['game'], doctor.GAME_REFERENCE)
        self.assertEqual(profile['prefix_identity'], self.plan['prefix_identity'])
        self.assertEqual(binding['active_profile_sha256'], transaction.digest(self.new['profile']))
        self.assertIn(transaction.digest(self.new['binding']).encode(), self.new['launcher'])
    def test_changed_old_pin_refused(self):
        with self.assertRaisesRegex(RuntimeError, 'pin missing'):
            transaction.proposed(self.old['profile'], self.old['binding'], b"PROFILE_SHA = 'wrong'", 'a'*64)
    def test_replay_derivation_does_not_depend_on_loaded_current_pins(self):
        with patch.object(transaction.run_current, 'PROFILE_SHA', transaction.digest(self.new['profile'])), patch.object(transaction.run_current, 'BINDING_SHA', transaction.digest(self.new['binding'])):
            self.assertEqual(transaction.proposed(self.old['profile'], self.old['binding'], self.old['launcher'], 'a'*64), self.new)
    def test_partial_transaction_restores_all_bytes_and_link(self):
        self.targets['profile'].write_bytes(self.new['profile'])
        transaction.atomic_link(self.prefix/'dosdevices/g:', self.plan['new_g'])
        transaction.restore(self.plan, self.prefix)
        transaction.check_state(self.plan, self.prefix, ('old',))
        for key,path in self.targets.items(): self.assertEqual(path.read_bytes(), self.old[key])
    def test_rollback_refuses_unrelated_changes(self):
        self.targets['profile'].write_bytes(b'unknown')
        with self.assertRaisesRegex(RuntimeError, 'target changed'): transaction.restore(self.plan, self.prefix)
        self.assertEqual(self.targets['profile'].read_bytes(), b'unknown')
    def test_apply_old_state_refuses_partial_migration(self):
        self.targets['profile'].write_bytes(self.new['profile'])
        with self.assertRaisesRegex(RuntimeError, 'target changed'): transaction.check_state(self.plan, self.prefix, ('old',))
    def test_rollback_refuses_replaced_prefix_identity(self):
        self.plan['prefix_identity']['inode'] += 1
        with self.assertRaisesRegex(RuntimeError, 'prefix replaced'): transaction.restore(self.plan, self.prefix)
    def test_rollback_refuses_unrelated_g_mapping(self):
        transaction.atomic_link(self.prefix/'dosdevices/g:', 'third-game')
        with self.assertRaisesRegex(RuntimeError, 'mapping changed'): transaction.restore(self.plan, self.prefix)
    def test_failed_postapply_validation_restores_every_target(self):
        with patch.object(transaction, 'load_plan', return_value=self.plan), patch.object(transaction, 'locked', return_value=nullcontext(self.prefix)), patch.object(transaction, 'check_comparison'), patch.object(transaction.doctor, 'validate', side_effect=RuntimeError('postapply failed')):
            with self.assertRaisesRegex(RuntimeError, 'postapply failed'): transaction.transition('apply', 'b'*64)
        transaction.check_state(self.plan, self.prefix, ('old',))
    def test_apply_runs_doctor_and_fresh_launcher_without_starting_client(self):
        with patch.object(transaction, 'load_plan', return_value=self.plan), patch.object(transaction, 'locked', return_value=nullcontext(self.prefix)), patch.object(transaction, 'check_comparison'), patch.object(transaction.doctor, 'validate') as validate, patch.object(transaction.subprocess, 'run') as run:
            self.assertEqual(transaction.transition('apply', 'b'*64)['status'], 'APPLIED')
        self.assertEqual(validate.call_args.args[0]['schema'],2)
        self.assertEqual(run.call_args.args[0][-1],'--check')
        transaction.check_state(self.plan, self.prefix, ('new',))
class TreeMetadataTest(unittest.TestCase):
    def test_metadata_detects_changes_and_refuses_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); (root/'file').write_bytes(b'original')
            initial=transaction.tree_metadata(root)
            (root/'file').write_bytes(b'changed')
            self.assertNotEqual(initial,transaction.tree_metadata(root))
            (root/'link').symlink_to(root/'file')
            with self.assertRaisesRegex(RuntimeError,'Unexpected GTA'): transaction.tree_metadata(root)


if __name__ == '__main__': unittest.main()
