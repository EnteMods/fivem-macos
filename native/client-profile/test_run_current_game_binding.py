import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import doctor
import run_current


class CurrentGameBindingTest(unittest.TestCase):
    def test_verified_game_is_selected_before_candidate_inventory_check(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix=Path(directory); (prefix/'drive_c').mkdir()
            info=prefix.stat(); drive=(prefix/'drive_c').stat()
            current={'device':info.st_dev,'inode':info.st_ino}
            drive_current={'device':drive.st_dev,'inode':drive.st_ino}
            old={'device':1,'inode':2}
            record={'schema':2,'game_reference':dict(doctor.GAME_REFERENCE),'active_profile_sha256':run_current.PROFILE_SHA,
                    'current_prefix_identity':current,'current_drive_identity':drive_current,'component_selection':'baseline',
                    'stage_files':422,'vendor_files':145,'game_executables':3,'current_vendor_manifest_sha256':doctor.VENDOR_SHA,
                    'stage_inventory_sha256':doctor.STAGE_INVENTORY_SHA,'game_inventory_sha256':doctor.GAME_INVENTORY_SHA,
                    'old_prefix_identity':old,'archived_profile_sha256':'a'*64}
            profile={'schema':2,'prefix_identity':current,'drive_identity':drive_current}
            target=Path(directory)/'canonical-original'
            helper=SimpleNamespace(game=SimpleNamespace(PREFIX=prefix,GAME=Path('old-clone'),first=SimpleNamespace(STATUS=Path('first-status'))),
                                   identity=SimpleNamespace(component_init_state=Mock(return_value={'status':'restored','selection':'baseline'})),
                                   reuse=SimpleNamespace(verify=Mock(),inventory=Mock(return_value=[])))
            def verify(game):
                self.assertEqual(game.GAME,target)
                return 422
            helper.identity.verify_input=verify
            def checked(path, expected):
                if path==run_current.BINDING:return json.dumps(record).encode()
                if path==doctor.PROFILE:return json.dumps(profile).encode()
                if path==prefix/'.source-update-prelogin':return json.dumps(old).encode()
                if path==Path('first-status'):return json.dumps({'prefix_binding':old}).encode()
                return b'archive'
            def validate(value):
                self.assertEqual(helper.game.GAME,Path('old-clone'))
                return {'status':'OK'}
            with patch.object(run_current,'checked',side_effect=checked), patch.object(doctor,'validate',side_effect=validate), patch.object(doctor,'game_location',return_value=(prefix,'fixed',target)):
                self.assertEqual(run_current.check_binding(helper),record)
    def test_rejected_doctor_does_not_assign_game(self):
        game=SimpleNamespace(GAME=Path('old-clone'))
        with patch.object(run_current,'checked',return_value=b'{}'), patch.object(doctor,'validate',side_effect=doctor.Invalid('GAME_BINDING')):
            with self.assertRaises(doctor.Invalid):run_current.check_binding(SimpleNamespace(game=game))
        self.assertEqual(game.GAME,Path('old-clone'))


if __name__=='__main__':unittest.main()
