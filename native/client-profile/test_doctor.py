import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import doctor

class ValidatorTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.root=Path(self.tmp.name).resolve()/'FiveM-macOS'
        self.prefix=self.root/doctor.PREFIX; self.drive=self.prefix/'drive_c'; self.stage=self.root/doctor.STAGE; self.game=self.root/doctor.GAME
        self.stage.mkdir(parents=True); self.game.mkdir(parents=True); (self.prefix/'dosdevices').mkdir()
        (self.prefix/'dosdevices/c:').symlink_to('../drive_c'); (self.prefix/'dosdevices/g:').symlink_to(self.game)
        def file(base,name,data=b'x'):
            p=base/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
            return {'path':name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
        self.file=file
        stage=[file(self.stage,'CitizenFX.ini',b'[Game]\nIVPath=G:\n')]+[file(self.stage,f'code/{i}.dll') for i in range(421)]
        vendor=[file(self.prefix,doctor.UPDATED_CODE_ROOTS[0]+f'/{i}.dll') for i in range(145)]
        manifest={'roots':list(doctor.UPDATED_CODE_ROOTS),'excluded_account_profiles_registry_sessions':True,'files':vendor}
        m=self.root/doctor.VENDOR_MANIFEST;m.parent.mkdir(parents=True,exist_ok=True);m.write_text(json.dumps(manifest));self.patch=patch.object(doctor,'VENDOR_SHA',hashlib.sha256(m.read_bytes()).hexdigest());self.patch.start()
        exes=[file(self.game,x) for x in ('GTA5.exe','PlayGTAV.exe','GTAVLauncher.exe')]
        p=self.prefix.stat();d=self.drive.stat()
        self.profile={'schema':1,'role':'SourceDev','code_verified_is_auth_ready':False,'official_version':1257409,'source_revision':'88a413835e9d7f56633f249880a13f42297153a2','prefix':doctor.PREFIX,'stage':doctor.STAGE,'game':doctor.GAME,'prefix_identity':{'device':p.st_dev,'inode':p.st_ino},'drive_identity':{'device':d.st_dev,'inode':d.st_ino},'stage_files':stage,'vendor_files':vendor,'game_executables':exes}
        self.stage_pin=patch.object(doctor,'STAGE_INVENTORY_SHA',doctor.inventory_hash(stage));self.stage_pin.start()
        self.game_pin=patch.object(doctor,'GAME_INVENTORY_SHA',doctor.inventory_hash(exes));self.game_pin.start()
    def tearDown(self): self.patch.stop();self.stage_pin.stop();self.game_pin.stop();self.tmp.cleanup()
    def run_check(self): return doctor.validate(self.profile,self.root,False)
    def fails(self):
        with self.assertRaises((doctor.Invalid,OSError)): self.run_check()
    def test_success_without_old_evidence(self): self.assertEqual(self.run_check()['stage_files'],422)
    def test_tampered_code(self): (self.stage/'code/1.dll').write_bytes(b'bad');self.fails()
    def test_escape(self):
        self.profile['stage_files'][1]['path']='../outside'
        with patch.object(doctor,'STAGE_INVENTORY_SHA',doctor.inventory_hash(self.profile['stage_files'])): self.fails()
    def test_symlink(self):
        p=self.stage/'code/1.dll';p.unlink();p.symlink_to(self.stage/'code/2.dll');self.fails()
    def test_missing_vendor(self): (self.prefix/self.profile['vendor_files'][0]['path']).unlink();self.fails()
    def test_g_mapping(self):
        link=self.prefix/'dosdevices/g:';link.unlink();link.symlink_to(self.stage);self.fails()
    def test_prefix_replace(self):
        self.prefix.rename(self.prefix.with_name('old-prefix'))
        (self.prefix/'drive_c').mkdir(parents=True)
        self.fails()
    def test_case_insensitive_executables(self):
        (self.game/'GTA5.exe').rename(self.game/'gta5.EXE');self.assertEqual(self.run_check()['game_executables'],3)
    def test_hard_link(self):
        p=self.stage/'code/1.dll';os.link(p,self.stage/'code/alias.dll');self.fails()
    def canonical(self):
        target=self.root.parent/doctor.SIBLING_GAME
        target.parent.mkdir(parents=True)
        self.game.rename(target);self.game=target
        self.profile.update(schema=2,game=dict(doctor.GAME_REFERENCE))
        link=self.prefix/'dosdevices/g:';link.unlink();link.symlink_to(target)
    def test_canonical_success(self):
        self.canonical();self.assertEqual(self.run_check()['game_executables'],3)
        self.assertEqual(doctor.game_location(self.profile,self.root)[2],self.game)
    def test_canonical_clone_mapping_rejected(self):
        clone=self.game;self.canonical();clone.mkdir()
        link=self.prefix/'dosdevices/g:';link.unlink();link.symlink_to(clone);self.fails()
    def test_schema1_cannot_select_sibling(self):
        self.canonical();self.profile['schema']=1;self.fails()
    def test_schema2_cannot_select_clone(self):
        self.profile['schema']=2;self.fails()
    def test_canonical_arbitrary_path_rejected(self):
        self.canonical();self.profile['game']['path']='../'+doctor.SIBLING_GAME;self.fails()
    def test_canonical_extra_reference_field_rejected(self):
        self.canonical();self.profile['game']['absolute']=str(self.game);self.fails()
    def test_canonical_symlink_directory_rejected(self):
        self.canonical();base=self.root.parent/'GTA-V-macOS';other=base.with_name('redirect')
        base.rename(other);base.symlink_to(other,target_is_directory=True);self.fails()
    def test_canonical_symlink_executable_rejected(self):
        self.canonical();p=self.game/'GTA5.exe';p.unlink();p.symlink_to(self.game/'PlayGTAV.exe');self.fails()
    def test_canonical_executable_bytes_rejected(self):
        self.canonical();(self.game/'GTA5.exe').write_bytes(b'changed');self.fails()
    def test_canonical_hardlink_executable_rejected(self):
        self.canonical();os.link(self.game/'GTA5.exe',self.game/'extra.exe');self.fails()
    def test_boolean_schema_rejected(self):
        self.profile['schema']=True;self.fails()
if __name__=='__main__': unittest.main()
