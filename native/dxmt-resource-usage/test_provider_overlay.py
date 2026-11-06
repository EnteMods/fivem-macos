import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import provider_overlay as p

class Tests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):cls.checker,cls.s2,cls.proof=p.trusted()
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name).resolve();self.base=self.root/'base';self.base.mkdir();self.overlay=self.base/'overlay';self.dir=self.overlay/'x86_64-windows';self.dir.mkdir(parents=True);self.dll=self.dir/'d3d11.dll';self.dll.write_bytes(b'own fixture');self.sha=hashlib.sha256(b'own fixture').hexdigest()
  self.patches=[patch.object(p,'ROOT',self.root),patch.object(p,'BASE',self.base),patch.object(p,'OVERLAY',self.overlay),patch.object(p,'ARTIFACT_SHA',self.sha),patch.object(p,'trusted',return_value=(self.checker,self.s2,self.proof))]
  for x in self.patches:x.start()
 def tearDown(self):
  for x in reversed(self.patches):x.stop()
  self.tmp.cleanup()
 def test_valid_and_hash_mismatch(self):
  self.assertEqual(p.verify()['sha256'],self.sha);self.dll.write_bytes(b'wrong')
  with self.assertRaises(Exception):p.verify()
 def test_closed_tree(self):
  (self.dir/'extra').write_bytes(b'x')
  with self.assertRaises(Exception):p.verify()
 def test_symlink_rejected(self):
  self.dll.unlink();(self.root/'outside').write_bytes(b'own fixture');self.dll.symlink_to(self.root/'outside')
  with self.assertRaises(Exception):p.verify()
 def test_disabled_env_untouched(self):
  env={'WINEDLLPATH_PREPEND':'original','other':'same'};before=dict(env)
  self.assertIsNone(p.apply(env,False));self.assertEqual(env,before)
 def test_binding_refuses_unknown_original(self):
  original=self.root/'original';original.mkdir();env={'WINEDLLPATH_PREPEND':str(original)}
  with patch.object(p,'ORIGINAL',original):
   with self.assertRaises(p.Invalid):p.apply(env,True,self.root/'other')
   env['WINEDLLPATH_PREPEND']='wrong'
   with self.assertRaises(p.Invalid):p.apply(env,True,original)
 def test_exclusive_rename_no_clobber(self):
  src=self.root/'src';dst=self.root/'dst';src.mkdir();dst.mkdir();(dst/'sentinel').write_text('keep')
  with self.assertRaises(FileExistsError):p.rename_exclusive(src,dst)
  self.assertTrue(src.is_dir());self.assertEqual((dst/'sentinel').read_text(),'keep')
 def test_resume_disabled_no_env_change(self):
  path=Path(__file__).resolve().parents[2]/'build/source-update-candidate-nqwlz36g/resume-candidate.py'
  spec=importlib.util.spec_from_file_location('overlay_resume_test',path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
  env={'WINEDLLPATH_PREPEND':'baseline'};self.assertIsNone(module.configure_resource_overlay(env,False,None));self.assertEqual(env,{'WINEDLLPATH_PREPEND':'baseline'})
if __name__=='__main__':unittest.main()
