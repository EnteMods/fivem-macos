import importlib.util
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('candidate_runner',Path(__file__).with_name('runner.py'))
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
class Tests(unittest.TestCase):
 def test_no_unsupported_path_proof(self):
  x=r.candidate_evidence();self.assertIs(x['physical_candidate_file_verified'],False);self.assertEqual(x['physical_candidate_mapping_status'],'UNKNOWN')
 def test_dependencies_pinned(self):
  s2=r.dependencies();self.assertEqual(s2.inputs.ARCHIVE_SHA,'27d87a3bcfb786008fd58730306b3097a747f8ec41a66f101636a819f161ed83')
 def test_frozen_fixture(self):
  s2=r.dependencies();_,names,schema=s2.verify_frozen(r.S2_BUILD,r.S2_PROOF);self.assertEqual(schema,'own-angle-shared-probe-api-v2');self.assertEqual(len(names),5)
  exe,contract=r.usage_fixture(s2);self.assertTrue(exe.is_file());self.assertTrue(callable(contract.parse))
 def test_closed_overlay(self):
  import hashlib
  with tempfile.TemporaryDirectory() as d:
   p=Path(d).resolve()/'overlay';q=p/'x86_64-windows';q.mkdir(parents=True);(q/'d3d11.dll').write_bytes(b'own')
   s2=r.dependencies();r.verify_overlay_tree(p,hashlib.sha256(b'own').hexdigest(),s2)
   (q/'extra.dll').write_bytes(b'other')
   with self.assertRaises(r.Invalid):r.verify_overlay_tree(p,hashlib.sha256(b'own').hexdigest(),s2)
 def test_search_path_order(self):
  self.assertEqual(r.ordered_paths(Path('/own'),Path('/original')),'/own:/original')
  with self.assertRaises(r.Invalid):r.ordered_paths(Path('/bad:path'),Path('/original'))
 def test_candidate_proof_readonly(self):
  s2=r.dependencies();p=r.ROOT/'build/dxmt-resource-usage-e95ais9r/frozen-artifact-proof.json'
  proof=r.verify_candidate(p,'4315d6bacc9618148d71231b07f2ae5fc4f2cf8a03e8616d7e95ff37f7c4fbb5',s2)
  self.assertFalse(proof['runtime_started'])
 def test_invalid_proof_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d).resolve()/'proof.json';p.write_text('{}');s2=r.dependencies()
   with self.assertRaises(r.Invalid):r.verify_candidate(p,'0'*64,s2)
if __name__=='__main__':unittest.main()
