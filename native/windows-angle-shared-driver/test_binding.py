import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import inputs
spec=importlib.util.spec_from_file_location('angle_runner_test',Path(__file__).with_name('run.py'))
runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(runner)

class ProofTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name).resolve();self.build=self.root/'build/windows-angle-shared-probe-test';self.build.mkdir(parents=True)
  self.archive=self.root/'archive.zip';self.archive.write_bytes(b'fixture');self.archash=hashlib.sha256(b'fixture').hexdigest()
  self.names={'libEGL.dll':'a'*64,'libGLESv2.dll':'b'*64};roles={'artifact':'artifact/angle_shared_probe.exe','build_record':'result.json','source':'source/probe.cpp','api_contract':'source/api-contract.json','headers_manifest':'source/vendor/manifest.json'};proof={}
  for key,rel in roles.items():
   p=self.build/rel;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(key.encode());proof[key]={'path':p.relative_to(self.root).as_posix(),'bytes':p.stat().st_size,'sha256':inputs.digest(p)}
  record=self.build/'result.json';record.write_text(json.dumps({'build_passed':True,'runtime_started':False,'runtime_staged':False,'artifact':proof['artifact'],'frozen_source_files':[proof['source'],proof['api_contract']]}));proof['build_record']={'path':record.relative_to(self.root).as_posix(),'bytes':record.stat().st_size,'sha256':inputs.digest(record)}
  rows=[{'archive_member':inputs.PACKAGE+'/Release/'+n,'relative_runtime_path':n,'bytes':2,'sha256':h} for n,h in self.names.items()]
  r=self.build/'runtime-requirements.json';r.write_text(json.dumps({'archive':{'path':self.archive.relative_to(self.root).as_posix(),'bytes':self.archive.stat().st_size,'sha256':self.archash},'files':rows,'runtime_staged':False}));proof['runtime_requirements']={'path':r.relative_to(self.root).as_posix(),'bytes':r.stat().st_size,'sha256':inputs.digest(r)}
  self.proof=self.build/'frozen-artifact-proof.json';self.proof.write_text(json.dumps(proof));self.digest=inputs.digest(self.proof)
  self.patches=[patch.object(runner,'ROOT',self.root),patch.object(inputs,'ARCHIVE',self.archive),patch.object(inputs,'ARCHIVE_SHA',self.archash),patch.object(inputs,'DLLS',self.names)]
  for p in self.patches:p.start()
 def tearDown(self):
  for p in reversed(self.patches):p.stop()
  self.tmp.cleanup()
 def test_frozen_source_accepted(self):
  artifact,names=runner.verify_frozen(self.build,self.digest);self.assertEqual(set(names),set(self.names))
 def test_source_mutation_fails(self):
  (self.build/'source/probe.cpp').write_bytes(b'changed')
  with self.assertRaises(inputs.Invalid):runner.verify_frozen(self.build,self.digest)
 def test_wrong_proof_fails(self):
  with self.assertRaises(inputs.Invalid):runner.verify_frozen(self.build,'0'*64)
if __name__=='__main__':unittest.main()
