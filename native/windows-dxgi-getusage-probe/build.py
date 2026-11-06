#!/usr/bin/env python3
"""Build the own GetUsage regression fixture offline; never run the executable."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent

def sha(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
def identity(p):return {'path':p.relative_to(ROOT).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)}

def main():
 work=Path(tempfile.mkdtemp(prefix='windows-dxgi-getusage-probe-',dir=ROOT/'build'));print(work,flush=True)
 source=work/'source';source.mkdir()
 for n in ('probe.cpp','CMakeLists.txt','README.md','build.py','contract.py','test_contract.py'):shutil.copyfile(HERE/n,source/n)
 result={'build_passed':False,'runtime_started':False,'source':[identity(p) for p in sorted(source.iterdir())], 'toolchain':identity(ROOT/'native/windows-core/toolchain.cmake')}
 def run(args,name):
  with (work/name).open('x') as out:subprocess.run(args,cwd=ROOT,stdout=out,stderr=subprocess.STDOUT,check=True)
 try:
  run(['cmake','-S',str(source),'-B',str(work/'objects'),'-G','Ninja','-DCMAKE_TOOLCHAIN_FILE='+str(ROOT/'native/windows-core/toolchain.cmake'),'-DCMAKE_BUILD_TYPE=RelWithDebInfo'], 'configure.log')
  run(['cmake','--build',str(work/'objects'),'--parallel','4'],'build.log')
  exe=work/'objects/dxgi_getusage_probe.exe';(work/'artifact').mkdir();shutil.copyfile(exe,work/'artifact/dxgi_getusage_probe.exe')
  result['artifact']=identity(work/'artifact/dxgi_getusage_probe.exe');result['build_passed']=True
 finally:
  (work/'result.json').write_text(json.dumps(result,indent=2)+'\n')
 if result['build_passed']:
  proof={'artifact':result['artifact'],'build_record':identity(work/'result.json'),'frozen_sources':result['source'],'runtime_started':False}
  (work/'frozen-artifact-proof.json').write_text(json.dumps(proof,indent=2)+'\n')
  print(json.dumps({'status':'BUILT_OFFLINE','artifact_sha256':result['artifact']['sha256'],'proof_sha256':sha(work/'frozen-artifact-proof.json')}))
if __name__=='__main__':main()
