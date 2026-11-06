#!/usr/bin/env python3
"""Prepare and verify only the pinned, independent client D3D11 overlay; never launch."""
import ctypes
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[2]
BASE=ROOT/'build/dxmt-resource-usage-e95ais9r'
OVERLAY=BASE/'client-overlay'
PROOF=BASE/'frozen-artifact-proof.json'
PROOF_SHA='4315d6bacc9618148d71231b07f2ae5fc4f2cf8a03e8616d7e95ff37f7c4fbb5'
ARTIFACT_SHA='a4974db072793e38c07d33a4afee1c1e8c01c592c5117c36f82c576fe94898af'
CHECKER=ROOT/'native/dxmt-resource-candidate-runner/runner.py'
CHECKER_SHA='d19c2cdb2ba2dfab0ab1c78da7278c36a3d758b330ee50f68eb8cdf7b400e128'
ORIGINAL=ROOT.parent/'GTA-V-macOS/runtime/matched-dxmt-a444716/highball'

class Invalid(Exception):pass

def trusted():
    if CHECKER.resolve(strict=True)!=CHECKER or hashlib.sha256(CHECKER.read_bytes()).hexdigest()!=CHECKER_SHA:raise Invalid('CHECKER')
    spec=importlib.util.spec_from_file_location('client_overlay_candidate_checker',CHECKER)
    checker=importlib.util.module_from_spec(spec);spec.loader.exec_module(checker)
    s2=checker.dependencies();proof=checker.verify_candidate(PROOF,PROOF_SHA,s2)
    if proof['artifact']['sha256']!=ARTIFACT_SHA:raise Invalid('ARTIFACT')
    return checker,s2,proof

def verify():
    checker,s2,proof=trusted()
    if BASE.resolve(strict=True)!=BASE or OVERLAY.is_symlink():raise Invalid('OVERLAY_PATH')
    file=checker.verify_overlay_tree(OVERLAY,ARTIFACT_SHA,s2)
    return {'file':file.relative_to(ROOT).as_posix(),'sha256':ARTIFACT_SHA,'proof_sha256':PROOF_SHA,
            'source_patch_sha256':proof['source_patch']['sha256'],'abi_audit_sha256':proof['audit_report']['sha256'],
            'selection':'INFERRED_FROM_PINNED_LOADER_AND_CLOSED_OVERLAY','physical_path_verified':False}

def rename_exclusive(source,target):
    libc=ctypes.CDLL(None,use_errno=True)
    try:fn=libc.renamex_np
    except AttributeError:raise Invalid('EXCLUSIVE_RENAME_UNAVAILABLE')
    fn.argtypes=(ctypes.c_char_p,ctypes.c_char_p,ctypes.c_uint);fn.restype=ctypes.c_int
    if fn(os.fsencode(source),os.fsencode(target),0x00000004)!=0:
        code=ctypes.get_errno()
        if code==errno.EEXIST:raise FileExistsError('OVERLAY_EXISTS')
        raise OSError(code,'EXCLUSIVE_RENAME_FAILED')

def prepare():
    checker,s2,proof=trusted()
    if BASE.resolve(strict=True)!=BASE:raise Invalid('BASE_PATH')
    if OVERLAY.exists() or OVERLAY.is_symlink():return verify()
    temp=Path(tempfile.mkdtemp(prefix='.client-overlay-',dir=BASE))
    try:
        directory=temp/'x86_64-windows';directory.mkdir(mode=0o700)
        source=ROOT/proof['artifact']['path'];dest=directory/'d3d11.dll'
        with source.open('rb') as inp,dest.open('xb') as out:
            shutil.copyfileobj(inp,out,1024*1024);out.flush();os.fsync(out.fileno())
        os.chmod(dest,0o444)
        checker.verify_overlay_tree(temp,ARTIFACT_SHA,s2)
        rename_exclusive(temp,OVERLAY)
    finally:
        if temp.exists():shutil.rmtree(temp)
    return verify()

def apply(env, enabled, original=ORIGINAL):
    if not enabled:return None
    metadata=verify()
    if original!=ORIGINAL or original.resolve(strict=True)!=original or env.get('WINEDLLPATH_PREPEND')!=str(ORIGINAL):raise Invalid('ORIGINAL_BINDING')
    if ':' in str(OVERLAY) or ':' in str(ORIGINAL):raise Invalid('SEARCH_PATH')
    env['WINEDLLPATH_PREPEND']=str(OVERLAY)+':'+str(ORIGINAL)
    return metadata

def main():
    if sys.argv[1:] not in (['prepare'],['verify']):
        print(json.dumps({'status':'FAIL','code':'ARGUMENT'}));return 2
    try:
        result=prepare() if sys.argv[1]=='prepare' else verify()
        print(json.dumps({'status':'OK','overlay':result}));return 0
    except Exception:
        print(json.dumps({'status':'FAIL','code':'OVERLAY_VALIDATION_FAILED'}));return 1
if __name__=='__main__':raise SystemExit(main())
