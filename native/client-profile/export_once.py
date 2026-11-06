#!/usr/bin/env python3
"""One-time code-only export from the already verified candidate configuration."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import doctor

root=doctor.ROOT
source=root/'build/source-update-candidate-nqwlz36g/resume-candidate.py'
spec=importlib.util.spec_from_file_location('profile_export_source',source)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
game=module.game; reuse=module.reuse; identity=module.identity
if doctor.PROFILE.exists(): raise SystemExit('PROFILE_ALREADY_EXISTS')
if identity.verify_stage(game) != 422: raise SystemExit('STAGE_COUNT')
rows=reuse.inventory(); reuse.verify(game.PREFIX,rows)
expected=game.first.expected_files(marker=True)
expected.update({'CoreRT.dll':identity.FIXED_CORE,'nui-core.dll':identity.SOFTWARE_NUI,'net.dll':identity.ORIGINAL_NET})
if len(expected)!=422: raise SystemExit('STAGE_COUNT')
stage=[]
for name,sha in sorted(expected.items()):
    info=doctor.fingerprint(doctor.plain(root,doctor.STAGE+'/'+name))
    if info['sha256']!=sha: raise SystemExit('STAGE_MISMATCH')
    stage.append({'path':name,**info})
status_path=root/'build/source-update-candidate-nqwlz36g/game-run/status.json'
status=json.loads(status_path.read_text())
exes=[]
for name,sha in sorted(status['game_executables'].items()):
    info=doctor.fingerprint(doctor.plain(root,doctor.GAME+'/'+name))
    if info['sha256']!=sha: raise SystemExit('GAME_MISMATCH')
    exes.append({'path':name,**info})
prefix=doctor.plain(root,doctor.PREFIX,True).stat(); drive=doctor.plain(root,doctor.PREFIX+'/drive_c',True).stat()
graphics=doctor.load_graphics(root); runtime=graphics.runtime.verify_runtime(); renderer=graphics.verify_renderer()
profile={'schema':1,'role':'SourceDev','code_verified_is_auth_ready':False,'official_version':1257409,'source_revision':'88a413835e9d7f56633f249880a13f42297153a2','prefix':doctor.PREFIX,'prefix_identity':{'device':prefix.st_dev,'inode':prefix.st_ino},'drive_identity':{'device':drive.st_dev,'inode':drive.st_ino},'stage':doctor.STAGE,'game':doctor.GAME,'stage_files':stage,'vendor_files':rows,'game_executables':exes,'runtime_manifest_sha256':runtime['manifest_sha256'],'renderer_review_sha256':renderer['review']['sha256'],'source_fingerprints':{'official_manifest_sha256':game.first.MANIFEST_SHA,'rockstar_manifest_sha256':doctor.VENDOR_SHA,'game_status_sha256':doctor.fingerprint(status_path)['sha256'],'resume_candidate_sha256':doctor.fingerprint(source)['sha256']}}
print(json.dumps(doctor.validate(profile,verify_graphics=False)))
data=(json.dumps(profile,indent=2)+'\n').encode(); fd=os.open(doctor.PROFILE,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
with os.fdopen(fd,'wb') as f: f.write(data)
print(json.dumps({'status':'EXPORTED','profile':'config/active-client-profile.json','sha256':__import__('hashlib').sha256(data).hexdigest()}))
