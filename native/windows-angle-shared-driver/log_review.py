#!/usr/bin/env python3
"""Extract fixed categories from precisely two own ANGLE test stderr logs."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import parse

ROOT=Path(__file__).resolve().parents[2]
LOGS={m:ROOT/f'logs/wine-parity-angle-shared-w3cn6ir7-20261105T121013712886Z-angle_mode_{m}-wine.log' for m in (0,1)}
OWN_WINDOWS_FOLDER='Z:'+str(ROOT/'build/windows-angle-shared-run-w3cn6ir7/runtime').replace('/','\\')
LIMIT=8*1024*1024
CATEGORIES={
 'angle_d3d_error':re.compile(r'(?=.*\b(?:error|failed|err:))(?=.*(?:angle|d3d|dxgi))',re.I),
 'texture_storage_error':re.compile(r'(?=.*\b(?:error|failed|err:))(?=.*(?:texturestorage|texturestorage11|texture storage))',re.I),
 'egl_image_error':re.compile(r'(?=.*\b(?:error|failed|err:))(?=.*(?:eglimage|egl_image|egl image))',re.I),
 'gl_invalid_operation':re.compile(r'\bgl_invalid_operation\b',re.I),
}
CODES=('0x80004005','0x80070057','0x80004002','0x887a0005','0x887a0006')

def read(path):
    if path.resolve(strict=True)!=path:raise ValueError('IDENTITY')
    st=path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1 or st.st_size>LIMIT:raise ValueError('LIMIT')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as f:
        before=os.fstat(f.fileno());data=f.read(LIMIT+1);after=os.fstat(f.fileno())
    identity=lambda x:(x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_ctime_ns,x.st_nlink)
    if len(data)>LIMIT or identity(st)!=identity(before) or identity(before)!=identity(after) or identity(path.lstat())!=identity(before):raise ValueError('CHANGED')
    return data

def extract(data):
    if len(data)>LIMIT:raise ValueError('LIMIT')
    lines=data.decode('utf-8',errors='replace').splitlines()
    counts={k:0 for k in CATEGORIES};first={k:None for k in CATEGORIES};codes={c:0 for c in CODES}
    for n,line in enumerate(lines,1):
        for name,pattern in CATEGORIES.items():
            if pattern.search(line):
                counts[name]+=1
                if first[name] is None:first[name]=n
        if re.search(r'error|failed|err:',line,re.I):
            for code in codes:
                if re.search(r'(?<![0-9a-f])'+code+r'(?![0-9a-f])',line,re.I):codes[code]+=1
    return {'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'categories':counts,'first_line_ordinals':first,'allowlisted_status_codes':codes}

def provider_checks(lines, exitcode):
    path=ROOT/'native/windows-dxgi-swapchain/run.py'
    spec=importlib.util.spec_from_file_location('angle_log_graphics',path);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    graphics=mod.graphics()
    actual=graphics.parse_provider_diagnostics(lines,exitcode)
    identity_only=graphics.parse_provider_diagnostics(lines,0)
    chain=identity_only['provider_chain']
    return {'reported_provider_diagnostics_passed':actual['passed'],
       'provider_chain_checks_pass_if_exit_ignored':identity_only['passed'],
       'native_angle_dll_paths_match':parse.angle_provider_lines(lines,OWN_WINDOWS_FOLDER),
       'complete_native_chain_observed':bool(chain['complete_native_process_ids']),
       'required_builtin_modules_observed':{'d3d11','dxgi','winemetal'}.issubset(chain['windows_builtin_modules']),
       'unexpected_native_renderer_observed':bool(chain['unexpected_native_renderer_modules'])}

def main():
    try:
        out={}
        for mode in (0,1):
            data=read(LOGS[mode]);out[f'mode_{mode}']=extract(data)
            out[f'mode_{mode}']['provider']=provider_checks(data.decode('utf-8',errors='replace').splitlines(),mode)
        print(json.dumps({'status':'OK','logs':out},indent=2));return 0
    except (OSError,ValueError,RuntimeError):
        print(json.dumps({'status':'FAIL','code':'INPUT_VALIDATION_FAILED'}));return 1
if __name__=='__main__':sys.exit(main())
