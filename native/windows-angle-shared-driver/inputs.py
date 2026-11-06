"""Read-only pins and bounded staging helpers for the independent ANGLE fixture."""
import hashlib
import os
from pathlib import Path
import re
import stat
import zipfile

ROOT=Path(__file__).resolve().parents[2]
PACKAGE='cef_binary_144.19.61-cfx-m144-osr.3461+gcbe8fd0+chromium-144.0.7559.264_windows64_minimal'
ARCHIVE=ROOT/'downloads/cef'/f'{PACKAGE}.zip'
ARCHIVE_SHA='27d87a3bcfb786008fd58730306b3097a747f8ec41a66f101636a819f161ed83'
DLLS={
 'libEGL.dll':'3b89d3ac1c5e6637b5b08be478d920c1c55f58ae05a0ae007c85a3e629a8a9c8',
 'libGLESv2.dll':'efc1b179c3e6f4ff3fbc1758cc50ceb863afdaca1575f50a332d0328b80f453b',
 'd3dcompiler_47.dll':'320565434e5d8a77e13980e9c0e641daa08d12693ac0d77df9ccf2b25d9e526c',
 'dxcompiler.dll':'55b01c047cb1a9fabe5e3ed6c6c7e2e2215c1c8ad2c943abb0ed4c43bb0ebec1',
 'dxil.dll':'038e461b1997d06560748bf9c545415b897b3b44a1e56297fa6a977ff5bff18b',
}
class Invalid(Exception): pass

def digest(path):
    if path.resolve(strict=True)!=path: raise Invalid('PATH')
    st=path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1: raise Invalid('FILE')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW);h=hashlib.sha256()
    with os.fdopen(fd,'rb') as file:
        before=os.fstat(file.fileno())
        for b in iter(lambda:file.read(1024*1024),b''):h.update(b)
        after=os.fstat(file.fileno())
    ident=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_nlink)
    if ident(st)!=ident(before) or ident(before)!=ident(after) or ident(path.lstat())!=ident(before): raise Invalid('FILE_CHANGED')
    return h.hexdigest()

def build_path(text):
    path=Path(text)
    if not path.is_absolute():path=ROOT/path
    if path.parent!=ROOT/'build' or not re.fullmatch(r'windows-angle-shared-probe-[a-z0-9_]+',path.name) or path.resolve(strict=True)!=path: raise Invalid('BUILD')
    return path

def verify_runtime_tree(folder,expected):
    if folder.is_symlink() or folder.resolve(strict=True)!=folder or not folder.is_dir():raise Invalid('RUNTIME')
    actual={p.name for p in folder.iterdir()}
    if actual!=set(expected):raise Invalid('RUNTIME_CONTENTS')
    for name,sha in expected.items():
        if digest(folder/name)!=sha:raise Invalid('RUNTIME_CONTENTS')

def stage_dlls(folder,names):
    if not {'libEGL.dll','libGLESv2.dll'}.issubset(names) or not set(names).issubset(DLLS):raise Invalid('DLL_SET')
    if digest(ARCHIVE)!=ARCHIVE_SHA: raise Invalid('ARCHIVE')
    with zipfile.ZipFile(ARCHIVE) as package:
        for name in sorted(names):
            sha=DLLS[name]
            member=PACKAGE+'/Release/'+name
            info=package.getinfo(member)
            if info.is_dir() or info.file_size<=0 or info.file_size>32*1024*1024:raise Invalid('ARCHIVE_MEMBER')
            h=hashlib.sha256()
            with package.open(info) as inp,(folder/name).open('xb') as out:
                for b in iter(lambda:inp.read(1024*1024),b''):h.update(b);out.write(b)
            if h.hexdigest()!=sha: raise Invalid('ARCHIVE_MEMBER')
