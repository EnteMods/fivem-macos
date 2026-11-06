#!/usr/bin/env python3
"""Build the native ARM64 read-only finder; never run a game or launcher."""
import datetime,hashlib,json,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
SOURCE=Path(__file__).with_name('main.swift')
BUILD=ROOT/'build/macos-discovery'
BUILD.mkdir(parents=True,exist_ok=True)
BINARY=BUILD/'gta-discovery'
command=['xcrun','swiftc','-target','arm64-apple-macosx13.0','-O','-o',str(BINARY),str(SOURCE)]
subprocess.run(command,cwd=ROOT,check=True)
architectures=subprocess.check_output(['lipo','-archs',str(BINARY)],text=True).strip()
if architectures!='arm64':raise RuntimeError('Require native ARM64 artifact')
r={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'command':command,'architecture':architectures,
   'path':str(BINARY.relative_to(ROOT)),'binary_sha256':hashlib.sha256(BINARY.read_bytes()).hexdigest(),
   'source_sha256':hashlib.sha256(SOURCE.read_bytes()).hexdigest(),'swift_version':subprocess.check_output(['xcrun','swiftc','--version'],text=True).strip(),
   'target':'arm64-apple-macosx13.0','read_only_cli':True,'game_or_launcher_executed':False,'packaged_dmg':False}
(ROOT/'research/macos-discovery-build.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps(r,indent=2))
