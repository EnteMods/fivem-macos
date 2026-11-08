#!/usr/bin/env python3
"""Build one explicitly selected app, using an existing verified Auth Bridge."""
import argparse
import os
from pathlib import Path
import plistlib
import subprocess
import tempfile

SOURCE = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', required=True, type=Path, help='New absolute .app path; must not exist')
parser.add_argument('--auth-bridge', required=True, type=Path, help='Existing FiveM Auth Bridge 0.1.2 app')
args = parser.parse_args()
output, bridge = args.output, args.auth_bridge
if not output.is_absolute() or output.suffix != '.app' or output.exists() or output.is_symlink():
    parser.error('--output must be an absolute, nonexistent .app path')
info = plistlib.loads((bridge / 'Contents/Info.plist').read_bytes())
if info.get('CFBundleIdentifier') != 'local.fivem-macos.auth-bridge' or info.get('CFBundleShortVersionString') != '0.1.2':
    parser.error('--auth-bridge must identify the existing 0.1.2 bridge')
subprocess.run(['/usr/bin/codesign', '--verify', '--strict', str(bridge)], check=True)
with tempfile.TemporaryDirectory(prefix='.fivem-build-', dir=output.parent) as temp:
    app = Path(temp) / output.name
    macos = app / 'Contents/MacOS'
    macos.mkdir(parents=True)
    info = {'CFBundleIdentifier': 'local.fivem-macos.launcher', 'CFBundleName': 'FiveM',
            'CFBundleDisplayName': 'FiveM', 'CFBundleExecutable': 'FiveMLauncher',
            'CFBundlePackageType': 'APPL', 'CFBundleVersion': '2',
            'CFBundleShortVersionString': '0.1.1', 'LSMinimumSystemVersion': '14.0',
            'NSHighResolutionCapable': True, 'LSApplicationCategoryType': 'public.app-category.games',
            'NSMicrophoneUsageDescription': 'FiveM benötigt dein Mikrofon für den Sprachchat im Spiel.'}
    with (app / 'Contents/Info.plist').open('wb') as f:
        plistlib.dump(info, f)
    subprocess.run(['/usr/bin/xcrun', 'swiftc', '-target', 'arm64-apple-macos14.0', '-O',
                    str(SOURCE / 'App.swift'), '-framework', 'AppKit', '-o', str(macos / 'FiveMLauncher')], check=True)
    helper = app / 'Contents/Helpers/FiveM Auth Bridge.app'
    helper.parent.mkdir()
    subprocess.run(['/usr/bin/ditto', str(bridge), str(helper)], check=True)
    plist = helper / 'Contents/Info.plist'
    helper_info = plistlib.loads(plist.read_bytes())
    helper_info['LSUIElement'] = True
    plist.write_bytes(plistlib.dumps(helper_info))
    subprocess.run(['/usr/bin/codesign', '--force', '--sign', '-', '--timestamp=none', str(helper)], check=True)
    subprocess.run(['/usr/bin/codesign', '--force', '--sign', '-', '--timestamp=none', str(app)], check=True)
    subprocess.run(['/usr/bin/codesign', '--verify', '--deep', '--strict', str(app)], check=True)
    subprocess.run([str(macos / 'FiveMLauncher'), '--self-test'], check=True)
    if output.exists() or output.is_symlink():
        raise SystemExit('Output appeared during build; refusing to replace')
    os.rename(app, output)
print(output)
