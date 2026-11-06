#!/usr/bin/env python3
"""Acquire the reviewed Microsoft headers/libraries from the pinned official manifest."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
TC = ROOT / 'toolchains'
META = TC / 'metadata'
HELPER = TC / 'helpers/msvc-wine/vsdownload.py'
EXPECTED_HELPER = json.loads((META / 'acquisition-plan.json').read_text())['helper_files_sha256']['vsdownload.py']
EXPECTED_MANIFEST = '963760b01f621ed4fa40d1cf97aeb042f7bc6e04e3176c13c38abb19d265f789'
BASE_PACKAGES = ['Microsoft.VC.14.44.17.14.CRT.Headers.base', 'Microsoft.VC.14.44.17.14.CRT.x64.Desktop.base', 'Microsoft.VC.14.44.17.14.CRT.x64.Store.base']
ATL_PACKAGES = ['Microsoft.VC.14.44.17.14.ATL.Headers.base', 'Microsoft.VC.14.44.17.14.ATL.X64.base']
PACKAGES = BASE_PACKAGES + ATL_PACKAGES
LICENSES = {
    'community': 'https://visualstudio.microsoft.com/license-terms/vs2022-ga-community/',
    'sdk': 'https://aka.ms/WinSDKLicenseURL',
    'build_tools_reference': 'https://visualstudio.microsoft.com/license-terms/vs2022-ga-diagnosticbuildtools/',
}


def ensure_pinned_file(path, url, digest):
    if path.is_file():
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise SystemExit('Pinned metadata/helper hash mismatch: ' + str(path))
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url, timeout=45) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != digest:
        raise SystemExit('Downloaded metadata/helper hash mismatch: ' + url)
    path.write_bytes(data)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--authorized-20261101', action='store_true', help='Use the user approval given on 2026-11-01 for these original Microsoft packages.')
    p.add_argument('--selection-only', action='store_true')
    p.add_argument('--atl-only', action='store_true', help='Acquire the separate ATL headers/x64 library wave without re-extracting the SDK/CRT.')
    args = p.parse_args()
    if not args.authorized_20261101:
        p.error('Explicit reviewed Microsoft license/download authorization is required; see docs/windows-corert-toolchain.md')
    plan = json.loads((META / 'acquisition-plan.json').read_text())
    helper_base = 'https://raw.githubusercontent.com/mstorsjo/msvc-wine/' + plan['helper_commit'] + '/'
    ensure_pinned_file(HELPER, helper_base + 'vsdownload.py', EXPECTED_HELPER)
    ensure_pinned_file(HELPER.parent / 'LICENSE.txt', helper_base + 'LICENSE.txt',
                       plan['helper_files_sha256']['LICENSE.txt'])
    ensure_pinned_file(META / 'vs17-manifest.json', plan['manifest_url'], EXPECTED_MANIFEST)
    TC.mkdir(exist_ok=True)
    cmd = [sys.executable, str(HELPER), '--major', '17', '--manifest', str(META / 'vs17-manifest.json'),
           '--architecture', 'x64', '--host-arch', 'x64', '--only-host', 'no', '--with-default', 'no',
           '--with-sdk', 'no' if args.atl_only else 'yes', '--sdk-version', '10.0.26100', '--skip-recommended', '--skip-patch',
           '--accept-license', '--cache', str(TC / 'cache'), '--dest', str(TC / 'msvc-2022')]
    if args.selection_only:
        cmd.append('--print-selection')
    cmd.extend(ATL_PACKAGES if args.atl_only else PACKAGES)
    record = {
        'recorded_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'authorization': 'User explicitly accepted VS Community 2022 and Windows SDK terms and authorized original Microsoft packages for this project on 2026-11-01; communicated by parent agent.',
        'license_urls': LICENSES,
        'scope': 'Local private development of public CoreRT/NUI; original MSVC/ATL headers and libraries plus Windows SDK, no account/client execution or distribution.',
        'command': cmd, 'selection_only': args.selection_only, 'atl_only': args.atl_only,
    }
    record_path = META / ('selection-only-invocation.json' if args.selection_only else
                          'atl-acquisition.json' if args.atl_only else 'full-toolchain-invocation.json')
    record_path.write_text(json.dumps(record, indent=2) + '\n')
    result = subprocess.run(cmd, cwd=ROOT)
    record['exit_code'] = result.returncode
    record['finished_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    record_path.write_text(json.dumps(record, indent=2) + '\n')
    return result.returncode

if __name__ == '__main__':
    raise SystemExit(main())
