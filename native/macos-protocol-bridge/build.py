#!/usr/bin/env python3
"""Build/test a local ARM64 OAuth receiver without registration or real URL use."""
import hashlib
import json
from pathlib import Path
import plistlib
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = Path(__file__).resolve().parent


def identity(path):
    data = path.read_bytes()
    return {'path': path.relative_to(ROOT).as_posix(), 'bytes': len(data),
            'sha256': hashlib.sha256(data).hexdigest()}


def run(command, log):
    with log.open('w') as stream:
        value = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT)
    if value.returncode:
        raise RuntimeError(f'Build/test exit {value.returncode}; see {log.relative_to(ROOT)}')


def main():
    work = Path(tempfile.mkdtemp(prefix='macos-protocol-bridge-', dir=ROOT / 'build'))
    print(work, flush=True)
    app = work / 'FiveM Auth Bridge.app'
    macos = app / 'Contents/MacOS'
    macos.mkdir(parents=True)
    helper_source = SOURCE / 'handoff_current.py'
    helper_snapshot = work / 'handoff_current.py'
    shutil.copyfile(helper_source, helper_snapshot)
    helper = str(helper_snapshot)
    config = work / 'BuildConfiguration.swift'
    config.write_text('enum BuildConfiguration { static let helper = ' +
                      json.dumps(helper, ensure_ascii=False) +
                      '; static let helperSHA256 = ' +
                      json.dumps(identity(helper_snapshot)['sha256']) + ' }\n')
    common = ['/usr/bin/xcrun', 'swiftc', '-target', 'arm64-apple-macos14.0',
              '-parse-as-library', '-O']
    fixture = work / 'route-tests'
    run([*common, str(SOURCE / 'Route.swift'), str(SOURCE / 'RouteTests.swift'), '-o', str(fixture)],
        work / 'fixture-build.log')
    run([str(fixture)], work / 'fixture-results.log')
    executable = macos / 'FiveMAuthBridge'
    command = [*common, '-module-name', 'FiveMAuthBridge', str(SOURCE / 'Route.swift'),
               str(SOURCE / 'App.swift'), str(config), '-framework', 'AppKit', '-o', str(executable)]
    run(command, work / 'app-build.log')
    info = {
        'CFBundleIdentifier': 'local.fivem-macos.auth-bridge',
        'CFBundleName': 'FiveM Auth Bridge', 'CFBundleDisplayName': 'FiveM Auth Bridge',
        'CFBundleExecutable': 'FiveMAuthBridge', 'CFBundlePackageType': 'APPL',
        'CFBundleVersion': '3', 'CFBundleShortVersionString': '0.1.2',
        'LSMinimumSystemVersion': '14.0', 'NSHighResolutionCapable': True,
        'CFBundleURLTypes': [{'CFBundleTypeRole': 'Viewer',
            'CFBundleURLName': 'local.fivem-macos.auth-return', 'CFBundleURLSchemes': ['fivem']}],
    }
    plist = app / 'Contents/Info.plist'
    with plist.open('wb') as stream:
        plistlib.dump(info, stream)
    run(['/usr/bin/codesign', '--force', '--sign', '-', '--timestamp=none', str(app)], work / 'sign.log')
    run(['/usr/bin/codesign', '--verify', '--strict', str(app)], work / 'verify-sign.log')
    architecture = subprocess.check_output(['/usr/bin/lipo', '-archs', str(executable)], text=True).strip()
    if architecture != 'arm64':
        raise RuntimeError('Unexpected receiver architecture')
    report = {'schema': 1, 'role': 'local-normal-fivem-auth-return', 'architecture': architecture,
        'bundle_identifier': info['CFBundleIdentifier'], 'app': app.relative_to(ROOT).as_posix(),
        'executable': identity(executable), 'info_plist': identity(plist),
        'helper_snapshot': identity(helper_snapshot),
        'source_inputs': [identity(SOURCE / name) for name in ('Route.swift', 'App.swift', 'RouteTests.swift',
                                                                'handoff_current.py', 'test_handoff.py', 'build.py')],
        'build_configuration': identity(config), 'build_command': command,
        'synthetic_fixture_passed': True, 'synthetic_fixture': identity(fixture),
        'synthetic_fixture_result': identity(work / 'fixture-results.log'),
        'app_executed': False, 'real_oauth_used': False, 'registration_performed': False,
        'default_handler_changed': False, 'signature': 'local_ad_hoc_not_vendor_identity',
        'handoff_contract': {'executable': '/usr/bin/python3', 'arguments': ['fixed_absolute_handoff.py'],
            'stdin': 'one validated opaque UTF8 URL then EOF; no added newline; at most 65536 bytes',
            'stdout': '/dev/null', 'stderr': '/dev/null', 'success': 'helper normal exit 0; secondary process exited 0',
            'pending': 'helper exit 6 after 30 seconds; keep bridge open',
            'failure': 'other exit or abnormal termination; keep bridge open'},
        'limits': ['Native application UI and URL delivery not executed in this build step.',
                   'Python helper is a hash-pinned candidate snapshot beside this app; retain the build directory.',
                   'No Cfx ticket, client identity or security decision is generated or replaced.']}
    result = work / 'result.json'
    result.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(identity(result)), flush=True)


if __name__ == '__main__':
    main()
