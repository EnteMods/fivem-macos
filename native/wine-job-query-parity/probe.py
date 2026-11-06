#!/usr/bin/env python3
"""Compile and execute only authored x86_64 dependency API probes, never Wine."""
import datetime
import argparse
import json
import os
from pathlib import Path
import subprocess
from prepare import ROOT, WORK, FRAMEWORKS, GST_LIB, identity, own, sha


def environment():
    value = dict(os.environ)
    for key in list(value):
        if key.startswith(('DYLD_', 'WINE', 'GST_')) or key.lower().startswith('citizenfx_'):
            value.pop(key)
    for key in ('CPATH', 'C_INCLUDE_PATH', 'CPLUS_INCLUDE_PATH', 'LIBRARY_PATH', 'SDKROOT'):
        value.pop(key, None)
    value.update(DYLD_FALLBACK_LIBRARY_PATH=str(FRAMEWORKS) + ':' + str(GST_LIB),
                 DYLD_FALLBACK_FRAMEWORK_PATH=str(FRAMEWORKS),
                 GST_PLUGIN_PATH='', GST_PLUGIN_SYSTEM_PATH_1_0='', GST_REGISTRY_UPDATE='no',
                 GST_REGISTRY=str(WORK / 'probes/gst-registry.bin'), GST_REGISTRY_FORK='no',
                 MACOSX_DEPLOYMENT_TARGET='14.0')
    return value


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('group', choices=('basic', 'media'), default='basic', nargs='?')
    args = parser.parse_args()
    manifest = WORK / 'dependency-preparation.json'
    value = json.loads(manifest.read_text())
    for item in value['headers'] + value['licenses'] + value['source_generation_evidence'] + value['libraries']['closure']:
        path = Path(item['path'])
        if sha(path) != item['sha256'] or path.stat().st_size != item['bytes']:
            raise RuntimeError('Dependency changed since preparation')
    sdk = None
    if args.group == 'media':
        sdk_manifest = WORK / 'sdk-acquisition.json'
        sdk = json.loads(sdk_manifest.read_text())
        for item in sdk['selected_development_files'] + [sdk['license_notice']]:
            path = Path(item['path'])
            if sha(path) != item['sha256'] or path.stat().st_size != item['bytes']:
                raise RuntimeError('Original SDK development file changed')
    directory = own(WORK / 'probes')
    directory.mkdir(exist_ok=True)
    binary = own(directory / (args.group + '-api-probe'))
    command = ['/usr/bin/clang', '--target=x86_64-apple-macos14', '-std=c11', '-Wall', '-Wextra', '-Werror',
               '-I' + str(WORK / 'dev/include'), '-I' + str(WORK / 'dev/include/freetype2'),
               '-I' + str(WORK / 'dev/include/SDL2'),
               str(ROOT / ('native/wine-job-query-parity/probe-' + args.group + '.c'))]
    if args.group == 'media':
        sdk_dir = WORK / 'dev-sdk'
        command += ['-I' + str(sdk_dir / 'base/include/glib-2.0'),
                    '-I' + str(sdk_dir / 'base/lib/glib-2.0/include'),
                    '-I' + str(sdk_dir / 'core/include/gstreamer-1.0'),
                    '-I' + str(sdk_dir / 'libav/include'), '-L' + str(GST_LIB),
                    '-lgstvideo-1.0', '-lgstaudio-1.0', '-lgsttag-1.0', '-lgstbase-1.0',
                    '-lgstreamer-1.0', '-lgobject-2.0', '-lglib-2.0', '-lavformat', '-lavcodec', '-lavutil']
    else:
        command += ['-L' + str(FRAMEWORKS), '-lgnutls', '-lfreetype', '-lSDL2']
    command += ['-o', str(binary)]
    record = {'at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'dependency_manifest': identity(manifest), 'compile_command': command,
              'probe_source': identity(ROOT / ('native/wine-job-query-parity/probe-' + args.group + '.c')),
              'group': args.group, 'no_wine_or_prefix': True, 'runtime_libraries_modified': False, 'passed': False}
    if sdk is not None:
        record['original_sdk_manifest'] = identity(sdk_manifest)
    record['compiler_version'] = subprocess.check_output(['/usr/bin/clang', '--version'], text=True).strip()
    compiled = subprocess.run(command, env=environment(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=45)
    record.update(compile_exit=compiled.returncode, compile_output=compiled.stdout)
    if compiled.returncode == 0:
        record['binary'] = identity(binary)
        record['file_description'] = subprocess.check_output(['/usr/bin/file', '-b', str(binary)], text=True).strip()
        executed = subprocess.run([str(binary)], env=environment(), cwd=directory,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30)
        record.update(run_exit=executed.returncode, run_output=executed.stdout, passed=executed.returncode == 0)
    for item in value['libraries']['closure']:
        if sha(Path(item['path'])) != item['sha256']:
            raise RuntimeError('Original runtime library changed during own ABI probe')
    own(WORK / (args.group + '-api-probe-results.json')).write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record, indent=2))
    return 0 if record['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
