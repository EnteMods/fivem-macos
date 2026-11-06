#!/usr/bin/env python3
"""Acquire the original SDK for its generated headers; never run its installer."""
import json
from concurrent.futures import ThreadPoolExecutor
import os
import subprocess
import urllib.request
from prepare import WORK, identity, own, put, sha

SDK = {'url': 'https://gstreamer.freedesktop.org/data/pkg/osx/1.28.2/gstreamer-1.0-devel-1.28.2-universal.pkg',
       'bytes': 747886277, 'sha256': '810ad1b7fb25cb90aab00d1c0469a46119f5ede9d7df2b746a102895832b27d6',
       'identity_source': 'https://gstreamer.freedesktop.org/data/pkg/osx/1.28.2/gstreamer-1.0-devel-1.28.2-universal.pkg.sha256sum'}


def download_sdk(package):
    if package.exists():
        if package.stat().st_size != SDK['bytes'] or sha(package) != SDK['sha256']:
            raise RuntimeError('Existing SDK does not match the original published checksum')
        return
    package.parent.mkdir(parents=True, exist_ok=True)
    chunks = own(WORK / 'downloads/sdk-ranges')
    chunks.mkdir(exist_ok=True)
    size = 16 * 1024 * 1024
    ranges = [(start, min(start + size, SDK['bytes']) - 1) for start in range(0, SDK['bytes'], size)]

    def fetch(pair):
        start, end = pair
        path = own(chunks / (str(start) + '-' + str(end)))
        if path.exists() and path.stat().st_size == end - start + 1:
            return path
        request = urllib.request.Request(SDK['url'], headers={'User-Agent': 'Original-SDK-headers-only',
                                                               'Range': f'bytes={start}-{end}'})
        with urllib.request.urlopen(request, timeout=60) as source:
            if source.status != 206 or source.headers.get('Content-Range') != f'bytes {start}-{end}/{SDK["bytes"]}':
                raise RuntimeError('Publisher did not honor the exact bounded SDK byte range')
            payload = source.read(end - start + 2)
        if len(payload) != end - start + 1:
            raise RuntimeError('Truncated SDK range')
        with path.open('xb') as output:
            output.write(payload)
        print('Verified SDK transfer range', start, end, flush=True)
        return path

    with ThreadPoolExecutor(max_workers=8) as executor:
        parts = list(executor.map(fetch, ranges))
    combined = own(package.with_suffix(package.suffix + '.combined'))
    with combined.open('xb') as output:
        for path in parts:
            output.write(path.read_bytes())
    if combined.stat().st_size != SDK['bytes'] or sha(combined) != SDK['sha256']:
        raise RuntimeError('Reassembled SDK differs from the published original checksum')
    os.replace(combined, package)


def main():
    package = own(WORK / 'downloads/gstreamer-1.0-devel-1.28.2-universal.pkg')
    print('Fetching SHA256-pinned official SDK into the project; installer will not execute', flush=True)
    download_sdk(package)
    print('Official SDK checksum verified', flush=True)
    expanded = own(WORK / 'sdk-package')
    if not expanded.exists():
        subprocess.run(['/usr/sbin/pkgutil', '--expand', str(package), str(expanded)], check=True, timeout=120)
    inventory = sorted(str(path.relative_to(expanded)) for path in expanded.rglob('*') if path.is_file())
    headers = []
    for role, component in (('base', 'base-system-1.0'), ('core', 'gstreamer-1.0-core'), ('libav', 'gstreamer-1.0-libav')):
        payload = expanded / (component + '-devel-1.28.2-universal.pkg/Payload')
        destination = own(WORK / 'dev-sdk' / role)
        if not destination.exists():
            destination.mkdir(parents=True)
            subprocess.run(['/usr/bin/aa', 'extract', '-i', str(payload), '-d', str(destination),
                            '-include-type', 'f', '-include-path', './include',
                            '-include-path', './lib/glib-2.0/include', '-include-path', './lib/pkgconfig',
                            '-include-path', './share/licenses'], check=True, timeout=120)
        headers += [identity(path) for path in sorted(destination.rglob('*')) if path.is_file()]
    put(WORK / 'licenses/GStreamer-SDK-license.txt', (expanded / 'Resources/license.txt').read_bytes())
    record = {'original_sdk': SDK, 'verified_package': identity(package),
              'unexpanded_payload_files': inventory, 'selected_development_files': headers,
              'license_notice': identity(WORK / 'licenses/GStreamer-SDK-license.txt'),
              'package_installer_executed': False,
              'wine_or_prefix_started': False, 'runtime_modified': False}
    own(WORK / 'sdk-acquisition.json').write_text(json.dumps(record, indent=2) + '\n')
    print('Expanded package container only; extracted', len(headers), 'development files', flush=True)


if __name__ == '__main__':
    main()
