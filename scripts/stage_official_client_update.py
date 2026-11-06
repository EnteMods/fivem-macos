#!/usr/bin/env python3
"""Stage a hash-pinned FiveM content manifest for offline Source update checks."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import hashlib
import json
import lzma
from pathlib import Path, PurePosixPath
import re
import tempfile
import urllib.request
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
CDN = 'https://content.cfx.re/updates'
MAX_FILE_BYTES = 512 * 1024 * 1024


@dataclass(frozen=True)
class ContentFile:
    path: PurePosixPath
    size: int
    packed_size: int
    sha256: str
    sha1: str

    def matches(self, data):
        return (len(data) == self.size and hashlib.sha256(data).hexdigest() == self.sha256
                and hashlib.sha1(data).hexdigest() == self.sha1)


def parse_manifest(data, expected_sha256):
    if not 0 < len(data) <= 512 * 1024 or hashlib.sha256(data).hexdigest() != expected_sha256:
        raise ValueError('Manifest bytes do not match the pinned SHA-256')
    root = ET.fromstring(data)
    if root.tag != 'CacheInfo' or not 0 < len(root) <= 2000:
        raise ValueError('Unexpected official content manifest shape')
    files = []
    names = set()
    for item in root:
        if item.tag != 'ContentFile' or set(item.attrib) != {'Name', 'Size', 'CompressedSize', 'SHA1Hash', 'SHA256Hash'}:
            raise ValueError('Unexpected file record or compression format')
        name = item.attrib['Name']
        relative = PurePosixPath(name)
        normalized = name.casefold()
        if (not relative.parts or relative.is_absolute() or relative.as_posix() != name
                or not re.fullmatch(r'[A-Za-z0-9_. /-]+', name)
                or any(part in ('.', '..') or part.rstrip(' .') != part for part in relative.parts)
                or normalized in names):
            raise ValueError('Unsafe or duplicate manifest path')
        size, packed = (int(item.attrib[key]) for key in ('Size', 'CompressedSize'))
        sha256, sha1 = (item.attrib[key].lower() for key in ('SHA256Hash', 'SHA1Hash'))
        if (not 0 <= packed <= MAX_FILE_BYTES or not 0 <= size <= MAX_FILE_BYTES or (size and not packed)
                or not re.fullmatch('[0-9a-f]{64}', sha256) or not re.fullmatch('[0-9a-f]{40}', sha1)):
            raise ValueError('Invalid file length or digest')
        names.add(normalized)
        files.append(ContentFile(relative, size, packed, sha256, sha1))
    if any(str(parent).casefold() in names for entry in files for parent in entry.path.parents):
        raise ValueError('A manifest file conflicts with a directory')
    if sum(entry.size for entry in files) > 2 * 1024 * 1024 * 1024:
        raise ValueError('Manifest exceeds the local staging size limit')
    return files


def read_seed(directory, entry):
    target = directory.joinpath(*entry.path.parts)
    if target.is_file() and target.resolve() == target and target.stat().st_size == entry.size:
        data = target.read_bytes()
        if entry.matches(data):
            return data
    return None


def download(entry):
    suffix = '' if entry.size == entry.packed_size else '.xz'
    url = f'{CDN}/{entry.sha256[:2]}/{entry.sha256[2:4]}/{entry.sha256}{suffix}'
    with urllib.request.urlopen(url, timeout=45) as response:
        if response.geturl() != url:
            raise ValueError('Unexpected redirect from the official content endpoint')
        packed = response.read(entry.packed_size + 1)
    if len(packed) != entry.packed_size:
        raise ValueError(f'Content download length differs for {entry.path}')
    if not suffix:
        return packed
    decoder = lzma.LZMADecompressor(memlimit=256 * 1024 * 1024)
    data = decoder.decompress(packed, max_length=entry.size + 1)
    if not decoder.eof or decoder.unused_data:
        raise ValueError(f'Unexpected XZ stream for {entry.path}')
    return data


def stage(manifest_path, manifest_sha256, seed_dirs, build_root):
    with manifest_path.open('rb') as source:
        manifest = source.read(512 * 1024 + 1)
    files = parse_manifest(manifest, manifest_sha256)
    folder = Path(tempfile.mkdtemp(prefix='official-content-update-', dir=build_root))
    output = folder / 'FiveM.app'
    output.mkdir()
    print(folder, flush=True)
    seeds = tuple(directory.resolve(strict=True) for directory in seed_dirs)

    def stage_file(entry):
        origin, data = 'manifest-empty', b'' if entry.size == 0 else None
        for seed in seeds:
            if data is not None:
                break
            data = read_seed(seed, entry)
            if data is not None:
                origin = 'verified-local-copy'
        if data is None:
            origin, data = 'official-cdn', download(entry)
        if not entry.matches(data):
            raise ValueError(f'Content digest differs for {entry.path}')
        path = output / entry.path
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as stream:
            stream.write(data)
        return {'name': entry.path.as_posix(), 'bytes': entry.size, 'sha256': entry.sha256, 'origin': origin}

    with ThreadPoolExecutor(max_workers=6) as executor:
        results = []
        for result in executor.map(stage_file, files):
            results.append(result)
            if len(results) % 100 == 0:
                print(f'Verified {len(results)}/{len(files)} manifest files', flush=True)
    (folder / 'manifest.xml').write_bytes(manifest)
    report = {'manifest_sha256': manifest_sha256, 'files': results}
    (folder / 'receipt.json').write_text(json.dumps(report, indent=2) + '\n')
    return folder


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path)
    parser.add_argument('manifest_sha256')
    parser.add_argument('--seed', type=Path, action='append', default=[])
    args = parser.parse_args()
    result = stage(args.manifest, args.manifest_sha256, args.seed, ROOT / 'build')
    print(result / 'receipt.json')
