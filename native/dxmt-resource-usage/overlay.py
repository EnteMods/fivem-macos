#!/usr/bin/env python3
"""Apply one hash-bound source patch only inside an isolated DXMT build tree."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent

def sha(data):
    return hashlib.sha256(data).hexdigest()

def apply(source, report, check_only=False):
    source = source.absolute()
    report = report.absolute()
    if source.resolve(strict=True) != source or not source.is_dir():
        raise ValueError('Require a canonical source directory')
    relative = source.relative_to(ROOT / 'build')
    if not relative.parts or not relative.parts[0].startswith(('dxmt-resource-usage-', 'windows-dxmt-resource-usage-')):
        raise ValueError('Require a dedicated new DXMT resource-usage build tree')
    owner = ROOT / 'build' / relative.parts[0]
    if not report.is_relative_to(owner) or report.parent.resolve(strict=True) != report.parent or report.exists():
        raise ValueError('Require a new report in the same isolated build tree')
    for parent in [source, *source.parents]:
        if parent == ROOT:
            break
        if (parent / 'frozen-artifact-proof.json').exists():
            raise ValueError('Never modify a sealed build')
    manifest = json.loads((HERE / 'manifest.json').read_text())
    target = source / manifest['target']
    if target.resolve(strict=True) != target or not target.is_file():
        raise ValueError('Require the exact regular source file')
    data = target.read_bytes()
    blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
    if sha(data) != manifest['original_sha256'] or blob != manifest['original_git_blob_sha1']:
        raise ValueError('Pinned original DXMT source does not match')
    patch = ROOT / manifest['patch']
    if sha(patch.read_bytes()) != manifest['patch_sha256']:
        raise ValueError('Reviewed patch changed')
    full_commit_checked = False
    if (source / '.git').exists():
        commit = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
        if commit != manifest['revision']:
            raise ValueError('Unexpected full source revision')
        full_commit_checked = True
    command = ['git', 'apply', '--whitespace=error-all', str(patch)]
    subprocess.run(command[:2] + ['--check'] + command[2:], cwd=source, check=True)
    if not check_only:
        subprocess.run(command, cwd=source, check=True)
        if sha(target.read_bytes()) != manifest['patched_sha256']:
            raise ValueError('Patched source hash mismatch')
    result = {'revision': manifest['revision'], 'target': str(target.relative_to(ROOT)),
              'original_sha256': manifest['original_sha256'], 'patch_sha256': manifest['patch_sha256'],
              'result_sha256': sha(target.read_bytes()), 'source_changed': not check_only,
              'target_git_blob_verified': True, 'full_checkout_commit_checked': full_commit_checked,
              'full_checkout_provenance_is_caller_responsibility': not full_commit_checked,
              'runtime_started': False, 'provider_installed': False}
    with report.open('x') as output:
        json.dump(result, output, indent=2)
        output.write('\n')
    return result

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--check-only', action='store_true')
    args = parser.parse_args()
    print(json.dumps(apply(args.source, args.report, args.check_only)))
