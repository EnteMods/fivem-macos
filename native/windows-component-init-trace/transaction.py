"""Guarded, recoverable transaction for the opt-in CitizenGame observer."""
import argparse
import configparser
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
PROOF = 'build/windows-component-init-trace-edw16lbb/frozen-artifact-proof.json'
PROOF_SHA = '7c5bc8123f5401242963c99e16bcdfe4e40d014db469d31267ccdcc71f9244ea'
BASE = '1f33031d7cdb2b4fd4558f9af442f62f50865326d607f8f2dfeb5764b8f28256'
DIAG = '7d459c35059a75cd0ae638189ff9dcab0d99deba6688fcaae92f462df3e49d68'
SOURCE = '6326c14dc3cad6cc5b29f45b1142381d6ceca698a133fe89ef2d648fb081fb3e'
RECEIPT = 'research/source-update-component-init-20261105.json'
BACKUP = 'build/checkpoints/source-update-component-init-20261105/CitizenGame.dll.previous'
ARTIFACT = 'build/windows-component-init-trace-edw16lbb/artifact/CitizenGame.dll'
REVISION = '88a413835e9d7f56633f249880a13f42297153a2'


def checked_file(path, expected=None):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise RuntimeError('Expected single-link regular file')
        h = hashlib.sha256()
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                h.update(block)
        digest = h.hexdigest()
        if expected is not None and digest != expected:
            raise RuntimeError('File hash mismatch')
        return digest, (info.st_dev, info.st_ino)
    finally:
        os.close(fd)


def evidence(root=ROOT):
    checked_file(root / PROOF, PROOF_SHA)
    proof = json.loads((root / PROOF).read_text())
    for key in ('artifact', 'baseline', 'source', 'trace_core', 'trace_platform', 'abi_review', 'build_record'):
        item = proof[key]
        path = root / item['path']
        checked_file(path, item['sha256'])
        if path.stat().st_size != item['bytes']:
            raise RuntimeError('Proof size mismatch')
    if (proof['artifact']['path'] != ARTIFACT or proof['artifact']['sha256'] != DIAG
            or proof['baseline']['sha256'] != BASE or proof['source']['sha256'] != SOURCE
            or any(proof.get(k) is not False for k in ('runtime_started', 'runtime_staged', 'prefix_accessed'))):
        raise RuntimeError('Proof identity mismatch')
    build = json.loads((root / proof['build_record']['path']).read_text())
    if (build.get('source_revision') != REVISION or build.get('build_passed') is not True
            or build.get('fixture_passed') is not True or build.get('compiled_all_four_units_fresh') is not True
            or len(build.get('header_inputs', [])) != 506 or len(build.get('reused_link_inputs', [])) != 15
            or len(build.get('tools', [])) != 6 or len(build.get('compile_commands', [])) != 4
            or build.get('artifact') != proof['artifact'] or build.get('baseline') != proof['baseline']):
        raise RuntimeError('Build evidence mismatch')
    entries = (build['header_inputs'] + build['reused_link_inputs'] + build['tools']
               + build['recipe_inputs'] + [build['original_source'], build['toolchain']]
               + [item[key] for item in build['compile_commands'] for key in ('source', 'object')])
    for item in entries:
        path = Path(item['path'])
        if not path.is_absolute():
            path = root / path
        if not path.is_file() or path.stat().st_size != item['bytes']:
            raise RuntimeError('Build input identity mismatch')
        with path.open('rb') as stream:
            hasher = hashlib.sha256()
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                hasher.update(block)
            digest = hasher.hexdigest()
        if digest != item['sha256']:
            raise RuntimeError('Build input hash mismatch')


def read_receipt(root, stage):
    path = root / RECEIPT
    if not path.exists() and not path.is_symlink():
        return None
    checked_file(path)
    record = json.loads(path.read_text())
    fixed = {'target': str((stage / 'CitizenGame.dll').relative_to(root)), 'baseline_sha256': BASE,
             'artifact_sha256': DIAG, 'proof_sha256': PROOF_SHA, 'source_sha256': SOURCE,
             'backup': BACKUP, 'source_revision': REVISION}
    if any(record.get(k) != v for k, v in fixed.items()) or record.get('status') not in ('prepared', 'verified', 'restored'):
        raise RuntimeError('Invalid transaction receipt')
    return record


def verify_receipt(stage, digest=None, root=ROOT):
    root, stage = Path(root), Path(stage)
    record = read_receipt(root, stage)
    status = record['status'] if record else 'absent'
    if status == 'prepared':
        raise RuntimeError('Transaction requires recovery')
    expected = DIAG if status == 'verified' else BASE
    actual, _ = checked_file(stage / 'CitizenGame.dll', expected)
    if digest is not None and digest != actual:
        raise RuntimeError('Selected module differs')
    if record:
        checked_file(root / BACKUP, BASE)
    evidence(root)
    return {'status': status, 'artifact_sha256': DIAG, 'baseline_sha256': BASE,
            'proof_sha256': PROOF_SHA, 'source_sha256': SOURCE,
            'selection': 'diagnostic' if status == 'verified' else 'baseline'}


def atomic_json(path, record, exclusive=False):
    fd, name = tempfile.mkstemp(prefix='.component-init-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as output:
            json.dump(record, output, indent=2)
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
        if exclusive:
            os.link(name, path)
            os.unlink(name)
        else:
            os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def copy_exclusive(source, dest, expected):
    checked_file(source, expected)
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with open(source, 'rb') as src, os.fdopen(fd, 'wb', closefd=False) as out:
            for block in iter(lambda: src.read(1024 * 1024), b''):
                out.write(block)
            out.flush()
            os.fsync(out.fileno())
        os.fchmod(fd, 0o444)
    finally:
        os.close(fd)
    checked_file(dest, expected)


def transition(action, root, stage, verify_inventory, quiescent):
    root, stage = Path(root), Path(stage)
    evidence(root)
    if not quiescent():
        raise RuntimeError('Prefix is not quiescent')
    target = stage / 'CitizenGame.dll'
    current, inode = checked_file(target)
    record = read_receipt(root, stage)
    backup = root / BACKUP
    if action == 'apply':
        if record is not None or backup.exists() or backup.is_symlink() or current != BASE:
            raise RuntimeError('Apply requires unused baseline transaction')
        verify_inventory(BASE)
        backup.parent.mkdir(parents=True, exist_ok=False)
        copy_exclusive(target, backup, BASE)
        record = {'status': 'prepared', 'target': str(target.relative_to(root)), 'baseline_sha256': BASE,
                  'artifact_sha256': DIAG, 'proof_sha256': PROOF_SHA, 'source_sha256': SOURCE,
                  'backup': BACKUP, 'source_revision': REVISION}
        atomic_json(root / RECEIPT, record, exclusive=True)
        desired, source, final = DIAG, root / ARTIFACT, 'verified'
    elif action == 'restore':
        if record is None or current not in (BASE, DIAG):
            raise RuntimeError('Restore requires known target and receipt')
        checked_file(backup, BASE)
        verify_inventory(current)
        if record['status'] == 'restored' and current != BASE:
            raise RuntimeError('Restored receipt contradicts target')
        desired, source, final = BASE, backup, 'restored'
    else:
        raise ValueError('Unknown transaction action')
    if current != desired:
        fd, name = tempfile.mkstemp(prefix='.citizengame-', dir=stage)
        os.close(fd)
        os.unlink(name)
        try:
            copy_exclusive(source, name, desired)
            if checked_file(target, current)[1] != inode:
                raise RuntimeError('Target identity changed')
            os.replace(name, target)
        finally:
            if os.path.exists(name):
                os.unlink(name)
    checked_file(target, desired)
    verify_inventory(desired)
    atomic_json(root / RECEIPT, {**record, 'status': final})
    return verify_receipt(stage, desired, root)


def verify_inventory(game, identity, expected_citizen):
    if not game.GAME_LINK.is_symlink() or game.GAME_LINK.resolve(strict=True) != game.GAME:
        raise RuntimeError('Game mapping changed')
    ini = game.STAGE / 'CitizenFX.ini'
    checked_file(ini)
    if ini.stat().st_size > 65536:
        raise RuntimeError('Unexpected game configuration')
    config = configparser.ConfigParser()
    config.read(ini, encoding='utf-8-sig')
    if config.get('Game', 'IVPath').rstrip('\\').upper() != 'G:':
        raise RuntimeError('Game mapping changed')
    game.verify_game(game.GAME, json.loads(game.STATUS.read_text())['game_executables'])
    expected = game.first.expected_files(marker=True)
    core_receipt = game.ROOT / identity.TRANSACTION
    if core_receipt.exists():
        r = json.loads(core_receipt.read_text())
        if (r['target'] != str((game.STAGE / 'CoreRT.dll').relative_to(game.ROOT)) or
            r['previous_sha256'] != identity.ORIGINAL_CORE or r['new_sha256'] != identity.FIXED_CORE or r['status'] != 'verified'):
            raise RuntimeError('Invalid core transaction')
        expected['CoreRT.dll'] = identity.FIXED_CORE
    nui_receipt = game.ROOT / identity.NUI_TRANSACTION
    if nui_receipt.exists():
        r = json.loads(nui_receipt.read_text())
        if (r['target'] != str((game.STAGE / 'nui-core.dll').relative_to(game.ROOT)) or
            r['previous_sha256'] != identity.ORIGINAL_NUI or r['new_sha256'] != identity.SOFTWARE_NUI or r['status'] != 'verified'):
            raise RuntimeError('Invalid NUI transaction')
        expected['nui-core.dll'] = identity.SOFTWARE_NUI
    active = 0
    for receipt_name, approved in identity.NET_HISTORY:
        path = game.ROOT / receipt_name
        if not path.exists():
            continue
        r = json.loads(path.read_text())
        if (r['target'] != str((game.STAGE / 'net.dll').relative_to(game.ROOT)) or
            r['previous_sha256'] != identity.ORIGINAL_NET or r['new_sha256'] != approved or
            r['status'] not in ('verified', 'restored')):
            raise RuntimeError('Invalid network transaction')
        if r['status'] == 'verified':
            active += 1
            expected['net.dll'] = approved
    if active or 'CitizenGame.dll' not in expected or len(expected) != 422:
        raise RuntimeError('Unexpected stage inventory')
    expected['CitizenGame.dll'] = expected_citizen
    for name, digest in expected.items():
        if game.first.digest(game.STAGE / name) != digest:
            raise RuntimeError('Candidate inventory changed')
    return len(expected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('apply', 'restore'))
    args = parser.parse_args()
    helper = ROOT / 'build/source-update-candidate-nqwlz36g/resume-candidate.py'
    spec = importlib.util.spec_from_file_location('component_transaction_resume', helper)
    resume = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(resume)
    game, identity = resume.game, resume.identity
    prelogin = game.verify_finished_prelogin()
    graphics, runtime, renderer, env = game.first.configure()
    if runtime['manifest_sha256'] != prelogin['engine_sha256'] or renderer['review']['sha256'] != prelogin['renderer_sha256']:
        raise RuntimeError('Runtime or renderer changed')
    def quiescent():
        try:
            return subprocess.run([graphics.runtime.ENGINE / 'bin/wineserver', '-w'], env=env,
                                  timeout=3, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
        except subprocess.TimeoutExpired:
            return False
    with game.first.prelogin_lock(prelogin):
        result = transition(args.action, ROOT, game.STAGE,
                            lambda expected: verify_inventory(game, identity, expected), quiescent)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
