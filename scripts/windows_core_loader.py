#!/usr/bin/env python3
"""Compare a pinned CoreRT candidate with the local fix in an account-free Wine prefix."""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import stat
import subprocess
import tempfile

from probe_environment import assert_account_free_prefix, probe_prefix


ROOT = Path(__file__).resolve().parents[1]
PREFIX = ROOT / 'prefixes/corert-regression'
MODULE = re.compile(r'^([0-9a-f]+):[0-9a-f]+:trace:loaddll:\w+ Loaded L"[^"\n]*\\(CoreRT|ntdll)\.dll" at ([0-9a-f]+):',
                    re.IGNORECASE | re.MULTILINE)
WRITE_FAULT = re.compile(
    r'^(([0-9a-f]+):[0-9a-f]+):trace:seh:dispatch_exception code=c0000005 [^\n]*?addr=([0-9a-f]+)\n'
    r'\1:trace:seh:dispatch_exception +info\[0\]=0*1\n'
    r'\1:trace:seh:dispatch_exception +info\[1\]=([0-9a-f]+)', re.IGNORECASE | re.MULTILINE)


def classify_loader(log, exit_code):
    lines = log.splitlines()
    if 'OWN_LOADER_BEFORE_INIT' in lines:
        images = {(pid.lower(), dll.lower()): int(base, 16) for pid, dll, base in MODULE.findall(log)}
        for _, pid, instruction, target in WRITE_FAULT.findall(log):
            core = images.get((pid.lower(), 'corert'))
            ntdll = images.get((pid.lower(), 'ntdll'))
            if (core is not None and ntdll is not None
                    and (int(instruction, 16) - core, int(target, 16) - ntdll) == (0x1C471, 0x18D8)):
                return 'known_loader_write_fault'
    if exit_code == 0 and 'OWN_LOADER_COMPONENT_LOADED' in lines:
        return 'loaded'
    return 'timeout' if exit_code is None else 'fixture_failed'


def artifact(path, expected_hash=None):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 32 * 1024 * 1024:
        raise ValueError(f'Expected a bounded regular probe input: {path.name}')
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if len(data) != info.st_size or (expected_hash is not None and digest != expected_hash):
        raise ValueError(f'Unexpected probe input identity: {path.name}')
    return data, digest


def run_logged(command, log, env, directory, timeout):
    with log.open('x') as output:
        try:
            return subprocess.run(command, cwd=directory, env=env, stdout=output, stderr=subprocess.STDOUT,
                                  timeout=timeout).returncode
        except subprocess.TimeoutExpired:
            return None


def run_probe(root, candidate, candidate_sha256, fixture_dir):
    staged = root / 'build/windows-source-integration'
    manifest = json.loads((root / 'research/client-source-code-inputs-v12.json').read_text())
    known = {row['name']: row['sha256'] for row in manifest['files'] if row['name'] in ('CoreRT.dll', 'tbb12.dll')}
    candidate_bytes, _ = artifact(candidate, candidate_sha256)
    local_bytes, local_sha256 = artifact(staged / 'CoreRT.dll', known['CoreRT.dll'])
    common = {
        'corert_loader_probe.exe': artifact(fixture_dir / 'corert_loader_probe.exe'),
        'windows-fixture.dll': artifact(fixture_dir / 'auto-fixture/windows-fixture.dll'),
        'tbb12.dll': artifact(staged / 'tbb12.dll', known['tbb12.dll']),
    }
    spec = importlib.util.spec_from_file_location('matched_gta_runtime', root.parent / 'GTA-V-macOS/scripts/gta-macos.py')
    runtime = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runtime)
    prefix = root / 'prefixes' / PREFIX.name
    if prefix.resolve() == runtime.PREFIX.resolve():
        raise ValueError('Expected the separate CoreRT probe prefix')
    wine, server = str(runtime.WINE), str(runtime.ENGINE / 'bin/wineserver')
    env = runtime.environment()
    env.update(WINEPREFIX=str(prefix), WINESERVER=server,
               WINEDEBUG='-all,err+all,+seh,+loaddll,+pid', WINEDLLOVERRIDES='winemenubuilder.exe=d')
    folder = Path(tempfile.mkdtemp(prefix='corert-release-compare-', dir=root / 'build'))
    print(folder, flush=True)
    report = {'fixture_sha256': {name: digest for name, (_, digest) in common.items()}, 'cases': []}
    with probe_prefix(prefix, root=root):
        subprocess.run([server, '-w'], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=15, check=True)
        for label, data, digest in (('candidate', candidate_bytes, candidate_sha256), ('patched', local_bytes, local_sha256)):
            stage = folder / label
            stage.mkdir()
            for name, (payload, _) in common.items():
                (stage / name).write_bytes(payload)
            (stage / 'CoreRT.dll').write_bytes(data)
            logfile = stage / 'wine.log'
            startup_log = stage / 'startup.log'
            exit_code = None
            outcome = 'wine_startup_failed'
            try:
                startup = run_logged([wine, 'cmd.exe', '/d', '/c', 'echo OWN_WINE_READY'], startup_log, env, stage, 90)
                if startup == 0 and 'OWN_WINE_READY' in startup_log.read_text(errors='replace').splitlines():
                    exit_code = run_logged([wine, str(stage / 'corert_loader_probe.exe')], logfile, env, stage, 30)
                    outcome = classify_loader(logfile.read_text(errors='replace'), exit_code)
            finally:
                cleanup = []
                for flag in ('-k', '-w'):
                    try:
                        result = subprocess.run([server, flag], env=env, stdout=subprocess.DEVNULL,
                                                stderr=subprocess.DEVNULL, timeout=15)
                        cleanup.append(result.returncode)
                    except subprocess.TimeoutExpired:
                        cleanup.append(None)
            case = {'role': label, 'corert_sha256': digest, 'wine_startup_exit': startup,
                    'exit': exit_code, 'result': outcome, 'cleanup': cleanup}
            report['cases'].append(case)
            (folder / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
            print(json.dumps(case), flush=True)
            if cleanup[1] != 0:
                raise RuntimeError('Wine probe prefix did not become idle')
            assert_account_free_prefix(prefix, root=root)
    return all(case['result'] == 'loaded' for case in report['cases'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('candidate_dll', type=Path)
    parser.add_argument('candidate_sha256')
    parser.add_argument('fixture_build', type=Path)
    args = parser.parse_args()
    if not re.fullmatch('[0-9a-f]{64}', args.candidate_sha256):
        parser.error('Use the exact lowercase SHA-256 from the verified release or build report')
    raise SystemExit(0 if run_probe(ROOT, args.candidate_dll, args.candidate_sha256, args.fixture_build) else 1)
