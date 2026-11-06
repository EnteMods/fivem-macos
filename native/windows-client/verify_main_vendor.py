#!/usr/bin/env python3
"""Inspect real MAIN /MT archives and its complete link-only fixture."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
NAMES = ('openssl_crypto', 'openssl_ssl', 'nghttp2', 'curl', 'cpr', 'mbedtls',
         'tbb', 'boost_locale', 'breakpad', 'compiler_rt', 'xz', 'zstd', 'zlib',
         'minizip', 'hdiffpatch')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, default=ROOT / 'build/windows-client-vendor')
    parser.add_argument('--output', type=Path, default=ROOT / 'research/main-vendor-build.json')
    args = parser.parse_args()
    reader = '/opt/homebrew/opt/llvm/bin/llvm-readobj'
    archives = []
    for name in NAMES:
        path = args.build / ('cfx_main_' + name + '.lib')
        inventory = subprocess.check_output([reader, '--file-headers', '--coff-directives', str(path)], text=True)
        directives = '\n'.join(re.findall(r'Directive\(s\): (.*)', inventory))
        defaults = sorted(set(re.findall(r'[-/]DEFAULTLIB:([^\s]+)', directives, re.IGNORECASE)))
        machines = sorted(set(re.findall(r'Machine: ([^\n]+)', inventory)))
        if machines != ['IMAGE_FILE_MACHINE_AMD64 (0x8664)']:
            raise SystemExit('Unexpected machine in ' + name + ': ' + str(machines))
        if any(re.search(r'msvcrt|msvcprt|vcruntimed', lib, re.IGNORECASE) for lib in defaults):
            raise SystemExit('Dynamic/debug CRT default library in ' + name + ': ' + str(defaults))
        if not any(lib.lower() == 'libcmt.lib' for lib in defaults):
            raise SystemExit('No static release CRT directive in ' + name)
        archives.append({'target': 'cfx_main_' + name, 'path': str(path.relative_to(ROOT)),
                         'sha256': digest(path), 'bytes': path.stat().st_size,
                         'object_count': inventory.count('ImageFileHeader {'),
                         'machines': machines, 'default_libraries': defaults})
    executable = args.build / 'cfx_main_vendor_link_probe.exe'
    pe = subprocess.check_output([reader, '--coff-imports', '--file-headers', str(executable)], text=True)
    imports = re.findall(r'^  Name: ([^\n]+)', pe, re.MULTILINE)
    if any(re.search(r'msvcp|vcruntime|libcrypto|libssl|ucrtbase', name, re.IGNORECASE) for name in imports):
        raise SystemExit('Link-only fixture unexpectedly imports a dynamic CRT/OpenSSL library')
    source = ROOT / 'port/fivem'
    base = json.loads((ROOT / 'config/native-port.json').read_text())['base_revision']
    submodules = []
    for name in ('curl', 'cpr', 'mbedtls', 'nghttp2', 'openssl', 'tbb', 'breakpad',
                 'xz', 'zstd', 'zlib', 'minizip', 'hdiffpatch', 'boost-submodules/boost-locale'):
        relative = 'vendor/' + name
        row = subprocess.check_output(['git', 'ls-tree', base, '--', relative], cwd=source, text=True)
        expected = row.split()[2]
        actual = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source / relative, text=True).strip()
        dirty = subprocess.check_output(['git', 'status', '--porcelain'], cwd=source / relative, text=True)
        if actual != expected or dirty:
            raise SystemExit('Vendor pin/source mismatch: ' + relative)
        submodules.append({'path': relative, 'base_gitlink': expected, 'head': actual, 'unmodified': True})
    enumeration = json.loads((args.build / 'main-vendor-generated/openssl-sources.json').read_text())
    overlay = json.loads((args.build / 'main-vendor-generated/curl/openssl.json').read_text())
    commands = subprocess.check_output(['ninja', '-C', str(args.build), '-t', 'commands',
                                        'cfx_main_vendor_link_probe'], text=True)
    if '/FORCE' in commands or 'Wno-error=int-conversion' in commands:
        raise SystemExit('Unexpected error/diagnostic bypass in the final link graph')
    if any('/WHOLEARCHIVE:' + str(args.build / ('cfx_main_' + name + '.lib')) not in commands for name in NAMES):
        raise SystemExit('Link fixture did not force every real vendor archive')
    record = {
        'at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'source_revision': base,
        'scope': 'Original public MAIN Windows x64 /MT vendor graph; all enabled upstream OpenSSL units, static inspection plus complete WHOLEARCHIVE fixture link. No fixture/client/TLS execution by this verifier.',
        'passed': True, 'archive_count': len(archives), 'object_count': sum(a['object_count'] for a in archives),
        'archives': archives, 'pinned_clean_submodules': submodules,
        'openssl_selection': {k: enumeration[k] for k in ('crypto_source_count', 'ssl_source_count', 'crypto_c_count', 'crypto_masm_count', 'upstream_excluded_groups')},
        'openssl_assembler': 'Original perlasm mingw64 Windows-COFF/Win64-SEH flavour, native Clang integrated assembler; source and translator digests beside each generated object.',
        'curl_overlay': overlay,
        'fixture': {'path': str(executable.relative_to(ROOT)), 'sha256': digest(executable),
                    'wholearchive_all_targets': True, 'imports': imports, 'executed': False},
        'runtime_or_account_execution_by_this_verifier': False,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, indent=2) + '\n')
    print('Verified', len(archives), 'real AMD64 /MT archives and complete WHOLEARCHIVE link; no execution.')
    print('Evidence:', args.output)


if __name__ == '__main__':
    main()
