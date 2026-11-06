#!/usr/bin/env python3
"""Assemble original OpenSSL Win64 perlasm using its supported mingw64 flavour."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--asm', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--clang', required=True)
    args = parser.parse_args()
    source = args.source.resolve()
    relative = args.asm.resolve().relative_to(source / 'code/vendor/openssl/asm')
    directory = source / 'vendor/openssl' / relative.parent
    descriptor = directory / 'build.info'
    name = relative.with_suffix('.s').name
    text = descriptor.read_text().replace('\\\n', '')
    match = re.search(r'^GENERATE\[' + re.escape(name) + r'\]=(.*)$', text, re.MULTILINE)
    if not match:
        raise SystemExit('Missing original perlasm generator for ' + str(relative))
    command = match.group(1).split()
    if len(command) != 2 or command[1] != '$(PERLASM_SCHEME)' or not command[0].endswith('.pl'):
        raise SystemExit('Review changed perlasm generation arguments: ' + match.group(1))
    generator = directory / command[0]
    generated = args.output.parent / 'perlasm' / relative.with_suffix('.s')
    generated.parent.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env['CC'] = args.clang + ' --target=x86_64-pc-windows-msvc'
    generate = ['perl', str(generator), 'mingw64', str(generated)]
    result = subprocess.run(generate, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=True)
    if result.stdout:
        print(result.stdout, end='')
    assemble = [args.clang, '--target=x86_64-pc-windows-msvc', '-c', str(generated), '-o', str(args.output)]
    subprocess.run(assemble, check=True)
    record = {
        'scope': 'Original pinned OpenSSL perlasm Windows ABI/SEH implementation, emitted with its supported mingw64 COFF syntax for native Clang assembly. No handwritten crypto or changes to source.',
        'original_masm_input': str(relative), 'generator': str(generator.relative_to(source)),
        'generator_sha256': hashlib.sha256(generator.read_bytes()).hexdigest(),
        'original_masm_sha256': hashlib.sha256(args.asm.read_bytes()).hexdigest(),
        'win64_translator_sha256': hashlib.sha256((source / 'vendor/openssl/crypto/perlasm/x86_64-xlate.pl').read_bytes()).hexdigest(),
        'build_info_sha256': hashlib.sha256(descriptor.read_bytes()).hexdigest(),
        'commands': [generate, assemble], 'generated_sha256': hashlib.sha256(generated.read_bytes()).hexdigest(),
        'object_sha256': hashlib.sha256(args.output.read_bytes()).hexdigest(),
    }
    args.output.with_suffix('.json').write_text(json.dumps(record, indent=2) + '\n')


if __name__ == '__main__':
    main()
