#!/usr/bin/env python3
"""Translate the pinned Cfx openssl_ext.lua source enumeration to CMake input.

Original enumeration: Matthew Endsley, Copyright 2012-2014.
See LICENSE.openssl-enumeration.txt for the retained BSD terms.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    source = args.source.resolve()
    vendor = source / 'vendor/openssl'
    ext = source / 'code/vendor/openssl_ext.lua'
    cfg = source / 'code/vendor/openssl_cfg.lua'
    text = ext.read_text()
    defaults = text.split('opensslimpl.templates = {', 1)[1].split('local other_templates = {', 1)[0]
    overrides = text.split('local other_templates = {', 1)[1].split('if  _OPTIONS[', 1)[0]
    templates = dict(re.findall(r'^\s*(\w+)\s*=\s*"([^"]*)"', defaults, re.MULTILINE))
    templates.update(re.findall(r'^\s*(\w+)\s*=\s*"([^"]*)"', overrides, re.MULTILINE))
    exclusions = re.findall(r'"([^"]+)"', cfg.read_text().split('excluded_libs = {', 1)[1].split('}', 1)[0])
    crypto, ssl, inputs = [], [], []
    descriptors = sorted((vendor / 'crypto').rglob('build.info')) + [vendor / 'ssl/build.info', vendor / 'build.info']
    for descriptor in descriptors:
        relative_dir = descriptor.parent.relative_to(vendor).as_posix()
        if relative_dir == '.':
            relative_dir = ''
        inputs.append({'path': str(descriptor.relative_to(source)),
                       'sha256': hashlib.sha256(descriptor.read_bytes()).hexdigest()})
        library, selected, pending = '', [], ''
        for line in descriptor.read_text().splitlines():
            if not line:
                pending = ''
                continue
            pending += line
            if line.endswith('\\'):
                pending = pending[:-1]
                continue
            if not pending.startswith(('LIBS=', 'SOURCE[')):
                pending = ''
                continue
            def substitute(match):
                key = match.group(1)
                if key not in templates:
                    raise SystemExit('Unknown upstream OpenSSL template: ' + key)
                return templates[key]
            expanded = re.sub(r'\{\- \$target\{([^}]*)\} \-\}', substitute, pending)
            if expanded.startswith('LIBS='):
                library = expanded[5:]
            elif expanded.startswith('SOURCE['):
                prefix = 'SOURCE[' + library + ']='
                if not expanded.startswith(prefix):
                    raise SystemExit('Review upstream SOURCE enumeration: ' + str(descriptor))
                selected = expanded[len(prefix):].split()
            pending = ''
        if relative_dir in {'crypto/' + name for name in exclusions}:
            continue
        destination = ssl if relative_dir == 'ssl' else crypto
        if relative_dir and not relative_dir.startswith('crypto') and relative_dir != 'ssl':
            continue
        for name in selected:
            path = (source / 'code/vendor/openssl/asm' / relative_dir / (name[:-2] + '.asm')
                    if name.endswith('.s') else vendor / relative_dir / name)
            if not path.is_file():
                raise SystemExit('Missing original OpenSSL source: ' + str(path))
            relative = str(path.relative_to(source))
            if relative not in destination:
                destination.append(relative)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    for variable, paths in [('CFX_MAIN_OPENSSL_CRYPTO_SOURCES', crypto), ('CFX_MAIN_OPENSSL_SSL_SOURCES', ssl)]:
        lines += ['set(' + variable] + ['  "${CFX_SOURCE_DIR}/' + path + '"' for path in paths] + [')']
    args.output.write_text('\n'.join(lines) + '\n')
    record = {'scope': 'All source units selected by original Cfx openssl_ext.lua for Windows x64/five, with its original excluded groups. No replacement crypto or TLS policy changes.',
              'crypto_source_count': len(crypto), 'ssl_source_count': len(ssl),
              'crypto_c_count': sum(p.endswith('.c') for p in crypto),
              'crypto_masm_count': sum(p.endswith('.asm') for p in crypto),
              'upstream_excluded_groups': exclusions,
              'recipe_sha256': {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest() for p in (ext, cfg)},
              'build_info_inputs': inputs, 'crypto_sources': crypto, 'ssl_sources': ssl}
    args.output.with_suffix('.json').write_text(json.dumps(record, indent=2) + '\n')
    print('Original OpenSSL selection:', len(crypto), 'crypto and', len(ssl), 'SSL units')


if __name__ == '__main__':
    main()
