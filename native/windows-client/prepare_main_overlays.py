#!/usr/bin/env python3
"""Generate the single reviewed clang-cl curl C compatibility adaptation."""
import argparse
import hashlib
import json
from pathlib import Path

EXPECTED_CURL_OPENSSL_SHA256 = '75e30c8d8e370d9d1412b6c64389f082d4be699e257e44b271dca13a86924ab7'
ORIGINAL = b'void* hStore = CertOpenSystemStoreA(NULL, "ROOT");'
COMPATIBLE = b'void* hStore = CertOpenSystemStoreA(0, "ROOT");'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    path = args.source / 'vendor/curl/lib/vtls/openssl.c'
    original = path.read_bytes()
    digest = hashlib.sha256(original).hexdigest()
    if digest != EXPECTED_CURL_OPENSSL_SHA256 or original.count(ORIGINAL) != 1:
        raise SystemExit('Pinned curl Windows certificate-store source changed; review the compatibility adaptation.')
    generated = original.replace(ORIGINAL, COMPATIBLE, 1)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(generated)
    args.output.with_suffix('.json').write_text(json.dumps({
        'source': str(path), 'source_sha256': digest, 'replacement_count': 1,
        'original': ORIGINAL.decode(), 'generated': COMPATIBLE.decode(),
        'generated_sha256': hashlib.sha256(generated).hexdigest(),
        'reason': 'The unused HCRYPTPROV_LEGACY argument must be integer zero. The original Windows ROOT certificate import and all TLS verification remain unchanged.',
        'vendor_source_unchanged': path.read_bytes() == original,
    }, indent=2) + '\n')


if __name__ == '__main__':
    main()
