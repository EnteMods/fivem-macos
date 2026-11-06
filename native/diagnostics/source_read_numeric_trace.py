#!/usr/bin/env python3
"""Separate read-diagnostic extraction using the unchanged numeric reader contract."""
import hashlib
import os
from pathlib import Path
import stat
import types

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / 'native/diagnostics/source_numeric_trace.py'
BASE_SHA = 'afc680dbe8e6e228f9ca0b26dbd1d88c651bf832f5968d9a0e3abc21fb80614e'
EDITS = (
    ("PARSER_PATH = 'native/wine-numeric-diagnostics/numeric_contract.py'",
     "PARSER_PATH = 'native/wine-read-diagnostics/numeric_contract.py'"),
    ("PARSER_SHA = 'f121fdf925ccc1a573adbdb843686b9d23b531cb430ce819bfa8d05213482c7a'",
     "PARSER_SHA = '8d4b2876158581d5b3bdc2a9b556ea463a092aa345dc4569e95deb4363a0255d'"),
    ("source_result.get('runtime_engine_profile') != 'numeric'",
     "source_result.get('runtime_engine_profile') != 'read'"),
    ("args.label + '-numeric-trace.json'", "args.label + '-read-numeric-trace.json'"),
)


def frozen_reader():
    current = ROOT
    for part in BASE.relative_to(ROOT).parts:
        current /= part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
            raise RuntimeError('Refusing an aliased or special frozen numeric reader')
        if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
            raise RuntimeError('Frozen numeric reader must be single-link code')
    descriptor = os.open(BASE, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise RuntimeError('Frozen numeric reader changed before reading')
        return source.read()


def derive(original):
    if type(original) is not bytes or hashlib.sha256(original).hexdigest() != BASE_SHA:
        raise RuntimeError('Require the exact frozen source numeric extractor bytes')
    rendered = original.decode()
    for before, after in EDITS:
        if rendered.count(before) != 1 or after in rendered:
            raise RuntimeError('Unexpected read extractor derivation inventory')
        rendered = rendered.replace(before, after, 1)
    restored = rendered
    for before, after in reversed(EDITS):
        if restored.count(after) != 1:
            raise RuntimeError('Unexpected derived read extractor inventory')
        restored = restored.replace(after, before, 1)
    if restored.encode() != original:
        raise RuntimeError('Read extractor must recover the complete frozen original')
    return rendered.encode()


def load_reader():
    original = frozen_reader()
    rendered = derive(original)
    reader = types.ModuleType('own_separate_source_read_numeric_extractor')
    reader.__file__ = str(Path(__file__).resolve())
    exec(compile(rendered, reader.__file__, 'exec'), reader.__dict__)
    return reader


def main(argv=None):
    return load_reader().main(argv)


if __name__ == '__main__':
    raise SystemExit(main())
