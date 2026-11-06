#!/usr/bin/env python3
"""Check the Steam OAuth exports expected by the public x64 client sources."""

import argparse
import json
from pathlib import Path
import re
import stat
import subprocess


LLVM_READOBJ = '/opt/homebrew/opt/llvm/bin/llvm-readobj'
# MSVC x64 names from references compiled against 88a41383's public headers.
REQUIRED = {
    'legitimacy.dll': {
        'IsSteamLinked': '?IsSteamLinked@legitimacy@cfx@@YA_NXZ',
        'AttemptSteamAuth': ('?AttemptSteamAuth@legitimacy@cfx@@YAXAEBV?$function@$$A6AXU?$pair@'
                             'V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@V12@@std@@@Z@std@@_N@Z'),
        'RefreshIdentities': '?RefreshIdentities@legitimacy@cfx@@YAXXZ',
    },
    'conhost-v2.dll': {
        'SetConfirmationModal': ('?SetConfirmationModal@ConHost@@YAXAEBV?$basic_string@DU?$char_traits@D@std@@'
                                 'V?$allocator@D@2@@std@@0V?$function@$$A6AX_N@Z@3@@Z'),
        'ClearConfirmationModal': '?ClearConfirmationModal@ConHost@@YAXXZ',
    },
}
EXPORT = re.compile(r'^Export \{\n +Ordinal: [0-9]+\n +Name: (\S+)', re.MULTILINE)
IMPORT_BLOCK = re.compile(r'^(?:Import|DelayImport) \{\n +Name: (\S+)\n(.*?)^\}', re.MULTILINE | re.DOTALL)
IMPORT_SYMBOL = re.compile(r'^ +Symbol: (\S+) \([0-9]+\)$', re.MULTILINE)
CONSUMERS = {
    'net.dll': {
        'legitimacy.dll': ('IsSteamLinked', 'AttemptSteamAuth'),
        'conhost-v2.dll': ('SetConfirmationModal', 'ClearConfirmationModal'),
    },
    'glue.dll': {'legitimacy.dll': ('RefreshIdentities',)},
}


def require_dll(library, inspection):
    if ('Machine: IMAGE_FILE_MACHINE_AMD64 (0x8664)' not in inspection
            or 'IMAGE_FILE_DLL (0x2000)' not in inspection):
        raise ValueError(f'Expected a Windows x64 DLL for {library}')


def missing_exports(library, inspection):
    require_dll(library, inspection)
    exports = set(EXPORT.findall(inspection))
    return [name for name, symbol in REQUIRED[library].items() if symbol not in exports]


def missing_imports(library, inspection):
    require_dll(library, inspection)
    imports = {}
    for provider, body in IMPORT_BLOCK.findall(inspection):
        imports.setdefault(provider.lower(), set()).update(IMPORT_SYMBOL.findall(body))
    return {provider: [name for name in names if REQUIRED[provider][name] not in imports.get(provider, ())]
            for provider, names in CONSUMERS[library].items()}


def inspect(client_dir, library, mode):
    path = client_dir.absolute() / library
    if not stat.S_ISREG(path.lstat().st_mode):
        raise SystemExit(f'Expected a regular file for {library}')
    return subprocess.check_output([LLVM_READOBJ, '--file-headers', mode, str(path)], text=True, timeout=15)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('client_dir', type=Path, help='Directory containing the four client DLLs to inspect')
    args = parser.parse_args()
    exports = {dll: missing_exports(dll, inspect(args.client_dir, dll, '--coff-exports')) for dll in REQUIRED}
    imports = {dll: missing_imports(dll, inspect(args.client_dir, dll, '--coff-imports')) for dll in CONSUMERS}
    exports_present = not any(exports.values())
    imports_present = not any(missing for providers in imports.values() for missing in providers.values())
    print(json.dumps({'required_exports_present': exports_present, 'required_imports_present': imports_present,
                      'missing_exports': exports, 'missing_imports': imports}, indent=2))
    return 0 if exports_present and imports_present else 1


if __name__ == '__main__':
    raise SystemExit(main())
