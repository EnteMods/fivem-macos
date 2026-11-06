#!/usr/bin/env python3
"""Replay the parity build's two recipes with separate User32 outputs."""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile

from overlay import apply


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BUILD = ROOT/'build/wine-job-query-parity/full-x86_64'
MAKE_SHA = '068b63388309e810763eb117cd76c3d8e7ff514dc04bf06c1f610a0e11a468e4'
DLL_SHA = '26e8adc9d50630a1f86f390f8196751430e4af3f08a02e8bb884c18617255813'
SOURCE = ROOT/'build/wine-job-query/source/dlls/user32/class.c'
OBJECT = 'dlls/user32/x86_64-windows/class.o'
DLL = 'dlls/user32/x86_64-windows/user32.dll'
HEADER = ROOT/'native/wine-numeric-diagnostics/cfx_numeric.h'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def recipe(text, target, variables):
    helper = ROOT/'native/wine-session-proxy-build/build.py'
    spec = importlib.util.spec_from_file_location('wine_build_rules', helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    block = module.rule(text, target)
    if block.count('\n\t') != 1:
        raise ValueError('Expected a single build recipe')
    command = block.split('\n\t', 1)[1].replace('\\\n', ' ').replace('$@', target)
    for name, value in variables.items():
        command = command.replace('$(' + name + ')', value)
    if any(char in command for char in ('$',';','`','|','>','<')):
        raise ValueError('Expected direct argv in Wine recipe')
    return shlex.split(command)


def pe_interface(path):
    llvm = '/opt/homebrew/opt/llvm/bin/llvm-readobj'
    output = subprocess.check_output([llvm, '--file-headers', '--coff-exports', '--coff-imports', path], text=True)
    if 'Machine: IMAGE_FILE_MACHINE_AMD64 (0x8664)' not in output:
        raise ValueError('Expected an AMD64 User32 DLL')
    exports = re.findall(r'Export \{\s+Ordinal: (\d+)\s+Name: ([^\n]*)', output)
    imports = [line.strip() for line in output.splitlines() if line.startswith(('  Name:', '  Symbol:'))]
    if not exports or not imports or not any(name == 'RegisterClassW' for _, name in exports):
        raise ValueError('Expected the original User32 interface')
    return exports, imports


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--resolved', action='store_true', help='Observe the name after the existing Wine resolution')
    args = parser.parse_args()
    makefile = BUILD/'Makefile'
    baseline = BUILD/DLL
    if sha(makefile) != MAKE_SHA or sha(baseline) != DLL_SHA:
        raise ValueError('Parity Makefile or baseline User32 changed')
    original_object = sha(BUILD/OBJECT)
    text = makefile.read_text()
    variables = {'x86_64_CC': '/opt/homebrew/bin/x86_64-w64-mingw32-gcc',
                 'x86_64_CFLAGS': '-g -O2', 'x86_64_LDFLAGS': ''}
    compile_argv = recipe(text, OBJECT, variables)
    link_argv = recipe(text, DLL, variables)
    if compile_argv[:4] != [variables['x86_64_CC'], '-c', '-o', OBJECT] or compile_argv.count(str(SOURCE)) != 1:
        raise ValueError('Unexpected class.o recipe')
    if link_argv[:4] != ['tools/winegcc/winegcc', '-o', DLL, '--wine-objdir'] or link_argv.count(OBJECT) != 1:
        raise ValueError('Unexpected user32.dll recipe')

    work = Path(tempfile.mkdtemp(prefix='wine-window-registration-', dir=ROOT/'build'))
    source = work/'class.c'
    obj = work/'class.o'
    dll = work/'x86_64-windows/user32.dll'
    dll.parent.mkdir()
    rendered = apply(SOURCE.read_bytes())
    if args.resolved:
        from resolved_overlay import apply as trace_resolved
        rendered = trace_resolved(rendered)
    source.write_bytes(rendered)
    shutil.copyfile(HEADER, work/HEADER.name)
    compile_argv = [str(obj) if arg == OBJECT else str(source) if arg == str(SOURCE) else arg for arg in compile_argv]
    link_argv = [str(dll) if arg == DLL else str(obj) if arg == OBJECT else arg for arg in link_argv]
    for command in (compile_argv, link_argv):
        subprocess.run(command, check=True, cwd=BUILD, timeout=90)

    exports, imports = pe_interface(dll)
    if (exports, imports) != pe_interface(baseline):
        raise ValueError('Candidate changed the User32 PE interface')
    if sha(baseline) != DLL_SHA or sha(BUILD/OBJECT) != original_object or sha(makefile) != MAKE_SHA:
        raise ValueError('Parity build inputs changed')
    report = {'baseline_sha256': DLL_SHA, 'source_sha256': sha(source), 'header_sha256': sha(HEADER),
              'candidate_sha256': sha(dll), 'provider': str(work.relative_to(ROOT)),
              'export_count': len(exports), 'imports_unchanged': True, 'exports_unchanged': True,
              'resolved_name_trace': args.resolved}
    (work/'build.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
