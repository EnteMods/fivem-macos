#!/usr/bin/env python3
"""Build three fixed own Core9 cases using the accepted RPM compile commands."""
import copy
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from types import ModuleType

ROOT = Path(__file__).resolve().parents[2]
HERE = ROOT / 'native/windows-core-mapping-fixture'
BUILD = ROOT / 'build/windows-core-mapping-fixture'
REPORT = ROOT / 'research/windows-core-mapping-fixture-build.json'
PREVIOUS = 'native/windows-ntdll-hook-fixture/run.py'
PREVIOUS_SHA = '13be462ec03809537dc1b0ad83b4c98922ecd9f82fe8a53782e00d19847929fd'
CORE_REPORT = 'research/core-lifecycle-diagnostic-build.json'
CORE_REPORT_SHA = 'bb309c253a6c1e77d1ed520ffe04a81668728801f722437ab9d42944299511ae'
PROVIDERS = {
    'build/windows-core-lifecycle-diagnostic/CoreRT.dll': ('CoreRT.dll', '51b7d6432f8a32b404144d19a5abf0a16bcadc764971e99e6fcb12e708a16396'),
    'build/windows-core-lifecycle-diagnostic/clang_23.1_cxx17_64_md_relwithdebinfo/tbb12.dll':
        ('tbb12.dll', 'c3931068206dc672fc8a070285b8623804d45c051d1ac73f33a13c6497e33038'),
    'build/windows-mapping-policy/socialclub.dll':
        ('Program Files/Rockstar Games/Social Club/socialclub.dll', '7ada69ccb50339f3f0cc5cb650fbe37f2a4fb2a5ab85afe2f7a5469394f04393'),
    'build/windows-mapping-policy/mapping-target.dll':
        ('Program Files/Rockstar Games/Social Club/mapping-target.dll', '4aba15a984cbbbd54e053541f445596e9e45bfcfac4ca041971ab33493eca00d')}
REFERENCES = {CORE_REPORT: CORE_REPORT_SHA,
    'research/windows-mapping-policy-build.json': '26dabe93f68c4eea9b018ea2c4e9c726e6bfa0318141f310032d6e55ea271346',
    'native/windows-mapping-nt-policy/probe.cpp': '33e44511a43d94c908c745b1dcc618b3cf0b1d0578778896a69c60f417749299'}


def load_previous():
    path = ROOT / PREVIOUS
    if path.resolve(strict=True) != path or path.stat().st_nlink != 1:
        raise RuntimeError('Require the unchanged RPM fixture helper')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PREVIOUS_SHA:
        raise RuntimeError('RPM helper changed before execution')
    module = ModuleType('_core_mapping_original_rpm')
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def main():
    if sys.argv[1:]: raise RuntimeError('Only the fixed own build is accepted')
    previous = load_previous()
    reused = previous.verify_inputs()
    control = previous.load_control()
    sources = [control.identity(str((HERE / name).relative_to(ROOT))) for name in ('probe.cpp', 'build.py')]
    selected = [control.identity(name) for name in (*REFERENCES, *PROVIDERS)]
    for item in selected:
        expected = REFERENCES.get(item['path']) or PROVIDERS[item['path']][1]
        if item['sha256'] != expected: raise RuntimeError('A fixed Core9/provider/template input changed')
    core_record = json.loads(control.read(CORE_REPORT))
    if (core_record.get('compiled') is not True or core_record.get('build', {}).get('exit') != 0
            or core_record['artifact']['sha256'] != PROVIDERS['build/windows-core-lifecycle-diagnostic/CoreRT.dll'][1]
            or core_record['tbb_artifact']['sha256'] != PROVIDERS['build/windows-core-lifecycle-diagnostic/clang_23.1_cxx17_64_md_relwithdebinfo/tbb12.dll'][1]):
        raise RuntimeError('Require the actual Core9/TBB build pair')
    if BUILD.exists() or REPORT.exists() or BUILD.resolve(strict=False) != BUILD or REPORT.resolve(strict=False) != REPORT:
        raise RuntimeError('Never replace an existing Core mapping build or report')
    BUILD.mkdir()
    header = BUILD / 'role_config.h'
    windows_root = 'Z:' + str(BUILD).replace('/', '\\')
    header.write_text('#pragma once\n#define CFX_CORE_OWN_ROOT L' + json.dumps(windows_root) + '\n')
    runtime = []
    for name, (destination, digest) in PROVIDERS.items():
        target = BUILD / destination
        target.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(['/bin/cp', '-c', '-n', str(ROOT / name), str(target)], check=True)
        item = control.identity(str(target.relative_to(ROOT)))
        if item['sha256'] != digest: raise RuntimeError('A code-only provider copy differs')
        runtime.append(item)
    old = ROOT / 'build/windows-ntdll-hook-fixture-rpm'
    old_report = json.loads(control.read('research/windows-ntdll-hook-fixture-rpm-build.json'))
    commands = copy.deepcopy(old_report['build']['commands'])
    substitutions = {
        str(ROOT / 'native/windows-ntdll-hook-fixture/probe.cpp'): str(HERE / 'probe.cpp'),
        str(old): str(BUILD), '/Fo' + str(old / 'probe.obj'): '/Fo' + str(BUILD / 'probe.obj'),
        str(old / 'probe.obj'): str(BUILD / 'probe.obj'),
        '/out:' + str(old / 'ntdll_hook_fixture.exe'): '/out:' + str(BUILD / 'core_mapping_fixture.exe'),
        '/map:' + str(old / 'ntdll_hook_fixture.map'): '/map:' + str(BUILD / 'core_mapping_fixture.map')}
    seen = {key: 0 for key in substitutions}
    for command in commands:
        for index, argument in enumerate(command):
            if argument in substitutions:
                seen[argument] += 1; command[index] = substitutions[argument]
    library = str(ROOT / 'build/windows-hook-state-observer/own_minhook.lib')
    if len(commands) != 2 or commands[1].count(library) != 1 or any(value != 1 for value in seen.values()):
        raise RuntimeError('Unexpected fixed RPM compiler/linker command shape')
    commands[1].remove(library)
    log = BUILD / 'build.log'
    with log.open('x') as output:
        for command in commands:
            if subprocess.run(command, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT).returncode:
                raise RuntimeError('Own Core mapping compile/link failed; preserve build log')
    llvm = '/opt/homebrew/opt/llvm/bin/llvm-readobj'
    binary, obj = BUILD / 'core_mapping_fixture.exe', BUILD / 'probe.obj'
    inspected = subprocess.check_output([llvm, '--file-headers', '--coff-imports', str(binary)], text=True)
    directives = subprocess.check_output([llvm, '--coff-directives', str(obj)], text=True)
    if ('IMAGE_FILE_MACHINE_AMD64' not in inspected
            or {name.lower() for name in re.findall(r'^\s+Name: (.+)$', inspected, re.M)} != {'kernel32.dll'}
            or re.search(r'/DEFAULTLIB:libcmt(?:\.lib)?\b', directives, re.I) is None):
        raise RuntimeError('Require AMD64/MT with only KERNEL32 imports')
    inspection = BUILD / 'inspection.txt'; inspection.write_text(inspected + directives)
    runtime.insert(0, control.identity(str(binary.relative_to(ROOT))))
    if reused != previous.verify_inputs() or sources + selected != [control.identity(item['path']) for item in sources + selected]:
        raise RuntimeError('Original or own inputs changed during compilation')
    report = {'schema_version': 1, 'compiled': True, 'architecture': 'AMD64', 'runtime': '/MT',
        'source_evidence': sources, 'runtime_inputs': runtime, 'code_references': selected,
        'reused_rpm_helper': control.identity(PREVIOUS), 'reused_rpm_inputs': reused,
        'generated_header': control.identity(str(header.relative_to(ROOT))), 'object': control.identity(str(obj.relative_to(ROOT))),
        'inspection': control.identity(str(inspection.relative_to(ROOT))),
        'map': control.identity(str((BUILD / 'core_mapping_fixture.map').relative_to(ROOT))),
        'build': {'commands': commands, 'exit': 0, 'log': control.identity(str(log.relative_to(ROOT)))},
        'contract': {'modes': ['baseline', 'core-load-only', 'core-mapping'], 'checkpoints': 8,
            'apis': ['LdrLoadDll', 'NtCreateFile', 'NtOpenFile'], 'rvas': [0x15b50, 0xf420, 0xefe0],
            'ntdll_size': 4349952, 'read_width': 21, 'real_self_rpm': True, 'local_before_after': True,
            'core_freelibrary_or_private_stop': False, 'toolmode_or_componentloader_called': False,
            'own_source_marker': 0x46585231, 'own_target_marker': 0x46585232},
        'wine_client_prefix_or_source_started': False}
    with REPORT.open('x') as output:
        json.dump(report, output, indent=2); output.write('\n')
    print(json.dumps(control.identity(str(REPORT.relative_to(ROOT)))))


if __name__ == '__main__': main()
