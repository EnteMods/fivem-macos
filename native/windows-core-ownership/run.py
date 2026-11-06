#!/usr/bin/env python3
"""Exercise only own mapping DLLs and an own component against ordinary CoreRT DLLs."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import stat
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from probe_environment import _plain_path

BASE = ROOT / 'build/windows-main-candidate-27nal69i/cmake'
BASE_CORE = BASE / 'dependencies/launcher/dependencies/core/CoreRT.dll'
BASE_TBB = BASE / 'clang_23.1_cxx17_64_md_relwithdebinfo/tbb12.dll'
BASE_HASHES = {BASE_CORE: '6c77ed23f7f63bcb861cad649485620f172d20402f0b8d6c5003a636626d3ddc',
    BASE_TBB: 'ce7e8e0ca760f2f8d65e16c2794d46be438ede3a94d68d4b3600be5393daba89'}
FIXTURES = ('ownership_component_probe.exe', 'ownership-source.exe', 'ownership-target.dll', 'windows-fixture.dll')
MARKER = re.compile(r'OWN_COMPONENT_MAPPING phase=([1-6]) pid=([0-9]+) mode=([01]) marker=0x([0-9a-f]{8}) hits=([0-9]+)')


def data(path):
    _plain_path(path, ROOT)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= 32 * 1024 * 1024:
        raise RuntimeError('Require a bounded own code artifact')
    raw = path.read_bytes()
    return raw, {'path': str(path.relative_to(ROOT)), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def parse(lines, exit_code, fixed):
    events = []
    for line in lines:
        match = MARKER.fullmatch(line)
        if match is None:
            return {'passed': False, 'events': events, 'failure': 'Unexpected own fixture output'}
        phase, pid, mode, marker, hits = match.groups()
        events.append(dict(phase=int(phase), pid=int(pid), mode=int(mode), marker=int(marker, 16), hits=int(hits)))
    good = (exit_code == 0 and len(events) == 6
        and [event['phase'] for event in events] == list(range(1, 7))
        and len({event['pid'] for event in events}) == 1
        and all(event['pid'] > 0 and event['mode'] == int(fixed) for event in events))
    if good:
        expected = 0x46585232 if fixed else 0x46585231
        good = (events[0]['marker'] == 0x46585231 and events[0]['hits'] == 0
            and events[1]['marker'] == 0x46585232 and events[1]['hits'] > 0
            and events[2]['marker'] == events[3]['marker'] == 0
            and events[4]['marker'] == events[5]['marker'] == expected
            and (events[4]['hits'] > 0 if fixed else events[4]['hits'] == 0))
    return {'passed': good, 'events': events, 'original_dll_loses_mapping': good and not fixed,
        'fixed_dll_preserves_mapping': good and fixed, 'client_or_authentication_tested': False}


def main(folder):
    folder = folder.absolute()
    if (folder.parent != ROOT / 'build'
            or re.fullmatch('windows-core-ownership-[a-z0-9_]+', folder.name) is None):
        raise ValueError('Use the isolated owned-hook build directory')
    _plain_path(folder, ROOT)
    record = json.loads(data(folder / 'result.json')[0])
    core, tbb = folder / 'cmake/CoreRT.dll', folder / 'cmake/clang_23.1_cxx17_64_md_relwithdebinfo/tbb12.dll'
    fixture_paths = [folder / 'cmake/fixture' / name for name in FIXTURES]
    if (record.get('source_revision') != '88a413835e9d7f56633f249880a13f42297153a2'
            or record.get('build_exit') != 0 or record.get('native_tests_passed') != 3
            or record.get('compiled_source_sha256') != 'c64b2f587608034c90c9b5b6ec6cb6206c698f0ee3f230ce6f035fb83eee43cd'
            or record.get('artifact', {}).get('path') != str(core.relative_to(ROOT))
            or record.get('tbb_artifact', {}).get('path') != str(tbb.relative_to(ROOT))
            or [item.get('path') for item in record.get('fixture_inputs', [])] != [str(path.relative_to(ROOT)) for path in fixture_paths]):
        raise RuntimeError('Require the exact completed ordinary CoreRT and fixture build')
    expected = [record['artifact'], record['tbb_artifact'], *record['fixture_inputs']]
    paths = [core, tbb, *fixture_paths]
    for path, identity in zip(paths, expected):
        if data(path)[1] != identity:
            raise RuntimeError('A compiled own artifact changed')
    for path, checksum in BASE_HASHES.items():
        if data(path)[1]['sha256'] != checksum:
            raise RuntimeError('Original comparison CoreRT/TBB changed')
    work = Path(tempfile.mkdtemp(prefix='ownership-runtime-', dir=folder))
    staged = []
    cases = []
    for label, selected_core, selected_tbb, fixed in (
            ('baseline', BASE_CORE, BASE_TBB, False), ('fixed-original-tbb', core, BASE_TBB, True),
            ('fixed-rebuilt-tbb', core, tbb, True)):
        directory = work / label
        directory.mkdir()
        for name, source in [('CoreRT.dll', selected_core), ('tbb12.dll', selected_tbb), *zip(FIXTURES, fixture_paths)]:
            target = directory / name
            target.write_bytes(data(source)[0])
            staged.append(data(target)[1])
        cases.append(dict(name=label, binary=directory / FIXTURES[0], cwd=directory,
            arguments=('--fixed' if fixed else '--baseline',),
            parse_output=lambda lines, code, fixed=fixed: parse(lines, code, fixed)))
    adapter = ROOT / 'native/wine-parity-probes/run.py'
    spec = importlib.util.spec_from_file_location('owned_core_parity_lifecycle', adapter)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)

    def verify():
        if [data(path)[1] for path in paths] != expected:
            raise RuntimeError('Owned runtime inputs changed before the fixture')
        if [data(ROOT / row['path'])[1] for row in staged] != staged:
            raise RuntimeError('A staged own fixture changed')
        return {'runtime_inputs': staged, 'source_inputs': [data(Path(__file__).resolve())[1]],
            'build_reports': [data(folder / 'result.json')[1]],
            'source_client_or_authenticated_prefix_used': False}

    return runner.run_cases(cases, verify_inputs=verify, role='corert-owned-component-mapping')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('build_directory', type=Path)
    args = parser.parse_args()
    raise SystemExit(main(args.build_directory))
