#!/usr/bin/env python3
"""Capture one own same-process DXGI experiment with the unchanged parity lifecycle."""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import stat

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
REPORT = 'research/windows-dxgi-swapchain-build.json'
REPORT_PIN = (4337, 'aa0e5f134e1f21667cc53b626a4f83bac8e18d35117b5ccc898d504deefed009')
BINARY = 'build/windows-dxgi-swapchain/dxgi_swapchain_probe.exe'
BINARY_PIN = (508416, '69f9fc6f5aae0f80fd27cc8fd1fd6151d1dda0f4dbbadac2b0797e652d5b53ae')
REUSE = {
    'native/wine-parity-probes/graphics.py': (15761, '5af8eacd28ebda5f32a1d2c3c5516ea5e48bc976433d53ea4d643e48f414de53'),
    'native/wine-parity-probes/health.py': (9662, 'b28736ae751c51ef190099f0d1ce2a1b5dd441af29704b5df1d609a87f681e1a'),
    'native/wine-parity-probes/run.py': (22555, '476315318538c8db93712ba74848d636a5af587492d590a2e33e4b4d3aae6fe7'),
    'native/wine-parity-probes/environment.py': (18569, '4af30c9481fe125d2ecf1b550e96c97610277ac44aa50e05c6bc3c57cd5f0e5d'),
    'native/windows-job-tests/run_query.py': (22545, 'f4020871a8abe55284976efdd9d6b6c84cbba325a405c145e6d61ba17f7ae07e'),
    'scripts/probe_environment.py': (7216, 'b3afd02bb39f4a7ca67842a348bb9e3b72ae7a3380270062daee03795720ed95'),
}
_graphics = None


def _raw(name):
    path = ROOT / name
    if path.resolve(strict=True) != path:
        raise RuntimeError('Require the exact regular code path')
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise RuntimeError('Require regular single-link code or evidence')
    raw = path.read_bytes()
    after = path.lstat()
    if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise RuntimeError('Code or evidence changed during read')
    return raw


def _identity(name):
    raw = _raw(name)
    return {'path': name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def _bound(name, pin):
    raw = _raw(name)
    if (len(raw), hashlib.sha256(raw).hexdigest()) != pin:
        raise RuntimeError('Fixed own DXGI input changed')
    return raw


def graphics():
    global _graphics
    payloads = {name: _bound(name, pin) for name, pin in REUSE.items()}
    if _graphics is None:
        name = 'native/wine-parity-probes/graphics.py'
        spec = importlib.util.spec_from_file_location('_own_dxgi_unchanged_graphics', ROOT / name)
        module = importlib.util.module_from_spec(spec)
        exec(compile(payloads[name], str(ROOT / name), 'exec'), module.__dict__)
        _graphics = module
    return _graphics


def _shape(item, expected):
    if (type(item) is not dict or set(item) != {'path', 'bytes', 'sha256'}
            or item['path'] != expected or type(item['bytes']) is not int or item['bytes'] <= 0
            or type(item['sha256']) is not str or re.fullmatch('[0-9a-f]{64}', item['sha256']) is None):
        raise RuntimeError('Unexpected fixed DXGI build-input role')


def verify_inputs():
    record = json.loads(_bound(REPORT, REPORT_PIN))
    sources = record.get('source_evidence')
    expected_sources = {str((HERE / name).relative_to(ROOT)) for name in ('probe.cpp', 'build.py')}
    if (type(sources) is not list or len(sources) != 2 or any(type(x) is not dict for x in sources)
            or {x.get('path') for x in sources} != expected_sources
            or record.get('compiled') is not True or record.get('runtime') != '/MT'
            or record.get('architecture') != 'AMD64' or record.get('build', {}).get('exit') != 0):
        raise RuntimeError('Unexpected complete fixed DXGI build report')
    build = 'build/windows-dxgi-swapchain/'
    obj = build + 'CMakeFiles/dxgi_swapchain_probe.dir/' + str(HERE / 'probe.cpp').lstrip('/') + '.obj'
    fixed = [(record.get('artifact'), BINARY),
        (record.get('toolchain'), 'native/windows-core/toolchain.cmake'),
        (record.get('reused_build_helper'), 'native/windows-winhttp-probe/build.py'),
        (record.get('generated_build_input'), build + 'CMakeLists.txt'),
        (record.get('object'), obj), (record.get('pe_inspection'), build + 'pe-inspection.txt'),
        (record.get('renderer_input_review'), 'research/dxmt-a444716-code-inputs.json'),
        (record['build'].get('log'), build + 'build.log'),
        (record['build'].get('compile_commands'), build + 'compile_commands.json')]
    for item in sources: _shape(item, item['path'])
    for item, name in fixed: _shape(item, name)
    if (record.get('runtime_inputs') != [record['artifact']]
            or (record['artifact']['bytes'], record['artifact']['sha256']) != BINARY_PIN):
        raise RuntimeError('Unexpected own DXGI runtime artifact')
    selected = sources + [item for item, _ in fixed]
    if any(_identity(item['path']) != item for item in selected):
        raise RuntimeError('Compiled own DXGI source or build evidence changed')
    context = graphics().verify_graphics_inputs()
    return {'probe_family': 'own-same-process-dxgi-swapchain', 'runtime_inputs': [record['artifact']],
        'source_inputs': [item for item in selected if item != record['artifact']],
        'build_reports': [{'path': REPORT, 'bytes': REPORT_PIN[0], 'sha256': REPORT_PIN[1]}],
        'runner_sources': [_identity(str((HERE / 'run.py').relative_to(ROOT))),
                           *[_identity(name) for name in REUSE]],
        'graphics_context_proof': context,
        'runtime_engine_manifest_required': graphics().runtime.MANIFEST_SHA,
        'capture_success_is_not_functional_success': True,
        'actual_game_descriptor_or_cross_process_behavior_claimed': False}


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result: raise ValueError('Duplicate field')
        result[key] = value
    return result


def _u32(value):
    return type(value) is int and 0 <= value <= 0xffffffff


def parse_output(lines, exitcode):
    accepted = []
    try:
        if type(exitcode) is not int or exitcode not in (0, 1): raise ValueError('Exit')
        if type(lines) is str: lines = lines.splitlines()
        if type(lines) not in (list, tuple) or not 3 <= len(lines) <= 13: raise ValueError('Count')
        if any(type(line) is not str or not line or len(line) > 1024 for line in lines): raise ValueError('Line')
        if sum(len(line) for line in lines) > 4096: raise ValueError('Budget')
        rows = [json.loads(line, object_pairs_hook=_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Number')))
                for line in lines]
        if any(type(row) is not dict for row in rows): raise ValueError('Object')
        expected = {'event': 'ready', 'schema': 1, 'width': 1280, 'height': 720, 'format': 28,
            'buffer_count': 2, 'sample_count': 1, 'swap_effect': 0, 'swapchain_flags': 2,
            'windowed': True, 'cross_process': False, 'present_called': False}
        ready = rows[0]
        if (set(ready) != set(expected) | {'windows_pid'} or not _u32(ready['windows_pid'])
                or not ready['windows_pid']
                or any(type(ready.get(k)) is not type(v) or ready[k] != v for k, v in expected.items())):
            raise ValueError('Ready')
        accepted.append(ready)
        failed = False
        api = []
        api_keys = {'event', 'stage', 'result_kind', 'status', 'succeeded', 'object_nonnull'}
        for row in rows[1:-1]:
            stage = len(api) + 1
            if (failed or set(row) != api_keys or row.get('event') != 'api'
                    or type(row.get('stage')) is not int or row['stage'] != stage or stage > 11
                    or type(row.get('result_kind')) is not int or row['result_kind'] != (1 if stage < 3 else 2)
                    or not _u32(row.get('status')) or type(row.get('succeeded')) is not bool
                    or type(row.get('object_nonnull')) is not bool):
                raise ValueError('Api')
            if ((stage < 3 and row['succeeded'] != row['object_nonnull'])
                    or (stage >= 3 and row['succeeded'] != (row['status'] < 0x80000000))):
                raise ValueError('Status')
            failed = not (row['succeeded'] and row['object_nonnull'])
            api.append(row); accepted.append(row)
        done = rows[-1]
        done_keys = {'event', 'last_stage', 'feature_level', 'create_swapchain_attempted',
            'swapchain_nonnull', 'query_interface_attempted', 'functional_success', 'window_destroyed',
            'class_unregistered', 'capture_complete', 'exit'}
        if (set(done) != done_keys or done.get('event') != 'completed' or not api
                or type(done.get('last_stage')) is not int or done['last_stage'] != len(api)
                or not _u32(done.get('feature_level')) or type(done.get('exit')) is not int
                or done['exit'] != exitcode
                or any(type(done.get(k)) is not bool for k in done_keys - {'event', 'last_stage', 'feature_level', 'exit'})):
            raise ValueError('Completion')
        functional = len(api) == 11 and not failed
        complete = done['window_destroyed'] and done['class_unregistered']
        if (not failed and not functional or done['functional_success'] != functional
                or done['create_swapchain_attempted'] != (len(api) >= 10)
                or done['swapchain_nonnull'] != (api[9]['object_nonnull'] if len(api) >= 10 else False)
                or done['query_interface_attempted'] != (len(api) == 11)
                or done['capture_complete'] != complete or exitcode != (0 if complete else 1)
                or (len(api) < 6 and done['feature_level'] != 0)
                or (len(api) >= 6 and api[5]['succeeded'] and api[5]['object_nonnull']
                    and done['feature_level'] != 0xb000)):
            raise ValueError('Coherence')
        accepted.append(done)
        return {'passed': complete and exitcode == 0, 'metadata_capture_passed': complete and exitcode == 0,
            'capture_complete': complete, 'functional_success': functional, 'events': accepted,
            'api_rejection_observed': failed, 'diagnostic_experiment_not_client_success': True}
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        return {'passed': False, 'metadata_capture_passed': False, 'capture_complete': False,
                'functional_success': False, 'events': accepted, 'error': 'invalid-fixed-dxgi-contract'}


def cases():
    verify_inputs()
    binary = ROOT / BINARY
    def diagnostics(lines, code):
        context = graphics().parse_provider_diagnostics(lines, code)
        context['prefix_bridge_binding'] = graphics().verify_bridge_binding()
        return context
    return [{'name': 'own_hwnd_discard_swapchain', 'binary': binary, 'cwd': binary.parent,
             'arguments': (), 'parse_output': parse_output, 'parse_diagnostics': diagnostics}]


def selftest():
    ready = {'event': 'ready', 'schema': 1, 'windows_pid': 32, 'width': 1280, 'height': 720,
        'format': 28, 'buffer_count': 2, 'sample_count': 1, 'swap_effect': 0, 'swapchain_flags': 2,
        'windowed': True, 'cross_process': False, 'present_called': False}
    api = [{'event': 'api', 'stage': i, 'result_kind': 1 if i < 3 else 2, 'status': 0,
            'succeeded': True, 'object_nonnull': True} for i in range(1, 12)]
    done = {'event': 'completed', 'last_stage': 11, 'feature_level': 0xb000,
        'create_swapchain_attempted': True, 'swapchain_nonnull': True, 'query_interface_attempted': True,
        'functional_success': True, 'window_destroyed': True, 'class_unregistered': True,
        'capture_complete': True, 'exit': 0}
    good = [ready, *api, done]
    encode = lambda rows: [json.dumps(row) for row in rows]
    assert parse_output(encode(good), 0)['functional_success'] is True
    rejected = copy.deepcopy(good[:-2] + [done])
    rejected[-2].update(status=0x80004005, succeeded=False, object_nonnull=False)
    rejected[-1].update(last_stage=10, swapchain_nonnull=False,
                        query_interface_attempted=False, functional_success=False)
    result = parse_output(encode(rejected), 0)
    assert result['passed'] is True and result['functional_success'] is False
    negative = []
    for index, key, value in [(0, 'windows_pid', True), (0, 'schema', True), (1, 'stage', 2),
            (3, 'status', True), (3, 'succeeded', False), (-1, 'functional_success', False),
            (-1, 'query_interface_attempted', False), (-1, 'feature_level', 0xffffffff),
            (-1, 'exit', False), (-1, 'last_stage', 10)]:
        rows = copy.deepcopy(good); rows[index][key] = value; negative.append((encode(rows), 0))
    rows = copy.deepcopy(good);rows[2]['private_address'] = 'PRIVATE';negative.append((encode(rows), 0))
    rows = copy.deepcopy(rejected);rows.insert(-1, copy.deepcopy(api[10]));negative.append((encode(rows), 0))
    negative.extend([(encode(good) + ['PRIVATE ARGS'], 0), (encode(good), False),
                     (encode(good)[:-1], 0), (encode(good) + [json.dumps(done)], 0)])
    duplicate = encode(good);duplicate[0] = duplicate[0][:-1] + ',"schema":1}'
    negative.append((duplicate, 0))
    for rows, code in negative:
        result = parse_output(rows, code)
        assert result['passed'] is False and 'PRIVATE' not in json.dumps(result)
    return {'positive': 2, 'negative': len(negative), 'runtime_started': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('inspect', 'run', 'selftest'))
    action = parser.parse_args().action
    if action == 'selftest':
        print(json.dumps(selftest())); return 0
    context = graphics()
    if action == 'inspect':
        print(json.dumps({'runtime': context.runtime.verify_runtime(), 'fixture': verify_inputs(),
                          'runtime_or_prefix_started': False}, indent=2)); return 0
    return context.runner.run_cases(cases(), verify_inputs=verify_inputs, role='dxgi-swapchain',
        environment_factory=context.graphics_environment, prepare_prefix=context.prepare_prefix)


if __name__ == '__main__':
    raise SystemExit(main())
