#!/usr/bin/env python3
"""Stage one verified V12 NUI resize trial and recover an interrupted swap."""

import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile

import graphics_blit_launch as graphics
from run_main import ROOT, plain
from source_code_identity import STAGE


TARGET = STAGE / 'nui-core.dll'
CHECKPOINT = STAGE / '.nui-core.dll.resize-v12.previous'
BASELINE_PIN = (1919072, '8357a32e24361d50878b24198f4706b3ad89036200b127e5fa78b96c65e80594')
BUILD = ROOT / 'build/windows-nui-m103-build-ky6984xe'
BUILD_INPUTS = BUILD / 'inputs.json'
BUILD_INPUTS_PIN = (113311, 'c141caea5ca563034389894d956806fb8121c6197802be214adb8d9f67443c3d')
CANDIDATE = BUILD / 'objects/nui-core.dll'
CANDIDATE_PIN = (2923008, 'c19601d85f34b6201f910f1db6c9df0628720e20ea1d7885c230b776aab9e649')
LOAD_REPORT = BUILD / 'load-ctdxrbou/result.json'
LOAD_REPORT_PIN = (3053, '6e58a11dc31cdf2ac26898d3c84aa87a66f8d61ee0e90628cc9df0edf56621fc')
TIMING_BUILD = ROOT / 'build/windows-nui-m103-build-d_qad97t'
TIMING_BUILD_INPUTS = TIMING_BUILD / 'inputs.json'
TIMING_BUILD_INPUTS_PIN = (113448, '6c13010ee3516f3b38f65079cf3cd7a183b78859f96feed9c14ef99858d69215')
TIMING_CANDIDATE = TIMING_BUILD / 'objects/nui-core.dll'
TIMING_CANDIDATE_PIN = (2930688, '13cd508f74747cff8e4a6fb3115ce9cacd709ff5c9ed11c1519cc2923aa8c9e9')
TIMING_LOAD_REPORT = TIMING_BUILD / 'load-ts3qch9g/result.json'
TIMING_LOAD_REPORT_PIN = (3053, 'c851905bdf4c64a809558d6cdb13ca5b5c8335b8403cd3a91e6244dc3da95411')
SOURCE_REVISION = '0105063b0394b1b9d085c917a8dc9c9abf0a620f'
TRANSACTION_FILE = 'transaction.json'


def read_pinned_json(path, pin):
    graphics.require(path, pin)
    data = path.read_bytes()
    if (len(data), hashlib.sha256(data).hexdigest()) != pin:
        raise RuntimeError(f'NUI evidence changed during verification: {path.name}')
    try:
        result = json.loads(data)
    except ValueError as error:
        raise RuntimeError(f'Invalid NUI evidence: {path.name}') from error
    if type(result) is not dict:
        raise RuntimeError(f'Unexpected NUI evidence format: {path.name}')
    return result


def binding(report):
    if report == LOAD_REPORT:
        candidate, candidate_pin = CANDIDATE, CANDIDATE_PIN
        inputs, inputs_pin, report_pin = BUILD_INPUTS, BUILD_INPUTS_PIN, LOAD_REPORT_PIN
    elif report == TIMING_LOAD_REPORT:
        candidate, candidate_pin = TIMING_CANDIDATE, TIMING_CANDIDATE_PIN
        inputs, inputs_pin, report_pin = TIMING_BUILD_INPUTS, TIMING_BUILD_INPUTS_PIN, TIMING_LOAD_REPORT_PIN
    else:
        raise RuntimeError('Require a canonical successful V12 NUI load report')
    evidence = {
        'artifact': graphics.artifact(candidate, candidate_pin),
        'build_inputs': graphics.artifact(inputs, inputs_pin),
        'load_test': graphics.artifact(report, report_pin),
        'baseline_manifest': graphics.artifact(graphics.MANIFEST, graphics.MANIFEST_PIN),
        'baseline_sha256': BASELINE_PIN[1],
        'recovery_checkpoint': CHECKPOINT.relative_to(ROOT).as_posix(),
    }
    if report == TIMING_LOAD_REPORT:
        evidence['timing_diagnostics'] = True
    return evidence


def artifact_pin(artifact):
    return artifact['bytes'], artifact['sha256']


def verify_candidate(report):
    report = Path(report).absolute()
    evidence = binding(report)
    candidate, build_inputs, load_test = (evidence[key] for key in ('artifact', 'build_inputs', 'load_test'))
    graphics.require(graphics.MANIFEST, graphics.MANIFEST_PIN)
    graphics.require(ROOT / candidate['path'], artifact_pin(candidate))
    inputs = read_pinned_json(ROOT / build_inputs['path'], artifact_pin(build_inputs))
    if (inputs.get('source_revision') != SOURCE_REVISION or inputs.get('resize_overlay') is not True
            or inputs.get('menu_timing_overlay', False) is not evidence.get('timing_diagnostics', False)):
        raise RuntimeError('Require the reviewed public CEF 103 resize build')
    result = read_pinned_json(report, artifact_pin(load_test))
    expected = dict(candidate, path=str(ROOT / candidate['path']))
    markers = result.get('markers', ())
    if (result.get('candidate') != expected or result.get('passed') is not True or result.get('boot') != 0
            or result.get('exit') != 0 or result.get('cleanup') != [0, 0]
            or result.get('probe_timed_out') is not False
            or not any(marker.startswith('NUI_CEF_API_MATCH version=103 ') for marker in markers)
            or not any(marker.startswith('NUI_LOAD_PROBE_OK ') for marker in markers)):
        raise RuntimeError('The account-free load test did not admit the exact NUI candidate')
    plain(CHECKPOINT)
    if CHECKPOINT.exists():
        raise RuntimeError('An interrupted NUI resize launch requires explicit recovery')
    graphics.require(TARGET, BASELINE_PIN)
    return evidence


def read_checkpoint():
    plain(CHECKPOINT)
    if not CHECKPOINT.is_dir() or {path.name for path in CHECKPOINT.iterdir()} != {TARGET.name, TRANSACTION_FILE}:
        raise RuntimeError('Unexpected V12 NUI resize checkpoint contents')
    transaction = CHECKPOINT / TRANSACTION_FILE
    pin = graphics.identity(transaction)
    if pin[0] > 4096:
        raise RuntimeError('Unexpected V12 NUI resize transaction size')
    evidence = read_pinned_json(transaction, pin)
    prefix = evidence.get('source_prefix_identity')
    load_test = evidence.get('load_test')
    if type(load_test) is not dict or type(load_test.get('path')) is not str:
        raise RuntimeError('Unexpected V12 NUI resize checkpoint identity')
    if (type(prefix) is not list or len(prefix) != 2 or any(type(value) is not int or value < 0 for value in prefix)
            or evidence != dict(binding(ROOT / load_test['path']), source_prefix_identity=prefix)):
        raise RuntimeError('Unexpected V12 NUI resize checkpoint identity')
    graphics.require_prefix(prefix)
    graphics.require(CHECKPOINT / TARGET.name, BASELINE_PIN)
    return evidence


def require_active(evidence):
    graphics.require_lock()
    graphics.require(graphics.MANIFEST, graphics.MANIFEST_PIN)
    if evidence != read_checkpoint():
        raise RuntimeError('NUI resize checkpoint differs from this run')
    graphics.require(TARGET, artifact_pin(evidence['artifact']))


def restore_locked(evidence):
    """Restore the original NUI DLL under the Source lock once Wine is idle."""
    graphics.require_lock()
    graphics.require(graphics.MANIFEST, graphics.MANIFEST_PIN)
    if evidence != read_checkpoint():
        raise RuntimeError('NUI resize checkpoint differs from this run')
    candidate_pin = artifact_pin(evidence['artifact'])
    current = graphics.identity(TARGET)
    if current not in (BASELINE_PIN, candidate_pin):
        raise RuntimeError('Unexpected NUI DLL bytes. Preserve the original checkpoint for review.')

    with tempfile.TemporaryDirectory(prefix='.nui-resize-restore-', dir=STAGE) as folder:
        temporary = Path(folder)
        if current == candidate_pin:
            restored = temporary / TARGET.name
            graphics.copy_verified(CHECKPOINT / TARGET.name, restored, BASELINE_PIN)
            graphics.require_prefix(evidence['source_prefix_identity'])
            graphics.require(TARGET, candidate_pin)
            os.replace(restored, TARGET)
        graphics.require(TARGET, BASELINE_PIN)
        # Retire the entire checkpoint at once so an interruption cannot strand half a record.
        os.replace(CHECKPOINT, temporary / 'retired')


def activate(report, runtime, environment):
    graphics.require_lock()
    evidence = verify_candidate(report)
    candidate = evidence['artifact']
    candidate_pin = artifact_pin(candidate)
    evidence['source_prefix_identity'] = graphics.prefix_identity()
    graphics.require_idle(runtime, environment)
    with tempfile.TemporaryDirectory(prefix='.nui-resize-prepare-', dir=STAGE) as folder:
        temporary = Path(folder)
        prepared = temporary / TARGET.name
        checkpoint = temporary / 'checkpoint'
        checkpoint.mkdir(mode=0o700)
        graphics.copy_verified(TARGET, checkpoint / TARGET.name, BASELINE_PIN)
        graphics.copy_verified(ROOT / candidate['path'], prepared, candidate_pin)
        with (checkpoint / TRANSACTION_FILE).open('x') as output:
            json.dump(evidence, output, indent=2)
            output.write('\n')
        graphics.require_prefix(evidence['source_prefix_identity'])
        plain(CHECKPOINT)
        if CHECKPOINT.exists():
            raise RuntimeError('NUI resize checkpoint appeared during staging')
        os.replace(checkpoint, CHECKPOINT)
        try:
            if evidence != read_checkpoint():
                raise RuntimeError('NUI resize checkpoint changed during staging')
            graphics.require(TARGET, BASELINE_PIN)
            os.replace(prepared, TARGET)
            graphics.require(TARGET, candidate_pin)
        except BaseException:
            restore_locked(evidence)
            raise
    return evidence


def recover():
    from run_source import check_inputs, select_runtime_profile, source_runtime_environment, use_system_dyld_search
    from source_main_environment import source_main_prefix

    runtime, _ = select_runtime_profile('parity')
    environment = source_runtime_environment(runtime, 12)
    use_system_dyld_search(environment)
    with source_main_prefix(graphics.PREFIX, root=ROOT):
        graphics.require_idle(runtime, environment)
        plain(CHECKPOINT)
        if CHECKPOINT.exists():
            restore_locked(read_checkpoint())
        else:
            graphics.require(TARGET, BASELINE_PIN)
        plain(graphics.CHECKPOINT)
        if graphics.CHECKPOINT.exists():
            graphics.restore_locked(lambda: check_inputs(require_preflight=True, resume=True))
        else:
            check_inputs(require_preflight=True, resume=True)
    print('Source V12 baseline restored and verified')


if __name__ == '__main__':
    if sys.argv[1:] != ['recover']:
        raise SystemExit('Usage: nui_resize_launch.py recover')
    recover()
