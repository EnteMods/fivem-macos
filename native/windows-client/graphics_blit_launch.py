#!/usr/bin/env python3
"""One-run graphics-blit overlay and recovery for the pinned Source V12 client."""
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

from run_main import ROOT, REVISION, plain, sha
from source_code_identity import STAGE

PREFIX = ROOT / 'prefixes/fivem-source-main'
TARGET = STAGE / 'rage-graphics-five.dll'
CHECKPOINT = STAGE / '.rage-graphics-five.dll.blit-v12.previous'
SOURCE = ROOT / 'build/windows-graphics-blit-diagnostics/rage-graphics-five.dll'
REPORT = ROOT / 'research/graphics-blit-diagnostics-build.json'
MANIFEST = ROOT / 'research/client-source-code-inputs-v12.json'
MANIFEST_PIN = (174675, '410d70694279d659ab84b90841eea547bdfa3c333b17e5f6bd9d0125c8a3d9b2')
REPORT_PIN = (4380, '588f7f20df8a5985e138a93e10d6e97db9fb702e16e7510979e42255abbc758a')
BASELINE_PIN = (1238528, 'a68f20b246393a24db05c727e6479c4cbfe3110c649df57d55871dc74f033cdf')
CANDIDATE_PIN = (1248256, '4d643959b71c7138c12435a65ca9341fbd63dd8da5695f793ef1b0f05d3f92c8')
GATE_SOURCE = ROOT / 'build/windows-graphics-blit-gates/rage-graphics-five.dll'
GATE_REPORT = ROOT / 'research/graphics-blit-gates-build.json'
GATE_REPORT_PIN = (2794, '0efc3c056a436f9201d969c8e230cd91c981ea693661a6b261697b55cf319aad')
GATE_CANDIDATE_PIN = (1250816, 'b1e9e21749c5cb28159a27fa3ad5e0a0eefb7b7a0475ef3090709a675060ce64')
VERTEX_SOURCE = ROOT / 'build/windows-graphics-blit-vertices/rage-graphics-five.dll'
VERTEX_REPORT = ROOT / 'research/graphics-blit-vertices-build.json'
VERTEX_REPORT_PIN = (3448, '2848a3f7a0d32d0ee984abef188e008dfd826d40f23425bccec1b49bb3795440')
VERTEX_CANDIDATE_PIN = (1269760, '300d62d22a148774ba04b09f9a5d13e338e8683eee05103c2d7df18658b6eb99')
PROJECTION_SOURCE = ROOT / 'build/windows-graphics-blit-projection/rage-graphics-five.dll'
PROJECTION_REPORT = ROOT / 'research/graphics-blit-projection-build.json'
PROJECTION_REPORT_PIN = (4294, 'db39cd80d812a3e7134027025ca3b93897827c06c4862f1856b2973ac0e42780')
PROJECTION_CANDIDATE_PIN = (1278464, '1eb9781c5987a52f451de2b2a0735fd21aea53ec7f9a3599f6e8a38ddb8a8bad')
Y_PROBE_SOURCE = ROOT / 'build/windows-graphics-blit-projection-y-probe/rage-graphics-five.dll'
Y_PROBE_REPORT = ROOT / 'research/graphics-blit-projection-y-probe-build.json'
Y_PROBE_REPORT_PIN = (4377, '30339ca7d75fe735ec5bad0a16e88b04cd61a30029a937b0e6f53fe524889144')
Y_PROBE_CANDIDATE_PIN = (1278464, '830b38926fb2b1d3bcd99f8473bcdbbdbb5009c35882f1c031646068a4f5af53')
ALIGNED_SOURCE = ROOT / 'build/windows-graphics-blit-projection-aligned/rage-graphics-five.dll'
ALIGNED_REPORT = ROOT / 'research/graphics-blit-projection-aligned-build.json'
ALIGNED_REPORT_PIN = (4410, '2bb02f4696cd25aec4c8b69856fd0698b6a3ca87d136074a11a2fa741be651c7')
ALIGNED_CANDIDATE_PIN = (1278464, '69e14cb430a71e3a2a16ffa72bb1f283fa5a0674f13a87f3c3a4ed13a4ffa1db')
SHARPNESS_SOURCE = ROOT / 'build/windows-graphics-blit-projection-sharpness/rage-graphics-five.dll'
SHARPNESS_REPORT = ROOT / 'research/graphics-blit-projection-sharpness-build.json'
SHARPNESS_REPORT_PIN = (4860, '692e0b3cd11bc76d915e67924ef1961565bec59952e00bcea90b019156c9d7a4')
SHARPNESS_CANDIDATE_PIN = (1288192, '41cc689bbee946f8ac98e982d923e16a3bcf3e1d2a1181d23fbbecacb2298ec8')
NATIVE_EXTENTS_SOURCE = ROOT / 'build/windows-graphics-blit-projection-sharpness-native-extents/rage-graphics-five.dll'
NATIVE_EXTENTS_REPORT = ROOT / 'research/graphics-blit-projection-sharpness-native-extents-build.json'
NATIVE_EXTENTS_REPORT_PIN = (5894, '560ffab8bb5b19dfac80461cde23233a60798a84ca2f66579760a578e3c101f0')
NATIVE_EXTENTS_CANDIDATE_PIN = (1288704, '74b0db771c24114b056e80b136de180b7e05019a0536d02a94aeda7514dbd3c4')
FAST_EXTENTS_SOURCE = ROOT / 'build/windows-graphics-blit-projection-native-extents-fast/rage-graphics-five.dll'
FAST_EXTENTS_REPORT = ROOT / 'research/graphics-blit-projection-native-extents-fast-build.json'
FAST_EXTENTS_REPORT_PIN = (6308, 'bb778bf85bfb727b3b5b07675a3bde517aa819d80ab88fcab5ac44294ab4f0ae')
FAST_EXTENTS_CANDIDATE_PIN = (1278464, '062f968fb3e5f8de60c6a9da679eb5e4f6ec5224d8a5ff3d915935304f43ea1d')
FULLSCREEN_Y_SOURCE = ROOT / 'build/windows-graphics-blit-projection-retina-fullscreen-y/rage-graphics-five.dll'
FULLSCREEN_Y_REPORT = ROOT / 'research/graphics-blit-projection-retina-fullscreen-y-build.json'
FULLSCREEN_Y_REPORT_PIN = (7201, 'd75c79e5d2ee77a91e0742a5ab1e27980097dc31180e4e2f499517d603599306')
FULLSCREEN_Y_CANDIDATE_PIN = (1283584, '6abf9f2b877d7db64d47705565f62607f51810d9f46712dfe7e2d643613acded')


def identity(path):
    plain(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise RuntimeError('Graphics code or evidence is not a regular single-link file')
    value = before.st_size, sha(path)
    after = path.lstat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise RuntimeError('Graphics code or evidence changed during verification')
    return value


def require(path, pin):
    if identity(path) != pin:
        raise RuntimeError('Graphics blit input differs from its reviewed identity: ' + path.name)


def artifact(path, pin):
    return {'path': str(path.relative_to(ROOT)), 'bytes': pin[0], 'sha256': pin[1]}


def verify_candidate(manifest, *, gate_census=False, vertices=False, projection=False, y_probe=False, aligned=False,
                     sharpness=False, native_extents=False, fast_extents=False, fullscreen_y=False):
    if manifest != MANIFEST:
        raise RuntimeError('Graphics blit requires the fixed V12 baseline manifest')
    require(manifest, MANIFEST_PIN)
    if vertices and not gate_census:
        raise ValueError('Vertex measurements require gate tracing')
    if projection and not vertices:
        raise ValueError('Projection A/B requires vertex tracing')
    if ((y_probe or aligned) and not projection) or (y_probe and aligned):
        raise ValueError('Require one explicit projection Y variant')
    if sharpness and not aligned:
        raise ValueError('Sharpness measurement requires the aligned projection')
    if fast_extents and (not native_extents or not aligned or sharpness):
        raise ValueError('Fast extents require the aligned native projection without sharpness measurement')
    if native_extents and not (sharpness or fast_extents):
        raise ValueError('Native menu extents require sharpness measurement')
    if fullscreen_y and not fast_extents:
        raise ValueError('The fullscreen Y trial requires fast native extents')
    if fullscreen_y:
        source, source_pin = FULLSCREEN_Y_SOURCE, FULLSCREEN_Y_CANDIDATE_PIN
        report_path, report_pin = FULLSCREEN_Y_REPORT, FULLSCREEN_Y_REPORT_PIN
    elif fast_extents:
        source, source_pin = FAST_EXTENTS_SOURCE, FAST_EXTENTS_CANDIDATE_PIN
        report_path, report_pin = FAST_EXTENTS_REPORT, FAST_EXTENTS_REPORT_PIN
    elif native_extents:
        source, source_pin = NATIVE_EXTENTS_SOURCE, NATIVE_EXTENTS_CANDIDATE_PIN
        report_path, report_pin = NATIVE_EXTENTS_REPORT, NATIVE_EXTENTS_REPORT_PIN
    elif sharpness:
        source, source_pin = SHARPNESS_SOURCE, SHARPNESS_CANDIDATE_PIN
        report_path, report_pin = SHARPNESS_REPORT, SHARPNESS_REPORT_PIN
    elif aligned:
        source, source_pin, report_path, report_pin = ALIGNED_SOURCE, ALIGNED_CANDIDATE_PIN, ALIGNED_REPORT, ALIGNED_REPORT_PIN
    elif y_probe:
        source, source_pin, report_path, report_pin = Y_PROBE_SOURCE, Y_PROBE_CANDIDATE_PIN, Y_PROBE_REPORT, Y_PROBE_REPORT_PIN
    elif projection:
        source, source_pin = PROJECTION_SOURCE, PROJECTION_CANDIDATE_PIN
        report_path, report_pin = PROJECTION_REPORT, PROJECTION_REPORT_PIN
    elif vertices:
        source, source_pin, report_path, report_pin = VERTEX_SOURCE, VERTEX_CANDIDATE_PIN, VERTEX_REPORT, VERTEX_REPORT_PIN
    elif gate_census:
        source, source_pin, report_path, report_pin = GATE_SOURCE, GATE_CANDIDATE_PIN, GATE_REPORT, GATE_REPORT_PIN
    else:
        source, source_pin, report_path, report_pin = SOURCE, CANDIDATE_PIN, REPORT, REPORT_PIN
    require(report_path, report_pin)
    require(source, source_pin)
    report = json.loads(report_path.read_text())
    exports_key = 'exports_match_blit' if gate_census else 'exports_match_v12'
    imports_key = 'import_symbols_match_blit' if gate_census else 'import_symbols_match_v12'
    if (report.get('source_revision') != REVISION or report.get('compiled') is not True
            or report.get('stage_or_prefix_modified') is not False or report.get(exports_key) != 80
            or report.get(imports_key) is not True or report.get('artifact') != artifact(source, source_pin)
            or (vertices and report.get('vertex_measurement_enabled') is not True)
            or (projection and report.get('projection_ab_candidate') is not True)
            or (y_probe and report.get('projection_probe_y_offset') != 90)
            or (aligned and report.get('projection_y_alignment') != 'target_height_minus_reference_height')
            or (sharpness and report.get('sharpness_texture_measurement') is not True)
            or (native_extents and report.get('native_extents_projection') is not True)
            or (fast_extents and (report.get('native_extents_fast_path') is not True
                                  or report.get('sharpness_texture_measurement') is not False))
            or (fullscreen_y and report.get('retina_fullscreen_y_projection') is not True)
            or (gate_census and (report.get('baseline_report') != artifact(REPORT, REPORT_PIN)
                                 or report.get('baseline_artifact') != artifact(SOURCE, CANDIDATE_PIN)))):
        raise RuntimeError('Unexpected graphics blit build report')
    plain(CHECKPOINT)
    if CHECKPOINT.exists():
        raise RuntimeError('An interrupted graphics blit launch requires explicit recovery')
    require(TARGET, BASELINE_PIN)
    return {'artifact': artifact(source, source_pin), 'build': artifact(report_path, report_pin),
            'baseline_manifest': artifact(manifest, MANIFEST_PIN), 'baseline_sha256': BASELINE_PIN[1],
            'recovery_checkpoint': str(CHECKPOINT.relative_to(ROOT))}


def require_lock():
    from source_main_environment import _ACTIVE_MAIN_LOCKS
    if _ACTIVE_MAIN_LOCKS.get(str(PREFIX), (None,))[0] != os.getpid():
        raise RuntimeError('Graphics blit replacement requires the Source-MAIN lock')


def prefix_identity():
    plain(PREFIX)
    info = PREFIX.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise RuntimeError('Graphics blit requires the bound Source prefix directory')
    return [info.st_dev, info.st_ino]


def require_prefix(expected):
    if prefix_identity() != expected:
        raise RuntimeError('The Source prefix changed during graphics blit observation')


def session_idle(runtime, environment):
    server = runtime.ENGINE / 'bin/wineserver'
    if environment.get('WINEPREFIX') != str(PREFIX) or environment.get('WINESERVER') != str(server):
        raise RuntimeError('Unexpected graphics blit Wine role')
    try:
        result = subprocess.run([str(server), '-w'], env=environment, timeout=3,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return False
    if result.returncode != 0:
        raise RuntimeError('Could not verify that the Source Wine session is idle')
    return True


def require_idle(runtime, environment):
    if not session_idle(runtime, environment):
        raise RuntimeError('Graphics blit requires the previous Wine session to end')


def copy_verified(source, destination, pin):
    require(source, pin)
    subprocess.run(['/bin/cp', '-c', '-n', str(source), str(destination)], check=True)
    require(destination, pin)


def restore_locked(validate_baseline=None):
    require_lock()
    require(MANIFEST, MANIFEST_PIN)
    require(CHECKPOINT, BASELINE_PIN)
    before = identity(TARGET)
    candidates = (CANDIDATE_PIN, GATE_CANDIDATE_PIN, VERTEX_CANDIDATE_PIN, PROJECTION_CANDIDATE_PIN,
                  Y_PROBE_CANDIDATE_PIN, ALIGNED_CANDIDATE_PIN, SHARPNESS_CANDIDATE_PIN,
                  NATIVE_EXTENTS_CANDIDATE_PIN, FAST_EXTENTS_CANDIDATE_PIN, FULLSCREEN_Y_CANDIDATE_PIN)
    if before in candidates:
        with tempfile.TemporaryDirectory(prefix='.blit-restore-', dir=STAGE) as folder:
            restored = Path(folder) / TARGET.name
            copy_verified(CHECKPOINT, restored, BASELINE_PIN)
            require(TARGET, before)
            os.replace(restored, TARGET)
    elif before != BASELINE_PIN:
        raise RuntimeError('Unexpected graphics DLL bytes; preserve the V12 checkpoint for review')
    require(TARGET, BASELINE_PIN)
    if validate_baseline is not None:
        validate_baseline()
    CHECKPOINT.unlink()


def activate(manifest, runtime, environment, *, gate_census=False, vertices=False, projection=False, y_probe=False,
             aligned=False, sharpness=False, native_extents=False, fast_extents=False, fullscreen_y=False):
    require_lock()
    evidence = verify_candidate(manifest, gate_census=gate_census, vertices=vertices, projection=projection,
                                y_probe=y_probe, aligned=aligned, sharpness=sharpness,
                                native_extents=native_extents, fast_extents=fast_extents, fullscreen_y=fullscreen_y)
    candidate = evidence['artifact']
    source = ROOT / candidate['path']
    candidate_pin = candidate['bytes'], candidate['sha256']
    evidence['source_prefix_identity'] = prefix_identity()
    require_idle(runtime, environment)
    with tempfile.TemporaryDirectory(prefix='.blit-prepare-', dir=STAGE) as folder:
        prepared = Path(folder) / TARGET.name
        saved = prepared.with_suffix('.previous')
        copy_verified(TARGET, saved, BASELINE_PIN)
        copy_verified(source, prepared, candidate_pin)
        require_prefix(evidence['source_prefix_identity'])
        plain(CHECKPOINT)
        if CHECKPOINT.exists():
            raise RuntimeError('Graphics blit checkpoint appeared during staging')
        os.replace(saved, CHECKPOINT)
        try:
            require(CHECKPOINT, BASELINE_PIN)
            require(TARGET, BASELINE_PIN)
            os.replace(prepared, TARGET)
            require(TARGET, candidate_pin)
        except BaseException:
            restore_locked()
            raise
    return evidence


def recover():
    from run_source import check_inputs, select_runtime_profile, source_runtime_environment, use_system_dyld_search
    from source_main_environment import source_main_prefix
    runtime, _ = select_runtime_profile('parity')
    env = source_runtime_environment(runtime, 12)
    use_system_dyld_search(env)
    with source_main_prefix(PREFIX, root=ROOT):
        require_idle(runtime, env)
        restore_locked(lambda: check_inputs(require_preflight=True, resume=True))
    print('Source V12 baseline restored and verified')


if __name__ == '__main__':
    if sys.argv[1:] != ['recover']:
        raise SystemExit('Usage: graphics_blit_launch.py recover')
    recover()
