"""Read-only parity-engine selection for the unchanged authorized Source7 role."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
SOURCE_PREFIX = ROOT/'prefixes/fivem-source-main'
ENGINE = ROOT/'runtime/wine-job-query-parity/engine'
MANIFEST_SHA = 'e4fc3167813864102909da696cf3a03e89bd00a4a9abe26d8478c88316600f9c'
RENDERER_SHA = '0703fd74b63eb144378dc7f298dcccb8ed423701507654785b1267e8a64f4eba'
spec = importlib.util.spec_from_file_location('source_parity_graphics_verifier', ROOT/'native/wine-parity-probes/graphics.py')
graphics = importlib.util.module_from_spec(spec)
spec.loader.exec_module(graphics)
health, runner, verifier = graphics.health, graphics.runner, graphics.runtime
JOB_LABEL = 'wine-parity-jobs-20261102T084737610462Z'
REASSESS = 'research/wine-parity-jobs-reassessment-20261102T090203179163Z-results.json'
LABELS = {'font': 'wine-parity-font-20261102T093022378678Z',
          'winhttp': 'wine-parity-winhttp-20261102T093147400973Z',
          'graphics-dxmt': 'wine-parity-graphics-dxmt-20261102T094206042417Z'}
PINS = {
    'logs/wine-parity-font-20261102T093022378678Z-font-wine.log': (5722, 'b5dfe56e65d4d7495c32983de11a36df60c4d1d3c1868a2108a7032440a1ffa9'),
    'logs/wine-parity-font-20261102T093022378678Z-font.ndjson': (797, 'ff3145cfe655d5e5e949b1fdae723db4db4de5c04111c50977f67b60ef970c81'),
    'logs/wine-parity-graphics-dxmt-20261102T094206042417Z-runtime_health_graphics_dxmt-wine.log': (1987425, '7828d0d5094d3f82a541c68bf389de185c33454850e28b83fcd7dbc9b36aa00f'),
    'logs/wine-parity-graphics-dxmt-20261102T094206042417Z-runtime_health_graphics_dxmt.ndjson': (627, '9dc48c0b47fc7ea72977268335ddffcea0bd2ad9347ce4a515b617e296d85329'),
    'logs/wine-parity-jobs-20261102T084737610462Z-job_parent-wine.log': (0, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'),
    'logs/wine-parity-jobs-20261102T084737610462Z-job_parent.ndjson': (10672, 'cbf5f5a41a35c0094b8cc99584db654f7302194a0e9c1746232266946bce0170'),
    'logs/wine-parity-jobs-20261102T084737610462Z-job_query_contract-wine.log': (134, '2dadccf8255edc1270540f6f906742896ff566be6e5d944e8f7667988932e1fa'),
    'logs/wine-parity-jobs-20261102T084737610462Z-job_query_contract.ndjson': (24517, 'dbea751dd3bcf2cc142a1a60c31b4a942fed36913b6996209313862965584d0a'),
    'logs/wine-parity-winhttp-20261102T093147400973Z-winhttp-wine.log': (221, 'dd70a293f39ed25633a687eb0bca1e18a016e214d7f475c45c0bfd559cbbee13'),
    'logs/wine-parity-winhttp-20261102T093147400973Z-winhttp.ndjson': (683, '5029753accbe2b98154d8550b019e9a5db64e472561885217c51dd3615c20c9d'),
    'research/wine-parity-font-20261102T093022378678Z-results.json': (8514, 'ec805e1375be0ee607d16818adcbcc0b75cc1e7330df5ac3ab240caac03f628a'),
    'research/wine-parity-graphics-dxmt-20261102T094206042417Z-results.json': (18489, 'b5bbde8748a3c5208209a19eb793e12e18e2c4a7a3654649214f9fd9b30d117e'),
    'research/wine-parity-jobs-20261102T084737610462Z-results.json': (70230, '5213648f43d98c7e8c09eebd6522f68520ade6cb13ee35fec6fe071c968e8bd9'),
    'research/wine-parity-jobs-reassessment-20261102T090203179163Z-results.json': (65634, '93daf23f164d4502bc70d9599657f014aa37301a6d8b4572f6a2c255cb0e8de4'),
    'research/wine-parity-winhttp-20261102T093147400973Z-results.json': (9783, '610b4aad0d4d069c217e415f0629cc8bc6827ce60134676226531d1897707163'),
}
CLEANUP = [{'flag': '-k', 'exit': 0}, {'flag': '-w', 'exit': 0}]
SOURCE_BRIDGES = {
    'drive_c/windows/system32/winemetal.dll': (74373, '79b5fda6a25223729c5b6a41f3e9c2320550bd040fe1ed730a89f84426cc75e8'),
    'drive_c/windows/syswow64/winemetal.dll': (74304, '2d9004f151f11e9f1250a46038a2fc3fd253e660372b79c28d3786f00429fa88'),
}


def _read(name):
    if type(name) is not str or name not in PINS:
        raise RuntimeError('Unreviewed parity prerequisite path')
    raw = verifier.read_regular(ROOT/name, ROOT)
    size, digest = PINS[name]
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
        raise RuntimeError('Parity prerequisite result or own-probe raw log changed')
    return raw


def _record(raw, role):
    record = json.loads(raw)
    if (record.get('profile') != verifier.ROLE or record.get('probe_role') != role
            or record.get('protocol_version') != 1810 or record.get('prefix') != 'prefixes/wine-parity-regression'
            or record.get('runtime_started') is not True or record.get('cleanup') != CLEANUP
            or record.get('quarantine_cleared_after_confirmed_cleanup') is not True
            or record.get('only_own_fixtures_and_builtin_initialization') is not True
            or record.get('client_cef_rockstar_game_or_account_code_started') is not False
            or any(key in record for key in ('failure', 'post_run_guard_failure', 'prefix_terminal_state_uncertain'))
            or record.get('runtime_verification', {}).get('manifest_sha256') != MANIFEST_SHA):
        raise RuntimeError('Parity prerequisite lacks the exact clean own-probe runtime context')
    return record


def _verify_prerequisites():
    data = {name: _read(name) for name in sorted(PINS)}
    original = _record(data['research/'+JOB_LABEL+'-results.json'], 'jobs')
    reassess = json.loads(data[REASSESS])
    if (reassess.get('reassessment_only') is not True or reassess.get('no_new_wine_run') is not True
            or reassess.get('runtime_started') is not False or reassess.get('prefix_or_engine_accessed') is not False
            or reassess.get('passed') is not True or reassess.get('original_reported_passed') is not False
            or reassess.get('original_cleanup') != CLEANUP or reassess.get('original_postguards_clean') is not True
            or original.get('passed') is not False):
        raise RuntimeError('Preserve the original Job report and the explicit successful reassessment separately')
    counts = []
    for name, count, final, kind in (('job_parent', 79, 'all_cases_passed', 'result'),
                                     ('job_query_contract', 170, 'all_query_cases_passed', 'assertion')):
        path = 'logs/'+JOB_LABEL+'-'+name+'.ndjson'
        parsed = runner.event_contract(data[path].decode().splitlines(), count, final, 0, final_kind=kind)
        matching = [row for row in reassess.get('runs', []) if row.get('name') == name]
        if (parsed.get('passed') is not True or len(matching) != 1 or matching[0].get('exit') != 0
                or matching[0].get('event_count') != count or matching[0].get('failed_assertions') != 0
                or matching[0].get('passed') is not True):
            raise RuntimeError('Actual Job parent/query raw-event contract failed')
        counts.append(count)
    summaries = {}
    health_parser, http_parser = health.load_health_contract(), health.load_winhttp_contract()
    for role, label in LABELS.items():
        record = _record(data['research/'+label+'-results.json'], role)
        if record.get('passed') is not True or len(record.get('runs', [])) != 1:
            raise RuntimeError('Require every actual font, HTTPS and graphics prerequisite')
        row = record['runs'][0]
        name = 'runtime_health_graphics_dxmt' if role == 'graphics-dxmt' else role
        log, wine_log = 'logs/'+label+'-'+name+'.ndjson', 'logs/'+label+'-'+name+'-wine.log'
        if row.get('name') != name or row.get('exit') != 0 or row.get('log') != log or row.get('wine_log') != wine_log:
            raise RuntimeError('Prerequisite selected another case or raw-log path')
        text = data[log].decode()
        parsed = http_parser(text, 0) if role == 'winhttp' else health_parser(text, 'graphics' if role == 'graphics-dxmt' else 'font', 0)
        if parsed.get('passed') is not True or parsed.get('summary') != row.get('summary'):
            raise RuntimeError('Actual font/HTTPS/graphics raw metadata does not meet its original contract')
        if role == 'graphics-dxmt':
            if parsed['summary'] != {'stage_code': 8, 'passed': 1, 'device': 1, 'context': 1,
                                     'feature_level': 0xb000, 'mapped': 1,
                                     'pixel_r': 64, 'pixel_g': 128, 'pixel_b': 191, 'pixel_a': 255}:
                raise RuntimeError('Require the precise observed hardware feature level and RGBA8 pixel')
            chain = graphics.parse_provider_diagnostics(data[wine_log].decode().splitlines(), 0)
            if (chain.get('passed') is not True
                    or chain.get('provider_chain') != row.get('diagnostics', {}).get('provider_chain')):
                raise RuntimeError('Graphics evidence must bind the same-process new-engine/DXMT provider chain')
            summaries['graphics_provider_chain'] = chain['provider_chain']
        summaries[role] = parsed['summary']
    return {'fixed_inputs': [{'path': name, 'bytes': size, 'sha256': digest} for name, (size, digest) in sorted(PINS.items())],
            'job_event_counts': counts, 'job_original_report_preserved_as_failed': True,
            'job_reassessment_is_reparse_not_another_runtime_run': True, 'probe_summaries': summaries,
            'historical_probe_runner_hashes_are_not_simultaneous_live_runner_claims': True,
            'api_prefix_files_read_copied_or_modified': False}


def verify_source_bridge_code():
    if SOURCE_PREFIX != ROOT/'prefixes/fivem-source-main':
        raise RuntimeError('Only the existing source role may provide the two code-only bridge inputs')
    bridges = []
    for name, (size, digest) in SOURCE_BRIDGES.items():
        raw = verifier.read_regular(SOURCE_PREFIX/name, ROOT)
        if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
            raise RuntimeError('Existing Source-only winemetal bridge differs; no implicit copy or repair is permitted')
        bridges.append({'path': str((SOURCE_PREFIX/name).relative_to(ROOT)), 'bytes': size, 'sha256': digest})
    return bridges


def _verify_live_components():
    engine = verifier.verify_runtime()
    renderer = graphics.verify_renderer()
    if engine.get('manifest_sha256') != MANIFEST_SHA or renderer.get('review', {}).get('sha256') != RENDERER_SHA:
        raise RuntimeError('Only the fixed complete parity engine and matched DXMT provider are admitted')
    bridges = verify_source_bridge_code()
    return {'engine': engine, 'renderer': renderer, 'source_bridge_code': bridges, 'job_fixture': runner.verify_jobs(),
            'health_fixture': health.verify_health(), 'winhttp_fixture': health.verify_winhttp()}


def verify_profile():
    return {'profile': 'parity', 'live_components': _verify_live_components(),
            'prerequisites': _verify_prerequisites(),
            'source_stage_update_performed': False, 'source_prefix_code_only_read': True,
            'source_profile_ticket_registry_or_account_state_accessed': False,
            'ui_authentication_anticheat_or_gameplay_success_claim': False}


def _matched_base(matched):
    environment = dict(matched.environment())
    if any(key.lower().startswith('citizenfx_') for key in environment):
        raise RuntimeError('Refusing inherited CitizenFX role variables before parity environment cleanup')
    return environment


def source_environment(matched, source_prefix):
    if source_prefix != SOURCE_PREFIX:
        raise RuntimeError('Parity Source runtime may use only the existing authorized source prefix')
    base = _matched_base(matched)
    banned = ('WINE', '_WINE', '__WINE', 'DYLD_', 'LD_', 'DXVK', 'DXMT', 'D3DMETAL', 'CX_', 'VK_',
              'MVK_', 'GST_', 'GIO_', 'G_MODULE_')
    env = {key: value for key, value in base.items() if not key.upper().startswith(banned)}
    search = os.pathsep.join(map(str, (ENGINE/'lib/wine/x86_64-unix', verifier.MOLTENVK.parent,
                                      verifier.FRAMEWORKS, verifier.GST_LIB)))
    env.update(WINEPREFIX=str(source_prefix), WINEARCH='win64', WINESERVER=str(ENGINE/'bin/wineserver'),
               PATH=str(ENGINE/'bin')+':/usr/bin:/bin:/usr/sbin:/sbin',
               WINEESYNC='0', WINEMSYNC='0', WINEDLLPATH_PREPEND=str(graphics.provider()),
               WINEDLLOVERRIDES='dxgi,d3d11,d3d10core,winemetal=b', DXMT_ALLOW_CROSS_PROCESS_SWAPCHAIN='1',
               DYLD_LIBRARY_PATH=search, DYLD_FALLBACK_LIBRARY_PATH=search,
               DYLD_FRAMEWORK_PATH=str(verifier.FRAMEWORKS), DYLD_FALLBACK_FRAMEWORK_PATH=str(verifier.FRAMEWORKS),
               GST_PLUGIN_PATH='', GST_PLUGIN_PATH_1_0='', GST_PLUGIN_SYSTEM_PATH='', GST_PLUGIN_SYSTEM_PATH_1_0='',
               GST_REGISTRY_UPDATE='no', GST_REGISTRY_FORK='no')
    return env


def select_runtime(matched, source_prefix=SOURCE_PREFIX):
    if source_prefix != SOURCE_PREFIX:
        raise RuntimeError('Refusing another prefix role before parity runtime verification')
    _matched_base(matched)
    sibling = ROOT.parent/'GTA-V-macOS'
    if (matched.ENGINE != sibling/'runtime/matched-wine11-r29/engine'
            or matched.WINE != matched.ENGINE/'bin/wine' or matched.PREFIX != sibling/'prefixes/rockstar-legacy'):
        raise RuntimeError('Parity Source selection requires the retained matched baseline role')
    context = verify_profile()

    def before_source_spawn():
        if verify_profile() != context:
            raise RuntimeError('Parity Source runtime or prerequisite identity changed before process creation')

    return SimpleNamespace(ENGINE=ENGINE, WINE=ENGINE/'bin/wine', PREFIX=matched.PREFIX,
                           environment=lambda: source_environment(matched, source_prefix),
                           before_source_spawn=before_source_spawn, source_runtime_profile=context)
