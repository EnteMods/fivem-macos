#!/usr/bin/env python3
"""Opt-in isolated ANGLE comparison; caller supplies an explicitly reviewed frozen proof."""
import argparse
from contextlib import contextmanager
import importlib.util
import json
import os
import re
from pathlib import Path
import shutil
import tempfile
import zipfile
import inputs
import parse
import parse_v1

ROOT=inputs.ROOT
HERE=Path(__file__).resolve().parent

# The build/ABI manifest is pinned by the caller, with required fields validated below.
def verify_frozen(build,proof_sha):
    if not re.fullmatch('[0-9a-f]{64}',proof_sha): raise inputs.Invalid('PROOF_HASH')
    proof_file=build/'frozen-artifact-proof.json'
    if inputs.digest(proof_file)!=proof_sha:raise inputs.Invalid('PROOF_HASH')
    proof=json.loads(proof_file.read_text())
    roles={'artifact':'artifact/angle_shared_probe.exe','build_record':'result.json',
           'source':'source/probe.cpp','runtime_requirements':'runtime-requirements.json',
           'api_contract':'source/api-contract.json','headers_manifest':'source/vendor/manifest.json'}
    for key,relative in roles.items():
        row=proof[key];path=build/relative
        if row['path']!=str(path.relative_to(ROOT)) or path.stat().st_size!=row['bytes'] or inputs.digest(path)!=row['sha256']:raise inputs.Invalid('PROOF_BINDING')
    result=json.loads((build/'result.json').read_text())
    if result.get('build_passed') is not True or result.get('runtime_started') is not False or result.get('runtime_staged') is not False or result.get('artifact')!=proof['artifact']:raise inputs.Invalid('BUILD_STATUS')
    sources=result['frozen_source_files']
    if not isinstance(sources,list) or not sources:raise inputs.Invalid('SOURCE_BINDING')
    seen=set()
    for row in sources:
        path=ROOT/row['path']
        if not path.is_relative_to(build/'source') or path in seen or path.stat().st_size!=row['bytes'] or inputs.digest(path)!=row['sha256']:raise inputs.Invalid('SOURCE_BINDING')
        seen.add(path)
    if build/'source/probe.cpp' not in seen or build/'source/api-contract.json' not in seen:raise inputs.Invalid('SOURCE_BINDING')
    requirements=json.loads((build/'runtime-requirements.json').read_text())
    archive=requirements['archive'];rows=requirements['files']
    if requirements.get('runtime_staged') is not False or archive['path']!=str(inputs.ARCHIVE.relative_to(ROOT)) or archive['bytes']!=inputs.ARCHIVE.stat().st_size or archive['sha256']!=inputs.ARCHIVE_SHA or inputs.digest(inputs.ARCHIVE)!=inputs.ARCHIVE_SHA:raise inputs.Invalid('ARCHIVE')
    names=[row['relative_runtime_path'] for row in rows]
    if len(names)!=len(set(names)) or not {'libEGL.dll','libGLESv2.dll'}.issubset(names) or not set(names).issubset(inputs.DLLS):raise inputs.Invalid('DLL_SET')
    for row in rows:
        name=row['relative_runtime_path']
        if row['archive_member']!=inputs.PACKAGE+'/Release/'+name or row['sha256']!=inputs.DLLS[name] or type(row['bytes']) is not int or not 0<row['bytes']<=32*1024*1024:raise inputs.Invalid('DLL_BINDING')
    contract=json.loads((build/'source/api-contract.json').read_text())
    schema=contract.get('schema')
    if schema not in ('own-angle-shared-probe-api-v1','own-angle-shared-probe-api-v2'):raise inputs.Invalid('CONTRACT_SCHEMA')
    return build/'artifact/angle_shared_probe.exe',names,schema

def parse_output(lines,exitcode,mode,schema):
    parser=parse_v1 if schema=='own-angle-shared-probe-api-v1' else parse
    return parser.evaluate(lines,exitcode,mode)

def run(build,proof_sha):
    artifact,dll_names,schema=verify_frozen(build,proof_sha)
    spec=importlib.util.spec_from_file_location('angle_dxgi_lifecycle',ROOT/'native/windows-dxgi-swapchain/run.py')
    dxgi=importlib.util.module_from_spec(spec);spec.loader.exec_module(dxgi)
    graphics=dxgi.graphics();runner=graphics.runner;runtime=graphics.runtime
    prefix=ROOT/'prefixes/wine-parity-regression'
    if runner.PREFIX!=prefix or runtime.PREFIX!=prefix or not prefix.is_dir() or not (prefix/'system.reg').is_file():raise inputs.Invalid('PREFIX')
    runtime.verify_runtime();graphics.verify_renderer();graphics.verify_bridge_binding()
    work=Path(tempfile.mkdtemp(prefix='windows-angle-shared-s2-run-',dir=ROOT/'build'))
    folder=work/'runtime';folder.mkdir();exe=folder/'angle_shared_probe.exe'
    shutil.copyfile(artifact,exe);inputs.stage_dlls(folder,dll_names)
    expected={name:inputs.DLLS[name] for name in dll_names};expected[exe.name]=inputs.digest(artifact)
    inputs.verify_runtime_tree(folder,expected)
    own_sources=[runner.identity(p) for p in (HERE/'run.py',HERE/'inputs.py',HERE/'parse.py',HERE/'parse_v1.py',ROOT/'native/windows-dxgi-swapchain/run.py')]
    own_artifact=runner.identity(exe)
    def verify_inputs():
        current,current_dlls,current_schema=verify_frozen(build,proof_sha)
        if current!=artifact or set(current_dlls)!=set(dll_names) or current_schema!=schema:raise inputs.Invalid('FROZEN_CHANGE')
        inputs.verify_runtime_tree(folder,expected)
        if any(runner.identity(ROOT/x['path'])!=x for x in own_sources):raise inputs.Invalid('SOURCE_CHANGE')
        return {'runtime_inputs':[own_artifact],'source_inputs':own_sources,'package_sha256':inputs.ARCHIVE_SHA,'proof_sha256':proof_sha,'api_schema':schema,'scope':'own D3D11/ANGLE image experiment; no client, account, or Skia'}
    fallback={'DYLD_FALLBACK_LIBRARY_PATH':os.pathsep.join(map(str,(runtime.ENGINE/'lib/wine/x86_64-unix',runtime.MOLTENVK.parent,runtime.FRAMEWORKS,runtime.GST_LIB))), 'DYLD_FALLBACK_FRAMEWORK_PATH':str(runtime.FRAMEWORKS)}
    original=runner.validate_environment
    def validate_environment(env):
        if 'DYLD_LIBRARY_PATH' in env or any(env.get(k)!=v for k,v in fallback.items()):raise inputs.Invalid('ENVIRONMENT')
        original({k:v for k,v in env.items() if k not in fallback})
    def environment(verified):
        env=graphics.graphics_environment(verified)
        allowed=('PATH','HOME','TMPDIR','LANG','LC_ALL','USER','LOGNAME','WINEPREFIX','WINESERVER','WINELOADER','WINEDEBUG','WINEESYNC','WINEMSYNC','WINEDLLOVERRIDES','WINEDLLPATH_PREPEND','DYLD_FRAMEWORK_PATH','DYLD_PRINT_LIBRARIES','DXMT_ALLOW_CROSS_PROCESS_SWAPCHAIN','GST_PLUGIN_PATH','GST_PLUGIN_PATH_1_0','GST_PLUGIN_SYSTEM_PATH','GST_PLUGIN_SYSTEM_PATH_1_0','GST_REGISTRY_FORK')
        env={k:v for k,v in env.items() if k in allowed};env.update(fallback);return env
    def validate_bridge(verified,env):return {'binding':graphics.verify_bridge_binding(),'created_relative_paths':[]}
    def diagnostics(lines,code):
        out=graphics.parse_provider_diagnostics(lines,code);out['prefix_bridge_binding']=graphics.verify_bridge_binding()
        folder_win='Z:'+str(folder).replace('/','\\')
        out['original_angle_libraries_loaded']=parse.angle_provider_lines(lines,folder_win)
        identity=graphics.parse_provider_diagnostics(lines,0)
        out['provider_identity_verified']=identity.get('passed') is True and out['original_angle_libraries_loaded']
        out['passed']=out.get('passed') is True and out['original_angle_libraries_loaded']
        return out
    runner.validate_environment=validate_environment
    original_probe_prefix=runner.probe_prefix
    @contextmanager
    def existing_prefix_only(path,root,create=False):
        with original_probe_prefix(path,root=root,create=False) as locked:
            if not (prefix/'system.reg').is_file(): raise inputs.Invalid('PREFIX_NOT_INITIALIZED')
            yield locked
    runner.probe_prefix=existing_prefix_only
    cases=[]
    for mode in (0,1):
        def output(lines,code,mode=mode):return parse_output(lines,code,mode,schema)
        cases.append({'name':'angle_mode_'+str(mode),'binary':exe,'cwd':folder,'arguments':['--control='+str(mode)],'parse_output':output,'parse_diagnostics':diagnostics})
    role='angle-shared-s2-'+work.name.removeprefix('windows-angle-shared-s2-run-')
    pattern='wine-parity-'+role+'-*-results.json';before=set((ROOT/'research').glob(pattern))
    try:
        status=runner.run_cases(cases,verify_inputs=verify_inputs,role=role,environment_factory=environment,prepare_prefix=validate_bridge)
    finally:
        added=set((ROOT/'research').glob(pattern))-before
        if len(added)!=1:raise inputs.Invalid('RESULT')
        report=added.pop()
        if report.is_symlink() or report.resolve(strict=True)!=report:raise inputs.Invalid('RESULT')
        result=json.loads(report.read_text());observed=any(r.get('numeric_contract_observed') is True for r in result.get('runs',[]))
        started=True if observed else (None if result.get('runtime_started') is True else False)
        result['only_own_fixtures_and_builtin_initialization']=not started if started is not None else None
        result['client_cef_rockstar_game_or_account_code_started']=False
        result['actual_started_scope']='own fixture and original CFX-packaged ANGLE DLLs only; no CEF browser, FiveM, RGL, GTA, Skia or accounts' if started is True else ('no fixture launch attempted' if started is False else 'ANGLE fixture execution unknown; runtime launch attempted')
        result['skia_client_auth_verified']=False
        pending=report.with_suffix('.corrected.tmp')
        with pending.open('x') as f:json.dump(result,f,indent=2);f.write('\n')
        os.replace(pending,report)
    return status

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--build',required=True);parser.add_argument('--proof-sha256',required=True);args=parser.parse_args()
    try:return run(inputs.build_path(args.build),args.proof_sha256)
    except (inputs.Invalid,OSError,ValueError,KeyError,TypeError,zipfile.BadZipFile):
        print(json.dumps({'status':'INCOMPLETE','code':'INPUT_OR_RUNNER_FAILURE'}));return 1
if __name__=='__main__':raise SystemExit(main())
