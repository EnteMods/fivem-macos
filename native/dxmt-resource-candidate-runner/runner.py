#!/usr/bin/env python3
"""Opt-in own-candidate regression runner. No runtime is started by import."""
import argparse
from contextlib import contextmanager, redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
S2=ROOT/'native/windows-angle-shared-s2-driver'
S2_PINS={'run.py':'7fbd1e93d780ca524510be9af7d11a19dc0f9aa0b917981e8cf6fed5fa093eef',
         'inputs.py':'ec3465ffeeecf0bb2005330c7848cecea1795b35118dd21db7d1643b6123f0cd',
         'parse.py':'a9f50dc5714b55e6a35deb1961de9cb588e231d51d609eeb3dd81818a11ca51d',
         'parse_v1.py':'c8eb8edff972e257dfffd927ad57a8fecb224e381fb7444999f46c456052f628'}
S2_PROOF='e880115070a5e1239908936c288b551db1744b35f0dbda6a4f16bfd63dc1665a'
S2_BUILD=ROOT/'build/windows-angle-shared-probe-pkfv7vmv'
USAGE_BUILD=ROOT/'build/windows-dxgi-getusage-probe-07ggl4tc'
USAGE_PROOF='e71b258e139e60b0d54f8e3055ebc9a000f782c75436cf415caec4d15a71ce69'

class Invalid(Exception):pass

def dependencies():
    # Reuse reviewed source without modifying its pins or global renderer policy.
    import hashlib
    for name,sha in S2_PINS.items():
        path=S2/name
        if path.resolve(strict=True)!=path or hashlib.sha256(path.read_bytes()).hexdigest()!=sha:raise Invalid('S2_SOURCE')
    sys.path.insert(0,str(S2))
    spec=importlib.util.spec_from_file_location('candidate_s2_driver',S2/'run.py')
    s2=importlib.util.module_from_spec(spec);spec.loader.exec_module(s2)
    for module,name in ((s2.inputs,'inputs.py'),(s2.parse,'parse.py'),(s2.parse_v1,'parse_v1.py')):
        if Path(module.__file__).resolve(strict=True)!=S2/name:raise Invalid('S2_MODULE')
    return s2

def usage_fixture(s2):
    proof=USAGE_BUILD/'frozen-artifact-proof.json'
    if s2.inputs.digest(proof)!=USAGE_PROOF:raise Invalid('USAGE_PROOF')
    item=json.loads(proof.read_text())
    for row in [item['artifact'],item['build_record'],*item['frozen_sources']]:
        path=ROOT/row['path']
        if not path.is_relative_to(USAGE_BUILD) or path.stat().st_size!=row['bytes'] or s2.inputs.digest(path)!=row['sha256']:raise Invalid('USAGE_SOURCE')
    module=USAGE_BUILD/'source/contract.py';spec=importlib.util.spec_from_file_location('candidate_usage_contract',module)
    contract=importlib.util.module_from_spec(spec);spec.loader.exec_module(contract)
    return ROOT/item['artifact']['path'],contract

def verify_overlay_tree(overlay, expected_sha, s2):
    directory=overlay/'x86_64-windows';candidate=directory/'d3d11.dll'
    if overlay.is_symlink() or directory.is_symlink() or list(overlay.iterdir())!=[directory] or list(directory.iterdir())!=[candidate] or s2.inputs.digest(candidate)!=expected_sha:raise Invalid('OVERLAY_CONTENTS')
    return candidate

def ordered_paths(overlay,original):
    if ':' in str(overlay) or ':' in str(original):raise Invalid('SEARCH_PATH')
    return str(overlay)+':'+str(original)

def candidate_evidence():
    # Static hash/ordered search and test behavior are not physical mapping proof.
    return {'physical_candidate_file_verified':False,'physical_candidate_mapping_status':'UNKNOWN',
            'physical_path_verified':False,'candidate_provider_binding':'INFERRED_FROM_PINNED_LOADER_AND_CLOSED_OVERLAY',
            'full_candidate_verification':'INCOMPLETE',
            'selection_evidence':'ordered candidate search; test behavior, if observed, is indirect only',
            'other_test_processes_loaded_code_verified':False,
            'production_client_skia_auth_verified':False}

# Candidate proof admission is defined only from the independently frozen proof schema.
def verify_candidate(proof_path,proof_sha,s2):
    import hashlib
    if proof_sha!='4315d6bacc9618148d71231b07f2ae5fc4f2cf8a03e8616d7e95ff37f7c4fbb5' or s2.inputs.digest(proof_path)!=proof_sha:raise Invalid('CANDIDATE_PROOF')
    proof=json.loads(proof_path.read_text())
    if proof.get('runtime_started') is not False or proof.get('runtime_staged') is not False or proof.get('provider_installed') is not False:raise Invalid('CANDIDATE_STATUS')
    base=ROOT/'build/dxmt-resource-usage-e95ais9r'
    roles={'artifact':'artifact/d3d11.dll','audit_report':'audit/artifact-audit.json','compiled_inputs':'audit/compiled-inputs.json','target_closure':'audit/target-closure.json','source_patch':'source/src/d3d11/d3d11_resource.hpp','import_closure':'audit/import-closure.json','link_inputs':'audit/link-inputs.json','toolchain_inputs':'audit/toolchain-inputs.json'}
    for key,rel in roles.items():
        row=proof[key];path=base/rel
        if row['path']!=str(path.relative_to(ROOT)) or path.stat().st_size!=row['bytes'] or s2.inputs.digest(path)!=row['sha256']:raise Invalid('CANDIDATE_BINDING')
    if proof['source_patch']['sha256']!='ae6aa8922a49ab6ce0faf36a83377164ed3682e8c715d6fa5e0398b4bbf03d96':raise Invalid('CANDIDATE_SOURCE')
    audit=json.loads((base/'audit/artifact-audit.json').read_text())
    if proof.get('architecture')!='AMD64' or proof.get('wine_builtin_marker') is not True or proof.get('exports_equal') is not True or proof.get('provider_imports_closed') is not True or proof.get('native_llvm_payload_built') is not False:raise Invalid('CANDIDATE_AUDIT')
    if audit.get('audit_passed') is not True or audit.get('architecture')!='AMD64' or audit.get('wine_builtin_marker') is not True or audit.get('wine_placeholder_marker') is not False or audit.get('export_name_and_ordinal_parity') is not True or audit.get('all_candidate_imports_closed') is not True or audit.get('native_llvm_payload_built') is not False:raise Invalid('CANDIDATE_AUDIT')
    original_prefix='../GTA-V-macOS/runtime/matched-dxmt-a444716/highball/'
    expected={arch+'-windows/'+name+'.dll' for arch in ('i386','x86_64') for name in ('d3d10core','d3d11','dxgi','winemetal')}|{'x86_64-windows/nvapi64.dll','x86_64-windows/nvngx.dll','x86_64-unix/winemetal.so'}
    rows=proof['retained_provider_files']
    if len(rows)!=11 or {r['path'] for r in rows}!={original_prefix+n for n in expected}:raise Invalid('ORIGINAL_PROVIDER')
    if proof['original_provider'] not in rows or proof['original_provider']['path']!=original_prefix+'x86_64-windows/d3d11.dll':raise Invalid('ORIGINAL_PROVIDER')
    for row in rows:
        name=row['path'].removeprefix(original_prefix);path=ROOT.parent/'GTA-V-macOS/runtime/matched-dxmt-a444716/highball'/name
        if path.stat().st_size!=row['bytes'] or s2.inputs.digest(path)!=row['sha256']:raise Invalid('ORIGINAL_PROVIDER')
    return proof

def run(proof_path,proof_sha):
    s2=dependencies();proof=verify_candidate(proof_path,proof_sha,s2)
    artifact=ROOT/proof['artifact']['path']
    angle,angle_dlls,schema=s2.verify_frozen(S2_BUILD,S2_PROOF)
    if schema!='own-angle-shared-probe-api-v2':raise Invalid('S2_SCHEMA')
    usage,usage_contract=usage_fixture(s2)
    spec=importlib.util.spec_from_file_location('candidate_dxgi',ROOT/'native/windows-dxgi-swapchain/run.py')
    dxgi=importlib.util.module_from_spec(spec);spec.loader.exec_module(dxgi)
    graphics=dxgi.graphics();runner=graphics.runner;runtime=graphics.runtime
    prefix=ROOT/'prefixes/wine-parity-regression'
    if runner.PREFIX!=prefix or runtime.PREFIX!=prefix or not prefix.is_dir() or not (prefix/'system.reg').is_file():raise Invalid('PREFIX')
    runtime.verify_runtime();graphics.verify_renderer();graphics.verify_bridge_binding()
    work=Path(tempfile.mkdtemp(prefix='dxmt-resource-candidate-run-',dir=ROOT/'build'))
    overlay=work/'overlay';(overlay/'x86_64-windows').mkdir(parents=True)
    candidate=overlay/'x86_64-windows/d3d11.dll';shutil.copyfile(artifact,candidate)
    angle_dir=work/'angle';angle_dir.mkdir();angle_exe=angle_dir/'angle_shared_probe.exe';shutil.copyfile(angle,angle_exe)
    s2.inputs.stage_dlls(angle_dir,angle_dlls)
    usage_dir=work/'usage';usage_dir.mkdir();usage_exe=usage_dir/'dxgi_getusage_probe.exe';shutil.copyfile(usage,usage_exe)
    if s2.inputs.digest(candidate)!=proof['artifact']['sha256'] or s2.inputs.digest(angle_exe)!=s2.inputs.digest(angle) or s2.inputs.digest(usage_exe)!=s2.inputs.digest(usage):raise Invalid('COPY')
    angle_expected={name:s2.inputs.DLLS[name] for name in angle_dlls};angle_expected[angle_exe.name]=s2.inputs.digest(angle)
    usage_expected={usage_exe.name:s2.inputs.digest(usage)}
    s2.inputs.verify_runtime_tree(angle_dir,angle_expected);s2.inputs.verify_runtime_tree(usage_dir,usage_expected)
    original=graphics.provider();ordered=ordered_paths(overlay,original)
    own_files=[runner.identity(p) for p in (candidate,angle_exe,usage_exe)]
    this_source=runner.identity(HERE/'runner.py')
    def verify_inputs():
        verify_candidate(proof_path,proof_sha,s2);s2.verify_frozen(S2_BUILD,S2_PROOF);usage_fixture(s2)
        if any(s2.inputs.digest(S2/n)!=h for n,h in S2_PINS.items()):raise Invalid('S2_SOURCE')
        if runner.identity(HERE/'runner.py')!=this_source:raise Invalid('RUNNER_SOURCE')
        verify_overlay_tree(overlay,proof['artifact']['sha256'],s2)
        s2.inputs.verify_runtime_tree(angle_dir,angle_expected);s2.inputs.verify_runtime_tree(usage_dir,usage_expected)
        graphics.verify_renderer();graphics.verify_bridge_binding()
        return {'runtime_inputs':own_files,'source_inputs':[this_source], 'candidate_proof_sha256':proof_sha,
                'candidate_overlay_file_count':1,'original_renderer_integrity_checked':True,
                **candidate_evidence()}
    fallback={'DYLD_FALLBACK_LIBRARY_PATH':os.pathsep.join(map(str,(runtime.ENGINE/'lib/wine/x86_64-unix',runtime.MOLTENVK.parent,runtime.FRAMEWORKS,runtime.GST_LIB))), 'DYLD_FALLBACK_FRAMEWORK_PATH':str(runtime.FRAMEWORKS)}
    original_validator=runner.validate_environment;original_probe_prefix=runner.probe_prefix
    def validate_environment(env):
        if env.get('WINEDLLPATH_PREPEND')!=ordered or 'DYLD_LIBRARY_PATH' in env or any(env.get(k)!=v for k,v in fallback.items()):raise Invalid('ENVIRONMENT')
        original_validator({k:v for k,v in env.items() if k not in fallback})
    def environment(verified):
        env=graphics.graphics_environment(verified)
        allowed=('PATH','HOME','TMPDIR','LANG','LC_ALL','USER','LOGNAME','WINEPREFIX','WINESERVER','WINELOADER','WINEDEBUG','WINEESYNC','WINEMSYNC','WINEDLLOVERRIDES','WINEDLLPATH_PREPEND','DYLD_FRAMEWORK_PATH','DYLD_PRINT_LIBRARIES','DXMT_ALLOW_CROSS_PROCESS_SWAPCHAIN','GST_PLUGIN_PATH','GST_PLUGIN_PATH_1_0','GST_PLUGIN_SYSTEM_PATH','GST_PLUGIN_SYSTEM_PATH_1_0','GST_REGISTRY_FORK')
        env={k:v for k,v in env.items() if k in allowed};env.update(fallback);env['WINEDLLPATH_PREPEND']=ordered
        return env
    @contextmanager
    def existing_prefix_only(path,root,create=False):
        with original_probe_prefix(path,root=root,create=False) as locked:
            if not (prefix/'system.reg').is_file():raise Invalid('PREFIX')
            yield locked
    def bridge(verified,env):return {'binding':graphics.verify_bridge_binding(),'created_relative_paths':[]}
    def diagnostics(lines,code,angle_case):
        out=graphics.parse_provider_diagnostics(lines,code)
        identity=graphics.parse_provider_diagnostics(lines,0)
        out['original_bridge_binding']=graphics.verify_bridge_binding()
        out['original_provider_chain_observed']=identity.get('passed') is True
        if angle_case:
            folder_win='Z:'+str(angle_dir).replace('/','\\')
            out['original_angle_libraries_loaded']=s2.parse.angle_provider_lines(lines,folder_win)
        out.update(candidate_evidence())
        out['passed']=False
        out['reason']='PHYSICAL_CANDIDATE_MAPPING_UNVERIFIED'
        return out
    runner.validate_environment=validate_environment;runner.probe_prefix=existing_prefix_only
    cases=[]
    for mode in (0,1):
        def output(lines,code,mode=mode):
            parsed=s2.parse_output(lines,code,mode,schema);parsed['api_contract_passed']=parsed.get('passed') is True;return parsed
        def angle_diag(lines,code):return diagnostics(lines,code,True)
        cases.append({'name':f'candidate_angle_mode_{mode}','binary':angle_exe,'cwd':angle_dir,'arguments':['--control='+str(mode)],'parse_output':output,'parse_diagnostics':angle_diag})
    def usage_output(lines,code):
        parsed=usage_contract.parse(lines,code);parsed['api_contract_passed']=parsed.get('passed') is True;return parsed
    cases.append({'name':'candidate_getusage_four_cases','binary':usage_exe,'cwd':usage_dir,'arguments':(), 'parse_output':usage_output,'parse_diagnostics':lambda lines,code:diagnostics(lines,code,False)})
    role='dxmt-candidate-'+work.name.removeprefix('dxmt-resource-candidate-run-')
    pattern='wine-parity-'+role+'-*-results.json';before=set((ROOT/'research').glob(pattern))
    try:
        with redirect_stdout(io.StringIO()):
            runner.run_cases(cases,verify_inputs=verify_inputs,role=role,environment_factory=environment,prepare_prefix=bridge)
    finally:
        created=set((ROOT/'research').glob(pattern))-before
        if len(created)!=1:raise Invalid('RESULT_BINDING')
        report=created.pop()
        if report.is_symlink() or report.resolve(strict=True)!=report:raise Invalid('RESULT_BINDING')
        result=json.loads(report.read_text());observed=any(x.get('status') in ('COMPLETE','OBSERVED_FAILURE') for x in result.get('runs',[]));result['only_own_fixtures_and_builtin_initialization']=False if observed else (None if result.get('runtime_started') else True)
        result['client_cef_rockstar_game_or_account_code_started']=False
        result['actual_scope']='own candidate D3D11 and ANGLE/GetUsage fixtures only; no browser, FiveM, Skia, RGL, GTA or accounts'
        result.update(candidate_evidence())
        recorded=result.get('runs',[])
        provider_ok=len(recorded)==len(cases) and all(x.get('diagnostics',{}).get('original_provider_chain_observed') is True and (not x['name'].startswith('candidate_angle_') or x.get('diagnostics',{}).get('original_angle_libraries_loaded') is True) for x in recorded)
        if not observed:result['candidate_provider_binding']='NOT_TESTED'
        elif not provider_ok:result['candidate_provider_binding']='INCOMPLETE_PROVIDER_EVIDENCE'
        result['own_api_cases_passed']=len(result.get('runs',[]))==len(cases) and all(x.get('api_contract_passed') is True for x in result.get('runs',[]));result['passed']=False
        result['status']='FUNCTIONAL_CASES_COMPLETE_BINDING_INFERRED' if result['own_api_cases_passed'] else 'FUNCTIONAL_CASES_INCOMPLETE_OR_FAILED'
        pending=report.with_suffix('.corrected.tmp')
        with pending.open('x') as f:json.dump(result,f,indent=2);f.write('\n')
        os.replace(pending,report)
    print(json.dumps({'status':result['status'],'candidate_provider_binding':result['candidate_provider_binding'],'full_candidate_verification':'INCOMPLETE','physical_path_verified':False}))
    return 1

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--candidate-proof',required=True);parser.add_argument('--proof-sha256',required=True);args=parser.parse_args()
    try:
        proof=Path(args.candidate_proof)
        if not proof.is_absolute():proof=ROOT/proof
        expected=ROOT/'build/dxmt-resource-usage-e95ais9r/frozen-artifact-proof.json'
        if proof!=expected or proof.resolve(strict=True)!=proof:raise Invalid('PROOF_PATH')
        return run(proof,args.proof_sha256)
    except Exception:
        print(json.dumps({'status':'INCOMPLETE','code':'CANDIDATE_RUNNER_VALIDATION_FAILED'}));return 1
if __name__=='__main__':raise SystemExit(main())
