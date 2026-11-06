#!/usr/bin/env python3
"""Build only an isolated CitizenGame overlay from the pinned existing MSVC recipe."""
import difflib
import hashlib
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import overlay

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
BASE = ROOT/'build/windows-main-candidate-27nal69i'
SOURCE = BASE/'source'
BASE_BUILD = BASE/'cmake'
BASE_BINARY = BASE_BUILD/'dependencies/launcher/CitizenGame.dll'
BASE_BINARY_SHA = '1f33031d7cdb2b4fd4558f9af442f62f50865326d607f8f2dfeb5764b8f28256'

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def identity(path):
    try:name=str(path.relative_to(ROOT))
    except ValueError:name=str(path)
    return {'path':name, 'bytes':path.stat().st_size, 'sha256':digest(path)}

def run(command, log, cwd):
    with log.open('x') as output:
        subprocess.run(command, cwd=cwd, stdout=output, stderr=subprocess.STDOUT, check=True)

def main():
    if digest(BASE_BINARY) != BASE_BINARY_SHA:
        raise RuntimeError('Pinned CitizenGame baseline changed')
    original = SOURCE/'code/client/citigame/Launcher.cpp'
    adapted = overlay.adapt(original.read_bytes())
    work = Path(tempfile.mkdtemp(prefix='windows-component-init-trace-', dir=ROOT/'build'))
    print(work,flush=True)
    record = {'scope':'Offline CitizenGame initialization-return observer only', 'baseline':identity(BASE_BINARY),
              'source_revision':'88a413835e9d7f56633f249880a13f42297153a2', 'original_source':identity(original),
              'runtime_started':False, 'runtime_staged':False, 'prefix_accessed':False}
    tool_paths=[Path(p).resolve() for p in ('/opt/homebrew/opt/llvm/bin/clang-cl','/opt/homebrew/opt/lld/bin/lld-link',
                '/opt/homebrew/opt/llvm/bin/llvm-rc','/opt/homebrew/opt/llvm/bin/llvm-mt','/opt/homebrew/bin/cmake',
                '/opt/homebrew/opt/llvm/bin/llvm-readobj')]
    record['tools']=[identity(p) for p in tool_paths]
    try:
        frozen = work/'recipe';frozen.mkdir()
        for p in sorted(HERE.iterdir()):
            if p.is_file():shutil.copyfile(p,frozen/p.name)
        record['recipe_inputs']=[identity(p) for p in sorted(frozen.iterdir())]
        source = work/'source';source.mkdir()
        for name in ('ComponentInitTraceCore.h','ComponentInitTrace.h'):
            shutil.copyfile(frozen/name,source/name)
        unit_paths=('code/client/common/Error.cpp','code/client/citigame/Launcher.cpp',
                    'code/client/citigame/NvCacheWorkaround.cpp','code/client/common/StdInc.cpp')
        for name in unit_paths:
            target=source/name;target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(adapted if name.endswith('/Launcher.cpp') else (SOURCE/name).read_bytes())
        (work/'initialization-only.patch').write_text(''.join(difflib.unified_diff(
            original.read_text().splitlines(True),adapted.decode().splitlines(True),
            fromfile='a/code/client/citigame/Launcher.cpp',tofile='b/code/client/citigame/Launcher.cpp')))
        # The host fixture compiles the actual adapted loop, rather than a second implementation.
        text=adapted.decode().replace('\r\n','\n')
        start=text.index('        const bool traceInitializations =')
        ending=text.index('            cfx::component_init_trace::Trace::Finish();',start)
        ending=text.index('\n        }',ending)+len('\n        }')
        fixture_dir=work/'fixture';fixture_dir.mkdir()
        (fixture_dir/'ObservedBlock.inc').write_text(text[start:ending]+'\n')
        for name in ('fixture.cpp','ComponentInitTraceCore.h'):
            shutil.copyfile(frozen/name,fixture_dir/name)
        run(['/usr/bin/clang++','-std=c++17','-O1','-g','-pthread','-fsanitize=address,undefined',
             str(fixture_dir/'fixture.cpp'),'-o',str(fixture_dir/'fixture')],work/'fixture-build.log',fixture_dir)
        run([str(fixture_dir/'fixture')],work/'fixture-test.log',fixture_dir)
        record['fixture_passed']=True
        record['fixture_scope']='Actual adapted loop; own types/platform only, no Windows/CEF/client/closed component executed'
        commands=subprocess.check_output(['ninja','-C',str(BASE_BUILD),'-t','commands',
                                         'dependencies/launcher/CitizenGame.dll'],text=True).splitlines()
        (work/'baseline-target-commands.txt').write_text('\n'.join(commands)+'\n')
        compiles=[];baseline_command_files=[];header_inputs=set()
        objects=work/'objects';objects.mkdir()
        for line in commands:
            args=shlex.split(line)
            output=next((x for x in args if x.startswith('/Fo') and 'CitiGame.dir/' in x),None)
            if not output:continue
            unit=Path(args[-1]);relative=unit.relative_to(SOURCE)
            if str(relative) not in unit_paths:raise RuntimeError('Unexpected original CitizenGame source unit')
            new_obj=objects/(unit.stem+'.obj');new_args=[]
            for token in args[:-1]:
                if token == '--':continue
                if token.startswith(('-clang:-MD','-clang:-MT','-clang:-MF')):continue
                if token.startswith('/Fo'):token='/Fo'+str(new_obj)
                elif token.startswith('/Fd'):token='/Fd'+str(objects)+'/'
                elif token.startswith('-I') and not token[2:].startswith('/'):
                    token='-I'+str((BASE_BUILD/token[2:]).resolve())
                new_args.append(token)
            new_args += ['-I'+str(source),'/showIncludes','--',str(source/relative)]
            log=work/(unit.stem+'-compile.log');run(new_args,log,work)
            compiled_text=log.read_text()
            for include in re.findall(r'^Note: including file:\s+(.+)$',compiled_text,re.M):
                p=Path(include.strip()).resolve(strict=True)
                if p.is_file():header_inputs.add(p)
            header_inputs.add((source/relative).resolve())
            compiles.append({'source':identity(source/relative),'object':identity(new_obj),'command':new_args,'log':identity(log)})
            baseline_command_files.append((output[3:],new_obj))
        if len(compiles)!=4:raise RuntimeError('Require exactly four fresh original CitizenGame source units')
        if not any(p.name=='ComponentInitTrace.h' for p in header_inputs):raise RuntimeError('Trace header missing from actual compiler includes')
        if not any(p.name=='EventCore.h' for p in header_inputs):raise RuntimeError('Public event ABI header missing from compiler includes')
        line=next(x for x in commands if ' -- /opt/homebrew/opt/lld/bin/lld-link ' in x and '/out:dependencies/launcher/CitizenGame.dll ' in x)
        tokens=shlex.split(line);tokens=tokens[2:-2]
        out_dir=work/'linked';out_dir.mkdir()
        libraries=set();new_link=[]
        mapping={old:str(new) for old,new in baseline_command_files}
        for token in tokens:
            if token in mapping:token=mapping[token]
            elif token.startswith('--intdir='):token='--intdir=objects'
            elif token.startswith('/out:'):token='/out:linked/CitizenGame.dll'
            elif token.startswith('/implib:'):token='/implib:linked/CitizenGame.lib'
            elif token.startswith('/pdb:'):token='/pdb:linked/CitizenGame.pdb'
            elif token.endswith('.lib') and not token.startswith('/') and '/' in token:
                p=(BASE_BUILD/token).resolve(strict=True);libraries.add(p);token=str(p)
            elif token.endswith('.lib') and token.startswith('/') and not token.startswith('/libpath:'):
                p=Path(token).resolve(strict=True);libraries.add(p)
            new_link.append(token)
        library_paths=[Path(token[len('/libpath:'):]) for token in new_link if token.startswith('/libpath:')]
        for token in new_link:
            if token.endswith('.lib') and '/' not in token and '\\' not in token:
                found=next((directory/token for directory in library_paths if (directory/token).is_file()),None)
                if found is None:raise RuntimeError('Unresolved original SDK library: '+token)
                libraries.add(found.resolve())
        link_before=[identity(p) for p in sorted(libraries)]
        run(new_link,work/'link.log',work)
        if link_before!=[identity(p) for p in sorted(libraries)]:raise RuntimeError('Bound link input changed')
        candidate=out_dir/'CitizenGame.dll'
        inventories={}
        for role,path in [('baseline',BASE_BINARY),('candidate',candidate),('CoreRT',ROOT/'build/windows-core-ownership-odvc860i/cmake/CoreRT.dll')]:
            output=subprocess.check_output(['/opt/homebrew/opt/llvm/bin/llvm-readobj','--file-headers','--coff-imports','--coff-exports',str(path)],text=True)
            (work/(role+'-pe.txt')).write_text(output)
            imports={}
            for block in re.findall(r'\n(?:Import|DelayImport) \{\n(.*?)\n\}',output,re.S):
                module=re.search(r'^  Name: (.+)$',block,re.M).group(1).lower()
                imports[module]=re.findall(r'^  Symbol: (.+) \([^\n]+\)$',block,re.M)
            exports=re.findall(r'\nExport \{\n  Ordinal: (\d+)\n  Name: ([^\n]*)\n',output)
            inventories[role]={'identity':identity(path),'imports':imports,'exports':exports,'AMD64':'Machine: IMAGE_FILE_MACHINE_AMD64' in output}
        if not inventories['candidate']['AMD64'] or inventories['baseline']['exports']!=inventories['candidate']['exports']:
            raise RuntimeError('CitizenGame architecture/export ordinal ABI changed')
        core_exports={x[1] for x in inventories['CoreRT']['exports']}
        if set(inventories['candidate']['imports'].get('corert.dll',[]))-core_exports:
            raise RuntimeError('Candidate requires absent P9 CoreRT API')
        before={k:set(v) for k,v in inventories['baseline']['imports'].items()};after={k:set(v) for k,v in inventories['candidate']['imports'].items()}
        extra={k:sorted(v-before.get(k,set())) for k,v in after.items() if v-before.get(k,set())}
        allowed={'kernel32.dll':{'GetEnvironmentVariableW','GetLastError','SetLastError','OutputDebugStringA','GetCurrentProcessId','GetCurrentThreadId'},
                 'api-ms-win-crt-string-l1-1-0.dll':{'strcmp'}}
        if any(set(values)-allowed.get(module,set()) for module,values in extra.items()):raise RuntimeError('Unexpected new API import')
        providers={ROOT/'runtime/wine-job-query-parity/engine/lib/wine/x86_64-windows/kernel32.dll':{'GetEnvironmentVariableW'},
                   ROOT/'runtime/wine-job-query-parity/engine/lib/wine/x86_64-windows/ucrtbase.dll':{'strcmp'}}
        new_api_providers=[]
        for path,expected in providers.items():
            output=subprocess.check_output(['/opt/homebrew/opt/llvm/bin/llvm-readobj','--coff-exports',str(path)],text=True)
            names=set(re.findall(r'^  Name: (.+)$',output,re.M))
            if expected-names:raise RuntimeError('New standard API export missing')
            new_api_providers.append({'provider':identity(path),'symbols':sorted(expected)})
        (work/'abi-review.json').write_text(json.dumps({'inventories':inventories,'new_imports':extra,'export_parity':True,'p9_corert_imports_closed':True,'runtime_executed':False},indent=2)+'\n')
        record['compile_commands']=compiles;record['link_command']=new_link
        record['header_inputs']=[identity(p) for p in sorted(header_inputs)]
        record['reused_link_inputs']=[identity(p) for p in sorted(libraries)]
        record['new_api_providers']=new_api_providers
        record['toolchain']=identity(ROOT/'native/windows-core/toolchain.cmake')
        record['abi_review']=identity(work/'abi-review.json')
        record['compiled_all_four_units_fresh']=True
        if identity(original)!=record['original_source'] or digest(BASE_BINARY)!=BASE_BINARY_SHA:
            raise RuntimeError('Protected baseline changed during isolated build')
        if record['tools']!=[identity(p) for p in tool_paths]:raise RuntimeError('Build tool changed')
        artifact=work/'artifact/CitizenGame.dll';artifact.parent.mkdir();shutil.copyfile(candidate,artifact);artifact.chmod(0o444)
        record['artifact']=identity(artifact);record['build_passed']=True
    finally:
        (work/'result.json').write_text(json.dumps(record,indent=2)+'\n')
    proof={'artifact':record['artifact'],'build_record':identity(work/'result.json'),'source':identity(source/'code/client/citigame/Launcher.cpp'),
           'trace_core':identity(source/'ComponentInitTraceCore.h'),'trace_platform':identity(source/'ComponentInitTrace.h'),
           'abi_review':identity(work/'abi-review.json'),'baseline':record['baseline'],'runtime_started':False,'runtime_staged':False,'prefix_accessed':False}
    (work/'frozen-artifact-proof.json').write_text(json.dumps(proof,indent=2)+'\n')
    print(json.dumps({'artifact':proof['artifact'],'proof':identity(work/'frozen-artifact-proof.json')}))

if __name__=='__main__':main()
