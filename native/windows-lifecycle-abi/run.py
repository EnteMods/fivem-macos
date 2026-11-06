"""Exercise the pinned public type-index interface with own component objects."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
RECORD = ROOT / 'build/windows-component-init-trace-edw16lbb/result.json'
RECORD_SHA = '80d8924cdf9782087a0ef2fa09d5098461bd3a84c8e37d44c9332b314c53b09a'
PREFIX = ROOT / 'prefixes/wine-parity-regression'
sys.path.insert(0, str(ROOT / 'scripts'))
from probe_environment import probe_prefix, assert_account_free_prefix


def identity(path):
    path = Path(path)
    return {'path': str(path), 'bytes': path.stat().st_size,
            'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def main():
    if identity(RECORD)['sha256'] != RECORD_SHA:
        raise RuntimeError('Pinned build recipe changed')
    recipe = json.loads(RECORD.read_text())
    work = Path(tempfile.mkdtemp(prefix='windows-lifecycle-abi-', dir=ROOT / 'build'))
    print(work, flush=True)
    source = work / 'probe.cpp'
    source.write_bytes(Path(__file__).with_name('probe.cpp').read_bytes())
    base = ROOT / 'build/windows-main-candidate-27nal69i/source'
    paths = [base / 'code/client/citicore/ResumeComponent.h',
             base / 'code/client/citicore/ComponentLoader.h',
             base / 'code/client/shared/Utils.h']
    bound = {x['path']: x for x in recipe['header_inputs']}
    snapshots = []
    for path in paths:
        item = identity(path)
        previous = bound[str(path.relative_to(ROOT))]
        if item['sha256'] != previous['sha256'] or item['bytes'] != previous['bytes']:
            raise RuntimeError('Pinned public header changed')
        snapshots.append(item)
    resume, component, utils = [path.read_text().replace('\r\n', '\n') for path in paths]
    lifecycle = resume[resume.index('class LifeCycleComponent\n'):]
    lifecycle = lifecycle[:lifecycle.index('\n};') + len('\n};')]
    cast = component[component.index('template<typename T, typename TOther>\n'):]
    cast = cast[:cast.index('\n#ifndef IS_FXSERVER')]
    hashing = utils[utils.index('inline constexpr char ToLower('):utils.index('\ninline void LowerString(')]
    observed = work / 'ObservedPublic.inc'
    observed.write_text(lifecycle + '\n' + hashing + '\n' + cast + '\n')
    obj, exe = work / 'probe.obj', work / 'probe.exe'
    original = next(x['command'] for x in recipe['compile_commands']
                    if x['source']['path'].endswith('/Launcher.cpp'))
    compile_args = []
    for token in original[:-1]:
        if token == '--':
            continue
        if token.startswith('/Fo'):
            token = '/Fo' + str(obj)
        elif token.startswith('/Fd'):
            token = '/Fd' + str(work) + '/'
        compile_args.append(token)
    compile_args += ['-I' + str(work), '--', str(source)]
    with (work / 'compile.log').open('x') as log:
        subprocess.run(compile_args, cwd=work, stdout=log, stderr=subprocess.STDOUT, check=True)
    includes = [Path(x.strip()).resolve(strict=True) for x in
                re.findall(r'^Note: including file:\s+(.+)$', (work / 'compile.log').read_text(), re.M)]
    vc = ROOT / 'toolchains/msvc-2022/VC/Tools/MSVC/14.44.35207'
    sdk = ROOT / 'toolchains/msvc-2022/Windows Kits/10'
    libraries = [vc / 'lib/x64'] + [sdk / 'Lib/10.0.26100.0' / x / 'x64' for x in ('ucrt', 'um')]
    link_args = ['/opt/homebrew/opt/lld/bin/lld-link', '/nologo', '/machine:x64',
                 '/subsystem:console', '/opt:ref', '/out:' + str(exe), str(obj),
                 *['/libpath:' + str(x) for x in libraries], 'kernel32.lib']
    with (work / 'link.log').open('x') as log:
        subprocess.run(link_args, cwd=work, stdout=log, stderr=subprocess.STDOUT, check=True)
    result = {'scope': 'Own objects and pinned public lifecycle/type-index headers only',
              'source_revision': recipe['source_revision'], 'source': identity(source),
              'build_recipe': identity(RECORD), 'compile_command': compile_args,
              'link_command': link_args, 'header_inputs': [identity(x) for x in sorted(set(includes))],
              'extracted_public_inputs': snapshots, 'extracted_public_code': identity(observed),
              'artifact': identity(exe), 'account_or_client_code_executed': False}
    path = ROOT / 'build/source-update-candidate-nqwlz36g/resume-candidate.py'
    spec = importlib.util.spec_from_file_location('lifecycle_runtime', path)
    runtime = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runtime)
    graphics, _, _, env = runtime.game.first.configure()
    engine = graphics.runtime.ENGINE
    if PREFIX.resolve(strict=True) == runtime.game.PREFIX.resolve(strict=True):
        raise RuntimeError('Refusing client prefix')
    env['WINEPREFIX'] = str(PREFIX)
    env['WINEDEBUG'] = '-all,err+all'
    env.pop('CFX_COMPONENT_INIT_TRACE', None)
    env.pop('CFX_AUTH_TRACE', None)
    with probe_prefix(PREFIX, root=ROOT):
        if subprocess.run([engine / 'bin/wineserver', '-w'], env=env, timeout=3,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
            raise RuntimeError('Probe prefix is busy')
        try:
            try:
                run = subprocess.run([engine / 'bin/wine', str(exe)], env=env, cwd=work,
                                     capture_output=True, text=True, timeout=60)
            except subprocess.TimeoutExpired as error:
                def decoded(value):
                    return value.decode('utf-8', errors='replace') if isinstance(value, bytes) else value or ''
                (work / 'run.stdout').write_text(decoded(error.stdout))
                (work / 'run.stderr').write_text(decoded(error.stderr))
                result.update(returncode=None, passed=False, numeric_values=None, timeout=True)
                raise
            assert_account_free_prefix(PREFIX, root=ROOT)
            (work / 'run.stdout').write_text(run.stdout)
            (work / 'run.stderr').write_text(run.stderr)
            match = re.fullmatch(r'LIFECYCLE_ABI ([0-9]+) ([0-9]+) ([0-9]+) ([01]) ([0-9]+) ([01])\s*', run.stdout)
            result.update(returncode=run.returncode, numeric_values=[int(x) for x in match.groups()] if match else None,
                          passed=run.returncode == 0 and bool(match) and match.group(6) == '1',
                          prefix=str(PREFIX.relative_to(ROOT)), engine=str(engine.relative_to(ROOT)))
        finally:
            result['cleanup'] = {}
            for flag in ('-k', '-w'):
                result['cleanup'][flag] = subprocess.run([engine / 'bin/wineserver', flag], env=env,
                    timeout=20, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
            (work / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: result[k] for k in ('passed', 'returncode', 'numeric_values', 'cleanup')}))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
