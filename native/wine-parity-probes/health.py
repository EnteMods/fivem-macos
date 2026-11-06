#!/usr/bin/env python3
"""Separate font/WinHTTP adapters for the unchanged account-free parity lifecycle."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('own_health_parity_lifecycle', HERE/'run.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
runner = base
ROOT = base.ROOT

PROFILES = {
    'health': {'directory': 'windows-runtime-health', 'report': 'research/windows-runtime-health-build.json',
               'report_sha256': '683467656719a2936840be8f5cd85e3138bd4a37c0ef9466e5bfb92c7e873bb3',
               'binary': 'runtime_health_probe', 'bytes': 507392,
               'sha256': '12ac497feee6638948eb128ba0a33dacfd3b53668b20a7210ae84b93b4c52d7b',
               'parser_sha256': '9f2f6c745542e77f47530020098e8858656f8a5c0010d30840d315499b14e8c7',
               'imports': ['d3d11.dll', 'GDI32.dll', 'KERNEL32.dll']},
    'winhttp': {'directory': 'windows-winhttp-probe', 'report': 'research/windows-winhttp-probe-build.json',
                'report_sha256': '030d91460214b5afdda83a4409d4a7df289d757028c03b6329269ea0ecf92964',
                'binary': 'winhttp_probe', 'bytes': 504320,
                'sha256': '0d9e50cf9db559ab827ede9f646ad137c4d32ced7610a08165ea4ceab02fb92b',
                'parser_sha256': '2ea3aa46ca854ee5242a6b6ddde71d3cfd0bbf666ab165dd9bbf224e954b1d5f',
                'imports': ['WINHTTP.dll', 'KERNEL32.dll']},
}
SOURCE_NAMES = {'CMakeLists.txt', 'probe.cpp', 'build.py', 'contract.py', 'test_contract.py', 'README.md'}
TARGET_URL = ('https://content.cfx.re/mirrors/vendor/cef/v144/'
              'cef_binary_144.19.61-cfx-m144-osr.3461%2Bgcbe8fd0%2Bchromium-144.0.7559.264_windows64_minimal.zip')
TARGET_SOURCES = {'port/fivem/code/tools/ci/psm1/cfxSetupCEF.psm1', 'port/fivem/vendor/cef/cef_build_name.txt'}


def _read(name, allowed):
    if type(name) is not str or name not in allowed:
        raise RuntimeError('Unreviewed health-probe input path')
    return base.runtime.read_regular(ROOT/name, ROOT)


def _identity(name, allowed):
    raw = _read(name, allowed)
    return {'path': name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def _shape(item, expected):
    if (not isinstance(item, dict) or item.get('path') != expected
            or type(item.get('bytes')) is not int or item['bytes'] <= 0
            or type(item.get('sha256')) is not str or re.fullmatch('[0-9a-f]{64}', item['sha256']) is None):
        raise RuntimeError('Unexpected own health-probe identity')


def _group(items, expected):
    if (not isinstance(items, list) or len(items) != len(expected)
            or any(not isinstance(item, dict) or type(item.get('path')) is not str for item in items)
            or {item['path'] for item in items} != expected):
        raise RuntimeError('Unexpected complete health-probe source path set')
    for item in items: _shape(item, item['path'])


def _verify(family):
    profile = PROFILES[family]
    report_path = profile['report']
    raw = _read(report_path, {report_path})
    if hashlib.sha256(raw).hexdigest() != profile['report_sha256']:
        raise RuntimeError('Own health-probe build report changed; no unreviewed rebuild is admitted')
    report = json.loads(raw)
    source_root, build_root = 'native/'+profile['directory'], 'build/'+profile['directory']
    binary = build_root+'/'+profile['binary']+'.exe'
    source_paths = {source_root+'/'+name for name in SOURCE_NAMES}
    _shape(report.get('artifact'), binary)
    _group(report.get('source_evidence'), source_paths)
    fixed = [(report.get('toolchain'), 'native/windows-core/toolchain.cmake'),
             (report.get('object'), build_root+'/CMakeFiles/'+profile['binary']+'.dir/probe.cpp.obj'),
             (report.get('pe_inspection'), build_root+'/pe-inspection.txt'),
             (report.get('build', {}).get('log'), build_root+'/build.log'),
             (report.get('build', {}).get('compile_commands'), build_root+'/compile_commands.json'),
             (report.get('no_wine_contract_tests', {}).get('log'), build_root+'/contract-tests.log')]
    target_metadata = None
    if family == 'winhttp':
        target = report.get('target', {})
        _group(target.get('original_url_sources'), TARGET_SOURCES)
        fixed += [(report.get('generated_target_header'), build_root+'/target.generated.h'),
                  (target.get('cef_config'), 'config/cef-package.json'),
                  (target.get('existing_main_https_build'), 'build/windows-client-tests/https/build-record.json')]
        if (target.get('url') != TARGET_URL or target.get('host') != 'content.cfx.re'
                or target.get('path') != TARGET_URL.removeprefix('https://content.cfx.re') or target.get('port') != 443):
            raise RuntimeError('Only the fixed official unauthenticated CEF HEAD target is admitted')
        target_metadata = {key: target[key] for key in ('url', 'host', 'path', 'port')}
    for item, path in fixed: _shape(item, path)
    if (report.get('compiled') is not True or report.get('architecture') != 'AMD64' or report.get('runtime') != '/MT'
            or report.get('artifact') != {'path': binary, 'bytes': profile['bytes'], 'sha256': profile['sha256']}
            or report.get('imports') != profile['imports'] or report.get('build', {}).get('exit') != 0
            or report.get('no_wine_contract_tests', {}).get('exit') != 0
            or report.get('no_wine_contract_tests', {}).get('passed') != 3
            or report.get('runtime_tested') is not False or report.get('wine_or_prefix_started') is not False
            or report.get('actual_client_game_or_account_code_used') is not False):
        raise RuntimeError('Require the exact own AMD64 /MT build and no-Wine evidence')
    if family == 'winhttp':
        policy = report.get('policy', {})
        if (report.get('network_request_performed') is not False
                or any(policy.get(key) != value for key, value in {
                    'method': 'HEAD', 'secure_flag': 'WINHTTP_FLAG_SECURE', 'expected_http_status': 200,
                    'redirect_policy': 'NEVER', 'body_read': False, 'custom_ca_or_ignore_flags': False,
                    'credentials_supplied': False, 'session_proxy_selection': 'WINHTTP_ACCESS_TYPE_DEFAULT_PROXY',
                    'proxy_configuration_changed': False, 'url_from_cli_or_environment': False,
                    'all_created_handles_closed_and_checked': True}.items())):
            raise RuntimeError('WinHTTP certificate/proxy/credential/body policy changed')
    selected = [report['artifact'], *report['source_evidence'], *(item for item, _ in fixed)]
    if family == 'winhttp': selected += report['target']['original_url_sources']
    allowed = {report_path} | {item['path'] for item in selected}
    checked = []
    for item in selected:
        actual = _identity(item['path'], allowed)
        if actual != item: raise RuntimeError('Bound own health-probe code/evidence bytes changed')
        checked.append(actual)
    parser = next(item for item in checked if item['path'] == source_root+'/contract.py')
    if parser['sha256'] != profile['parser_sha256']:
        raise RuntimeError('Only the original health acceptance parser may execute')
    result = {'probe_family': 'runtime-health' if family == 'health' else 'winhttp-secure-head',
              'runtime_inputs': [report['artifact']], 'source_inputs': checked[1:], 'parser_source': parser,
              'build_reports': [{'path': report_path, 'bytes': len(raw), 'sha256': profile['report_sha256']}],
              'runner_sources': [_identity('native/wine-parity-probes/'+name,
                               {'native/wine-parity-probes/'+n for n in ('health.py', 'run.py', 'environment.py')})
                               for name in ('health.py', 'run.py', 'environment.py')]}
    if target_metadata is not None: result['fixed_target'] = target_metadata
    return result


def verify_health():
    return _verify('health')


def verify_winhttp():
    return _verify('winhttp')


def _load_contract(family):
    profile = PROFILES[family]
    name = 'native/'+profile['directory']+'/contract.py'
    raw = _read(name, {name})
    if hashlib.sha256(raw).hexdigest() != profile['parser_sha256']:
        raise RuntimeError('Refusing changed acceptance-parser code')
    namespace = {'__name__': 'own_verified_'+family+'_contract', '__file__': str(ROOT/name)}
    exec(compile(raw, str(ROOT/name), 'exec'), namespace)
    return namespace['parse_output']


def load_health_contract():
    return _load_contract('health')


def load_winhttp_contract():
    return _load_contract('winhttp')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('font', 'winhttp'))
    args = parser.parse_args(argv)
    verifier = verify_health if args.mode == 'font' else verify_winhttp
    fixture = verifier()
    binary = ROOT/fixture['runtime_inputs'][0]['path']
    if args.mode == 'font':
        contract = load_health_contract()
        parse = lambda lines, code: contract('\n'.join(lines), 'font', code)
        arguments = ('--font',)
    else:
        contract = load_winhttp_contract()
        parse = lambda lines, code: contract('\n'.join(lines), code)
        arguments = ()
    return base.run_cases([{'name': args.mode, 'binary': binary, 'cwd': binary.parent,
                            'arguments': arguments, 'parse_output': parse}], verify_inputs=verifier, role=args.mode)


if __name__ == '__main__':
    raise SystemExit(main())
