#!/usr/bin/env python3
"""Bind prepared development dependencies and the real API probe evidence."""
import json
from pathlib import Path
import re
import shlex
import subprocess
from prepare import ROOT, WORK, FRAMEWORKS, GST_LIB, identity, own, sha


def flags(arguments):
    return ' '.join(shlex.quote(argument) for argument in arguments)


def main():
    prepared = json.loads((WORK / 'dependency-preparation.json').read_text())
    sdk = json.loads((WORK / 'sdk-acquisition.json').read_text())
    for item in (prepared['headers'] + prepared['licenses'] + prepared['source_generation_evidence']
                 + prepared['libraries']['closure'] + sdk['selected_development_files'] + [sdk['license_notice']]):
        if sha(Path(item['path'])) != item['sha256']:
            raise RuntimeError('Dependency changed before manifest issuance')
    evidence = []
    for group in ('basic', 'media'):
        path = WORK / (group + '-api-probe-results.json')
        value = json.loads(path.read_text())
        if value.get('passed') is not True or value.get('compile_exit') != 0 or value.get('run_exit') != 0:
            raise RuntimeError('Both real x86_64 API probe groups must pass')
        if value.get('dependency_manifest') != identity(WORK / 'dependency-preparation.json'):
            raise RuntimeError('API probe was not run against the current dependency inventory')
        if group == 'media' and value.get('original_sdk_manifest') != identity(WORK / 'sdk-acquisition.json'):
            raise RuntimeError('API probe was not run against the current SDK inventory')
        if value['binary'] != identity(Path(value['binary']['path'])):
            raise RuntimeError('Own API probe binary changed')
        if value.get('probe_source') != identity(ROOT / ('native/wine-job-query-parity/probe-' + group + '.c')):
            raise RuntimeError('Own API probe source changed')
        evidence.append({'record': identity(path), 'binary': value['binary'], 'output': value['run_output']})
    selected = prepared['libraries']['selected']
    requirements = (
        ('gnutls', 'dlls/secur32/schannel_gnutls.c', 'gnutls_'),
        ('gnutls', 'dlls/bcrypt/gnutls.c', 'gnutls_'),
        ('freetype', 'dlls/win32u/freetype.c', 'FT_'),
        ('sdl2', 'dlls/winebus.sys/bus_sdl.c', 'SDL_'),
    )
    exports = {}
    audits = []
    for library, relative, prefix in requirements:
        source = ROOT / 'build/wine-job-query/source' / relative
        symbols = sorted({name for name in re.findall(r'\bLOAD_FUNCPTR\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)', source.read_text())
                          if name.startswith(prefix)})
        if not symbols:
            raise RuntimeError('No original Wine dynamic API requirements found')
        if library not in exports:
            output = subprocess.check_output(['/usr/bin/nm', '-gU', selected[library]], text=True)
            exports[library] = {line.split()[-1].lstrip('_') for line in output.splitlines() if line.split()}
        missing = sorted(set(symbols) - exports[library])
        audits.append({'source': identity(source), 'library': selected[library], 'symbols': symbols,
                       'missing': missing, 'passed': not missing})
    if any(not audit['passed'] for audit in audits):
        raise RuntimeError('An original Wine required dynamic API export is missing: ' + str(audits))
    includes = WORK / 'dev/include'
    development = WORK / 'dev-sdk'
    gstreamer_includes = ['-I' + str(development / 'base/include/glib-2.0'),
                          '-I' + str(development / 'base/lib/glib-2.0/include'),
                          '-I' + str(development / 'core/include/gstreamer-1.0')]
    suggested = {
        'GNUTLS_CFLAGS': flags(['-I' + str(includes)]),
        'GNUTLS_LIBS': flags(['-L' + str(FRAMEWORKS), '-lgnutls']),
        'FREETYPE_CFLAGS': flags(['-I' + str(includes / 'freetype2')]),
        'FREETYPE_LIBS': flags(['-L' + str(FRAMEWORKS), '-lfreetype']),
        'SDL2_CFLAGS': flags(['-I' + str(includes / 'SDL2')]),
        'SDL2_LIBS': flags(['-L' + str(FRAMEWORKS), '-lSDL2']),
        'GSTREAMER_CFLAGS': flags(gstreamer_includes),
        'GSTREAMER_LIBS': flags(['-L' + str(GST_LIB), '-lgstvideo-1.0', '-lgstaudio-1.0', '-lgsttag-1.0',
                                 '-lgstbase-1.0', '-lgstreamer-1.0', '-lgobject-2.0', '-lglib-2.0', '-lintl']),
        'FFMPEG_CFLAGS': flags(['-I' + str(development / 'libav/include')]),
        'FFMPEG_LIBS': flags(['-L' + str(GST_LIB), '-lavformat', '-lavcodec', '-lavutil']),
    }
    sources = [identity(path) for path in sorted((ROOT / 'native/wine-job-query-parity').iterdir())
               if path.is_file() and path.suffix in ('.py', '.c', '.md')]
    result = {'schema_version': 1, 'dependency_preparation': identity(WORK / 'dependency-preparation.json'),
              'official_sdk_preparation': identity(WORK / 'sdk-acquisition.json'), 'sources': sources,
              'real_x86_64_probe_evidence': evidence, 'original_wine_dynamic_export_audits': audits,
              'suggested_configure_environment_not_yet_run': suggested,
              'source_versions_equal_to_runtime_claimed': False,
              'complete_wine_configure_run': False, 'complete_wine_build_run': False,
              'wine_or_prefix_started': False, 'existing_runtime_or_candidate_changed': False,
              'scope': 'Own native library API/ABI probes, not complete Wine dependency or launcher compatibility',
              'passed': True}
    own(WORK / 'parity-dependencies.json').write_text(json.dumps(result, indent=2) + '\n')
    print('Dependency manifest PASS;', sum(len(a['symbols']) for a in audits),
          'original Wine dynamic API requirements exported; 2 native probe groups passed')


if __name__ == '__main__':
    main()
