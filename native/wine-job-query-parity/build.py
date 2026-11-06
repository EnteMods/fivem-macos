#!/usr/bin/env python3
"""Build a separate full x86_64 Wine engine; never start Wine or a prefix."""
import argparse
import datetime
import difflib
import hashlib
import json
import os
from pathlib import Path
import shlex
import signal
import stat
import subprocess
import time

from prepare import ROOT, WORK, FRAMEWORKS, GST_LIB, identity, own, sha

BUILD = WORK / 'full-x86_64'
SOURCE = ROOT / 'build/wine-job-query/source'
OLD_WORK = ROOT / 'build/wine-job-query'
INSTALL = ROOT / 'runtime/wine-job-query-parity/engine'
DEPENDENCY_SHA = 'c341e162a10d890dfc1b3a53d67581b133672e745a3860c84038739254c6d2b2'
OWNER = {'project': str(ROOT), 'build': str(BUILD), 'install': str(INSTALL),
         'purpose': 'Separate complete Job-query Wine engine; no Wine/prefix starts'}


def write(path, value):
    if BUILD not in path.parents:
        raise RuntimeError('Build records must stay in the separate build directory')
    own(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + '\n')


def verify_dependencies():
    manifest = WORK / 'parity-dependencies.json'
    if sha(manifest) != DEPENDENCY_SHA:
        raise RuntimeError('Reviewed parity dependency manifest changed')
    value = json.loads(manifest.read_text())
    inputs = list(value['sources'])
    for key in ('dependency_preparation', 'official_sdk_preparation'):
        item = value[key]
        if identity(Path(item['path'])) != item:
            raise RuntimeError('Dependency preparation identity changed')
    prepared = json.loads(Path(value['dependency_preparation']['path']).read_text())
    sdk = json.loads(Path(value['official_sdk_preparation']['path']).read_text())
    inputs += prepared['headers'] + prepared['licenses'] + prepared['source_generation_evidence']
    inputs += prepared['libraries']['closure'] + sdk['selected_development_files'] + [sdk['license_notice']]
    for evidence in value['real_x86_64_probe_evidence']:
        inputs += [evidence['record'], evidence['binary']]
    for item in inputs:
        path = Path(item['path'])
        if identity(path) != {key: item[key] for key in ('path', 'bytes', 'sha256')}:
            raise RuntimeError('Bound development input changed: ' + str(path))
    for evidence in value['real_x86_64_probe_evidence']:
        probe = json.loads(Path(evidence['record']['path']).read_text())
        if probe.get('passed') is not True or probe.get('run_exit') != 0 or probe.get('compile_exit') != 0:
            raise RuntimeError('Require both successful real native API probes')
    return value


def verify_source():
    pins_path = ROOT / 'native/wine-job-query/pins.json'
    pins = json.loads(pins_path.read_text())
    prepared_path = OLD_WORK / 'source-preparation.json'
    prepared = json.loads(prepared_path.read_text())
    expected_numbers = ['0001', '0002', '0003'] + [str(number).zfill(4) for number in range(5, 25)]
    if pins['highball']['applied_patch_numbers'] != expected_numbers:
        raise RuntimeError('Unexpected original Highball patch queue')
    cached = ROOT / 'build/windows-job-tests/source-patch-audit/upstream'
    for item in pins['highball']['files']:
        path = cached / item['path']
        if sha(path) != item['sha256'] or path.stat().st_size != item['bytes']:
            raise RuntimeError('Pinned original Highball input changed')
        blob = hashlib.sha1(b'blob ' + str(path.stat().st_size).encode() + b'\0' + path.read_bytes()).hexdigest()
        if blob != item['git_blob_sha1']:
            raise RuntimeError('Original Highball Git blob changed')
    actual_patches = {Path(item['path']).name: item['sha256'] for item in prepared['original_patches']}
    expected_patches = {Path(item['path']).name: item['sha256'] for item in pins['highball']['files']
                        if item['path'].startswith('patches/')}
    if actual_patches != expected_patches or prepared['original_patch_fuzz'] != 0:
        raise RuntimeError('Prepared source patch evidence differs from the matched queue')
    archive = ROOT / prepared['source_archive']
    if sha(archive) != pins['archives'][0]['sha256']:
        raise RuntimeError('Original CrossOver source archive changed')
    if sha(ROOT / pins['query_patch']['path']) != pins['query_patch']['sha256']:
        raise RuntimeError('Reviewed Job-query patch changed')
    for item in pins['query_patch']['source_files']:
        if sha(SOURCE / item['path']) != item['proposed_sha256']:
            raise RuntimeError('Reviewed query source changed')
    generator = pins['original_generator']
    if sha(SOURCE / generator['path']) != generator['sha256']:
        raise RuntimeError('Original protocol generator changed')
    for relative, expected in generator['generated_after_sha256'].items():
        if sha(SOURCE / relative) != expected:
            raise RuntimeError('Original generated protocol output changed')
    files = []
    for path in sorted(SOURCE.rglob('*')):
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode) or not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            raise RuntimeError('Unexpected source link or special file')
        if stat.S_ISREG(mode):
            files.append({'path': str(path.relative_to(SOURCE)), 'bytes': path.stat().st_size, 'sha256': sha(path)})
    return {'source_root': str(SOURCE), 'files': files, 'pins': identity(pins_path),
            'prepared_source_record': identity(prepared_path), 'query_patch': identity(ROOT / pins['query_patch']['path']),
            'original_source_archive': identity(archive), 'protocol_version': generator['new_protocol_version'],
            'highball_commit': pins['highball']['commit'], 'highball_tree': pins['highball']['tree'],
            'original_patch_numbers': expected_numbers}


def tools():
    paths = {'clang': subprocess.check_output(['/usr/bin/xcrun', '--find', 'clang'], text=True).strip(),
             'clang++': subprocess.check_output(['/usr/bin/xcrun', '--find', 'clang++'], text=True).strip(),
             'i386_cc': '/opt/homebrew/bin/i686-w64-mingw32-gcc',
             'x86_64_cc': '/opt/homebrew/bin/x86_64-w64-mingw32-gcc',
             'bison': str(OLD_WORK / 'tools/bison-3.8.2/bin/bison'), 'make': '/usr/bin/make'}
    result = {key: {'binary': identity(Path(path).resolve()),
                    'version': subprocess.check_output([path, '--version'], text=True).strip()}
              for key, path in paths.items()}
    bison_record = json.loads((OLD_WORK / 'bison-build.json').read_text())
    if sha(Path(paths['bison'])) != bison_record['binary_sha256']:
        raise RuntimeError('Local original Bison build changed')
    result['macos_sdk'] = {'path': subprocess.check_output(['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-path'], text=True).strip(),
                           'version': subprocess.check_output(['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-version'], text=True).strip()}
    settings = Path(result['macos_sdk']['path']) / 'SDKSettings.json'
    result['macos_sdk']['settings'] = identity(settings)
    return result


def environment(dependencies):
    value = dict(os.environ)
    for key in list(value):
        if key.startswith(('DYLD_', 'LD_', 'WINE', 'GST_')) or key.lower().startswith('citizenfx_'):
            value.pop(key)
    for key in ('CONFIG_SITE', 'CFLAGS', 'CXXFLAGS', 'CPPFLAGS', 'LDFLAGS', 'LIBS', 'CPATH',
                'C_INCLUDE_PATH', 'CPLUS_INCLUDE_PATH', 'LIBRARY_PATH', 'PKG_CONFIG_PATH', 'PKG_CONFIG_LIBDIR', 'SDKROOT'):
        value.pop(key, None)
    # Autoconf expands these variables as words; embedded shell quotes become literal bytes.
    for key, proposed in dependencies['suggested_configure_environment_not_yet_run'].items():
        arguments = shlex.split(proposed)
        if any(any(character.isspace() for character in argument) for argument in arguments):
            raise RuntimeError('This configure recipe requires dependency paths without whitespace')
        value[key] = ' '.join(arguments)
    value.update(PATH=str(OLD_WORK / 'tools/bison-3.8.2/bin') + ':/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin',
                 MACOSX_DEPLOYMENT_TARGET='14.0',
                 CC='/usr/bin/clang --target=x86_64-apple-macos14',
                 CXX='/usr/bin/clang++ --target=x86_64-apple-macos14',
                 OBJC='/usr/bin/clang --target=x86_64-apple-macos14',
                 BISON=str(OLD_WORK / 'tools/bison-3.8.2/bin/bison'),
                 i386_CC='/opt/homebrew/bin/i686-w64-mingw32-gcc',
                 x86_64_CC='/opt/homebrew/bin/x86_64-w64-mingw32-gcc',
                 DYLD_FALLBACK_LIBRARY_PATH=str(FRAMEWORKS) + ':' + str(GST_LIB),
                 DYLD_FALLBACK_FRAMEWORK_PATH=str(FRAMEWORKS),
                 GST_PLUGIN_PATH='', GST_PLUGIN_SYSTEM_PATH_1_0='', GST_REGISTRY_UPDATE='no')
    molten = BUILD / 'dependencies/moltenvk'
    value['LDFLAGS'] = ' '.join((
        '-L' + str(molten), '-Wl,-rpath,' + str(FRAMEWORKS), '-Wl,-rpath,' + str(GST_LIB)))
    return value


def prepare_build():
    dependencies = verify_dependencies()
    source = verify_source()
    toolchain = tools()
    own(BUILD)
    marker = BUILD / '.parity-build-owner.json'
    if BUILD.exists():
        if not marker.is_file() or json.loads(marker.read_text()) != OWNER:
            raise RuntimeError('Refuse an existing unowned build directory')
        previous = json.loads((BUILD / 'source-inputs.json').read_text())
        if previous != source:
            raise RuntimeError('Reviewed source tree changed since separate build preparation')
    else:
        BUILD.mkdir()
        write(marker, OWNER)
        write(BUILD / 'source-inputs.json', source)
    dependency_record = json.loads((OLD_WORK / 'moltenvk-build-dependency.json').read_text())
    original = OLD_WORK / dependency_record['path']
    if sha(original) != dependency_record['sha256']:
        raise RuntimeError('Pinned original MoltenVK dependency changed')
    destination = own(BUILD / 'dependencies/moltenvk/libMoltenVK.dylib')
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if sha(destination) != dependency_record['sha256']:
            raise RuntimeError('Own MoltenVK dependency changed')
    else:
        with destination.open('xb') as output:
            output.write(original.read_bytes())
    env = environment(dependencies)
    recipe = Path(__file__)
    recipe_snapshot = own(BUILD / 'logs' / ('recipe-' + sha(recipe) + '.py'))
    recipe_snapshot.parent.mkdir(exist_ok=True)
    if not recipe_snapshot.exists():
        with recipe_snapshot.open('xb') as output:
            output.write(recipe.read_bytes())
    record = {'recipe': identity(recipe_snapshot), 'recipe_source_path': str(recipe),
              'source_inventory': identity(BUILD / 'source-inputs.json'),
              'reviewed_dependency_manifest': identity(WORK / 'parity-dependencies.json'),
              'toolchain': toolchain, 'moltenvk': identity(destination),
              'external_runtime_library_roots': [str(FRAMEWORKS), str(GST_LIB)],
              'external_runtime_libraries_copied_into_engine': False, 'dxmt_overlay_applied': False,
              'build_environment': {key: value for key, value in env.items()
                                    if key in dependencies['suggested_configure_environment_not_yet_run']
                                    or key in ('PATH', 'MACOSX_DEPLOYMENT_TARGET', 'CC', 'CXX', 'OBJC', 'BISON',
                                               'i386_CC', 'x86_64_CC', 'LDFLAGS', 'DYLD_FALLBACK_LIBRARY_PATH',
                                               'DYLD_FALLBACK_FRAMEWORK_PATH', 'GST_PLUGIN_PATH',
                                               'GST_PLUGIN_SYSTEM_PATH_1_0', 'GST_REGISTRY_UPDATE')}}
    write(BUILD / 'build-provenance.json', record)
    return env


def verify_configuration():
    text = (BUILD / 'include/config.h').read_text()
    required = ('SONAME_LIBGNUTLS', 'HAVE_GNUTLS_CIPHER_INIT', 'SONAME_LIBFREETYPE', 'HAVE_FT2BUILD_H',
                'SONAME_LIBSDL2', 'HAVE_SDL_H', 'HAVE_FFMPEG', 'SONAME_LIBVULKAN')
    for name in required:
        if re_search_define(text, name) is None:
            raise RuntimeError('Required real configure check did not pass: ' + name)
    import re
    for name in ('SONAME_LIBGNUTLS', 'SONAME_LIBFREETYPE', 'SONAME_LIBSDL2', 'SONAME_LIBVULKAN'):
        definition = re.search(r'^#define ' + name + r' "([^"]+)"$', text, re.MULTILINE)
        if definition is None or re.fullmatch(r'[A-Za-z0-9_.+-]+\.dylib', definition[1]) is None:
            raise RuntimeError('Configure did not derive a genuine library basename: ' + name)
    makefile = (BUILD / 'Makefile').read_text().replace('\\\n', '')
    disabled = next(line for line in makefile.splitlines() if line.startswith('DISABLED_SUBDIRS ='))
    if 'dlls/winegstreamer' in disabled:
        raise RuntimeError('Configure disabled the required GStreamer module')
    for variable in ('GSTREAMER_LIBS', 'COREAUDIO_LIBS'):
        line = next(line for line in makefile.splitlines() if line.startswith(variable + ' ='))
        if not line.split('=', 1)[1].strip():
            raise RuntimeError('Required configure dependency flags are empty: ' + variable)


def re_search_define(text, name):
    import re
    return re.search(r'^#define ' + re.escape(name) + r'\b', text, re.MULTILINE)


def install_guard():
    base = ROOT / 'runtime/wine-job-query-parity'
    for path in (ROOT / 'runtime', base, INSTALL):
        if path.is_symlink():
            raise RuntimeError('Refuse a redirected separate install path')
    marker = base / '.parity-runtime-owner.json'
    if base.exists():
        if not marker.is_file() or json.loads(marker.read_text()) != OWNER:
            raise RuntimeError('Refuse an existing unowned runtime directory')
    else:
        base.mkdir(parents=True)
        marker.write_text(json.dumps(OWNER, indent=2) + '\n')
    return base


def patched_configure():
    original = SOURCE / 'configure'
    text = original.read_text()
    old = r's/^.*\/\('
    new = r's/^.*[\/[:space:]]\('
    changes = 0
    lines = []
    for line in text.splitlines(keepends=True):
        if 'dylib) ac_cv_lib_soname_' in line and old in line:
            changes += 1
            line = line.replace(old, new)
        lines.append(line)
    if changes == 0:
        raise RuntimeError('Expected original Darwin SONAME parser was not found')
    rendered = ''.join(lines)
    destination = own(BUILD / 'configure-source/configure')
    destination.parent.mkdir(exist_ok=True)
    destination.write_text(rendered)
    destination.chmod(0o755)
    patch = own(BUILD / 'build-tool-patches/0001-configure-darwin-bare-install-id.patch')
    patch.parent.mkdir(exist_ok=True)
    patch.write_text(''.join(difflib.unified_diff(text.splitlines(keepends=True), lines,
                                               fromfile='original/configure', tofile='build-only/configure')))
    write(BUILD / 'configure-parser-adjustment.json', {
        'original': identity(original), 'build_only_configure': identity(destination), 'patch': identity(patch),
        'changed_darwin_parser_lines': changes,
        'reason': 'Accept the actual bare dylib install ID in otool output as well as path-qualified IDs',
        'runtime_source_modified': False, 'manual_soname_or_cache_value_supplied': False})
    return destination


def prepare_font_helper(env, stamp):
    log = own(BUILD / 'logs' / ('font-helper-' + stamp + '.log'))
    with log.open('x') as output:
        process = subprocess.Popen(['/usr/bin/make', '-j4', 'tools/sfnt2fon/sfnt2fon'], cwd=BUILD, env=env,
                                   stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            returncode = process.wait(timeout=300)
        except BaseException:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=15)
            raise
    if returncode != 0:
        raise RuntimeError('Native font build helper compilation failed; see ' + str(log))
    helper = BUILD / 'tools/sfnt2fon/sfnt2fon'
    before = identity(helper)
    load_commands_before = subprocess.check_output(['/usr/bin/otool', '-L', str(helper)], text=True)
    adjusted = '\tlibfreetype.dylib (' in load_commands_before
    if adjusted:
        subprocess.run(['/usr/bin/install_name_tool', '-change', 'libfreetype.dylib',
                        '@rpath/libfreetype.dylib', str(helper)], check=True)
        subprocess.run(['/usr/bin/codesign', '--force', '--sign', '-', str(helper)],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    load_commands_after = subprocess.check_output(['/usr/bin/otool', '-L', str(helper)], text=True)
    if '@rpath/libfreetype.dylib' not in load_commands_after:
        raise RuntimeError('Native font helper does not reference the real FreeType library through its runpath')
    smoke_env = {key: value for key, value in env.items() if not key.startswith('DYLD_')}
    generated = own(BUILD / 'font-helper-smoke.fon')
    smoke = subprocess.run([str(helper), '-q', '-o', str(generated), str(SOURCE / 'fonts/courier.ttf'),
                            '-d', '128', '13,1252,8'], env=smoke_env, cwd=BUILD,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=30)
    if smoke.returncode != 0 or not generated.is_file() or generated.stat().st_size == 0:
        raise RuntimeError('Native font helper failed its real font conversion without DYLD overrides: ' + smoke.stdout)
    write(BUILD / ('font-helper-' + stamp + '-results.json'), {
        'before': before, 'after': identity(helper), 'dependency_load_command_adjusted': adjusted,
        'load_commands_before': load_commands_before, 'load_commands_after': load_commands_after,
        'reason': 'Bare install ID does not use LC_RPATH; system make/shell removes DYLD fallback variables',
        'only_own_native_build_helper_modified': True, 'original_dependency_modified': False,
        'font_conversion_exit': smoke.returncode, 'font_conversion_output': smoke.stdout,
        'font_output': identity(generated), 'smoke_environment_has_no_DYLD_overrides': True, 'passed': True})


def run(phase):
    env = prepare_build()
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    provenance = BUILD / 'build-provenance.json'
    snapshot = own(BUILD / 'logs' / ('provenance-' + sha(provenance) + '.json'))
    snapshot.parent.mkdir(exist_ok=True)
    if not snapshot.exists():
        with snapshot.open('xb') as output:
            output.write(provenance.read_bytes())
    if phase in ('configure', 'reconfigure'):
        if (BUILD / 'Makefile').exists():
            if phase != 'reconfigure':
                raise RuntimeError('Use the explicit owned-build reconfigure phase for an existing build')
        command = [str(patched_configure()), '--srcdir=' + str(SOURCE),
                   '--build=x86_64-apple-darwin', '--host=x86_64-apple-darwin',
                   '--prefix=' + str(INSTALL), '--enable-archs=i386,x86_64', '--with-mingw', '--disable-tests',
                   '--without-alsa', '--without-capi', '--with-coreaudio', '--without-cups', '--without-dbus',
                   '--without-fontconfig', '--with-freetype', '--with-gnutls', '--without-gphoto', '--with-gstreamer',
                   '--without-krb5', '--without-netapi', '--without-oss', '--without-pulse', '--without-sane',
                   '--with-sdl', '--without-udev', '--without-usb', '--without-v4l2', '--without-x',
                   '--without-wayland', '--with-vulkan', '--with-ffmpeg']
        timeout = 600
    elif phase == 'all':
        verify_configuration()
        prepare_font_helper(env, stamp)
        command = ['/usr/bin/make', '-j4']
        timeout = 3600
    else:
        verify_configuration()
        install_guard()
        complete = json.loads((BUILD / 'all-results.json').read_text())
        if complete.get('passed') is not True:
            raise RuntimeError('Require a complete successful Wine build before installation')
        command = ['/usr/bin/make', '-j4', 'install-lib']
        timeout = 900
    log = own(BUILD / 'logs' / (phase + '-' + stamp + '.log'))
    log.parent.mkdir(exist_ok=True)
    start = time.monotonic()
    interrupted = False
    with log.open('x') as output:
        process = subprocess.Popen(command, cwd=BUILD, env=env, stdout=output,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            returncode = process.wait(timeout=timeout)
        except BaseException:
            interrupted = True
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=15)
            returncode = process.returncode
    passed = returncode == 0 and not interrupted
    diagnostics = None
    if phase in ('configure', 'reconfigure') and (BUILD / 'config.log').is_file():
        copy = own(BUILD / 'logs' / ('configure-' + stamp + '-config.log'))
        with copy.open('xb') as output:
            output.write((BUILD / 'config.log').read_bytes())
        diagnostics = identity(copy)
    if passed and phase in ('configure', 'reconfigure'):
        verify_configuration()
    record = {'at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'phase': phase,
              'command': command, 'log': identity(log), 'exit': returncode, 'interrupted_or_timeout': interrupted,
              'elapsed_seconds': round(time.monotonic() - start, 3), 'passed': passed,
              'build_provenance': identity(snapshot),
              'configure_diagnostics': diagnostics,
              'wine_or_prefix_started': False, 'active_engine_replaced': False, 'old_candidate_modified': False}
    write(BUILD / (phase + '-' + stamp + '-results.json'), record)
    write(BUILD / (phase + '-results.json'), record)
    print(json.dumps({key: record[key] for key in ('phase', 'passed', 'exit', 'elapsed_seconds', 'log')}, indent=2))
    return 0 if passed else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('phase', choices=('configure', 'reconfigure', 'all', 'install'))
    raise SystemExit(run(parser.parse_args().phase))
