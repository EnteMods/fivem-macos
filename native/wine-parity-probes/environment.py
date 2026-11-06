"""Verify the complete installed parity engine and construct a clean API environment."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path(__file__).resolve().parents[2]
ENGINE = ROOT/'runtime/wine-job-query-parity/engine'
WORK = ROOT/'build/wine-job-query-parity'
BUILD = WORK/'full-x86_64'
SOURCE = ROOT/'build/wine-job-query/source'
MANIFEST = BUILD/'engine-manifest.json'
MANIFEST_SHA = 'e4fc3167813864102909da696cf3a03e89bd00a4a9abe26d8478c88316600f9c'
PREFIX = ROOT/'prefixes/wine-parity-regression'
FRAMEWORKS = ROOT.parent/'GTA-V-macOS/runtime/template-1.0.11-source/Template-1.0.11.app/Contents/Frameworks'
GST_LIB = FRAMEWORKS/'GStreamer.framework/Versions/1.0/lib'
MOLTENVK = BUILD/'dependencies/moltenvk/libMoltenVK.dylib'
MOLTENVK_SHA = '294e9ef77c6036ab4f4d93117d752b6e31fa6c8c4345bc085e062a6ee3ced80a'
PROTOCOL = 1810
ROLE = 'wine-parity-api-probes'
SDK_ROOT = Path('/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs')
SDK_SETTINGS_ALIAS = SDK_ROOT/'MacOSX27.2.sdk/SDKSettings.json'
MULTILINK_BUILD_TOOLS = {
    Path('/opt/homebrew/Cellar/mingw-w64/14.0.0_3/toolchain-i686/bin/i686-w64-mingw32-gcc'),
    Path('/opt/homebrew/Cellar/mingw-w64/14.0.0_3/toolchain-x86_64/bin/x86_64-w64-mingw32-gcc'),
    Path('/usr/bin/make'),
}
ENTRY_COUNT = 1761
CLOSURE_COUNT = 36
FORMAT_COUNTS = {'mach_o_x86_64': 34, 'pe_amd64': 763, 'pe_i386': 824, 'data': 140, 'symlinks': 0}
RECIPE_NAMES = {'BUILD.md', 'README.md', 'build.py', 'inspect_engine.py', 'manifest.py', 'prepare.py',
                'prepare_sdk.py', 'probe-basic.c', 'probe-media.c', 'probe.py', 'test_build.py', 'test_paths.py'}
sys.path.insert(0, str(ROOT/'scripts'))
from probe_environment import _plain_path


def canonical(path, boundary):
    path, boundary = Path(path), Path(boundary)
    if not path.is_absolute() or '..' in path.parts or str(path) != str(path.absolute()):
        raise RuntimeError('Require a canonical absolute path')
    try:
        path.relative_to(boundary)
    except ValueError:
        raise RuntimeError('Artifact outside its admitted boundary')
    _plain_path(path, boundary)
    return path


def read_regular(path, boundary=None):
    path = canonical(path, boundary or ROOT)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise RuntimeError('Require a regular single-link artifact: '+str(path))
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise RuntimeError('Artifact changed before reading')
        return source.read()


def item_shape(item):
    if (not isinstance(item, dict) or not isinstance(item.get('path'), str)
            or type(item.get('bytes')) is not int or item['bytes'] < 0
            or not isinstance(item.get('sha256'), str) or re.fullmatch('[0-9a-f]{64}', item['sha256']) is None):
        raise RuntimeError('Malformed artifact identity')


def verify_item(item, path, boundary=None):
    item_shape(item)
    if item['path'] != str(path):
        raise RuntimeError('Unexpected artifact path')
    data = read_regular(path, boundary)
    if len(data) != item['bytes'] or hashlib.sha256(data).hexdigest() != item['sha256']:
        raise RuntimeError('Bound artifact changed: '+str(path))
    return data


def admit_provenance(path):
    path = Path(path)
    if path == SDK_SETTINGS_ALIAS:
        return SDK_ROOT
    roots = (WORK, SOURCE, ROOT/'build/wine-job-query', ROOT/'native/wine-job-query-parity',
             ROOT/'native/wine-job-query', FRAMEWORKS, ROOT/'patches/wine',
             Path('/Applications/Xcode.app/Contents/Developer'), Path('/opt/homebrew/Cellar/mingw-w64'))
    if path == Path('/usr/bin/make'):
        return Path('/usr')
    if path == ROOT/'downloads/crossover-sources-26.3.0.tar.gz':
        return ROOT/'downloads'
    for boundary in roots:
        if path.is_relative_to(boundary):
            canonical(path, boundary)
            return boundary
    raise RuntimeError('Unreviewed provenance path: '+str(path))


def provenance_path(path, boundary):
    if path == SDK_SETTINGS_ALIAS:
        resolved = path.resolve(strict=True)
        canonical(resolved, SDK_ROOT)
        return resolved
    return canonical(path, boundary)


def read_bound_build_tool(item, path, boundary):
    if path not in MULTILINK_BUILD_TOOLS:
        raise RuntimeError('Not a fixed historical build compiler')
    canonical(path, boundary)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink < 1:
            raise RuntimeError('Build compiler must be a regular file')
        data = source.read()
    if len(data) != item['bytes'] or hashlib.sha256(data).hexdigest() != item['sha256']:
        raise RuntimeError('Bound build compiler changed')
    return data, info.st_nlink


def provenance_items(value, relative_root=None):
    found = []
    if isinstance(value, dict):
        if 'source_root' in value:
            if value['source_root'] != str(SOURCE):
                raise RuntimeError('Unexpected Wine source root')
            relative_root = SOURCE
        if {'path', 'bytes', 'sha256'} <= value.keys():
            item_shape(value)
            path = Path(value['path'])
            # Public repository pins describe remote members, not local paths.
            if not path.is_absolute() and isinstance(value.get('url'), str):
                if not value['url'].startswith('https://raw.githubusercontent.com/gauthierpiarrette/highball-engine/'):
                    raise RuntimeError('Unexpected remote provenance member')
                return found
            if not path.is_absolute():
                if relative_root is None or '..' in path.parts or path.as_posix() != value['path']:
                    raise RuntimeError('Unexpected relative provenance identity: '+value['path'])
                path = relative_root/path
            boundary = admit_provenance(path)
            found.append((dict(value, path=str(path)), path, boundary))
        for child in value.values():
            found.extend(provenance_items(child, relative_root))
    elif isinstance(value, list):
        for child in value:
            found.extend(provenance_items(child, relative_root))
    return found


def verify_provenance(items):
    pending = list(items)
    checked = {}
    while pending:
        # Admit the complete next layer before opening any path from that layer.
        for item, path, boundary in pending:
            item_shape(item)
            provenance_path(path, boundary)
        next_layer = []
        for item, path, boundary in pending:
            key = (str(path), item['sha256'])
            if key in checked:
                continue
            resolved = provenance_path(path, boundary)
            tool_links = None
            if path in MULTILINK_BUILD_TOOLS:
                data, tool_links = read_bound_build_tool(item, path, boundary)
            else:
                data = verify_item(dict(item, path=str(resolved)), resolved, boundary)
            checked[key] = {'path': str(path), 'bytes': len(data), 'sha256': item['sha256']}
            if tool_links is not None:
                checked[key].update(link_count=tool_links, path_role=(
                    'fixed_historical_system_build_tool' if path == Path('/usr/bin/make')
                    else 'fixed_historical_mingw_build_compiler'))
            if resolved != path:
                checked[key]['resolved_path'] = str(resolved)
            if path.suffix == '.json':
                try:
                    document = json.loads(data)
                    if path.parent == BUILD and re.fullmatch(r'font-helper-[0-9]{8}T[0-9]{12}Z-results\.json', path.name):
                        tool = BUILD/'tools/sfnt2fon/sfnt2fon'
                        for phase in ('before', 'after'):
                            item_shape(document[phase])
                            if document[phase]['path'] != str(tool):
                                raise RuntimeError('Unexpected historical native font helper path')
                        if (document.get('passed') is not True or document.get('font_conversion_exit') != 0
                                or document.get('only_own_native_build_helper_modified') is not True
                                or document.get('original_dependency_modified') is not False):
                            raise RuntimeError('Native font helper adjustment did not succeed')
                        claim = dict(document['before'], historical_artifact_claim='before_native_load_command_adjustment',
                                     source_record=str(path))
                        checked[(str(tool), document['before']['sha256'])] = claim
                        document = {name: value for name, value in document.items() if name != 'before'}
                    next_layer.extend(provenance_items(document))
                except RuntimeError as error:
                    raise RuntimeError('Provenance scope in '+str(path)+': '+str(error)) from error
        pending = next_layer
    return list(checked.values())


def validate_manifest(value):
    if (value.get('schema_version') != 1 or value.get('engine_root') != str(ENGINE)
            or value.get('build_root') != str(BUILD) or value.get('job_protocol_version') != PROTOCOL
            or value.get('unix_architecture') != 'x86_64' or value.get('pe_architectures') != ['i386', 'AMD64']
            or value.get('format_counts') != FORMAT_COUNTS
            or any(value.get(key) is not True for key in ('sources_unchanged', 'macdrv_functions_export_present', 'passed_static_artifact_review'))
            or any(value.get(key) is not False for key in ('external_libraries_copied_into_engine', 'dxmt_overlay_applied',
                'mono_or_gecko_addons_copied', 'installed_engine_self_contained', 'wine_or_prefix_started',
                'graphics_job_or_client_runtime_tests_performed', 'active_runtime_or_old_candidate_changed'))):
        raise RuntimeError('Require the complete reviewed parity engine profile')
    entries = value['entries']
    if not isinstance(entries, list) or len(entries) != ENTRY_COUNT:
        raise RuntimeError('Unexpected complete engine entry count')
    paths = set()
    for item in entries:
        item_shape(item)
        relative = Path(item['path'])
        if (relative.is_absolute() or '..' in relative.parts or relative.as_posix() != item['path']
                or item['path'] in paths or item.get('kind') not in FORMAT_COUNTS or item.get('kind') == 'symlinks'
                or type(item.get('executable')) is not bool):
            raise RuntimeError('Unexpected installed engine code/data path')
        canonical(ENGINE/relative, ROOT)
        paths.add(item['path'])
    if not set(value['required_components']) <= paths or not {'bin/wine', 'bin/wineserver'} <= paths:
        raise RuntimeError('Missing mandatory complete engine components')
    closure = value['external_library_closure']['closure']
    if len(closure) != CLOSURE_COUNT or len({item['path'] for item in closure}) != CLOSURE_COUNT:
        raise RuntimeError('Unexpected external library closure')
    for item in closure:
        item_shape(item)
        canonical(Path(item['path']), FRAMEWORKS)
    closure_paths = {item['path'] for item in closure}
    if not set(value['external_library_closure']['selected'].values()) <= closure_paths:
        raise RuntimeError('Unbound selected external library')
    for item in closure:
        for dependency in item['dependencies']:
            if 'resolved_path' in dependency:
                if dependency['resolved_path'] not in closure_paths:
                    raise RuntimeError('Unbound external dependency edge')
            elif (dependency.get('resolution') != 'macOS system library' or not
                  dependency['load_command'].startswith(('/usr/lib/', '/System/Library/'))):
                raise RuntimeError('Unknown library dependency resolution')
    directories = [str(MOLTENVK.parent), str(FRAMEWORKS), str(GST_LIB)]
    if (value.get('external_library_search_order_for_root_review') != directories
            or value.get('framework_search_root_for_root_review') != str(FRAMEWORKS)
            or value['pinned_moltenvk'].get('path') != str(MOLTENVK)
            or value['pinned_moltenvk'].get('sha256') != MOLTENVK_SHA):
        raise RuntimeError('Unexpected external runtime search paths or MoltenVK')
    expected = {str(ROOT/'native/wine-job-query-parity'/name) for name in RECIPE_NAMES}
    if {item['path'] for item in value['own_recipe_sources']} != expected or len(value['own_recipe_sources']) != len(expected):
        raise RuntimeError('Unexpected parity recipe sources')
    fixed = {'source_inventory': BUILD/'source-inputs.json', 'reviewed_dependency_manifest': WORK/'parity-dependencies.json',
             'configure_parser_adjustment': BUILD/'configure-parser-adjustment.json'}
    direct = []
    for key, path in fixed.items():
        if value[key]['path'] != str(path):
            raise RuntimeError('Unexpected engine provenance record')
        direct.append((value[key], path, ROOT))
    groups = (('own_recipe_sources', None), ('real_configure_outputs', {str(BUILD/name) for name in ('config.status', 'include/config.h', 'Makefile')}),
              ('successful_phases', {str(BUILD/name) for name in ('all-results.json', 'install-results.json')}))
    for key, expected_paths in groups:
        items = value[key]
        if expected_paths is not None and ({item['path'] for item in items} != expected_paths or len(items) != len(expected_paths)):
            raise RuntimeError('Unexpected configure/build provenance paths')
        direct.extend((item, Path(item['path']), ROOT) for item in items)
    for key, folder, pattern in (('native_font_build_helper_records', BUILD, r'font-helper-[0-9]{8}T[0-9]{12}Z-results\.json'),
                                  ('archived_builder_recipes', BUILD/'logs', r'recipe-[a-f0-9]{64}\.py')):
        if not value[key]:
            raise RuntimeError('Missing native helper or archived build recipe evidence')
        for item in value[key]:
            path = Path(item['path'])
            if path.parent != folder or re.fullmatch(pattern, path.name) is None:
                raise RuntimeError('Unexpected build helper evidence path')
            direct.append((item, path, ROOT))
    return entries, closure, direct


def verify_runtime():
    raw = read_regular(MANIFEST)
    if hashlib.sha256(raw).hexdigest() != MANIFEST_SHA:
        raise RuntimeError('Parity engine manifest differs from the reviewed fixed digest')
    value = json.loads(raw)
    entries, closure, provenance = validate_manifest(value)
    canonical(ENGINE, ROOT)
    actual = set()
    for directory, folders, files in os.walk(ENGINE, followlinks=False):
        for name in folders:
            canonical(Path(directory)/name, ROOT)
        for name in files:
            path = Path(directory)/name
            canonical(path, ROOT)
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise RuntimeError('Unbound alias/special installed runtime entry')
            actual.add(str(path.relative_to(ENGINE)))
    if actual != {item['path'] for item in entries}:
        raise RuntimeError('Engine contains missing or unbound code/data files')
    for item in entries:
        path = ENGINE/item['path']
        verify_item(dict(item, path=str(path)), path)
        if bool(path.stat().st_mode & 0o111) != item['executable']:
            raise RuntimeError('Installed executable mode changed')
    for item in closure:
        verify_item(item, Path(item['path']), FRAMEWORKS)
    verify_item(value['pinned_moltenvk'], MOLTENVK)
    checked = verify_provenance(provenance)
    for item in value['successful_phases']:
        phase = json.loads(read_regular(Path(item['path'])))
        if phase.get('passed') is not True or phase.get('exit') != 0 or phase.get('interrupted_or_timeout') is not False:
            raise RuntimeError('Complete Wine build/install evidence is not successful')
    if read_regular(MANIFEST) != raw:
        raise RuntimeError('Engine manifest changed during verification')
    return {'profile': ROLE, 'protocol_version': PROTOCOL, 'manifest': str(MANIFEST.relative_to(ROOT)),
            'manifest_sha256': MANIFEST_SHA, 'engine': str(ENGINE.relative_to(ROOT)),
            'entries': len(entries), 'external_library_count': len(closure),
            'provenance_alias_resolutions': [item for item in checked if 'resolved_path' in item],
            'historical_artifact_claims': [item for item in checked if 'historical_artifact_claim' in item],
            'provenance_toolchain_multilinks': [item for item in checked if 'link_count' in item],
            'provenance_identities_checked': sum('historical_artifact_claim' not in item for item in checked),
            'loader_sha256': next(i['sha256'] for i in entries if i['path']=='bin/wine'),
            'server_sha256': next(i['sha256'] for i in entries if i['path']=='bin/wineserver')}


def environment(verified=None, inherited=None):
    verified = verify_runtime() if verified is None else verified
    if verified.get('manifest_sha256') != MANIFEST_SHA or verified.get('protocol_version') != PROTOCOL:
        raise RuntimeError('Require current complete engine verification')
    inherited = os.environ if inherited is None else inherited
    banned = ('WINE', 'DYLD_', 'LD_', 'DXVK', 'DXMT', 'D3DMETAL', 'CITIZENFX_', 'CX_', 'VK_', 'GST_', 'GIO_', 'G_MODULE_')
    env = {key: value for key, value in inherited.items() if not key.upper().startswith(banned)}
    env.update(PATH='/usr/bin:/bin:/usr/sbin:/sbin', WINEPREFIX=str(PREFIX), WINELOADER=str(ENGINE/'bin/wine'),
        WINESERVER=str(ENGINE/'bin/wineserver'), WINEDEBUG='-all,err+all', WINEESYNC='0', WINEMSYNC='0',
        WINEDLLOVERRIDES='winemenubuilder.exe,mscoree,mshtml=d',
        DYLD_LIBRARY_PATH=os.pathsep.join(str(p) for p in (MOLTENVK.parent, FRAMEWORKS, GST_LIB)),
        DYLD_FRAMEWORK_PATH=str(FRAMEWORKS), GST_PLUGIN_PATH='', GST_PLUGIN_PATH_1_0='',
        GST_PLUGIN_SYSTEM_PATH='', GST_PLUGIN_SYSTEM_PATH_1_0='', GST_REGISTRY_FORK='no')
    return env
