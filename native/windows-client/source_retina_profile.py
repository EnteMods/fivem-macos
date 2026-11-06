"""Scope an opt-in Retina trial to the isolated Source-MAIN Wine prefix."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

import graphics_blit_launch as boundary
from retina_video import parse, restore, transform
from run_main import ROOT, plain


SOURCE = Path(__file__).with_name('retina_registry.cpp')
REGISTRY_STATES = ('absent_key', 'absent_value', 'value')


def read_video(path):
    plain(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= 262144:
            raise ValueError('Require the regular FiveM-only video settings file')
        data = source.read(262145)
        if len(data) != info.st_size or fingerprint(path.lstat()) != fingerprint(info):
            raise ValueError('Video settings changed during read')
        return data, info


def fingerprint(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink


def replace_video(path, data, before):
    fd, name = tempfile.mkstemp(prefix='.fivem-retina-video-', dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, 'wb') as output:
            os.fchmod(output.fileno(), stat.S_IMODE(before.st_mode))
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        if fingerprint(path.lstat()) != fingerprint(before):
            raise RuntimeError('Video settings changed before replacement')
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def save(path, data):
    with path.open('xb') as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


@contextmanager
def profile(runtime, environment, logical_size, evidence):
    """Hold the caller's existing Source-MAIN lock from idle proof through rollback."""
    boundary.require_lock()
    boundary.require_idle(runtime, environment)
    prefix = boundary.PREFIX
    prefix_id = boundary.prefix_identity()
    width, height = logical_size
    pixel_size = (2 * width, 2 * height)
    files = list((prefix / 'drive_c/users').glob('*/AppData/Roaming/CitizenFX/gta5_settings.xml'))
    if len(files) != 1 or files[0].resolve(strict=True) != files[0]:
        raise ValueError('Require exactly one canonical FiveM video settings file')
    path = files[0]
    original, info = read_video(path)
    modified = transform(original, *pixel_size)
    before, applied = parse(original), parse(modified)

    build = Path(tempfile.mkdtemp(prefix='source-retina-window-', dir=ROOT / 'build'))
    binary = build / 'retina_registry.exe'
    subprocess.run(['/opt/homebrew/bin/x86_64-w64-mingw32-g++', '-std=c++17', '-O2', '-Wall', '-Wextra',
                    '-Werror', '-static', '-municode', str(SOURCE), '-o', str(binary), '-ladvapi32'],
                   cwd=build, check=True, timeout=20)
    binary_pin = boundary.identity(binary)
    control = dict(environment, WINEDEBUG='-all')
    control.pop('WINEDLLPATH_PREPEND', None)
    control.pop('DYLD_PRINT_LIBRARIES', None)
    wine = str(runtime.ENGINE / 'bin/wine')
    server = str(runtime.ENGINE / 'bin/wineserver')

    def registry(*args):
        boundary.require_prefix(prefix_id)
        boundary.require(binary, binary_pin)
        result = subprocess.check_output([wine, str(binary), *args], cwd=build, env=control,
                                         stderr=subprocess.DEVNULL, timeout=20)
        row = json.loads(result)
        if (set(row) != {'state', 'value'} or row['state'] not in REGISTRY_STATES or type(row['value']) is not str
                or len(row['value']) > 64 or any(not 32 <= ord(char) < 127 for char in row['value'])
                or (row['state'] != 'value' and row['value'])):
            raise RuntimeError('Unexpected exact Retina registry result')
        return row

    def stop_helper_server():
        boundary.require_prefix(prefix_id)
        stopped = subprocess.run([server, '-k'], env=control, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, timeout=10)
        if stopped.returncode not in (0, 1):
            raise RuntimeError('Retina helper server did not stop normally')
        boundary.require_idle(runtime, environment)

    registry_before = None
    registry_attempted = False
    checkpoint = build / 'original.json'
    evidence.update(logical_window=list(logical_size), requested_render_pixels=list(pixel_size),
                    checkpoint=str(checkpoint.relative_to(ROOT)),
                    rollback_record=str((build / 'restored.json').relative_to(ROOT)))
    try:
        try:
            registry_before = registry('query')
            save(build / 'gta5_settings.original.xml', original)
            save(checkpoint, (json.dumps({'prefix_identity': prefix_id, 'video_before': before._asdict(),
                  'video_trial': applied._asdict(), 'registry_before': registry_before,
                  'original_sha256': hashlib.sha256(original).hexdigest()}, indent=2) + '\n').encode())
            registry_attempted = True
            if registry('apply') != {'state': 'value', 'value': 'Y'}:
                raise RuntimeError('Could not enable exact Wine RetinaMode value')
        finally:
            stop_helper_server()
        replace_video(path, modified, info)
        yield
    finally:
        if registry_attempted:
            boundary.require_prefix(prefix_id)
            boundary.require_idle(runtime, environment)
            try:
                args = ['restore', registry_before['state']]
                if registry_before['state'] == 'value':
                    args.append(registry_before['value'])
                result = registry(*args)
                if result != registry_before and not (registry_before['state'] == 'absent_key'
                                                       and result == {'state': 'absent_value', 'value': ''}):
                    raise RuntimeError('RetinaMode rollback differs from the checkpoint')
            finally:
                stop_helper_server()
            current, current_info = read_video(path)
            restored = restore(current, before, applied)
            if restored != current:
                replace_video(path, restored, current_info)
            save(build / 'restored.json', (json.dumps({'registry': result, 'video': parse(restored)._asdict()}) + '\n').encode())
