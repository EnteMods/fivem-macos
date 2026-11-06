"""Retain fixed NUI blit geometry markers without retaining controller log text."""
import io
import os
from pathlib import Path
import re
import stat


ROOT = Path(__file__).resolve().parents[2]
MAX_LINE_CHARS = 2048
MAX_EVENTS = 256
DWORD_MAX = 0xffffffff
_CHUNK_BYTES = 64 * 1024
_MARKER = '[CFX_GRAPHICS_BLIT]'
_LOG_NAME = re.compile(r'client-source-ui(?:-resume)?-[0-9]{8}T[0-9]{12}Z\.log')
_UINT = r'(?:0|[1-9][0-9]{0,9})'
_SIGNED = r'(?:0|-?[1-9][0-9]{0,6})'
_VP_FIELDS = ('vp_x16', 'vp_y16', 'vp_w16', 'vp_h16')
_FIELDS = (('pid', _UINT), ('tid', _UINT), ('quad_w', _UINT), ('quad_h', _UINT),
           ('vp_count', _UINT), ('vp_valid', r'[01]'), *((name, _SIGNED) for name in _VP_FIELDS),
           ('rt_w', _UINT), ('rt_h', _UINT))
_BLIT = re.compile(re.escape(_MARKER) + ' ' + ' '.join(f'{name}=(?P<{name}>{field})' for name, field in _FIELDS))
_WINE = re.compile(r'(?P<prefix>(?:[0-9a-fA-F]{1,8}:){1,2})'
    r'(?:trace:debugstr:OutputDebugStringA|warn:debugstr:OutputDebugStringA|warn:seh:dispatch_exception) '
    r'"(?P<payload>\[CFX_GRAPHICS_BLIT\] [^"\r\n]*)\\n"')
_OVERSIZED = object()
_INCOMPLETE = object()


def _event(body):
    wrapped = _WINE.fullmatch(body)
    match = _BLIT.fullmatch(wrapped['payload'] if wrapped else body)
    if match is None:
        return None
    event = {name: int(value) for name, value in match.groupdict().items()}
    pid, tid = event['pid'], event['tid']
    if (not 1 <= pid <= DWORD_MAX or not 1 <= tid <= DWORD_MAX
            or not all(1 <= event[key] <= 65535 for key in ('quad_w', 'quad_h'))
            or event['vp_count'] > 16 or any(event[key] > DWORD_MAX for key in ('rt_w', 'rt_h'))
            or bool(event['rt_w']) != bool(event['rt_h'])):
        return None
    viewport = tuple(event[name] for name in _VP_FIELDS)
    if event['vp_valid']:
        if event['vp_count'] != 1 or any(abs(value) > 1048576 for value in viewport):
            return None
    elif any(viewport):
        return None
    if wrapped:
        prefix = [int(part, 16) for part in wrapped['prefix'].rstrip(':').split(':')]
        if prefix[-1] != tid or (len(prefix) == 2 and prefix[0] != pid):
            return None
    return event


def parse_lines(lines):
    """Accept only complete logical marker rows and preserve their order and duplicates."""
    result = {'accepted': 0, 'rejected': 0, 'capped': False, 'events': [],
              'oversized_lines': 0, 'incomplete_lines': 0, 'duplicates_preserved': True,
              'rendered_frame_established': False}
    if type(lines) is str:
        lines = io.StringIO(lines)
    for line in lines:
        if line is _OVERSIZED or (type(line) is str and len(line) > MAX_LINE_CHARS):
            result['oversized_lines'] += 1
            result['rejected'] += 1
            continue
        if line is _INCOMPLETE:
            result['incomplete_lines'] += 1
            result['rejected'] += 1
            continue
        if type(line) is not str:
            result['rejected'] += 1
            continue
        if _MARKER not in line:
            continue
        event = _event(line.removesuffix('\n').removesuffix('\r'))
        if event is None:
            result['rejected'] += 1
            continue
        if len(result['events']) == MAX_EVENTS:
            result['capped'] = True
            break
        result['events'].append(event)
        result['accepted'] += 1
    return result


def _snapshot_lines(descriptor, size):
    offset = 0
    pending = bytearray()
    oversized = False
    while offset < size:
        chunk = os.pread(descriptor, min(_CHUNK_BYTES, size - offset), offset)
        if not chunk:
            raise ValueError('Controller log was truncated during metadata read')
        offset += len(chunk)
        start = 0
        while start < len(chunk):
            newline = chunk.find(b'\n', start)
            end = newline + 1 if newline >= 0 else len(chunk)
            if not oversized:
                oversized = len(pending) + end - start > MAX_LINE_CHARS
                if oversized:
                    pending.clear()
                else:
                    pending.extend(chunk[start:end])
            if newline >= 0:
                yield _OVERSIZED if oversized else pending.decode('utf-8', errors='replace')
                pending.clear()
                oversized = False
            start = end
    if oversized:
        yield _OVERSIZED
    elif pending:
        yield _INCOMPLETE


def _identity(info):
    return info.st_dev, info.st_ino


def parse_log(path, *, live=False):
    """Inspect the exact Source controller log, optionally taking a bounded live snapshot."""
    if type(live) is not bool:
        raise ValueError('Live log mode must be explicit')
    path = Path(path)
    if not path.is_absolute():
        path = ROOT / path
    if path.parent != ROOT / 'logs' or _LOG_NAME.fullmatch(path.name) is None:
        raise ValueError('Require the fixed Source-controller log role')
    if ROOT.resolve(strict=True) != ROOT or path.parent.resolve(strict=True) != path.parent:
        raise ValueError('Refuse redirected controller log directories')

    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise ValueError('Require a regular single-link controller log')
            result = parse_lines(_snapshot_lines(descriptor, before.st_size))
            current = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
            grew = current.st_size > before.st_size
            if (_identity(path.parent.lstat()) != _identity(os.fstat(directory))
                    or _identity(current) != _identity(before) or not stat.S_ISREG(current.st_mode)
                    or current.st_nlink != 1 or current.st_size < before.st_size
                    or (grew and not live)
                    or (not grew and (current.st_mtime_ns, current.st_ctime_ns) !=
                        (before.st_mtime_ns, before.st_ctime_ns))):
                raise ValueError('Controller log identity changed during metadata read')
            return dict(result, live_snapshot=live, log_grew_during_read=grew)
        finally:
            os.close(descriptor)
    finally:
        os.close(directory)
