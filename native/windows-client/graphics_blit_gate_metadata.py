"""Read only fixed numeric blit gate rows from a Source controller log."""
import io
import os
from pathlib import Path
import re
import stat

from graphics_blit_metadata import (
    DWORD_MAX, MAX_LINE_CHARS, ROOT, _INCOMPLETE, _LOG_NAME, _OVERSIZED,
    _identity, _snapshot_lines,
)

MAX_EVENTS = 256
MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024
_MARKER = '[CFX_GRAPHICS_BLIT_GATE]'
_PAYLOAD = re.escape(_MARKER) + r' pid=(?P<pid>[1-9][0-9]{0,9}) tid=(?P<tid>[1-9][0-9]{0,9}) gate=(?P<gate>[1-9]|1[0-6])'
_RAW = re.compile(_PAYLOAD)
_WINE = re.compile(
    r'(?:(?P<wine_pid>[0-9a-fA-F]{1,8}):)?(?P<wine_tid>[0-9a-fA-F]{1,8}):'
    r'(?:trace:debugstr:OutputDebugStringA|warn:debugstr:OutputDebugStringA|warn:seh:dispatch_exception) "'
    + _PAYLOAD + r'\\n"')


def parse_lines(lines, *, require_wine_prefix=False):
    """Deduplicate identical numeric events in first-occurrence order."""
    if type(lines) is str:
        lines = io.StringIO(lines)
    events = {}
    duplicates = rejected = mismatches = oversized = incomplete = 0
    capped = False
    for line in lines:
        if line is _OVERSIZED or (type(line) is str and len(line) > MAX_LINE_CHARS):
            oversized += 1
            continue
        if line is _INCOMPLETE:
            incomplete += 1
            continue
        if type(line) is not str or _MARKER not in line:
            continue
        body = line.removesuffix('\n').removesuffix('\r')
        wrapped = _WINE.fullmatch(body)
        match = wrapped or (None if require_wine_prefix else _RAW.fullmatch(body))
        if match is None:
            rejected += 1
            continue
        pid, tid, gate = (int(match[key]) for key in ('pid', 'tid', 'gate'))
        if pid > DWORD_MAX or tid > DWORD_MAX:
            rejected += 1
            continue
        if wrapped and (int(wrapped['wine_tid'], 16) != tid
                        or (wrapped['wine_pid'] is not None and int(wrapped['wine_pid'], 16) != pid)):
            rejected += 1
            mismatches += 1
            continue
        key = pid, tid, gate
        if key in events:
            duplicates += 1
            continue
        if len(events) == MAX_EVENTS:
            capped = True
            break
        events[key] = {'pid': pid, 'tid': tid, 'gate': gate}
    return {'accepted': len(events), 'duplicates': duplicates, 'rejected': rejected,
            'identity_mismatches': mismatches, 'oversized_lines': oversized, 'incomplete_lines': incomplete,
            'capped': capped, 'events': list(events.values())}


def parse_source_snapshot(path, parse, *, live=False):
    """Read one bounded, path-bound controller-log snapshot without storing text."""
    if type(live) is not bool:
        raise ValueError('Live log mode must be explicit')
    path = ROOT / Path(path)
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
            length = min(before.st_size, MAX_SNAPSHOT_BYTES)
            result = parse(_snapshot_lines(descriptor, length))
            current = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
            grew = current.st_size > before.st_size
            if (_identity(path.parent.lstat()) != _identity(os.fstat(directory))
                    or _identity(current) != _identity(before) or not stat.S_ISREG(current.st_mode)
                    or current.st_nlink != 1 or current.st_size < before.st_size
                    or (grew and not live)
                    or (not grew and (current.st_mtime_ns, current.st_ctime_ns) !=
                        (before.st_mtime_ns, before.st_ctime_ns))):
                raise ValueError('Controller log identity changed during metadata read')
            return dict(result, snapshot_bytes=length, snapshot_capped=length < before.st_size,
                        live_snapshot=live, log_grew_during_read=grew)
        finally:
            os.close(descriptor)
    finally:
        os.close(directory)


def parse_log(path, *, live=False):
    return parse_source_snapshot(path, lambda lines: parse_lines(lines, require_wine_prefix=True), live=live)
