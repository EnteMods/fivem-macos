"""Fixed numeric graphics-window markers; top-level counts, no handles or pairs."""
import os
from pathlib import Path
import re
import stat

ROOT = Path(__file__).resolve().parents[2]
MAX_LINE_CHARS = 2048
MAX_EVENTS = 256
DWORD_MAX = 0xffffffff
_MARKER = '[CFX_GRAPHICS_WND]'
_LOG_NAME = re.compile(r'client-source-ui(?:-resume)?-[0-9]{8}T[0-9]{12}Z\.log')
_WINDOW = re.compile(r'\[CFX_GRAPHICS_WND\] pid=([0-9]{1,10}) tid=([0-9]{1,10}) phase=1 '
    r'returned=([01]) error=([0-9]{1,10}) style=([0-9]{1,10}) exstyle=([0-9]{1,10}) parent_nonnull=([01])')
_QUERY = re.compile(r'\[CFX_GRAPHICS_WND\] pid=([0-9]{1,10}) tid=([0-9]{1,10}) phase=2 '
    r'swapchain_requested=([01]) count=([0-9]{1,3}) capped=([01]) enum_ok=([01]) query_failures=([0-9]{1,10})')
_WINE = re.compile(r'(?P<prefix>(?:[0-9a-fA-F]{1,8}:){1,2})'
    r'(?:trace:debugstr:OutputDebugStringA|warn:debugstr:OutputDebugStringA|warn:seh:dispatch_exception) '
    r'"(?P<payload>\[CFX_GRAPHICS_WND\] [^"\r\n]*)\\n"')
_OVERSIZED = object()
_INCOMPLETE = object()


def _event(body):
    wrapped = _WINE.fullmatch(body)
    payload = wrapped['payload'] if wrapped else body
    match = _WINDOW.fullmatch(payload)
    phase = 1
    if match is None:
        match = _QUERY.fullmatch(payload)
        phase = 2
    if match is None:
        return None
    values = list(map(int, match.groups()))
    pid, tid = values[:2]
    if not 1 <= pid <= DWORD_MAX or not 1 <= tid <= DWORD_MAX or max(values) > DWORD_MAX:
        return None
    if wrapped:
        prefix = [int(part, 16) for part in wrapped['prefix'].rstrip(':').split(':')]
        if prefix[-1] != tid or (len(prefix) == 2 and prefix[0] != pid):
            return None
    event = {'pid': pid, 'tid': tid, 'phase': phase}
    if phase == 1:
        event.update(zip(('returned', 'error', 'style', 'exstyle', 'parent_nonnull'), values[2:]))
    else:
        if values[3] > 256:
            return None
        event.update(zip(('swapchain_requested', 'count', 'capped', 'enum_ok', 'query_failures'), values[2:]))
    return event


def parse_lines(lines):
    """Read complete logical iterable lines; preserve phases and duplicates."""
    result = {'accepted': 0, 'rejected': 0, 'capped': False, 'events': [],
              'oversized_lines': 0, 'incomplete_lines': 0, 'top_level_windows_only': True,
              'calls_paired': False, 'exception_cause_established': False,
              'functional_success_established': False}
    if type(lines) is str:
        lines = lines.splitlines(keepends=True)
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
        body = line[:-1] if line.endswith('\n') else line
        body = body[:-1] if body.endswith('\r') else body
        event = _event(body)
        if event is None:
            result['rejected'] += 1
            continue
        if len(result['events']) == MAX_EVENTS:
            result['capped'] = True
            break
        result['events'].append(event)
        result['accepted'] += 1
    return result


def parse_log(path):
    """Read the fixed direct Source-controller log role without hashing/copying."""
    path = Path(path)
    if not path.is_absolute():
        path = ROOT / path
    if path.parent != ROOT / 'logs' or _LOG_NAME.fullmatch(path.name) is None:
        raise ValueError('Require the fixed Source-controller log role')
    if ROOT.resolve(strict=True) != ROOT or path.parent.resolve(strict=True) != path.parent:
        raise ValueError('Refuse redirected controller log directories')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError('Require a regular single-link controller log')
        with os.fdopen(descriptor, 'rb', closefd=False) as source:
            def bounded_lines():
                while True:
                    raw = source.readline(MAX_LINE_CHARS + 1)
                    if not raw:
                        return
                    if len(raw) > MAX_LINE_CHARS:
                        while not raw.endswith(b'\n'):
                            raw = source.readline(MAX_LINE_CHARS + 1)
                            if not raw:
                                break
                        yield _OVERSIZED
                    elif not raw.endswith(b'\n'):
                        yield _INCOMPLETE
                    else:
                        yield raw.decode('utf-8', errors='replace')
            result = parse_lines(bounded_lines())
        after = os.fstat(descriptor)
        current = path.lstat()
        if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                or (current.st_dev, current.st_ino) != (after.st_dev, after.st_ino)
                or not stat.S_ISREG(current.st_mode) or current.st_nlink != 1):
            raise ValueError('Controller log identity changed during metadata read')
        return result
    finally:
        os.close(descriptor)
