"""Three numeric Wine window checkpoints; no window text or generic win payloads.

accept() receives one complete logical line (with or without its line ending).
A stream caller must pass complete=False for a truncated/unfinished frame.
Only 'passthrough' permits the caller to retain its original baseline line.
The created checkpoint is not a universal API return trace; absence proves no
NULL return, and a one-field Wine prefix supplies no process identity.
"""
import re

MAX_LINE_CHARS = 4096
MAX_EVENTS = 4096
DWORD_MAX = 0xffffffff
QWORD_MAX = 0xffffffffffffffff

_PREFIX = r'(?P<prefix>(?:[0-9a-fA-F]{1,8}:){1,2})'
_HANDLE = r'(?P<hwnd>(?:0[xX])?[0-9a-fA-F]{1,16})'
_CREATED = re.compile(_PREFIX + r'trace:win:NtUserCreateWindowEx created window ' + _HANDLE)
_SERVER_ERROR = re.compile(_PREFIX + r'warn:win:create_window_handle error (?P<error>[0-9]{1,10}) creating window')
_ABORTED = re.compile(_PREFIX + r'warn:win:NtUserCreateWindowEx ' + _HANDLE + r': aborted by WM_NCCREATE')
# Also catch damaged/duplicate prefixes. Overclassification only drops a line.
_WIN_CHANNEL = re.compile(r'(?:^|:)(?:trace|warn|err|fixme):win:')
_LOOSE_WIN_HEADER = re.compile(r'^(?:[^\s:]*:)*win:')


class Collector:
    def __init__(self):
        self._events = []
        self._counts = dict(accepted_events=0, dropped_win_lines=0,
                            rejected_win_lines=0, passthrough_lines=0,
                            oversized_lines=0, incomplete_lines=0,
                            invalid_lines=0, capped_win_lines=0)
        self._capped = False

    def accept(self, line, *, complete=True):
        """Return exactly 'accepted', 'drop', or 'passthrough'; never a raw line."""
        if type(complete) is not bool or type(line) is not str:
            self._counts['invalid_lines'] += 1
            return 'drop'
        if not complete:
            self._counts['incomplete_lines'] += 1
            return 'drop'
        if len(line) > MAX_LINE_CHARS:
            self._counts['oversized_lines'] += 1
            return 'drop'
        body = line[:-1] if line.endswith('\n') else line
        body = body[:-1] if body.endswith('\r') else body
        win = bool(_WIN_CHANNEL.search(body) or _LOOSE_WIN_HEADER.match(body))
        if '\n' in body or '\r' in body or '\0' in body:
            self._counts['invalid_lines'] += 1
            if win:
                self._counts['dropped_win_lines'] += 1
                self._counts['rejected_win_lines'] += 1
            return 'drop'
        if not win:
            self._counts['passthrough_lines'] += 1
            return 'passthrough'
        if len(self._events) >= MAX_EVENTS:
            self._capped = True
            self._counts['dropped_win_lines'] += 1
            self._counts['capped_win_lines'] += 1
            return 'drop'
        event = self._parse(body)
        if event is None:
            self._counts['dropped_win_lines'] += 1
            self._counts['rejected_win_lines'] += 1
            return 'drop'
        self._events.append(event)
        self._counts['accepted_events'] += 1
        return 'accepted'

    @staticmethod
    def _parse(body):
        for pattern, kind in ((_CREATED, 'created'), (_SERVER_ERROR, 'server_error'),
                              (_ABORTED, 'nccreate_aborted')):
            match = pattern.fullmatch(body)
            if match is None:
                continue
            prefix = [int(value, 16) for value in match['prefix'].rstrip(':').split(':')]
            if any(not 1 <= value <= DWORD_MAX for value in prefix):
                return None
            event = {'event': kind, 'wine_pid': prefix[0] if len(prefix) == 2 else None,
                     'wine_tid': prefix[-1]}
            if kind == 'server_error':
                value = int(match['error'], 10)
                if value > DWORD_MAX:
                    return None
                event['win32_error'] = value
            else:
                value = int(match['hwnd'], 16)
                if not 1 <= value <= QWORD_MAX:
                    return None
                event['hwnd'] = value
            return event
        return None

    def summary(self):
        """Return detached numeric/fixed-enum metadata; repeated rows stay rows."""
        return {**self._counts, 'capped': self._capped,
                'events': [dict(event) for event in self._events],
                'missing_created_event_proves_null': False,
                'unknown_pid_attributed': False,
                'api_return_trace_complete': False}


def parse_lines(lines):
    """Collect complete logical iterable lines, or newline-framed text.

    The final unterminated fragment of a text string is dropped. An iterable
    may contain complete logical lines without endings (e.g. splitlines()).
    """
    collector = Collector()
    if type(lines) is str:
        for line in lines.splitlines(keepends=True):
            collector.accept(line, complete=line.endswith('\n'))
    else:
        for line in lines:
            collector.accept(line)
    return collector.summary()
