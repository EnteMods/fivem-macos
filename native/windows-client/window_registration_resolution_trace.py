"""Collect resolved name categories and the actual Win32 registration result."""

import re

from window_registration_name_trace import Collector as NameCollector


_PREFIX = r'(?P<pid>[0-9a-f]{1,8}):(?P<tid>[0-9a-f]{1,8}):trace:cfxwndreg:trace_class_'
_RECORDS = re.compile(
    _PREFIX + r'(?:resolution role=(?P<role>[12]) kind=(?P<kind>[0-2]) units=(?P<units>[0-9]{1,5})'
    r' prefix=(?P<prefix>[0-9]{1,5}) atom_input=(?P<atom_input>[01])'
    r'|removal ok=(?P<ok>[01]) error=(?P<error>[0-9]{1,10})|atom atom=(?P<atom>[0-9]{1,5}))')


class Collector(NameCollector):
    def __init__(self):
        super().__init__()
        self._resolved = []
        self._resolved_capped = False

    def accept(self, line, *, complete=True):
        match = _RECORDS.fullmatch(line.removesuffix('\n').removesuffix('\r')) if complete and type(line) is str else None
        if match is None:
            return super().accept(line, complete=complete)
        self._line_number += 1
        fields = match.groupdict()
        pid, tid = (int(fields.pop(key), 16) for key in ('pid', 'tid'))
        numeric = {key: int(value) for key, value in fields.items() if value is not None}
        if (not pid or not tid or numeric.get('atom', 0) > 0xffff or numeric.get('error', 0) > 0xffffffff
                or numeric.get('units', 0) > 32767 or numeric.get('prefix', 0) > 32767
                or (numeric.get('ok') and numeric.get('error'))):
            self._api_invalid += 1
            return 'drop'
        if len(self._resolved) >= 256:
            self._resolved_capped = True
            return 'drop'
        self._resolved.append({'wine_pid': pid, 'wine_tid': tid, 'trace_line': self._line_number, **numeric})
        return 'accepted'

    def summary(self):
        result = super().summary()
        result['capped'] |= self._resolved_capped
        result['resolved_api_events'] = [dict(row) for row in self._resolved]
        return result
