"""Retain registration results and scope counts from the isolated User32 probe."""

from collections import Counter
import re

from window_class_trace import Collector as ClassCollector


_CHANNEL = re.compile(r'(?:^|:)cfxwndreg:', re.IGNORECASE)
_MARKER = re.compile(r'([0-9a-f]{1,8}):([0-9a-f]{1,8}):trace:cfxwndreg:trace_registration '
                     r'phase=([1-5]) ok=([01]) error=([0-9]{1,10})')
_MAX_TARGET_EVENTS = 256
_MAX_TRACE_RECORDS = 16384


class Collector(ClassCollector):
    def __init__(self):
        super().__init__()
        self._depth = Counter()
        self._starts = Counter()
        self._returns = Counter()
        self._api_events = []
        self._api_count = self._api_invalid = self._api_unmatched_returns = 0
        self._api_capped = False

    def accept(self, line, *, complete=True):
        if type(line) is not str or not _CHANNEL.search(line):
            return super().accept(line, complete=complete)
        if self._api_count >= _MAX_TRACE_RECORDS:
            self._api_capped = True
            return 'drop'
        self._api_count += 1
        match = _MARKER.fullmatch(line.removesuffix('\n').removesuffix('\r')) if complete else None
        if not match:
            self._api_invalid += 1
            return 'drop'
        pid, tid = (int(value, 16) for value in match.groups()[:2])
        phase, ok, error = map(int, match.groups()[2:])
        if not pid or not tid or error > 0xffffffff or ((phase <= 2 or ok) and error) or (phase <= 3 and ok):
            self._api_invalid += 1
            return 'drop'
        thread = pid, tid
        if phase == 1:
            self._depth[thread] += 1
            self._starts[pid] += 1
        elif phase == 5:
            self._returns[pid] += 1
            if self._depth[thread] > 1:
                self._depth[thread] -= 1
            elif thread in self._depth:
                del self._depth[thread]
            else:
                self._api_unmatched_returns += 1
        elif len(self._api_events) < _MAX_TARGET_EVENTS:
            self._api_events.append({'wine_pid': pid, 'wine_tid': tid, 'phase': phase,
                'inside_observed_register_class_w': self._depth[thread] > 0,
                'success': bool(ok) if phase in (3, 4) else None,
                'last_error': error if phase in (3, 4) and not ok else None})
        else:
            self._api_capped = True
            return 'drop'
        return 'accepted'

    def summary(self):
        stock = super().summary()
        stock['invalid_lines'] += self._api_invalid
        stock['capped'] |= self._api_capped
        stock['registration_api'] = {
            'records_seen': self._api_count,
            'invalid_records': self._api_invalid,
            'unmatched_register_class_w_returns': self._api_unmatched_returns,
            'open_register_class_w_scopes': sum(self._depth.values()),
            'register_class_w_by_pid': [
                {'wine_pid': pid, 'entries': self._starts[pid], 'returns': self._returns[pid]}
                for pid in sorted(self._starts.keys() | self._returns.keys())],
            'grc_window_events': [dict(event) for event in self._api_events],
        }
        return stock
