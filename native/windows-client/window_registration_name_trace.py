"""Track the resolved class role and lifetime without recording Wine's names or pointers."""

import re

from window_registration_trace import Collector as RegistrationCollector


_PREFIX = r'(?P<pid>[0-9a-f]{1,8}):(?P<tid>[0-9a-f]{1,8}):trace:class:'
_PTR = r'(?:0x)?[0-9a-f]{1,16}'
_VERSION = r'(?:[0-9]{1,5}\.){3}[0-9]{1,5}!'
_TARGET = r'(?i:grcwindow)'
_SUCCESS = re.compile(
    _PREFIX + rf'NtUserRegisterClassExWOW name=L"{_TARGET}"->L"(?P<version>{_VERSION})?{_TARGET}"'
    rf' atom=(?P<atom>[0-9a-f]{{4}}) wndproc={_PTR} hinst={_PTR} bg={_PTR}'
    rf' style=[0-9a-f]{{8}} clsExt=[0-9]{{1,10}} winExt=[0-9]{{1,10}} class=(?P<token>{_PTR})')
_UNREGISTER = re.compile(_PREFIX + rf'NtUserUnregisterClass (?P<token>{_PTR})')
_MAX_NAMES = 256


class Collector(RegistrationCollector):
    def __init__(self):
        super().__init__()
        self._line_number = 0
        self._name_events = []
        self._tracked_classes = {}
        self._name_capped = False

    def accept(self, line, *, complete=True):
        self._line_number += 1
        if complete and type(line) is str and len(line) <= 2048:
            body = line.removesuffix('\n').removesuffix('\r')
            match = _SUCCESS.fullmatch(body) or _UNREGISTER.fullmatch(body)
            if match is not None:
                pid, tid, token = (int(match[name], 16) for name in ('pid', 'tid', 'token'))
                self._observe_name(match, pid, tid, token)
        api_count, class_count = len(self._api_events), len(self._events)
        action = super().accept(line, complete=complete)
        if len(self._api_events) > api_count:
            self._api_events[-1]['trace_line'] = self._line_number
        if len(self._events) > class_count:
            self._events[-1]['trace_line'] = self._line_number
        return action

    def _observe_name(self, match, pid, tid, token):
        if not pid or not tid or not token:
            return
        key = (pid, token)
        if match.re is _SUCCESS:
            if not int(match['atom'], 16):
                return
            name_kind = 'versioned' if match['version'] else 'bare'
            event = 'register_success'
        else:
            name_kind = self._tracked_classes.get(key)
            if name_kind is None:
                return
            event = 'unregistered'
        if len(self._name_events) >= _MAX_NAMES:
            self._name_capped = True
            return
        if event == 'register_success':
            self._tracked_classes[key] = name_kind
        else:
            del self._tracked_classes[key]
        self._name_events.append({'event': event, 'name_kind': name_kind, 'wine_pid': pid,
                                  'wine_tid': tid, 'trace_line': self._line_number})

    def summary(self):
        stock = super().summary()
        stock['capped'] |= self._name_capped
        stock['resolved_name_events'] = [dict(event) for event in self._name_events]
        return stock
