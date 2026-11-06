"""Keep fixed Wine class checkpoints and compare instance tokens only in memory."""
import re

MAX_LINE_CHARS = 2048
MAX_EVENTS = 256
_GLOBAL_CLASS = 0x4000
_PREFIX = r'(?P<ids>(?:[0-9a-fA-F]{1,8}:){1,2})trace:'
_NAME = r'L"(?P<name>[A-Za-z_][A-Za-z0-9_]{0,63})"'
_HEX = r'[0-9a-fA-F]{1,16}'
_PTR = rf'(?:(?:0[xX])?{_HEX}|\(nil\))'
_INSTANCE = rf'(?P<instance>{_PTR})'
_CLASS_TOKEN = rf'(?P<class_token>{_PTR})'
_U32_HEX = r'[0-9a-fA-F]{1,8}'
_ORIGINAL_NAME = r'(?:L"(?:[^"\\\r\n]|\\(?:[nrt"\\]|[0-9a-f]{4}))*"(?:\.\.\.)?|#[0-9a-f]{4}|\(null\)|\(invalid\))'
_REGISTER = _PREFIX + r'class:NtUserRegisterClassExWOW name='
_PATTERNS = (
    ('registration_attempt', re.compile(
        _REGISTER + _NAME + rf' hinst={_INSTANCE} style=0x(?P<style>{_U32_HEX})'
        rf' clExtr=0x{_U32_HEX} winExtr=0x{_U32_HEX}')),
    ('registration_succeeded', re.compile(
        _REGISTER + _ORIGINAL_NAME + '->' + _NAME + rf' atom=(?P<atom>[0-9a-fA-F]{{4}}) wndproc={_PTR}'
        rf' hinst={_INSTANCE} bg={_PTR} style=(?P<style>[0-9a-fA-F]{{8}})'
        rf' clsExt=[0-9]{{1,10}} winExt=[0-9]{{1,10}} class={_CLASS_TOKEN}')),
    ('lookup_hit', re.compile(
        _PREFIX + r'class:find_class ' + _NAME + rf' (?P<instance>{_HEX}) -> {_CLASS_TOKEN}')),
    ('create_lookup_miss', re.compile(
        _PREFIX + r'win:WIN_CreateWindowEx ' + _NAME + rf' {_INSTANCE} -> not found')),
    ('unregistered', re.compile(_PREFIX + r'class:NtUserUnregisterClass ' + _CLASS_TOKEN)),
)
# Overclassification is safe here. The original class payload must never pass through.
_CLASS_LINE = re.compile(r'(?:^|:)(?:trace|warn|err|fixme):class:|^(?:[^\s:]*:)*class:', re.IGNORECASE)
_CREATE_LINE = re.compile(r'(?:^|:)win:WIN_CreateWindowEx(?:[\s:]|$)', re.IGNORECASE)


def is_sensitive_line(line):
    return type(line) is str and bool(_CLASS_LINE.search(line) or _CREATE_LINE.search(line))


def _pointer(text):
    return 0 if text == '(nil)' else int(text, 16)


class Collector:
    def __init__(self, class_names=('grcWindow',)):
        if (type(class_names) is not tuple or not 1 <= len(class_names) <= 8
                or any(type(name) is not str or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}', name)
                       for name in class_names)
                or len(set(class_names)) != len(class_names)):
            raise ValueError('Require a bounded tuple of distinct owned class names')
        self._roles = {name: index for index, name in enumerate(class_names, 1)}
        self._events = []
        self._registrations = {}
        self._counts = dict(accepted=0, rejected=0, oversized_lines=0, incomplete_lines=0,
                            invalid_lines=0, capped_lines=0)

    def accept(self, line, *, complete=True):
        """Return 'accepted', 'drop', or 'passthrough'; never return input text."""
        if type(complete) is not bool or type(line) is not str:
            self._counts['invalid_lines'] += 1
            return 'drop'
        if not complete:
            self._counts['incomplete_lines'] += 1
            return 'drop'
        if len(line) > MAX_LINE_CHARS:
            self._counts['oversized_lines'] += 1
            return 'drop'
        body = line.removesuffix('\n').removesuffix('\r')
        if any(char in body for char in ('\n', '\r', '\0')):
            self._counts['invalid_lines'] += 1
            return 'drop'
        if not is_sensitive_line(body):
            return 'passthrough'
        if len(self._events) >= MAX_EVENTS:
            self._counts['capped_lines'] += 1
            return 'drop'
        for kind, pattern in _PATTERNS:
            match = pattern.fullmatch(body)
            if match:
                event = self._event(kind, match.groupdict())
                if event is not None:
                    self._events.append(event)
                    self._counts['accepted'] += 1
                    return 'accepted'
                break
        self._counts['rejected'] += 1
        return 'drop'

    def _event(self, kind, fields):
        ids = [int(part, 16) for part in fields['ids'][:-1].split(':')]
        if not all(ids):
            return None
        pid = ids[0] if len(ids) == 2 else None
        class_id = self._roles.get(fields.get('name'))
        token = _pointer(fields['class_token']) if 'class_token' in fields else None
        key = (pid, token)
        if token == 0:
            return None
        if kind == 'unregistered':
            if pid is None or key not in self._registrations:
                return None
            class_id = self._registrations.pop(key)[0]
        if class_id is None:
            return None
        event = {'event': kind, 'wine_pid': pid, 'wine_tid': ids[-1], 'class_id': class_id}
        if kind == 'unregistered':
            return event
        instance = _pointer(fields['instance'])
        event['instance_is_null'] = instance == 0
        if 'style' in fields:
            global_class = bool(int(fields['style'], 16) & _GLOBAL_CLASS)
            event['global_class'] = global_class
            if kind == 'registration_succeeded':
                if int(fields['atom'], 16) == 0:
                    return None
                if pid is not None:
                    self._registrations[key] = (class_id, instance, global_class)
            return event
        observed = []
        if pid is not None:
            if kind == 'lookup_hit':
                observed = [self._registrations[key]] if key in self._registrations else []
            else:
                observed = [item for (owner, _), item in self._registrations.items() if owner == pid]
        candidates = {(registered, global_class) for role, registered, global_class in observed if role == class_id}
        event['observed_registration_contexts'] = len(candidates)
        event.update(instance_equal=None, instance_same_64k=None, registration_global=None)
        if len(candidates) == 1:
            (registered, global_class), = candidates
            event.update(instance_equal=instance == registered,
                         instance_same_64k=bool(instance and registered >= 0x10000
                                                and instance >> 16 == registered >> 16),
                         registration_global=global_class)
        return event

    def summary(self):
        return {**self._counts, 'capped': self._counts['capped_lines'] != 0,
                'events': [dict(event) for event in self._events],
                'repeated_rows_preserved': True, 'missing_registration_proves_absence': False,
                'registration_api_return_trace_complete': False}


def parse_lines(lines, class_names=('grcWindow',)):
    collector = Collector(class_names)
    if type(lines) is str:
        for line in lines.splitlines(keepends=True):
            collector.accept(line, complete=line.endswith('\n'))
    else:
        for line in lines:
            collector.accept(line)
    return collector.summary()
