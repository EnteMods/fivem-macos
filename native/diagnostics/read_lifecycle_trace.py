"""Select fixed lifecycle markers from the existing public startup diagnostics."""
import re

MARKER = b'[CFX_SOURCE_COMPONENT] '
COMPONENTS = {b'sticky': 1, b'adhesive': 2, b'net': 3, b'glue': 4,
              b'legitimacy': 5, b'nui:core': 6}
PHASES = {b'citigame.pre-resume.' + name: value for value, name in enumerate(
    (b'component.before', b'cast.before', b'cast.after', b'callback.before',
     b'callback.after', b'component.after'), 1)}
PATTERN = re.compile(rb'pid=([0-9]{1,10}) tid=([0-9]{1,10}) phase=([a-z0-9_.-]{1,96}) '
                     rb'component=([a-zA-Z0-9_:.-]{1,96})(?:\\n")?')


def parse_debug_line(line):
    if type(line) is not bytes or len(line) > 4096 or line.count(MARKER) != 1:
        return None
    match = PATTERN.fullmatch(line.split(MARKER, 1)[1].rstrip(b'\r\n'))
    if not match:
        return None
    pid, tid, phase, component = match.groups()
    if phase not in PHASES or component not in COMPONENTS:
        return None
    if not 0 < int(pid) <= 0xffffffff or not 0 < int(tid) <= 0xffffffff:
        return None
    return dict(pid=int(pid), tid=int(tid), phase=PHASES[phase], component=COMPONENTS[component])


def summarize(records):
    groups = {}
    for row in records:
        if (type(row) is not dict or set(row) != {'pid', 'tid', 'phase', 'component'}
                or any(type(x) is not int for x in row.values())
                or not 0 < row['pid'] <= 0xffffffff or not 0 < row['tid'] <= 0xffffffff
                or row['phase'] not in range(1, 7) or row['component'] not in range(1, 7)):
            raise ValueError('Invalid lifecycle record')
        key = row['pid'], row['tid'], row['component']
        groups.setdefault(key, []).append(row['phase'])
    return {'schema': 'lifecycle-observation-v1', 'groups': [
        {'pid': key[0], 'tid': key[1], 'component': key[2], 'phases': phases,
         'state': ('CALLBACK_RETURNED' if phases == [1, 2, 3, 4, 5, 6]
                   else 'NO_CALLBACK_BRANCH' if phases == [1, 2, 3, 6] else 'UNKNOWN')}
        for key, phases in sorted(groups.items())],
        'limits': ['Only existing public PreResumeGame markers are observed.',
                   'A returned callback does not prove authentication readiness.',
                   'Unobserved or incomplete groups remain unknown.']}
