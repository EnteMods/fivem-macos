"""Join two bounded numeric Wine markers for each captured NUI draw."""
import re

from graphics_blit_gate_metadata import MAX_EVENTS, parse_source_snapshot
from graphics_blit_metadata import DWORD_MAX


_WRAPPER = re.compile(r'(?:(?P<pid>[0-9a-fA-F]{1,8}):)?(?P<tid>[0-9a-fA-F]{1,8}):'
    r'(?:trace:debugstr:OutputDebugStringA|warn:debugstr:OutputDebugStringA|warn:seh:dispatch_exception) '
    r'"(?P<payload>\[CFX_GRAPHICS_BLIT_(?:VERTICES|VERTEX_CONTEXT)\] [^"\r\n]{1,252})\\n"')
_IDENTITY = r' pid=(?P<pid>[1-9][0-9]{0,9}) tid=(?P<tid>[1-9][0-9]{0,9}) id=(?P<id>[1-8])'
_SIGNED = r'(?:0|-?[1-9][0-9]{0,9})'
_VERTICES = re.compile(r'\[CFX_GRAPHICS_BLIT_VERTICES\]' + _IDENTITY
                       + r' legacy=(?P<legacy>[01]) v=(?P<vertices>' + _SIGNED + '(?:,' + _SIGNED + '){19})')
_CONTEXT_FIELDS = ('ctx', 'vp_count', 'vp_valid', 'vp_x16', 'vp_y16', 'vp_w16', 'vp_h16',
                   'rt_w', 'rt_h', 'sc_enabled', 'sc_count', 'sc_l', 'sc_t', 'sc_r', 'sc_b')
_CONTEXT = re.compile(r'\[CFX_GRAPHICS_BLIT_VERTEX_CONTEXT\]' + _IDENTITY
                      + ''.join(f' {name}=(?P<{name}>{_SIGNED})' for name in _CONTEXT_FIELDS))


def _body(line):
    wrapper = _WRAPPER.fullmatch(line.rstrip('\r\n'))
    if wrapper is None:
        return None
    payload = wrapper['payload']
    vertex = _VERTICES.fullmatch(payload)
    match = vertex or _CONTEXT.fullmatch(payload)
    if match is None:
        return None
    pid, tid, sample = (int(match[name]) for name in ('pid', 'tid', 'id'))
    if (max(pid, tid) > DWORD_MAX or int(wrapper['tid'], 16) != tid
            or (wrapper['pid'] is not None and int(wrapper['pid'], 16) != pid)):
        return None
    if vertex:
        values = [int(value) for value in match['vertices'].split(',')]
        if any(abs(value) > 65536 * (16 if i % 5 < 2 else 4096) for i, value in enumerate(values)):
            return None
        data = {'legacy': int(match['legacy']), 'vertices': [values[i:i + 5] for i in range(0, 20, 5)]}
    else:
        data = {name: int(match[name]) for name in _CONTEXT_FIELDS}
        if (not 9 <= data['ctx'] <= 15 or any(not -(2**31) <= value < 2**31 for value in data.values())
                or any(not 0 <= data[name] <= 16 for name in ('vp_count', 'sc_count'))
                or any(data[name] not in (0, 1) for name in ('vp_valid', 'sc_enabled'))
                or any(not 0 <= data[name] <= 16384 for name in ('rt_w', 'rt_h'))
                or (data['ctx'] != 15 and any(data[name] for name in _CONTEXT_FIELDS[1:]))):
            return None
    return (pid, tid, sample), 'vertices' if vertex else 'context', data


def parse_lines(lines):
    pending, conflicts = {}, set()
    rejected = duplicates = 0
    capped = False
    for line in lines:
        if type(line) is not str or ('[CFX_GRAPHICS_BLIT_VERTICES]' not in line
                                    and '[CFX_GRAPHICS_BLIT_VERTEX_CONTEXT]' not in line):
            continue
        parsed = _body(line)
        if parsed is None:
            rejected += 1
            continue
        key, kind, data = parsed
        if key not in pending and len(pending) >= MAX_EVENTS:
            capped = True
            break
        parts = pending.setdefault(key, {})
        if kind in parts:
            if parts[kind] == data:
                duplicates += 1
            else:
                conflicts.add(key)
                rejected += 1
            continue
        parts[kind] = data
    events = [dict(pid=key[0], tid=key[1], sample=key[2], **parts['vertices'], context=parts['context'])
              for key, parts in pending.items() if key not in conflicts and len(parts) == 2]
    return {'accepted': len(events), 'duplicates': duplicates, 'rejected': rejected,
            'incomplete_pairs': sum(len(parts) < 2 for parts in pending.values()), 'capped': capped, 'events': events}


def parse_log(path, *, live=False):
    return parse_source_snapshot(path, parse_lines, live=live)
