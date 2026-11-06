"""Read fixed numeric initialization observations without authentication data."""

import re


MARKER = b'[CFX_COMPONENT_INIT] '
KEYS = ('seq', 'event', 'pid', 'tid', 'component', 'ordinal', 'call', 'value')
PATTERN = re.compile(
    rb'seq=([0-9]{1,10}) event=([0-9]{1,10}) pid=([0-9]{1,10}) '
    rb'tid=([0-9]{1,10}) component=([0-9]{1,10}) ordinal=([0-9]{1,10}) '
    rb'call=([0-9]{1,10}) value=([0-9]{1,10})(?:\\n\")?'
)
COMPONENTS = {
    1: 'sticky', 2: 'adhesive', 3: 'net', 4: 'glue',
    5: 'legitimacy', 6: 'nui:core',
}


def valid_record(record):
    if type(record) is not dict or set(record) != set(KEYS):
        return False
    if any(type(value) is not int or not 0 <= value <= 0xffffffff
           for value in record.values()):
        return False
    seq, event, pid, tid, component, ordinal, call, value = (
        record[key] for key in KEYS
    )
    if not 1 <= seq <= 128 or not pid or not tid:
        return False
    if event == 5:
        return seq == 128 and (component, ordinal, call, value) == (0, 0, 0, 1)
    if seq == 128:
        return False
    if event == 1:
        return component in COMPONENTS and ordinal == call == 0 and value in (0, 1)
    if event == 2:
        return component in COMPONENTS and ordinal > 0 and call == seq and value == 1
    if event == 3:
        return component in COMPONENTS and ordinal > 0 and 0 < call < seq and value in (0, 1)
    if event == 4:
        return component == ordinal == call == 0 and value <= 63
    if event == 6:
        return (component, ordinal, call, value) == (0, 0, 0, 1)
    return False


def parse_debug_line(line):
    """Return only the fixed fields; never retain a Wine debug prefix or suffix."""
    if type(line) is not bytes or len(line) > 4096 or line.count(MARKER) != 1:
        return None
    payload = line.split(MARKER, 1)[1].rstrip(b'\r\n')
    match = PATTERN.fullmatch(payload)
    if match is None:
        return None
    record = dict(zip(KEYS, (int(value) for value in match.groups())))
    return record if valid_record(record) else None


def summarize(records, malformed_rows=0, dropped_rows=0):
    """Pair by process, thread and call ID; a missing return stays unknown."""
    if type(malformed_rows) is not int or type(dropped_rows) is not int:
        raise ValueError('Invalid observation counters')
    if malformed_rows < 0 or dropped_rows < 0:
        raise ValueError('Invalid observation counters')
    per_process = {}
    duplicates = {}
    conflicts = set()
    for record in records:
        if not valid_record(record):
            raise ValueError('Invalid numeric initialization record')
        pid, seq = record['pid'], record['seq']
        process = per_process.setdefault(pid, {})
        if seq in process:
            duplicates[pid] = duplicates.get(pid, 0) + 1
            if process[seq] != record:
                conflicts.add(pid)
        else:
            process[seq] = dict(record)

    processes = []
    for pid, by_sequence in sorted(per_process.items()):
        ordered = [by_sequence[seq] for seq in sorted(by_sequence)]
        starts, returns = {}, {}
        seen = []
        complete_masks = []
        for record in ordered:
            event = record['event']
            if event == 1:
                seen.append({
                    'seq': record['seq'], 'component': COMPONENTS[record['component']],
                    'has_instances': bool(record['value']),
                })
            elif event in (2, 3):
                key = (record['tid'], record['call'])
                (starts if event == 2 else returns).setdefault(key, []).append(record)
            elif event == 4:
                complete_masks.append({'seq': record['seq'], 'cumulative_seen_mask': record['value']})

        calls = []
        for key in sorted(set(starts) | set(returns)):
            before, after = starts.get(key, []), returns.get(key, [])
            matched = (
                pid not in conflicts and len(before) == len(after) == 1
                and before[0]['component'] == after[0]['component']
                and before[0]['ordinal'] == after[0]['ordinal']
                and before[0]['seq'] < after[0]['seq']
            )
            origin = (before or after)[0]
            calls.append({
                'tid': key[0], 'call': key[1],
                'component': COMPONENTS[origin['component']],
                'ordinal': origin['ordinal'],
                'before_observed': bool(before), 'return_observed': bool(after),
                'state': 'RETURNED' if matched else 'UNKNOWN',
                'return_value': bool(after[0]['value']) if matched else None,
            })

        sequence_contiguous = sorted(by_sequence) == list(range(1, max(by_sequence) + 1))
        budget_exhausted = any(record['event'] == 5 for record in ordered)
        classification_failed = any(record['event'] == 6 for record in ordered)
        observation_complete = bool(
            complete_masks and sequence_contiguous and not budget_exhausted
            and not classification_failed and not duplicates.get(pid)
            and not malformed_rows and not dropped_rows
            and all(call['state'] == 'RETURNED' for call in calls)
        )
        processes.append({
            'pid': pid, 'record_count': len(ordered),
            'duplicate_rows': duplicates.get(pid, 0),
            'conflicting_sequence': pid in conflicts,
            'sequence_contiguous': sequence_contiguous,
            'budget_exhausted': budget_exhausted,
            'classification_failed': classification_failed,
            'loop_complete_markers': complete_masks,
            'observation_complete': observation_complete,
            'component_observations': seen, 'calls': calls,
        })

    return {
        'schema': 'component-init-observation-v1',
        'malformed_marker_rows': malformed_rows, 'dropped_marker_rows': dropped_rows,
        'processes': processes,
        'limitations': [
            'Return values describe Initialize only, not authentication or server admission.',
            'A missing return can reflect an exception, incomplete logging or the output limit.',
            'Complete seen masks are cumulative within a process, not per PreLoadGame call.',
            'Unobserved components are not classified as absent.',
            'A complete observation is not proof of a complete client startup.',
        ],
    }


def read_stream(stream, max_records=2048):
    records, malformed, dropped = [], 0, 0
    partial = False
    while chunk := stream.readline(8192):
        complete = chunk.endswith(b'\n')
        if not partial and MARKER in chunk:
            record = parse_debug_line(chunk) if complete else None
            if record is None:
                malformed += 1
            elif len(records) >= max_records:
                dropped += 1
            else:
                records.append(record)
        partial = not complete
    return summarize(records, malformed, dropped)
