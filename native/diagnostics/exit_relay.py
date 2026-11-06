"""Filter three ordinary Wine exit-API calls before writing any diagnostic bytes."""
import json
import os
import re
import selectors
import stat
import time

RELAY_INCLUDE = 'kernel32.ExitProcess;ntdll.RtlExitUserProcess;ntdll.NtTerminateProcess'
RELAY_REGISTRY_KEY = r'HKCU\Software\Wine\Debug'
OWN_BASENAME = 'named_pipe_probe.exe'
SOURCE_BASENAME = 'FiveM_ROSLauncher'
MAX_LINE_BYTES = 4096
MAX_RECORDS = 256
DWORD_MAX = 0xffffffff
QWORD_MAX = 0xffffffffffffffff
CALL = re.compile(rb'([0-9a-fA-F]{1,8}):([0-9a-fA-F]{1,8}):Call '
                  rb'((?i:kernel32)\.ExitProcess|(?i:ntdll)\.RtlExitUserProcess|(?i:ntdll)\.NtTerminateProcess)'
                  rb'\(([0-9a-fA-F]{1,16})(?:,([0-9a-fA-F]{1,16}))?\) ret=([0-9a-fA-F]{1,16})\r?')
TARGETS = tuple(name.lower().encode('ascii') for name in RELAY_INCLUDE.split(';'))


def source_selector_candidate(basename):
    """Check only the known extensionless role, without querying a process or profile."""
    return type(basename) is str and basename.casefold() == SOURCE_BASENAME.casefold()


def relay_debug(basename=OWN_BASENAME, *, source_authorized=False):
    if type(source_authorized) is not bool or type(basename) is not str:
        raise ValueError('Require a fixed relay role and explicit boolean Source authorization')
    if basename.casefold() == OWN_BASENAME.casefold():
        selected = OWN_BASENAME
    elif source_authorized and source_selector_candidate(basename):
        selected = SOURCE_BASENAME
    else:
        raise ValueError('Only the own probe or explicitly authorized Source selector is admitted')
    return '-all,+pid,' + selected + ':trace+relay'


class RelayFilter:
    """Bounded byte framing; no raw lines, API arguments or handles are returned."""
    def __init__(self):
        self.pending = bytearray()
        self.dropping = False
        self.finished = False
        self.counts = {'input_bytes': 0, 'complete_lines': 0, 'accepted_records': 0,
                       'rejected_candidate_lines': 0, 'discarded_other_lines': 0,
                       'oversized_lines': 0, 'discarded_partial_lines': 0,
                       'record_limit_reached': False}

    def _line(self, line):
        self.counts['complete_lines'] += 1
        match = CALL.fullmatch(line)
        if match:
            qualified = match[3]
            api = qualified.split(b'.')[1]
            second = match[5]
            terminate = api == b'NtTerminateProcess'
            if (terminate != (second is not None)):
                match = None
            else:
                pid, tid, caller = int(match[1], 16), int(match[2], 16), int(match[6], 16)
                if not (0 < pid <= DWORD_MAX and 0 < tid <= DWORD_MAX and 0 < caller <= QWORD_MAX):
                    match = None
        if match is None:
            key = ('rejected_candidate_lines' if b'Call ' in line and any(name in line.lower() for name in TARGETS)
                   else 'discarded_other_lines')
            self.counts[key] += 1
            return None
        if self.counts['accepted_records'] == MAX_RECORDS:
            self.counts['record_limit_reached'] = True
            return None
        # Both signatures consume a 32-bit status. The first Nt argument is never retained.
        status = int(second if terminate else match[4], 16) & DWORD_MAX
        self.counts['accepted_records'] += 1
        return {'kind': 'exit_api_call', 'api': api.decode('ascii'),
                'pid': pid, 'tid': tid, 'status': status, 'caller_address': caller}

    def feed(self, data):
        if self.finished or type(data) is not bytes:
            raise ValueError('Require bytes before relay-filter completion')
        self.counts['input_bytes'] += len(data)
        records = []
        offset = 0
        while offset < len(data):
            end = data.find(b'\n', offset)
            stop = len(data) if end < 0 else end
            if not self.dropping:
                if len(self.pending) + stop - offset > MAX_LINE_BYTES:
                    self.pending.clear()
                    self.dropping = True
                    self.counts['oversized_lines'] += 1
                else:
                    self.pending.extend(data[offset:stop])
            if end < 0:
                break
            if self.dropping:
                self.counts['complete_lines'] += 1
                self.dropping = False
            else:
                record = self._line(bytes(self.pending))
                if record is not None:
                    records.append(record)
            self.pending.clear()
            offset = end + 1
        return records

    def finish(self):
        if not self.finished:
            if self.pending or self.dropping:
                self.counts['discarded_partial_lines'] += 1
            self.pending.clear()
            self.dropping = False
            self.finished = True
        return {**self.counts, 'all_exit_calls_observed_claim': False,
                'private_arguments_buffers_or_handles_persisted': False,
                'authentication_or_integrity_decisions_modified': False,
                'processes_started_or_terminated_by_filter': False,
                'exit_cause_established': False, 'caller_module_or_rva_established': False}


def pump(stderr_pipe, binary_sink, *, stop_event, timeout_seconds=45):
    """Bounded pipe draining; retains neither a process handle nor ownership of the pipe.

    The caller supplies a fresh Popen stderr pipe and a binary regular-file sink.
    Stop drains only immediately queued bytes for at most 0.1 seconds; an inherited
    writer cannot postpone return until EOF. The caller closes its pipe afterwards.
    """
    if (type(timeout_seconds) not in (int, float) or isinstance(timeout_seconds, bool)
            or not 0 < timeout_seconds <= 3600 or not callable(getattr(stop_event, 'is_set', None))):
        raise ValueError('Require a finite relay capture duration and a stop event')
    fd = stderr_pipe if type(stderr_pipe) is int else stderr_pipe.fileno()
    if not stat.S_ISFIFO(os.fstat(fd).st_mode):
        raise ValueError('Relay capture accepts only its own stderr pipe')
    try:
        sink_fd = binary_sink.fileno()
    except (AttributeError, OSError):
        # BytesIO is useful for the pure/inert harness; actual runners use a regular file.
        if type(binary_sink).__module__ != '_io' or type(binary_sink).__name__ != 'BytesIO':
            raise ValueError('Relay persistence requires a binary regular file') from None
    else:
        info = os.fstat(sink_fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('Relay persistence requires a regular single-link file')
    filtered = RelayFilter()
    start = time.monotonic()
    deadline = start + timeout_seconds
    stop_deadline = None
    reason = None
    was_blocking = os.get_blocking(fd)
    selector = selectors.DefaultSelector()
    os.set_blocking(fd, False)
    try:
        selector.register(fd, selectors.EVENT_READ)
        while reason is None:
            now = time.monotonic()
            if now >= deadline:
                reason = 'timeout'
                break
            if stop_event.is_set() and stop_deadline is None:
                stop_deadline = min(deadline, now + 0.1)
            if stop_deadline is not None and now >= stop_deadline:
                reason = 'stop'
                break
            ready = selector.select(0 if stop_deadline is not None else min(0.05, deadline - now))
            if not ready:
                if stop_deadline is not None:
                    reason = 'stop'
                continue
            try:
                data = os.read(fd, 16384)
            except BlockingIOError:
                continue
            if not data:
                reason = 'eof'
                break
            for record in filtered.feed(data):
                payload = (json.dumps(record, separators=(',', ':')) + '\n').encode('ascii')
                if binary_sink.write(payload) != len(payload):
                    raise RuntimeError('The numeric relay sink did not accept a complete record')
        binary_sink.flush()
    finally:
        selector.close()
        os.set_blocking(fd, was_blocking)
    return {**filtered.finish(), 'termination_reason': reason,
            'elapsed_seconds': round(time.monotonic() - start, 6),
            'eof_observed': reason == 'eof', 'stop_requested': stop_event.is_set()}
