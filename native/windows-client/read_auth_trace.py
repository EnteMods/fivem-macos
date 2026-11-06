"""Read only the fixed numeric fields emitted by the opt-in auth observer."""
import argparse
import json
import re
from pathlib import Path

MARKER = '[cfx-auth-trace] '
ROOT = Path(__file__).resolve().parents[2]
LOGS = ROOT / 'prefixes/fivem-source-update-prelogin-1257409/drive_c/source-update-game-client/logs'
LOG_NAME = re.compile(r'CitizenFX_log_[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{6}\.log')
PATTERNS = (
    (re.compile(r'after_create_notification=1 handler_present=([01])'),
     'after_create_notification', ('handler_present',)),
    (re.compile(r'idle_status_query=1 handler_present=([01])'),
     'idle_status_query', ('handler_present',)),
    (re.compile(r'attempt=([0-9]{1,10}) handler_present=([01])'),
     'dispatch_begin', ('attempt', 'handler_present')),
    (re.compile(r'attempt=([0-9]{1,10}) dispatch_return=([01])'),
     'dispatch_return', ('attempt', 'dispatch_return')),
    (re.compile(r'attempt=([0-9]{1,10}) callback=1 success=([01]) additional_cfxTicket2_present=([01])'),
     'natural_completion', ('attempt', 'success', 'additional_cfxTicket2_present')),
    (re.compile(r'attempt=([0-9]{1,10}) perform_request=1'),
     'perform_request', ('attempt',)),
)


def parse_event(line):
    if MARKER not in line:
        return None
    value = line.split(MARKER, 1)[1].rstrip('\r\n')
    for pattern, phase, names in PATTERNS:
        match = pattern.fullmatch(value)
        if match:
            record = {'phase': phase, **{name: int(value) for name, value in zip(names, match.groups())}}
            if record.get('attempt', 0) <= 0xffffffff:
                return record
    return None


def summarize(stream):
    records = []
    malformed = 0
    dropped = 0
    partial = False
    while chunk := stream.readline(8192):
        complete = chunk.endswith(b'\n')
        if complete and not partial:
            line = chunk.decode('utf-8', errors='replace')
            record = parse_event(line)
            if record is not None:
                if len(records) < 512:
                    records.append(record)
                else:
                    dropped += 1
            elif MARKER in line:
                malformed += 1
        partial = not complete
    return {'records': records, 'malformed_marker_rows': malformed,
            'reader_dropped_records': dropped,
            'source_output_limit_may_have_been_reached': len(records) >= 128,
            'url_token_or_payload_values_exported': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log_name')
    args = parser.parse_args()
    if not LOG_NAME.fullmatch(args.log_name):
        parser.error('Expected a single candidate log basename')
    path = LOGS / args.log_name
    if path.is_symlink() or path.resolve(strict=True) != path or not path.is_file():
        raise RuntimeError('Expected a regular candidate log')
    with path.open('rb') as stream:
        print(json.dumps(summarize(stream), sort_keys=True))


if __name__ == '__main__':
    main()
