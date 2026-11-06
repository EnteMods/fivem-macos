"""Reduce an explicitly selected Procmon CSV to bounded, allowlisted metadata."""

import argparse
from collections import Counter
import csv
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import time


HEADER = ['Time of Day', 'Process Name', 'PID', 'Operation', 'Path', 'Result', 'Detail']
MAX_INPUT = 1 << 30
MAX_ROWS = 10_000_000
MAX_FIELD = 262144
MAX_GROUPS = 25000
MAX_REPORT = 2 << 20
PROCESS = re.compile(
    r'^(?:FiveM(?:_b[0-9]{1,6})?(?:_(?:GameProcess|GTAProcess|DumpServer|'
    r'ROSLauncher|ROSService|ChromeBrowser|Launcher|Main))?|GTA5(?:_Enhanced)?|'
    r'PlayGTAV|Launcher|LauncherPatcher|RockstarService|RockstarSteamHelper|SocialClubHelper)\.exe$', re.I
)
TIME = re.compile(r'^([0-9]{1,2}):([0-5][0-9]):([0-5][0-9])(?:[.,]([0-9]{1,9}))?(?: (AM|PM))?$')
DLLS = {
    'adhesive.dll', 'sticky.dll', 'net.dll', 'glue.dll', 'legitimacy.dll',
    'corert.dll', 'nui-core.dll', 'libcef.dll', 'citizengame.dll',
    'winhttp.dll', 'wininet.dll', 'ws2_32.dll', 'dnsapi.dll', 'secur32.dll',
    'crypt32.dll', 'bcrypt.dll', 'ntdll.dll', 'kernelbase.dll',
    'd3d11.dll', 'dxgi.dll', 'user32.dll', 'win32u.dll',
}
OPERATION_GROUPS = {
    'Process': ('Process Start', 'Process Create', 'Process Exit', 'Thread Create', 'Thread Exit', 'Load Image'),
    'Network': ('TCP Connect', 'TCP Accept', 'TCP Disconnect', 'TCP Reconnect',
                'TCP Retransmit', 'TCP Send', 'TCP Receive', 'TCP Copy', 'UDP Send', 'UDP Receive'),
    'Registry': ('RegOpenKey', 'RegCreateKey', 'RegCloseKey', 'RegQueryKey', 'RegQueryValue',
                 'RegSetValue', 'RegDeleteKey', 'RegDeleteValue', 'RegEnumKey', 'RegEnumValue',
                 'RegQueryMultipleValueKey', 'RegFlushKey', 'RegSetInfoKey', 'RegRenameKey',
                 'RegLoadKey', 'RegUnloadKey', 'RegQueryKeySecurity', 'RegSetKeySecurity'),
    'File': ('CreateFile', 'CloseFile', 'ReadFile', 'WriteFile', 'QueryOpen', 'QueryDirectory',
             'NotifyChangeDirectory', 'CreateFileMapping', 'FileSystemControl', 'DeviceIoControl',
             'LockFile', 'UnlockFile', 'Cleanup', 'FlushBuffersFile', 'QueryInformationFile',
             'QueryBasicInformationFile', 'QueryStandardInformationFile', 'QueryNameInformationFile',
             'QueryNetworkOpenInformationFile', 'QueryAttributeTagFile', 'QuerySecurityFile',
             'QueryVolumeInformation', 'SetBasicInformationFile', 'SetEndOfFileInformationFile',
             'SetRenameInformationFile', 'SetDispositionInformationFile', 'SetAllocationInformationFile',
             'SetSecurityFile'),
}
OPERATIONS = {op: group for group, values in OPERATION_GROUPS.items() for op in values}
RESULTS = {
    'SUCCESS', 'ACCESS DENIED', 'NAME NOT FOUND', 'PATH NOT FOUND', 'NO SUCH FILE',
    'NO MORE FILES', 'NO MORE ENTRIES', 'BUFFER OVERFLOW', 'BUFFER TOO SMALL', 'REPARSE',
    'END OF FILE', 'SHARING VIOLATION', 'LOCK VIOLATION', 'FILE LOCKED WITH ONLY READERS',
    'INVALID PARAMETER', 'INVALID DEVICE REQUEST', 'NOT SUPPORTED', 'FAST IO DISALLOWED',
    'CANCELLED', 'PENDING', 'RETRY', 'BAD NETWORK PATH', 'NETWORK NAME DELETED', 'DISCONNECTED',
}
SERVICES = {'https': 443, 'http': 80, 'domain': 53, 'dns': 53, 'microsoft-ds': 445}
DOMAINS = {'fivem.net': 'CFX_DOMAIN', 'cfx.re': 'CFX_DOMAIN', 'rockstargames.com': 'ROCKSTAR_DOMAIN'}


class InvalidCapture(Exception):
    pass


class HashingReader(io.RawIOBase):
    def __init__(self, raw):
        self.raw = raw
        self.digest = hashlib.sha256()
        self.bytes = 0

    def readable(self):
        return True

    def readinto(self, buffer):
        count = self.raw.readinto(buffer)
        if count:
            self.digest.update(memoryview(buffer)[:count])
            self.bytes += count
        return count


def checked_time(value):
    match = TIME.fullmatch(value)
    if match is None:
        return None
    hour, minute, second, fraction, period = match.groups()
    hour = int(hour)
    if period:
        if not 1 <= hour <= 12:
            return None
        hour = hour % 12 + (12 if period == 'PM' else 0)
    elif hour > 23:
        return None
    return '{:02d}:{}:{}.{}'.format(hour, minute, second, (fraction or '0').ljust(9, '0'))


def endpoint(value):
    host, separator, suffix = value.strip().rpartition(':')
    port = None
    if separator and re.fullmatch(r'[0-9]{1,5}', suffix):
        candidate = int(suffix)
        port = candidate if candidate <= 65535 else None
    elif separator:
        port = SERVICES.get(suffix.lower())
    if not separator:
        host = value.strip()
    host = host.strip('[]').rstrip('.').lower()
    for domain, label in DOMAINS.items():
        if host == domain or host.endswith('.' + domain):
            return port, label
    try:
        address = ipaddress.ip_address(host)
        scope = ('LOOPBACK' if address.is_loopback else 'UNSPECIFIED' if address.is_unspecified
                 else 'PRIVATE' if address.is_private else 'PUBLIC' if address.is_global else 'OTHER')
        return port, 'IPV{}_{}'.format(address.version, scope)
    except ValueError:
        return port, 'UNCLASSIFIED'


def area(path):
    lower = path.replace('/', '\\').lower()
    for needle, label in (
        ('\\device\\namedpipe\\', 'NAMED_PIPE'), ('\\data\\game-storage\\', 'GAME_STORAGE'),
        ('\\data\\server-cache', 'SERVER_CACHE'), ('\\rockstar games\\', 'ROCKSTAR'),
        ('\\windows\\system32\\', 'WINDOWS_SYSTEM32'), ('\\windows\\syswow64\\', 'WINDOWS_SYSWOW64'),
        ('\\fivem application data\\', 'FIVEM_DATA'), ('\\fivem.app\\', 'FIVEM_DATA'),
    ):
        if needle in lower:
            return label
    return 'OTHER'


def reduce_rows(stream):
    csv.field_size_limit(MAX_FIELD)
    reader = csv.reader(stream, strict=True)
    if next(reader, None) != HEADER:
        raise InvalidCapture('HEADER')
    counters = Counter()
    operations = Counter()
    errors = Counter()
    processes, modules, network, files = {}, {}, {}, {}
    lifecycle = []
    capture_first = capture_last = None

    def note(mapping, key, sequence, timestamp):
        if key not in mapping:
            if len(mapping) >= MAX_GROUPS:
                raise InvalidCapture('GROUP_LIMIT')
            mapping[key] = {'count': 0, 'first_sequence': sequence, 'last_sequence': sequence,
                            'first_time': timestamp, 'last_time': timestamp}
        item = mapping[key]
        item['count'] += 1
        item['last_sequence'], item['last_time'] = sequence, timestamp

    for sequence, row in enumerate(reader, 1):
        counters['total_rows'] += 1
        if sequence > MAX_ROWS or len(row) != len(HEADER):
            raise InvalidCapture('ROW_LIMIT_OR_SCHEMA')
        clock, name, raw_pid, operation, path, result, detail = row
        timestamp = checked_time(clock)
        if timestamp is None:
            counters['invalid_time_rows'] += 1
            continue
        capture_first = capture_first or timestamp
        capture_last = timestamp
        if not PROCESS.fullmatch(name):
            counters['unselected_process_rows'] += 1
            continue
        if not re.fullmatch(r'[0-9]{1,10}', raw_pid) or not 0 < int(raw_pid) <= 0xffffffff:
            counters['invalid_pid_rows'] += 1
            continue
        name, pid = name.lower(), int(raw_pid)
        counters['selected_process_rows'] += 1
        note(processes, (pid, name), sequence, timestamp)
        group = OPERATIONS.get(operation)
        if group is None:
            counters['unknown_operation_rows'] += 1
            continue
        status = result if result in RESULTS else 'OTHER'
        if status == 'OTHER':
            counters['unknown_result_rows'] += 1
        operations[(group, operation, status)] += 1
        if status not in ('SUCCESS', 'PENDING', 'REPARSE', 'NO MORE FILES', 'NO MORE ENTRIES', 'END OF FILE'):
            error_key = (pid, name, group, operation, status)
            if error_key not in errors and len(errors) >= MAX_GROUPS:
                raise InvalidCapture('GROUP_LIMIT')
            errors[error_key] += 1
        if operation == 'Load Image':
            basename = re.split(r'[\\/]', path)[-1].lower()
            if basename in DLLS:
                note(modules, (pid, name, basename, status), sequence, timestamp)
            else:
                counters['unselected_image_rows'] += 1
        elif operation in ('Process Start', 'Process Create', 'Process Exit'):
            if len(lifecycle) >= 4096:
                raise InvalidCapture('LIFECYCLE_LIMIT')
            event = {'sequence': sequence, 'time': timestamp, 'pid': pid, 'process': name,
                     'operation': operation, 'result': status}
            pattern = r'^Parent PID:\s*([0-9]{1,10})(?:,|$)' if operation == 'Process Start' else r'^PID:\s*([0-9]{1,10})(?:,|$)'
            if operation != 'Process Exit':
                match = re.match(pattern, detail)
                if match and int(match.group(1)) <= 0xffffffff:
                    event['parent_pid' if operation == 'Process Start' else 'child_pid'] = int(match.group(1))
            lifecycle.append(event)
        elif group == 'Network':
            parts = re.split(r'\s*->\s*', path, maxsplit=1)
            port_a, scope_a = endpoint(parts[0])
            port_b, scope_b = endpoint(parts[1]) if len(parts) == 2 else (None, 'UNCLASSIFIED')
            note(network, (pid, name, operation, status, port_a, port_b, scope_a, scope_b), sequence, timestamp)
        elif group == 'File':
            note(files, (area(path), status), sequence, timestamp)

    if not counters['total_rows'] or not counters['selected_process_rows']:
        raise InvalidCapture('NO_SELECTED_ROWS')

    def expanded(mapping, keys):
        return [dict(zip(keys, key), **value) for key, value in sorted(mapping.items(), key=lambda item: str(item[0]))]

    return {
        'schema': 'procmon-allowlisted-reduction-v1', 'coverage': dict(counters),
        'capture_first_time': capture_first, 'capture_last_time': capture_last,
        'processes': expanded(processes, ('pid', 'process')),
        'selected_modules': expanded(modules, ('pid', 'process', 'module', 'result')),
        'network': expanded(network, ('pid', 'process', 'operation', 'result', 'endpoint_a_port',
                                     'endpoint_b_port', 'endpoint_a_class', 'endpoint_b_class')),
        'file_areas': expanded(files, ('area', 'result')),
        'operations': [dict(zip(('category', 'operation', 'result'), key), count=count)
                       for key, count in sorted(operations.items())],
        'top_error_or_probe_groups': [dict(zip(('pid', 'process', 'category', 'operation', 'result'), key), count=count)
                                     for key, count in errors.most_common(30)],
        'process_lifecycle': lifecycle,
        'limits': [
            'Procmon started shortly before the join, not at client startup, according to the user.',
            'Times are local time-of-day values in file order; no date or alignment to the separate Stopwatch is inferred.',
            'Network events are not HTTP request counts or proof of ticket issuance.',
            'Endpoint A/B follow the recorded arrow; neither is assumed to mean remote.',
            'A selected DLL not observed in this time window is not classified as absent.',
            'File/registry probe errors can be normal; counts alone do not establish a cause.',
        ],
    }


def reduce_file(source):
    source = Path(source)
    descriptor = os.open(source, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(descriptor, 'rb', buffering=0) as raw:
        before = os.fstat(raw.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_INPUT:
            raise InvalidCapture('INPUT')
        hashed = HashingReader(raw)
        with io.TextIOWrapper(io.BufferedReader(hashed, 1 << 20), encoding='utf-8-sig', newline='') as text:
            result = reduce_rows(text)
            after = os.fstat(raw.fileno())
            if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                    != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                    or hashed.bytes != before.st_size):
                raise InvalidCapture('SOURCE_CHANGED')
            result['input_identity'] = {'bytes': hashed.bytes, 'sha256': hashed.digest.hexdigest()}
    return result


def overview(report):
    ports = Counter()
    for event in report['network']:
        ports[(event['operation'], event['endpoint_b_port'], event['result'])] += event['count']
    selected = [item for item in report['selected_modules'] if item['module'] in
                {'adhesive.dll', 'sticky.dll', 'net.dll', 'corert.dll', 'nui-core.dll', 'legitimacy.dll'}]
    return {
        'input_identity': report['input_identity'], 'coverage': report['coverage'],
        'time_window': [report['capture_first_time'], report['capture_last_time']],
        'process_count': len(report['processes']),
        'selected_module_groups': len(selected),
        'critical_modules': sorted({item['module'] for item in selected}),
        'lifecycle_events': report['process_lifecycle'][:20],
        'top_network_event_groups': [dict(operation=key[0], endpoint_b_port=key[1], result=key[2], count=count)
                                     for key, count in ports.most_common(12)],
        'top_error_or_probe_groups': report['top_error_or_probe_groups'][:8],
        'retained_groups': {key: len(report[key]) for key in ('processes', 'selected_modules', 'network', 'file_areas', 'operations')},
        'raw_values_exported': False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    started = time.monotonic()
    try:
        output_path = Path(args.output)
        if output_path.exists() or output_path.is_symlink():
            raise InvalidCapture('OUTPUT_EXISTS')
        report = reduce_file(args.input)
        payload = (json.dumps(report, indent=2) + '\n').encode()
        if len(payload) > MAX_REPORT:
            raise InvalidCapture('REPORT_LIMIT')
        descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        with os.fdopen(descriptor, 'wb') as output:
            output.write(payload)
        compact = overview(report)
        compact.update(report_bytes=len(payload), elapsed_seconds=round(time.monotonic() - started, 3))
        print(json.dumps(compact, sort_keys=True))
        return 0
    except Exception:
        print('{"status":"FAILED","reason":"INPUT_OUTPUT_OR_BOUNDS_REJECTED"}')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
