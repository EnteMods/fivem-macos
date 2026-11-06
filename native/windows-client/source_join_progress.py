#!/usr/bin/env python3
"""Report only fixed milestones from one Source client log."""

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import re
import stat


LOG_NAME = re.compile(r'CitizenFX_log_[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{6}\.log')
LINE = re.compile(r'^\[ *([0-9]{1,14})\] +\[b[0-9]{1,6}_GameProc\] +[^/\r\n]{1,24}/ (.*)$')
PROGRESS = {
    'Requesting server variables...': 'server_variables',
    'Waiting for game to shut down...': 'waiting_for_game_shutdown',
    'Handshaking with server...': 'handshake_started',
    'Downloading content': 'server_resource_download_started',
    'Downloading completed': 'server_resource_download_complete',
}
CACHE = re.compile(r'(Verifying game content|Updating game storage)\.\.\. \(([0-9]{1,3})%\)')
ACK = re.compile(r'Received connectOK: ServerID -?[0-9]+, SlotID -?[0-9]+, HostID -?[0-9]+')
BUILD_SWITCH = re.compile(r'Switching from build ([0-9]{1,6}) to build ([0-9]{1,6}) \(exe ([0-9]{1,6})\)\.\.\.')
MOUNTER_FAILURE = re.compile(r'Could not get resource mounter for resource [A-Za-z0-9_.-]{1,128}\.')
MOUNTER_URI_FAILURE = re.compile(r'Resource URI ([A-Za-z][A-Za-z0-9+.-]{0,31}):[^\r\n]{0,4096} has no mounter\.')
MAX_LINE_BYTES = 8192


def parse_event(line):
    match = LINE.fullmatch(line.rstrip('\r\n'))
    if not match:
        return None
    tick, message = match.groups()
    message = message.removeprefix('^2')
    percent = None
    if uri_failure := MOUNTER_URI_FAILURE.fullmatch(message):
        scheme = uri_failure[1].lower()
        return {'tick_ms': int(tick), 'phase': 'resource_uri_without_mounter',
                'scheme_class': scheme if scheme in ('global', 'ci') else 'other'}
    if switch := BUILD_SWITCH.fullmatch(message):
        return {'tick_ms': int(tick), 'phase': 'game_build_switch_requested',
                'from_build': int(switch[1]), 'to_build': int(switch[2]), 'exe_build': int(switch[3])}
    if message.startswith('OnConnectionProgress: '):
        progress = message.removeprefix('OnConnectionProgress: ')
        phase = PROGRESS.get(progress)
        cache = CACHE.fullmatch(progress)
        if cache and int(cache[2]) <= 100:
            percent = int(cache[2])
            phase = 'game_cache_verify' if cache[1] == 'Verifying game content' else 'game_cache_update'
    elif ACK.fullmatch(message):
        phase = 'server_protocol_ack'
    elif message == 'Network connected, triggering initial game load...':
        phase = 'network_active_game_load_requested'
    elif message == 'Network connected, triggering game reload...':
        phase = 'network_active_game_reload_requested'
    elif message == 'Game finished loading!':
        phase = 'game_load_finalized'
    elif message.startswith('Game cache error: '):
        phase = 'game_cache_error'
    elif message == 'OnConnectionError: Connection rejected by server: No authentication ticket was specified.':
        phase = 'server_rejected_missing_auth_ticket'
    elif message.startswith('OnConnectionError: '):
        error = re.sub(r'\^[0-9]', '', message.removeprefix('OnConnectionError: '))
        phase = 'resource_mounter_error' if MOUNTER_FAILURE.fullmatch(error) else 'connection_error'
    elif MOUNTER_FAILURE.fullmatch(message):
        phase = 'resource_mounter_error'
    else:
        return None
    if phase is None:
        return None
    event = {'tick_ms': int(tick), 'phase': phase}
    if percent is not None:
        event['percent'] = percent
    return event


def summarize(stream):
    counts = Counter()
    last = None
    previous_chunk_incomplete = False
    while chunk := stream.readline(MAX_LINE_BYTES):
        complete = chunk.endswith(b'\n')
        if complete and not previous_chunk_incomplete:
            event = parse_event(chunk.decode('utf-8', errors='replace'))
            if event is not None:
                counts[event['phase']] += 1
                last = event
        previous_chunk_incomplete = not complete
    return {'counts': dict(counts), 'latest': last}


def open_client_log(path):
    path = Path(os.path.abspath(path))
    if not LOG_NAME.fullmatch(path.name):
        raise ValueError('Expected one CitizenFX client log basename')
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parent = os.open(path.anchor, directory_flags)
    descriptor = None
    try:
        for name in path.parts[1:-1]:
            next_parent = os.open(name, directory_flags, dir_fd=parent)
            os.close(parent)
            parent = next_parent
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('Expected an independent regular client log file')
        stream = os.fdopen(descriptor, 'rb')
        descriptor = None
        return stream
    finally:
        os.close(parent)
        if descriptor is not None:
            os.close(descriptor)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log_name', nargs='?', help='One client log basename, used with --logs-dir')
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument('--log', type=Path, help='Explicit client log file; no installation discovery')
    selection.add_argument('--logs-dir', type=Path, help='Explicit logs directory, followed by a log basename')
    args = parser.parse_args(argv)
    if args.log is not None:
        if args.log_name is not None:
            parser.error('--log takes no additional basename')
        path = args.log
    else:
        if args.log_name is None or not LOG_NAME.fullmatch(args.log_name):
            parser.error('--logs-dir requires one CitizenFX_log_YYYY-MM-DDTHHMMSS.log basename')
        path = args.logs_dir / args.log_name
    try:
        with open_client_log(path) as stream:
            summary = summarize(stream)
    except (OSError, ValueError) as error:
        parser.exit(1, 'Client log could not be read (' + type(error).__name__ +
                    '); select one regular file through a path without redirects.\n')
    print(json.dumps(summary, sort_keys=True))


if __name__ == '__main__':
    main()
