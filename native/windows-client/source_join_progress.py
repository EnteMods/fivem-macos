#!/usr/bin/env python3
"""Report only fixed milestones from one Source client log."""

import argparse
from collections import Counter
import json
import os
import re
import stat

from run_main import plain
from source_code_identity import STAGE


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
MAX_LINE_BYTES = 8192


def parse_event(line):
    match = LINE.fullmatch(line.rstrip('\r\n'))
    if not match:
        return None
    tick, message = match.groups()
    message = message.removeprefix('^2')
    percent = None
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
        phase = 'connection_error'
    elif message.startswith('Could not get resource mounter for resource '):
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log_name', help='One CitizenFX_log_YYYY-MM-DDTHHMMSS.log basename from the Source stage')
    args = parser.parse_args()
    if not LOG_NAME.fullmatch(args.log_name):
        parser.error('Expected one Source client log basename')
    path = STAGE / 'logs' / args.log_name
    plain(path)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise RuntimeError('Expected a regular Source client log file')
        summary = summarize(stream)
    print(json.dumps(summary, sort_keys=True))


if __name__ == '__main__':
    main()
