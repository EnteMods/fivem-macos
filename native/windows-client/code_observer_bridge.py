"""Read the fixed ROS code-observer schema; native scope is verified before launch."""
import json
import re

SOURCE_RVA = 0x3203b0
CODE_LENGTH = 64
FIELDS = {
    'ready': {'mode', 'pid', 'duration_ms', 'rva', 'length', 'poll_ms', 'record_limit'},
    'module': {'time_ms', 'pid', 'creation', 'base', 'size'},
    'code': {'time_ms', 'pid', 'creation', 'sample', 'rva', 'length', 'hex'},
    'denied': {'time_ms', 'pid', 'creation', 'probe', 'reason', 'state', 'protect',
               'read_attempted', 'error', 'type', 'allocation_base'},
    'process_completed': {'time_ms', 'pid', 'creation', 'polls', 'read_calls',
                          'code_records', 'record_limit_reached'},
    'completed': {'mode', 'polls', 'processes', 'failures', 'exit'},
}
QWORDS = {'creation', 'base', 'allocation_base'}
BOOLS = {'read_attempted', 'record_limit_reached'}


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('Duplicate code-observer field')
        value[key] = item
    return value


class SourceCodeRecords:
    def __init__(self):
        self.modules = {}
        self.samples = {}
        self.events = []
        self.rejected = 0
        self.ready = False
        self.completed = False
        self.ended_processes = set()
        self.last_code = {}
        self.duration_ms = 0
        self.completion_succeeded = False

    def accept(self, line):
        if self.completed or not isinstance(line, str) or len(line) > 2048 or len(self.events) >= 4096:
            self.rejected += 1
            return None
        try:
            row = json.loads(line, object_pairs_hook=unique_object)
        except (ValueError, TypeError):
            self.rejected += 1
            return None
        if not isinstance(row, dict) or type(row.get('event')) is not str or row['event'] not in FIELDS:
            self.rejected += 1
            return None
        kind = row['event']
        if set(row) != FIELDS[kind] | {'event'}:
            self.rejected += 1
            return None
        for key, value in row.items():
            if key in ('event', 'hex', 'mode'):
                continue
            if key in BOOLS:
                valid = type(value) is bool
            else:
                limit = 0xffffffffffffffff if key in QWORDS else 0xffffffff
                valid = type(value) is int and 0 <= value <= limit
            if not valid:
                self.rejected += 1
                return None
        if 'time_ms' in row and (not self.ready or row['time_ms'] > self.duration_ms + 2000):
            self.rejected += 1
            return None
        if kind == 'ready':
            valid = (not self.ready and row['mode'] == 'source' and row['pid'] > 0
                     and 1 <= row['duration_ms'] <= 600000 and row['rva'] == SOURCE_RVA
                     and row['length'] == CODE_LENGTH and row['poll_ms'] == 250
                     and row['record_limit'] == 20)
        elif kind == 'module':
            key = row['pid'], row['creation']
            valid = (self.ready and key not in self.modules and key not in self.ended_processes and row['pid'] > 0
                     and len(self.modules) < 64 and row['creation'] > 0 and row['base'] > 0
                     and row['size'] >= CODE_LENGTH
                     and row['base'] + row['size'] <= 0xffffffffffffffff)
        elif kind == 'code':
            key = row['pid'], row['creation']
            valid = (self.ready and key in self.modules and key not in self.ended_processes and row['rva'] == SOURCE_RVA
                     and row['length'] == CODE_LENGTH
                     and type(row['hex']) is str and re.fullmatch(r'[0-9a-f]{128}', row['hex']) is not None
                     and SOURCE_RVA + CODE_LENGTH <= self.modules[key]['size']
                     and row['sample'] == self.samples.get(key, 0) + 1 and row['sample'] <= 20
                     and row['hex'] != self.last_code.get(key))
        elif kind == 'denied':
            key = row['pid'], row['creation']
            valid = (self.ready and key in self.modules and key not in self.ended_processes
                     and row['probe'] == 0 and 1 <= row['reason'] <= 7
                     and row['read_attempted'] == (row['reason'] == 7))
        elif kind == 'process_completed':
            key = row['pid'], row['creation']
            valid = (self.ready and row['pid'] > 0 and row['creation'] > 0
                     and key not in self.ended_processes and row['code_records'] == self.samples.get(key, 0)
                     and len(self.ended_processes) < 64
                     and (key in self.modules or row['read_calls'] == 0)
                     and row['code_records'] <= min(20, row['read_calls'])
                     and row['read_calls'] <= row['polls'] <= 2400
                     and row['record_limit_reached'] == (row['code_records'] == 20))
        else:
            valid = (self.ready and row['mode'] == 'source' and row['polls'] <= 2400
                     and len(self.modules) <= row['processes'] == len(self.ended_processes) <= 64
                     and self.modules.keys() <= self.ended_processes
                     and row['exit'] in (0, 3) and (row['failures'] == 0) == (row['exit'] == 0))
        if not valid:
            self.rejected += 1
            return None
        if kind == 'ready':
            self.ready = True
            self.duration_ms = row['duration_ms']
        elif kind == 'module':
            self.modules[(row['pid'], row['creation'])] = row
        elif kind == 'code':
            self.samples[(row['pid'], row['creation'])] = row['sample']
            self.last_code[(row['pid'], row['creation'])] = row['hex']
        elif kind == 'process_completed':
            self.ended_processes.add((row['pid'], row['creation']))
        elif kind == 'completed':
            self.completed = True
            self.completion_succeeded = row['exit'] == 0
        self.events.append(row)
        return row

    def summary(self):
        return {'ready': self.ready, 'accepted_records': len(self.events), 'rejected_records': self.rejected,
                'module_records': len(self.modules), 'code_records': sum(self.samples.values()),
                'native_completion_observed': self.completed,
                'native_completion_succeeded': self.completion_succeeded,
                'actual_ros_exit_caller_or_cause_claim': False,
                'nonexecutable_data_or_account_contents_requested': False}
