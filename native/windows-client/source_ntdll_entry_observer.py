"""Opt-in passive entry comparisons for the unchanged parity Source role."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import threading
from types import ModuleType

ROOT = Path(__file__).resolve().parents[2]
STAGE = ROOT / 'build/windows-source-integration'
PREFIX = ROOT / 'prefixes/fivem-source-main'
ENGINE = ROOT / 'runtime/wine-job-query-parity/engine'
MANIFEST_SHA = 'e4fc3167813864102909da696cf3a03e89bd00a4a9abe26d8478c88316600f9c'
BASE = 'native/windows-client/source_code_observer.py'
ADAPTER = 'native/windows-hook-state-observer/run_control.py'
CONTRACT = 'native/windows-hook-state-observer/contract.py'
OBSERVER = 'build/windows-hook-state-observer/hook_state_observer.exe'
CONTROL_LABEL = 'wine-parity-hook-state-control-20261103T104448915817Z'
CONTROL = 'research/' + CONTROL_LABEL + '-results.json'
POLICY = 'scripts/source_main_environment.py'
CASES = (('gated_hook_state_fixture', 'build/windows-hook-state-observer/hook_state_fixture.exe', 0),
         ('outside_root_rejection', OBSERVER, 2), ('empty_source_binding', OBSERVER, 0))
PINS = {
    BASE: (13045, '1ccf9f8e1cad43d3100153a01f713689512f9fc85269527d722c890945ef82ec'),
    ADAPTER: (12863, 'd266fea145f4fd5642d28cb70dcd6309d00c6e7cf1c78aec13398bb87be0e5d2'),
    CONTRACT: (10282, '2a5787bfbfb80376b30d44ceab303320e5744892004df665f16bff2520c8d9fb'),
    CONTROL: (19929, '05a5e5caeb755be9cdeed481379f63e9a96370c3edc115fccb5782b837a7372c'),
    POLICY: (15981, 'e78f556ee12921c1b62a381538724e373b7b8beb91eb9da1f49929e4a109eeff'),
    'logs/' + CONTROL_LABEL + '-gated_hook_state_fixture.ndjson':
        (1821, '690a2d1cfbda57b8d9f61524cb3654330d84744b701543021eddeb0f49544636'),
    'logs/' + CONTROL_LABEL + '-outside_root_rejection.ndjson':
        (51, 'fd872f1fd8727a6618743a04481ae1a28986282bb81743785fffb5c0cb5e78c8'),
    'logs/' + CONTROL_LABEL + '-empty_source_binding.ndjson':
        (264, '810e0771a6361edfcb7968e06649d90087e862ad99c885b07ffa3f48a61bf690'),
}


def read(name):
    if (type(name) is not str or name.startswith('/') or '..' in Path(name).parts
            or Path(name).as_posix() != name):
        raise RuntimeError('Require a canonical project-relative code/control role')
    path = ROOT / name
    if path.resolve(strict=True) != path:
        raise RuntimeError('Source entry-observer inputs may not use aliases')
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise RuntimeError('Source entry-observer inputs must be regular and single-link')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as source:
        opened = os.fstat(source.fileno())
        raw = source.read()
        after = os.fstat(source.fileno())
    final = path.lstat()
    fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    if any(getattr(before, k) != getattr(opened, k) or getattr(opened, k) != getattr(after, k)
           or getattr(after, k) != getattr(final, k) for k in fields):
        raise RuntimeError('Source entry-observer input changed while reading')
    return raw


def identity(name, raw=None):
    raw = read(name) if raw is None else raw
    return {'path': name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def bound(name):
    if name not in PINS:
        raise RuntimeError('Undeclared entry-observer provider role')
    raw = read(name)
    if (len(raw), hashlib.sha256(raw).hexdigest()) != PINS[name]:
        raise RuntimeError('A frozen entry-observer provider or own control changed')
    return raw


def execute(name, raw):
    module = ModuleType('_source_ntdll_entry_' + Path(name).stem)
    module.__file__ = str(ROOT / name)
    previous_path = sys.path[:]
    try:
        exec(compile(raw, str(ROOT / name), 'exec'), module.__dict__)
    finally:
        sys.path[:] = previous_path
    return module


_base = execute(BASE, bound(BASE))


def validate_selection(runtime_profile, exit_relay=False):
    if runtime_profile != 'parity' or exit_relay is not False:
        raise ValueError('NTDLL entry comparison requires explicit parity without exit-relay')


def same(left, right):
    return json.dumps(left, sort_keys=True, separators=(',', ':')) == json.dumps(right, sort_keys=True, separators=(',', ':'))


def load_binding():
    data = {name: bound(name) for name in PINS}
    record = json.loads(data[CONTROL])
    if (record.get('profile') != 'wine-parity-api-probes' or record.get('probe_role') != 'hook-state-control'
            or record.get('protocol_version') != 1810 or record.get('prefix') != 'prefixes/wine-parity-regression'
            or record.get('passed') is not True or record.get('runtime_started') is not True
            or record.get('only_own_fixtures_and_builtin_initialization') is not True
            or record.get('client_cef_rockstar_game_or_account_code_started') is not False
            or not same(record.get('cleanup'), [{'flag': '-k', 'exit': 0}, {'flag': '-w', 'exit': 0}])
            or record.get('quarantine_cleared_after_confirmed_cleanup') is not True
            or record.get('runtime_verification', {}).get('manifest_sha256') != MANIFEST_SHA
            or any(key in record for key in ('failure', 'post_run_guard_failure', 'prefix_terminal_state_uncertain'))):
        raise RuntimeError('Require the exact clean actual three-case entry-observer control')
    runs = record.get('runs')
    if not isinstance(runs, list) or len(runs) != len(CASES):
        raise RuntimeError('All three original observer controls are required')
    for row, (name, binary, exitcode) in zip(runs, CASES):
        if (row.get('name') != name or row.get('binary') != binary or type(row.get('exit')) is not int
                or row['exit'] != exitcode or row.get('passed') is not True
                or row.get('log') != 'logs/' + CONTROL_LABEL + '-' + name + '.ndjson'
                or row.get('wine_log') != 'logs/' + CONTROL_LABEL + '-' + name + '-wine.log'):
            raise RuntimeError('Actual own control case or fixed log role differs')
    adapter = execute(ADAPTER, data[ADAPTER])
    fixture = adapter.verify_inputs()
    if not same(record.get('fixture_inputs'), fixture):
        raise RuntimeError('Actual own observer fixture/parser/lifecycle inputs changed')
    runner = adapter.load_runner()
    verified = runner.runtime.verify_runtime()  # Code/dependency verification only; no API-prefix access.
    if verified.get('manifest_sha256') != MANIFEST_SHA or not same(record['runtime_verification'], verified):
        raise RuntimeError('Actual observer control belongs to another current engine verification')
    cases = adapter.make_cases(fixture)
    for case, row, (name, binary, _) in zip(cases, runs, CASES):
        if case.get('name') != name or case.get('binary') != ROOT / binary:
            raise RuntimeError('Original observer parser delegation selected another case')
        parsed = case['parse_output'](data[row['log']].decode('utf-8').splitlines(), row['exit'])
        if parsed.get('passed') is not True or any(not same(value, row.get(key)) for key, value in parsed.items()):
            raise RuntimeError('Actual own numeric stdout no longer meets its original strict parser')
    contract = execute(CONTRACT, data[CONTRACT])
    inputs = [*(identity(name, raw) for name, raw in data.items()), *fixture['runtime_inputs'],
              *fixture['source_inputs'], *fixture['build_reports'], *fixture['adapter_sources']]
    unique = {}
    for item in inputs:
        if item['path'] in unique and unique[item['path']] != item:
            raise RuntimeError('Conflicting entry-observer code/control identities')
        unique[item['path']] = item
    return contract, list(unique.values())


class EntryRecords:
    """Admit each prefix through the unchanged strict parser before persistence."""
    def __init__(self, contract, duration_ms):
        self.contract, self.duration_ms = contract, duration_ms
        self.lines, self.events = [], []
        self.ready = self.complete = False
        self.rejected = self.attempted = 0

    def accept(self, line):
        self.attempted += 1
        if self.attempted > 8192 or type(line) is not str or len(line.encode('utf-8')) > 2048:
            self.rejected += 1
            return None
        parsed = self.contract.parse_source([*self.lines, line], 0)
        if parsed.get('rejected') != 0 or len(parsed.get('events', [])) != len(self.events) + 1:
            self.rejected += 1
            return None
        row = parsed['events'][-1]
        if row['event'] == 'ready' and row.get('duration_ms') != self.duration_ms:
            self.rejected += 1
            return None
        self.lines.append(line)
        self.events.append(dict(row))
        self.ready = self.ready or row['event'] == 'ready'
        self.complete = parsed.get('complete') is True
        return dict(row)

    def summary(self, exitcode=None):
        parsed = self.contract.parse_source(self.lines, exitcode if type(exitcode) is int else 1)
        return {'accepted_records': len(self.events), 'rejected_records': self.rejected,
                'native_summary': parsed.get('summary'), 'native_completion_observed': self.complete,
                'capture_incomplete': not self.complete or self.rejected != 0,
                'passed': bool(parsed.get('passed') is True and self.rejected == 0)}


class SourceNtdllEntryObserver(_base.SourceCodeObserver):
    def __init__(self, runtime, environment, stage, label, duration):
        if (stage != STAGE or runtime.ENGINE != ENGINE or runtime.WINE != ENGINE / 'bin/wine'
                or getattr(runtime, 'source_runtime_profile', {}).get('profile') != 'parity'
                or environment.get('WINEPREFIX') != str(PREFIX)
                or environment.get('WINESERVER') != str(ENGINE / 'bin/wineserver')
                or any(key in environment for key in ('WINESERVERSOCKET', 'WINELOADERNOEXEC'))
                or environment.get('WINELOADER', str(ENGINE / 'bin/wine')) != str(ENGINE / 'bin/wine')):
            raise RuntimeError('Entry observation requires the exact baseline-parity Source role')
        if (type(duration) is not int or not 1 <= duration <= 3600 or type(label) is not str
                or re.fullmatch(r'client-source-ui(?:-resume)?-\d{8}T\d{12}Z', label) is None):
            raise ValueError('Require the existing bounded Source duration and label')
        self.policy = sys.modules.get('source_main_environment')
        self.prefix_identity = None
        self._assert_held_context()
        self.runtime, self.environment = runtime, dict(environment)
        self.label, self.duration = label, min(duration, 300)
        self.contract, inputs = load_binding()
        self.inputs = [*inputs, identity('native/windows-client/source_ntdll_entry_observer.py'),
                       identity('native/windows-client/run_source.py')]
        self.records = EntryRecords(self.contract, self.duration * 1000)
        self.path = ROOT / 'logs' / (label + '-ntdll-entries.ndjson')
        self.output = self.process = self.thread = None
        self.thread_started = False
        self.reader_error = self.start_error = self.lifecycle_error = None
        self.ready, self.stop = threading.Event(), threading.Event()
        self.exit = None
        self.own_observer_terminated_after_cleanup = self.finished = False

    def _assert_held_context(self):
        policy = self.policy
        if (policy is None or sys.modules.get('source_main_environment') is not policy
                or getattr(policy, 'ROOT', None) != ROOT or Path(policy.__file__).resolve() != ROOT / POLICY):
            raise RuntimeError('Require the same source-MAIN policy module as the controller')
        held = policy._ACTIVE_MAIN_LOCKS.get(str(PREFIX))
        if not held or held[0] != os.getpid():
            raise RuntimeError('Entry observation requires the existing held source-MAIN lock')
        fd = os.fstat(held[1])
        lock = PREFIX.parent / '.fivem-source-main.source-main.lock'
        ls = lock.lstat()
        if (not stat.S_ISREG(fd.st_mode) or fd.st_nlink != 1 or stat.S_ISLNK(ls.st_mode)
                or (fd.st_dev, fd.st_ino) != (ls.st_dev, ls.st_ino)
                or PREFIX.resolve(strict=True) != PREFIX or not PREFIX.is_dir()):
            raise RuntimeError('Source-MAIN lock or direct prefix directory identity differs')
        info = PREFIX.stat()
        current = (info.st_dev, info.st_ino)
        if self.prefix_identity is None:
            self.prefix_identity = current
        elif self.prefix_identity != current:
            raise RuntimeError('The Source prefix directory changed during entry observation')

    def verify_sources(self):
        self._assert_held_context()
        if [identity(item['path']) for item in self.inputs] != self.inputs:
            raise RuntimeError('Bound entry-observer code/control changed during observation')

    def start(self):
        self.verify_sources()
        contract, current = load_binding()
        if current != self.inputs[:-2]:
            raise RuntimeError('Actual own control or baseline changed before helper creation')
        if self.process is not None or self.output is not None:
            raise RuntimeError('Start the passive entry observer exactly once')
        if self.path.parent.resolve(strict=True) != ROOT / 'logs':
            raise RuntimeError('Entry-observer output must remain in the existing project log directory')
        self.output = os.fdopen(os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'w')
        quiet = {key: value for key, value in self.environment.items() if not key.lower().startswith('citizenfx_')}
        quiet['WINEDEBUG'] = '-all'
        command = [str(self.runtime.WINE), str(ROOT / OBSERVER), '--source-root',
                   'Z:' + str(STAGE).replace('/', '\\'), '--duration-ms', str(self.duration * 1000)]
        try:
            self.process = subprocess.Popen(command, cwd=STAGE, env=quiet,
                                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            self.thread = threading.Thread(target=self._drain, daemon=True)
            try:
                self.thread.start()
            finally:
                self.thread_started = self.thread.ident is not None
        except BaseException as error:
            self.start_error = type(error).__name__
            raise

    def wait_ready(self):
        super().wait_ready()
        if self.records.rejected:
            raise RuntimeError('Entry-observer records failed validation before Main')

    def finish_after_wineserver_cleanup(self):
        try:
            super().finish_after_wineserver_cleanup()
        except BaseException as error:
            self.lifecycle_error = type(error).__name__
            self.finished = True
        return self.result()

    def result(self):
        stopped = self.thread is None or not self.thread.is_alive()
        summary = self.records.summary(self.exit) if stopped else {'capture_incomplete': True, 'reader_running': True}
        events = [dict(row) for row in self.records.events] if stopped else []
        succeeded = (stopped and summary.get('passed') is True and type(self.exit) is int and self.exit == 0
                     and self.reader_error is None and self.start_error is None and self.lifecycle_error is None)
        return {'enabled': True, 'code_inputs': self.inputs, 'positive_own_control': CONTROL,
                'observer_log': str(self.path.relative_to(ROOT)), 'observer_exit': self.exit,
                'observer_native_pid': self.process.pid if self.process is not None else None,
                'observer_duration_seconds': self.duration, 'reader_thread_stopped': stopped,
                'start_failure': self.start_error, 'reader_failure': self.reader_error,
                'own_lifecycle_failure': self.lifecycle_error,
                'own_observer_terminated_after_source_cleanup': self.own_observer_terminated_after_cleanup,
                'entry_comparison_summary': summary, 'entry_comparison_events': events,
                'native_completion_observed': bool(stopped and self.records.complete),
                'native_completion_succeeded': bool(succeeded),
                'only_accepted_numeric_records_persisted': True,
                'helper_deadline_terminates_client': False, 'target_process_terminated_or_modified': False,
                'raw_code_bytes_addresses_paths_arguments_auth_or_wine_logs_persisted': False,
                'entry_comparison_only': True, 'hook_execution_or_ownership_proved': False}
