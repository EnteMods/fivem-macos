"""Opt-in, numeric-only Source PID relations from the tested Wine1810 watcher."""
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import threading
import time
from types import ModuleType

ROOT = Path(__file__).resolve().parents[2]
STAGE = ROOT / 'build/windows-source-integration'
PREFIX = ROOT / 'prefixes/fivem-source-main'
ENGINE = ROOT / 'runtime/wine-job-query-parity/engine'
BASE = 'native/windows-client/source_code_observer.py'
EXIT_BASE = 'native/windows-client/source_exit_relay.py'
OBSERVER = 'build/windows-wine-pid-watch/pid_watch.exe'
ADAPTER = 'native/windows-wine-pid-watch/run.py'
CONTRACT = 'native/windows-wine-pid-watch/contract.py'
BUILD = 'research/windows-wine-pid-watch-build.json'
V1_CONTROL = 'research/wine-parity-wine-pid-map-20261102T201936506179Z-results.json'
CONTROL = 'research/wine-parity-wine-pid-watch-20261102T204251815829Z-results.json'
MANIFEST_SHA = 'e4fc3167813864102909da696cf3a03e89bd00a4a9abe26d8478c88316600f9c'
PINS = {
    BASE: (13045, '1ccf9f8e1cad43d3100153a01f713689512f9fc85269527d722c890945ef82ec'),
    EXIT_BASE: (12025, '58c09882d3db67bb46bd66751c3807333ac20d4c17e2d9d538d697b7ea955875'),
    V1_CONTROL: (24186, '801fa937662bcba6ff16d5d147dd1bf4667033ed0f482bd4892990502a7b22d6'),
    BUILD: (26108, '106cae1554ef608006479a9f7b1457424736a3f14e2d4e1864b2bea0a62dfb96'),
    CONTRACT: (9155, '35821c6100e7ef8ca7c9b314f03d8e6462a81ad7236c41394e32dc56b78ef7ce'),
    ADAPTER: (11854, 'aa16378c9ac134c50e0d7883fcb7be530713b2cec55f554f348202c934a1a035'),
    CONTROL: (31288, '3e9d97bebe507903c66b34b04b7984885ed6195745d2d95a7e6c84b6b419e4d3'),
}


def _bound(name):
    if name not in PINS:
        raise RuntimeError('Unknown fixed Source PID-watch input role')
    path = ROOT / name
    if path.resolve(strict=True) != path:
        raise RuntimeError('Source PID-watch input roles may not use aliases')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise RuntimeError('Source PID-watch inputs must be regular and single-link')
        raw = source.read()
    if (len(raw), hashlib.sha256(raw).hexdigest()) != PINS[name]:
        raise RuntimeError('A fixed Source PID-watch provider or actual own control changed')
    return raw


def _execute(name, raw):
    module = ModuleType('source_pid_watch_' + Path(name).stem)
    module.__file__ = str(ROOT / name)
    exec(compile(raw, str(ROOT / name), 'exec'), module.__dict__)
    return module


_base = _execute(BASE, _bound(BASE))


def validate_selection(runtime_profile, exit_relay):
    if runtime_profile != 'parity' or exit_relay is not True:
        raise ValueError('Source host-PID observation requires explicit parity together with exit-relay')


def load_binding():
    if CONTROL is None or not {CONTROL, ADAPTER, CONTRACT, BUILD}.issubset(PINS):
        raise RuntimeError('The new multi-role PID watcher needs its actual completed own control before Source use')
    data = {name: _bound(name) for name in PINS}
    record = json.loads(data[CONTROL])
    runs = record.get('runs', [])
    if (record.get('profile') != 'wine-parity-api-probes' or record.get('probe_role') != 'wine-pid-watch'
            or record.get('passed') is not True or record.get('prefix') != 'prefixes/wine-parity-regression'
            or record.get('runtime_verification', {}).get('manifest_sha256') != MANIFEST_SHA
            or record.get('cleanup') != [{'flag': '-k', 'exit': 0}, {'flag': '-w', 'exit': 0}]
            or record.get('quarantine_cleared_after_confirmed_cleanup') is not True
            or record.get('only_own_fixtures_and_builtin_initialization') is not True
            or record.get('client_cef_rockstar_game_or_account_code_started') is not False
            or [(row.get('name'), row.get('exit'), row.get('passed')) for row in runs]
                != [('multi_role_fixture', 0, True)]
            or runs[0].get('matched_roles') != 2
            or runs[0].get('driver_host_matches_actual_popen') is not True
            or runs[0].get('observer', {}).get('completed') is not True
            or runs[0].get('observer', {}).get('passed') is not True
            or runs[0].get('observer', {}).get('rejected') != 0
            or runs[0].get('observer', {}).get('mapped_records') != 2
            or runs[0].get('observer', {}).get('process_identities') != 2):
        raise RuntimeError('Require the exact actual multi-role/actual-host PID-watch control')
    historical = json.loads(data[V1_CONTROL])
    if (historical.get('profile') != 'wine-parity-api-probes' or historical.get('probe_role') != 'wine-pid-map'
            or historical.get('passed') is not True
            or historical.get('runtime_verification', {}).get('manifest_sha256') != MANIFEST_SHA
            or historical.get('cleanup') != [{'flag': '-k', 'exit': 0}, {'flag': '-w', 'exit': 0}]):
        raise RuntimeError('Require the preserved historical own Wine1810 host-PID control')
    adapter = _execute(ADAPTER, data[ADAPTER])
    fixture = adapter.verify_inputs()
    if any(record.get('fixture_inputs', {}).get(key) != value for key, value in fixture.items()):
        raise RuntimeError('The actual own run selected different PID-watch inputs')
    contract = _execute(CONTRACT, data[CONTRACT])
    identities = [*(_base.identity(name, raw) for name, raw in data.items()),
                  *fixture['build_reports'], *fixture['runtime_inputs'], *fixture['source_inputs']]
    unique = {}
    for item in identities:
        if item['path'] in unique and unique[item['path']] != item:
            raise RuntimeError('Conflicting PID-watch provider identities')
        unique[item['path']] = item
    return contract.WatchRecords, list(unique.values())


class SourcePidWatcher(_base.SourceCodeObserver):
    def __init__(self, runtime, environment, stage, label, duration, exit_context):
        if (stage != STAGE or runtime.ENGINE != ENGINE or runtime.WINE != ENGINE / 'bin/wine'
                or getattr(runtime, 'source_runtime_profile', {}).get('profile') != 'parity'
                or environment.get('WINEPREFIX') != str(PREFIX)
                or environment.get('WINESERVER') != str(ENGINE / 'bin/wineserver')
                or exit_context.runtime is not runtime or exit_context.environment != environment
                or exit_context.prepared is not True):
            raise RuntimeError('Source PID watcher requires the exact prepared parity Source exit context')
        if (type(duration) is not int or not 1 <= duration <= 3600 or type(label) is not str
                or re.fullmatch(r'client-source-ui(?:-resume)?-\d{8}T\d{12}Z', label) is None):
            raise ValueError('Require the bounded existing Source controller duration/label')
        self.context = exit_context
        self.context._assert_held_context()
        self.runtime, self.environment = runtime, dict(environment)
        self.label, self.duration = label, min(duration, 600)
        self.record_type, self.inputs = load_binding()
        self.inputs += [_base.identity('native/windows-client/source_pid_watch.py'),
                        _base.identity('native/windows-client/run_source.py')]
        self.records = None
        self.path = ROOT / 'logs' / (label + '-host-pids.ndjson')
        self.output = self.process = self.thread = None
        self.thread_started = False
        self.reader_error = self.start_error = self.lifecycle_error = None
        self.ready, self.stop = threading.Event(), threading.Event()
        self.exit = None
        self.own_observer_terminated_after_cleanup = False
        self.finished = False

    def _drain(self):
        pending, dropping = bytearray(), False
        selector = selectors.DefaultSelector()
        fd = self.process.stdout.fileno()
        was_blocking = os.get_blocking(fd)
        os.set_blocking(fd, False)
        stop_deadline = None
        try:
            selector.register(fd, selectors.EVENT_READ)
            while True:
                if self.stop.is_set() and stop_deadline is None:
                    stop_deadline = time.monotonic() + 0.1
                if stop_deadline is not None and time.monotonic() >= stop_deadline:
                    break
                available = selector.select(0 if stop_deadline is not None else 0.05)
                if not available:
                    if stop_deadline is not None:
                        break
                    continue
                try:
                    data = os.read(fd, 8192)
                except BlockingIOError:
                    continue
                if not data:
                    break
                for segment in data.splitlines(keepends=True):
                    ended = segment.endswith(b'\n')
                    if not dropping:
                        if len(pending) + len(segment) > 1024:
                            pending.clear()
                            dropping = True
                        else:
                            pending.extend(segment)
                    if ended:
                        self._accept(b'' if dropping else bytes(pending))
                        pending.clear()
                        dropping = False
            if pending or dropping:
                self._accept(b'')
        except BaseException as error:
            self.reader_error = type(error).__name__
        finally:
            selector.close()
            os.set_blocking(fd, was_blocking)

    def start(self):
        self.verify_sources()
        if self.process is not None or self.output is not None:
            raise RuntimeError('Start the own Source PID watcher exactly once')
        if self.path.parent.resolve(strict=True) != ROOT / 'logs':
            raise RuntimeError('The own Source PID-watch log must stay in the project log directory')
        self.output = os.fdopen(os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'w')
        env = {key: value for key, value in self.environment.items() if not key.lower().startswith('citizenfx_')}
        env['WINEDEBUG'] = '-all'
        command = [str(self.runtime.WINE), str(ROOT / OBSERVER), '--source-root',
                   'Z:' + str(STAGE).replace('/', '\\'), '--duration-ms', str(self.duration * 1000)]
        try:
            self.process = subprocess.Popen(command, cwd=STAGE, env=env,
                                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            self.records = self.record_type('source', native_pid=self.process.pid)
            self.thread = threading.Thread(target=self._drain, daemon=True)
            try:
                self.thread.start()
            finally:
                self.thread_started = self.thread.ident is not None
        except BaseException as error:
            self.start_error = type(error).__name__
            raise

    def result(self):
        stopped = self.thread is None or not self.thread.is_alive()
        rows = self.records.events if stopped and self.records is not None else []
        summary = self.records.summary() if stopped and self.records is not None else {
            'capture_incomplete': True, 'capture_not_started': self.records is None}
        completed = stopped and self.records is not None and self.records.complete
        return {'enabled': True, 'code_inputs': self.inputs, 'positive_own_control': CONTROL,
                'historical_v1_host_proof': V1_CONTROL,
                'observer_log': str(self.path.relative_to(ROOT)), 'observer_exit': self.exit,
                'observer_native_pid': self.process.pid if self.process is not None else None,
                'observer_duration_seconds': self.duration, 'reader_thread_stopped': stopped,
                'start_failure': self.start_error, 'reader_failure': self.reader_error,
                'own_lifecycle_failure': self.lifecycle_error,
                'own_observer_terminated_after_source_cleanup': self.own_observer_terminated_after_cleanup,
                'pid_mappings_summary': summary,
                'pid_mappings': [row for row in rows if row['event'] == 'mapped'],
                'metadata_events': [row for row in rows if row['event'] != 'mapped'],
                'native_completion_observed': bool(completed),
                'native_completion_succeeded': bool(completed and summary.get('passed')),
                'ready_host_bound_to_actual_helper_popen_pid': bool(stopped and self.records is not None and self.records.ready),
                'only_accepted_numeric_records_persisted': True,
                'process_names_paths_arguments_or_account_contents_persisted': False,
                'mappings_valid_across_later_process_id_reuse_claim': False,
                'target_process_termination_by_observer': False,
                'target_memory_read': False, 'target_modified': False,
                'actual_error_window_owner_or_cause_established': False}
