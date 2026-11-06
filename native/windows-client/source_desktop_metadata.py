"""Opt-in numeric Source desktop/window metadata from a proven localized helper."""
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
OBSERVER = 'build/windows-desktop-metadata-localized/desktop_probe.exe'
ADAPTER = 'native/windows-desktop-metadata-localized/run.py'
CONTRACT = 'native/windows-desktop-metadata-localized/contract.py'
BUILD = 'research/windows-desktop-metadata-localized-build.json'
CONTROL = 'research/wine-parity-desktop-localized-20261102T214723949919Z-results.json'
MANIFEST_SHA = 'e4fc3167813864102909da696cf3a03e89bd00a4a9abe26d8478c88316600f9c'
PINS = {
    BASE: (13045, '1ccf9f8e1cad43d3100153a01f713689512f9fc85269527d722c890945ef82ec'),
    EXIT_BASE: (12025, '58c09882d3db67bb46bd66751c3807333ac20d4c17e2d9d538d697b7ea955875'),
    BUILD: (24170, '7fc8a9679d3d9628777954c91f1c4a329bc86e3c9746919c23475fe8f2ef707d'),
    CONTRACT: (13323, 'a035ca2ad21e8c14d4a30c897d19d8a13e0977aa1e068b857d6b9752067f2e1b'),
    ADAPTER: (11821, 'dd9d8b0b5da350627fb2bc9fcc5cfd65e337280d3feb9a88174ceb26132c4b8c'),
    CONTROL: (45248, 'c1b1ca714422bfc5067185651568e602cd37703d963ce4d763a1c79b4a8a087a'),
}
OWN_EXPECTATIONS = {
    'identity_and_actual_popen_bound', 'default_error_on_current', 'alternate_not_on_current',
    'alternate_error_on_target_desktop', 'default_child_metadata', 'alternate_child_metadata',
    'default_compare_self_true', 'all_enumerations_and_comparisons_consistent',
}


def _bound(name):
    if name not in PINS:
        raise RuntimeError('Unknown fixed Source desktop-metadata input role')
    path = ROOT / name
    if path.resolve(strict=True) != path:
        raise RuntimeError('Source desktop-metadata providers may not use aliases')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise RuntimeError('Source desktop-metadata inputs must be regular and single-link')
        raw = source.read()
    if (len(raw), hashlib.sha256(raw).hexdigest()) != PINS[name]:
        raise RuntimeError('The Source desktop-metadata provider or actual own control changed')
    return raw


def _execute(name, raw):
    module = ModuleType('source_desktop_metadata_' + Path(name).stem)
    module.__file__ = str(ROOT / name)
    exec(compile(raw, str(ROOT / name), 'exec'), module.__dict__)
    return module


_base = _execute(BASE, _bound(BASE))


def validate_selection(runtime_profile, exit_relay):
    if runtime_profile != 'parity' or exit_relay is not True:
        raise ValueError('Source desktop metadata requires explicit parity together with exit-relay')


def load_binding():
    if CONTROL is None or CONTROL not in PINS:
        raise RuntimeError('Source desktop metadata needs its actual successful localized two-desktop own control')
    data = {name: _bound(name) for name in PINS}
    record = json.loads(data[CONTROL])
    runs = record.get('runs', [])
    if (record.get('profile') != 'wine-parity-api-probes' or record.get('probe_role') != 'desktop-localized'
            or record.get('passed') is not True or record.get('prefix') != 'prefixes/wine-parity-regression'
            or record.get('runtime_verification', {}).get('manifest_sha256') != MANIFEST_SHA
            or record.get('cleanup') != [{'flag': '-k', 'exit': 0}, {'flag': '-w', 'exit': 0}]
            or record.get('quarantine_cleared_after_confirmed_cleanup') is not True
            or record.get('only_own_fixtures_and_builtin_initialization') is not True
            or record.get('client_cef_rockstar_game_or_account_code_started') is not False
            or [(row.get('name'), row.get('exit'), row.get('passed')) for row in runs]
                != [('desktop_fixture', 0, True)]):
        raise RuntimeError('Require the exact actual successful localized desktop control')
    own = runs[0]
    expectations = own.get('control_expectations')
    if (type(expectations) is not dict or set(expectations) != OWN_EXPECTATIONS
            or any(value is not True for value in expectations.values())
            or own.get('observer', {}).get('completed') is not True
            or own.get('observer', {}).get('passed') is not True
            or own.get('observer', {}).get('rejected') != 0
            or own.get('observer', {}).get('api_failures') != 0
            or own.get('observer', {}).get('targets') != 2):
        raise RuntimeError('Default/alternate desktop, child metadata or zero-API-failure own proof is missing')
    adapter = _execute(ADAPTER, data[ADAPTER])
    fixture = adapter.verify_inputs()
    if any(record.get('fixture_inputs', {}).get(key) != value for key, value in fixture.items()):
        raise RuntimeError('The actual own control selected other localized desktop inputs')
    contract = _execute(CONTRACT, data[CONTRACT])
    identities = [*(_base.identity(name, raw) for name, raw in data.items()),
                  *fixture['build_reports'], *fixture['runtime_inputs'], *fixture['source_inputs']]
    unique = {}
    for item in identities:
        if item['path'] in unique and unique[item['path']] != item:
            raise RuntimeError('Conflicting Source desktop-metadata identities')
        unique[item['path']] = item
    return contract.MetaRecords, list(unique.values())


class SourceDesktopMetadata(_base.SourceCodeObserver):
    def __init__(self, runtime, environment, stage, label, duration, exit_context):
        if (stage != STAGE or runtime.ENGINE != ENGINE or runtime.WINE != ENGINE / 'bin/wine'
                or getattr(runtime, 'source_runtime_profile', {}).get('profile') != 'parity'
                or environment.get('WINEPREFIX') != str(PREFIX)
                or environment.get('WINESERVER') != str(ENGINE / 'bin/wineserver')
                or exit_context.runtime is not runtime or exit_context.environment != environment
                or exit_context.prepared is not True):
            raise RuntimeError('Desktop metadata requires the exact prepared parity Source exit context')
        if (type(duration) is not int or not 1 <= duration <= 3600 or type(label) is not str
                or re.fullmatch(r'client-source-ui(?:-resume)?-\d{8}T\d{12}Z', label) is None):
            raise ValueError('Require the bounded existing Source controller duration/label')
        self.context = exit_context
        self.context._assert_held_context()
        self.runtime, self.environment = runtime, dict(environment)
        self.label, self.duration = label, min(duration, 600)
        self.record_type, self.inputs = load_binding()
        self.inputs += [_base.identity('native/windows-client/source_desktop_metadata.py'),
                        _base.identity('native/windows-client/run_source.py')]
        self.records = None
        self.path = ROOT / 'logs' / (label + '-desktop-metadata.ndjson')
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
                        if len(pending) + len(segment) > 8192:
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
            raise RuntimeError('Start the own Source desktop-metadata helper exactly once')
        if self.path.parent.resolve(strict=True) != ROOT / 'logs':
            raise RuntimeError('The Source desktop-metadata log must stay in the project log directory')
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
                'observer_log': str(self.path.relative_to(ROOT)), 'observer_exit': self.exit,
                'observer_native_pid': self.process.pid if self.process is not None else None,
                'observer_duration_seconds': self.duration, 'reader_thread_stopped': stopped,
                'start_failure': self.start_error, 'reader_failure': self.reader_error,
                'own_lifecycle_failure': self.lifecycle_error,
                'own_observer_terminated_after_source_cleanup': self.own_observer_terminated_after_cleanup,
                'desktop_metadata_summary': summary,
                'targets': [row for row in rows if row['event'] == 'target'],
                'desktop_probes': [row for row in rows if row['event'] == 'desktop_probe'],
                'window_metadata': [row for row in rows if row['event'] == 'window'],
                'observer_metadata': [row for row in rows if row['event'] in ('ready', 'completed')],
                'native_completion_observed': bool(completed),
                'native_completion_succeeded': bool(completed and summary.get('passed')),
                'ready_host_bound_to_actual_helper_popen_pid': bool(stopped and self.records is not None and self.records.ready),
                'only_accepted_numeric_metadata_persisted': True,
                'child_text_or_desktop_names_persisted': False,
                'desktop_switched_or_acl_changed_by_observer': False,
                'borrowed_desktop_handles_closed_by_observer': False,
                'target_process_termination_by_observer': False,
                'target_memory_read': False, 'target_modified': False,
                'actual_error_window_owner_or_cause_established': False}
