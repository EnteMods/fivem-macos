"""Opt-in Source Error-dialog text capture through the tested read-only helper."""
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
OBSERVER = 'build/windows-text-observer/text_observer.exe'
ADAPTER = 'native/windows-text-observer/run.py'
CONTRACT = 'native/windows-text-observer/contract.py'
BUILD = 'research/windows-text-observer-build.json'
BASE = 'native/windows-client/source_code_observer.py'
EXIT_BASE = 'native/windows-client/source_exit_relay.py'
CONTROL = 'research/wine-parity-text-observer-20261102T193920797338Z-results.json'
MANIFEST_SHA = 'e4fc3167813864102909da696cf3a03e89bd00a4a9abe26d8478c88316600f9c'
PINS = {
    BASE: (13045, '1ccf9f8e1cad43d3100153a01f713689512f9fc85269527d722c890945ef82ec'),
    EXIT_BASE: (12025, '58c09882d3db67bb46bd66751c3807333ac20d4c17e2d9d538d697b7ea955875'),
    CONTROL: (17062, '6df59a8b8372d785968b15da7c8afab1316c8f05c485e78cb45c80a79795a14f'),
    ADAPTER: (7380, '5f2b466a97c61f14da01c117e632cb6ceac4f0f28a5e2dfbd86cc4cd03834f39'),
    CONTRACT: (8157, '24c2dce483cbcc35efe355c3464b49d8f9b17777cea334ee81038d2093c5c3f7'),
    BUILD: (14976, 'fb1995301eebfc6974759ef6c625a99a15a5437d19952ebca224fbfc6be88540'),
}


def _bound(name):
    if name not in PINS:
        raise RuntimeError('Unknown fixed Source-text provider role')
    path = ROOT / name
    if path.resolve(strict=True) != path:
        raise RuntimeError('Source-text provider code/evidence may not use aliases')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise RuntimeError('Source-text provider inputs must be regular and single-link')
        raw = source.read()
    if (len(raw), hashlib.sha256(raw).hexdigest()) != PINS[name]:
        raise RuntimeError('The fixed Source-text provider code or actual own control changed')
    return raw


def _execute(name, raw):
    module = ModuleType('source_text_' + Path(name).stem)
    module.__file__ = str(ROOT / name)
    exec(compile(raw, str(ROOT / name), 'exec'), module.__dict__)
    return module


# Inherit unchanged guard/accept/readiness/cleanup methods, without changing their module or globals.
_base = _execute(BASE, _bound(BASE))


def validate_selection(runtime_profile, exit_relay):
    if runtime_profile != 'parity' or exit_relay is not True:
        raise ValueError('ROS Error-text observation requires explicit parity together with exit-relay')


def load_binding():
    data = {name: _bound(name) for name in PINS}
    record = json.loads(data[CONTROL])
    runs = record.get('runs', [])
    if (record.get('profile') != 'wine-parity-api-probes' or record.get('probe_role') != 'text-observer'
            or record.get('passed') is not True or record.get('prefix') != 'prefixes/wine-parity-regression'
            or record.get('runtime_verification', {}).get('manifest_sha256') != MANIFEST_SHA
            or record.get('cleanup') != [{'flag': '-k', 'exit': 0}, {'flag': '-w', 'exit': 0}]
            or record.get('quarantine_cleared_after_confirmed_cleanup') is not True
            or record.get('only_own_fixtures_and_builtin_initialization') is not True
            or record.get('client_cef_rockstar_game_or_account_code_started') is not False
            or [(row.get('name'), row.get('exit'), row.get('passed')) for row in runs]
                != [('text_fixture', 0, True), ('outside_root', 2, True)]
            or runs[0].get('matched_texts') != 2
            or runs[0].get('observer', {}).get('completed') is not True
            or runs[0].get('observer', {}).get('passed') is not True
            or runs[0].get('observer', {}).get('rejected') != 0
            or runs[0].get('observer', {}).get('text_records') != 2):
        raise RuntimeError('Require the exact actual positive/negative own text-observer control')
    adapter = _execute(ADAPTER, data[ADAPTER])
    fixture = adapter.verify_inputs()
    if any(record.get('fixture_inputs', {}).get(key) != value for key, value in fixture.items()):
        raise RuntimeError('The actual own control selected different text-observer inputs')
    parser = _execute(CONTRACT, data[CONTRACT])
    identities = [*(_base.identity(name, raw) for name, raw in data.items()),
                  *fixture['build_reports'], *fixture['runtime_inputs'], *fixture['source_inputs']]
    unique = {}
    for item in identities:
        if item['path'] in unique and unique[item['path']] != item:
            raise RuntimeError('Conflicting Source-text provider identities')
        unique[item['path']] = item
    return parser.TextRecords, list(unique.values())


class SourceTextObserver(_base.SourceCodeObserver):
    def __init__(self, runtime, environment, stage, label, duration, exit_context):
        if (stage != STAGE or runtime.ENGINE != ENGINE or runtime.WINE != ENGINE / 'bin/wine'
                or getattr(runtime, 'source_runtime_profile', {}).get('profile') != 'parity'
                or environment.get('WINEPREFIX') != str(PREFIX)
                or environment.get('WINESERVER') != str(ENGINE / 'bin/wineserver')
                or exit_context.runtime is not runtime or exit_context.environment != environment
                or exit_context.prepared is not True):
            raise RuntimeError('ROS text observer requires the exact prepared parity Source exit context')
        if (type(duration) is not int or not 1 <= duration <= 3600 or type(label) is not str
                or re.fullmatch(r'client-source-ui(?:-resume)?-\d{8}T\d{12}Z', label) is None):
            raise ValueError('Require the bounded existing Source controller duration/label')
        self.context = exit_context
        self.context._assert_held_context()
        self.runtime, self.environment = runtime, dict(environment)
        self.label, self.duration = label, min(duration, 600)
        parser, self.inputs = load_binding()
        self.inputs += [_base.identity('native/windows-client/source_text_observer.py'),
                        _base.identity('native/windows-client/run_source.py')]
        self.records = parser('source')
        self.path = ROOT / 'logs' / (label + '-ros-text.ndjson')
        self.output = self.process = self.thread = None
        self.thread_started = False
        self.reader_error = self.start_error = self.lifecycle_error = None
        self.ready, self.stop = threading.Event(), threading.Event()
        self.exit = None
        self.own_observer_terminated_after_cleanup = False
        self.finished = False

    def _drain(self):
        # Same bounded byte-framing lifecycle as the pinned base, with the text protocol's 8192-byte cap.
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
            raise RuntimeError('Start the own text observer exactly once')
        if self.path.parent.resolve(strict=True) != ROOT / 'logs':
            raise RuntimeError('The own Source text log must stay in the project log directory')
        self.output = os.fdopen(os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'w')
        env = {key: value for key, value in self.environment.items() if not key.lower().startswith('citizenfx_')}
        env['WINEDEBUG'] = '-all'
        command = [str(self.runtime.WINE), str(ROOT / OBSERVER), '--source-root',
                   'Z:' + str(STAGE).replace('/', '\\'), '--duration-ms', str(self.duration * 1000)]
        try:
            self.process = subprocess.Popen(command, cwd=STAGE, env=env,
                                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
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
        rows = self.records.events if stopped else []
        summary = self.records.summary() if stopped else {'capture_incomplete': True}
        return {'enabled': True, 'code_inputs': self.inputs, 'positive_own_control': CONTROL,
                'observer_log': str(self.path.relative_to(ROOT)), 'observer_exit': self.exit,
                'observer_duration_seconds': self.duration, 'reader_thread_stopped': stopped,
                'start_failure': self.start_error, 'reader_failure': self.reader_error,
                'own_lifecycle_failure': self.lifecycle_error,
                'own_observer_terminated_after_source_cleanup': self.own_observer_terminated_after_cleanup,
                'text_records_summary': summary,
                'text_records': [row for row in rows if row['event'] == 'error_text'],
                'metadata_events': [row for row in rows if row['event'] != 'error_text'],
                'native_completion_observed': stopped and self.records.complete,
                'native_completion_succeeded': stopped and bool(summary.get('passed')),
                'only_text_records_accepted_before_persistence': True,
                'target_process_termination_by_observer': False,
                'target_memory_read': False, 'target_modified': False,
                'account_profile_ticket_or_browser_files_requested': False,
                'ui_text_is_error_cause_claim': False}
