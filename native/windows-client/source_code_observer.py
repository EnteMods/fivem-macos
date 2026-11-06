"""Source-only launch/lifetime bridge for the separately tested executable-code observer."""
from contextlib import contextmanager
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
OBSERVER = 'build/windows-code-observer/code_observer.exe'
ADAPTER = 'native/windows-code-observer/run.py'
PARSER = 'native/windows-client/code_observer_bridge.py'
CONTROL = 'research/wine-parity-code-observer-20261102T184628339709Z-results.json'
MANIFEST_SHA = 'e4fc3167813864102909da696cf3a03e89bd00a4a9abe26d8478c88316600f9c'
PINS = {
    CONTROL: (17592, '31254b7bcda8d3759b3400c2372cae511cccf33fe541d57f183074425d68d877'),
    ADAPTER: (10880, '3bdd0b685ecc9ce86f9374dad1b958c97a1c606e6e5d34730d28ffcac40b6ff1'),
    PARSER: (6531, '4bef480b3b5931d18428c9e9cf2224c6fb8e3c7598433cfde61f48f79ea133d4'),
}


def validate_selection(runtime_profile, exit_relay):
    if runtime_profile != 'parity' or exit_relay is not True:
        raise ValueError('ROS code observation requires explicit parity together with exit-relay')


def read(name):
    if (type(name) is not str or name.startswith('/') or '..' in Path(name).parts
            or Path(name).as_posix() != name):
        raise RuntimeError('Require an exact project-relative observer code role')
    path = ROOT / name
    if path.resolve(strict=True) != path:
        raise RuntimeError('Observer code/control identities may not use aliases')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise RuntimeError('Observer code/control inputs must be regular and single-link')
        return source.read()


def identity(name, raw=None):
    raw = read(name) if raw is None else raw
    return {'path': name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def execute(name, raw):
    module = ModuleType('source_observer_' + Path(name).stem)
    module.__file__ = str(ROOT / name)
    exec(compile(raw, str(ROOT / name), 'exec'), module.__dict__)
    return module


def load_binding():
    data = {}
    for name, (length, digest) in PINS.items():
        raw = read(name)
        if len(raw) != length or hashlib.sha256(raw).hexdigest() != digest:
            raise RuntimeError('The actual observer control or its fixed provider changed')
        data[name] = raw
    record = json.loads(data[CONTROL])
    if (record.get('profile') != 'wine-parity-api-probes' or record.get('probe_role') != 'code-observer'
            or record.get('passed') is not True or record.get('prefix') != 'prefixes/wine-parity-regression'
            or record.get('runtime_verification', {}).get('manifest_sha256') != MANIFEST_SHA
            or record.get('cleanup') != [{'flag': '-k', 'exit': 0}, {'flag': '-w', 'exit': 0}]
            or record.get('quarantine_cleared_after_confirmed_cleanup') is not True
            or record.get('only_own_fixtures_and_builtin_initialization') is not True
            or record.get('client_cef_rockstar_game_or_account_code_started') is not False
            or [(row.get('name'), row.get('exit'), row.get('passed')) for row in record.get('runs', [])]
                != [('code_fixture', 0, True), ('outside_root', 2, True)]):
        raise RuntimeError('Require the exact successful own executable/NX/outside-root observer control')
    adapter = execute(ADAPTER, data[ADAPTER])
    fixture = adapter.verify_inputs()  # This unchanged verifier admits every build role before selected reads.
    if (fixture['runtime_inputs'] != record['fixture_inputs']['runtime_inputs']
            or fixture['build_reports'] != record['fixture_inputs']['build_reports']):
        raise RuntimeError('The actual own control selected other observer code/build inputs')
    parser = execute(PARSER, data[PARSER])
    inputs = [*(identity(name, raw) for name, raw in data.items()),
              *fixture['build_reports'], *fixture['runtime_inputs'], *fixture['source_inputs']]
    return parser.SourceCodeRecords, inputs


class SourceCodeObserver:
    def __init__(self, runtime, environment, stage, label, duration, exit_context):
        if (stage != STAGE or runtime.ENGINE != ENGINE or runtime.WINE != ENGINE / 'bin/wine'
                or getattr(runtime, 'source_runtime_profile', {}).get('profile') != 'parity'
                or environment.get('WINEPREFIX') != str(PREFIX)
                or environment.get('WINESERVER') != str(ENGINE / 'bin/wineserver')
                or exit_context.runtime is not runtime or exit_context.environment != environment
                or exit_context.prepared is not True):
            raise RuntimeError('ROS code observer requires the exact prepared parity Source exit context')
        if (type(duration) is not int or not 1 <= duration <= 3600 or type(label) is not str
                or re.fullmatch(r'client-source-ui(?:-resume)?-\d{8}T\d{12}Z', label) is None):
            raise ValueError('Require the bounded existing Source controller duration/label')
        self.context = exit_context
        self.context._assert_held_context()
        self.runtime, self.environment = runtime, dict(environment)
        self.label, self.duration = label, min(duration, 600)
        parser, self.inputs = load_binding()
        self.inputs += [identity('native/windows-client/source_code_observer.py'),
                        identity('native/windows-client/run_source.py')]
        self.records = parser()
        self.path = ROOT / 'logs' / (label + '-ros-code.ndjson')
        self.output = None
        self.process = None
        self.thread = None
        self.thread_started = False
        self.reader_error = None
        self.start_error = None
        self.lifecycle_error = None
        self.ready = threading.Event()
        self.stop = threading.Event()
        self.exit = None
        self.own_observer_terminated_after_cleanup = False
        self.finished = False

    def verify_sources(self):
        self.context._assert_held_context()
        self.context.verify_sources()
        if [identity(row['path']) for row in self.inputs] != self.inputs:
            raise RuntimeError('Bound observer code/control inputs changed during the Source observation')

    def _accept(self, raw):
        try:
            line = raw.decode('utf-8')
        except UnicodeDecodeError:
            line = ''
        row = self.records.accept(line)
        if row is not None:
            self.output.write(json.dumps(row, separators=(',', ':')) + '\n')
            self.output.flush()
            if self.records.ready:
                self.ready.set()

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
                        if len(pending) + len(segment) > 2048:
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
            raise RuntimeError('Start the own code observer exactly once')
        if self.path.parent.resolve(strict=True) != ROOT / 'logs':
            raise RuntimeError('The own Source code log must stay in the project log directory')
        self.output = os.fdopen(os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'w')
        env = {key: value for key, value in self.environment.items() if not key.lower().startswith('citizenfx_')}
        env['WINEDEBUG'] = '-all'
        windows_stage = 'Z:' + str(STAGE).replace('/', '\\')
        command = [str(self.runtime.WINE), str(ROOT / OBSERVER), '--source-root', windows_stage,
                   '--duration-ms', str(self.duration * 1000)]
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

    def wait_ready(self):
        if not self.ready.wait(30) or self.reader_error is not None or self.process.poll() is not None:
            raise RuntimeError('The own executable-code observer did not signal ready before Main')

    def finish_after_wineserver_cleanup(self):
        if self.finished:
            return
        try:
            if self.process is not None:
                try:
                    self.exit = self.process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self.own_observer_terminated_after_cleanup = True
                    self.process.terminate()  # Only this bridge's own native helper process.
                    self.exit = self.process.wait(timeout=5)
        except BaseException as error:
            self.lifecycle_error = type(error).__name__
        finally:
            self.stop.set()
            if self.thread_started:
                self.thread.join(timeout=2)
            if self.thread is not None and self.thread.is_alive():
                self.reader_error = 'ReaderThreadDidNotStop'
            else:
                if self.process is not None and self.process.stdout is not None:
                    self.process.stdout.close()
                if self.output is not None:
                    self.output.close()
            try:
                self.verify_sources()
            except BaseException as error:
                self.lifecycle_error = type(error).__name__
            self.finished = True

    @contextmanager
    def finishing_after_cleanup(self):
        try:
            yield
        finally:
            self.finish_after_wineserver_cleanup()

    def result(self):
        stopped = self.thread is None or not self.thread.is_alive()
        rows = self.records.events if stopped else []
        return {'enabled': True, 'code_inputs': self.inputs, 'positive_own_control': CONTROL,
                'observer_log': str(self.path.relative_to(ROOT)), 'observer_exit': self.exit,
                'observer_duration_seconds': self.duration, 'reader_thread_stopped': stopped,
                'start_failure': self.start_error, 'reader_failure': self.reader_error,
                'own_lifecycle_failure': self.lifecycle_error,
                'own_observer_terminated_after_source_cleanup': self.own_observer_terminated_after_cleanup,
                'parser_summary': self.records.summary() if stopped else {'capture_incomplete': True},
                'metadata_events': [row for row in rows if row['event'] != 'code'],
                'code_frames': [row for row in rows if row['event'] == 'code'],
                'only_accepted_numeric_and_64_executable_code_records_persisted': True,
                'target_process_termination_by_observer': False,
                'account_or_nonexecutable_data_contents_requested': False,
                'actual_ros_exit_caller_or_cause_claim': False}
