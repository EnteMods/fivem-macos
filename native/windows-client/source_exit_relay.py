"""Opt-in exit-only diagnostics for the authorized parity Source-MAIN role."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import threading
from types import ModuleType

ROOT = Path(__file__).resolve().parents[2]
PREFIX = ROOT / 'prefixes/fivem-source-main'
STAGE = ROOT / 'build/windows-source-integration'
ENGINE = ROOT / 'runtime/wine-job-query-parity/engine'
MANIFEST_SHA = 'e4fc3167813864102909da696cf3a03e89bd00a4a9abe26d8478c88316600f9c'
CONTROL = 'research/wine-parity-own-exit-relay-20261102T174128765975Z-results.json'
PINS = {
    CONTROL: (24036, '1e108dd183d4dc363272b92e6715f03123bf80d489c53d30862dd6bde782b4d3'),
    'native/diagnostics/run_own_exit_relay.py':
        (12051, '48c4fa938ac5881cd74da567b3ed1e8e94d949799e296a55445529ac010153ab'),
    'native/diagnostics/exit_relay.py':
        (8466, '02bae2105f9011472092292a7c02c14f2253a628a53f7ddfef58b60260c56fb7'),
}
DEBUG = '-all,+pid,FiveM_ROSLauncher:trace+relay'


def validate_selection(runtime_profile, process_trace=False):
    if runtime_profile != 'parity' or process_trace is not False:
        raise ValueError('Exit relay requires explicit parity and no process-exit-trace')


def read_code(name):
    allowed = {*PINS, 'native/windows-client/source_exit_relay.py', 'native/windows-client/run_source.py'}
    if name not in allowed:
        raise RuntimeError('Unreviewed Source exit diagnostic code role')
    path = ROOT / name
    if path.resolve(strict=True) != path:
        raise RuntimeError('Source exit diagnostic code may not use aliases')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise RuntimeError('Source exit diagnostic code must be regular and single-link')
        return source.read()


def identity(name, raw=None):
    raw = read_code(name) if raw is None else raw
    return {'path': name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def load_helpers():
    data = {}
    for name, (length, digest) in PINS.items():
        raw = read_code(name)
        if len(raw) != length or hashlib.sha256(raw).hexdigest() != digest:
            raise RuntimeError('The actual positive exit-relay control or its exact code changed')
        data[name] = raw
    record = json.loads(data[CONTROL])
    if (record.get('profile') != 'wine-parity-api-probes' or record.get('probe_role') != 'own-exit-relay'
            or record.get('prefix') != 'prefixes/wine-parity-regression' or record.get('passed') is not True
            or record.get('runtime_verification', {}).get('manifest_sha256') != MANIFEST_SHA
            or record.get('cleanup') != [{'flag': '-k', 'exit': 0}, {'flag': '-w', 'exit': 0}]
            or record.get('quarantine_cleared_after_confirmed_cleanup') is not True
            or record.get('own_debug_setting_restored') is not True
            or record.get('exit_relay_stream', {}).get('accepted_records') != 2
            or len(record.get('runs', [])) != 1
            or record['runs'][0].get('diagnostics', {}).get('positive_parent0_and_child17_observed') is not True):
        raise RuntimeError('Require the exact actual own parent0/child17 exit-relay control')
    modules = []
    for name in ('native/diagnostics/run_own_exit_relay.py', 'native/diagnostics/exit_relay.py'):
        module = ModuleType('source_exit_' + Path(name).stem)
        module.__file__ = str(ROOT / name)
        exec(compile(data[name], str(ROOT / name), 'exec'), module.__dict__)
        modules.append(module)
    helper, relay = modules
    if relay.relay_debug('FiveM_ROSLauncher', source_authorized=True) != DEBUG:
        raise RuntimeError('The tested relay provider changed its exact Source selector')
    return helper, relay, [identity(name, raw) for name, raw in data.items()]


class SourceExitRelay:
    def __init__(self, runtime, environment, prefix, stage, duration):
        if type(duration) is not int or not 1 <= duration <= 3600:
            raise ValueError('Source exit observation must be bounded to 1–3600 seconds')
        if (prefix != PREFIX or stage != STAGE or runtime.ENGINE != ENGINE or runtime.WINE != ENGINE / 'bin/wine'
                or getattr(runtime, 'source_runtime_profile', {}).get('profile') != 'parity'
                or environment.get('WINEPREFIX') != str(PREFIX)
                or environment.get('WINESERVER') != str(ENGINE / 'bin/wineserver')
                or environment.get('WINEDEBUG') != DEBUG):
            raise RuntimeError('Only the exact authorized Source prefix and parity runtime may use exit relay')
        self.runtime, self.environment = runtime, dict(environment)
        self.duration = duration
        self.helper, self.relay, self.inputs = load_helpers()
        self.inputs += [identity('native/windows-client/source_exit_relay.py'),
                        identity('native/windows-client/run_source.py')]
        self.prefix_identity = None
        self.query_exit_codes = []
        self.exclude_state = None
        self.change_attempted = False
        self.prepared = False
        self.restored = False
        self.restore_failure = None
        self.pump_summary = None
        self.pump_failure = None
        self.thread = None
        self.thread_started = False
        self.process = None
        self.stop_event = threading.Event()
        self._assert_held_context()

    def _assert_held_context(self):
        import source_main_environment as policy
        held = policy._ACTIVE_MAIN_LOCKS.get(str(PREFIX))
        if (ROOT != policy.ROOT or PREFIX != ROOT / 'prefixes/fivem-source-main'
                or not held or held[0] != os.getpid()):
            raise RuntimeError('Source exit registry operations require the already held MAIN lock')
        os.fstat(held[1])
        if PREFIX.resolve(strict=True) != PREFIX or not PREFIX.is_dir():
            raise RuntimeError('The exact Source prefix must retain its direct directory identity')
        info = PREFIX.stat()
        current = (info.st_dev, info.st_ino)
        if self.prefix_identity is None:
            self.prefix_identity = current
        elif self.prefix_identity != current:
            raise RuntimeError('The Source prefix directory changed during exit observation')

    def verify_sources(self):
        if [identity(item['path']) for item in self.inputs] != self.inputs:
            raise RuntimeError('Source exit diagnostic code/control changed during observation')

    def registry(self, *arguments, capture=False):
        self._assert_held_context()
        allowed = {('query', self.helper.KEY, '/v', 'RelayInclude'),
                   ('query', self.helper.KEY, '/v', 'RelayExclude'),
                   ('add', self.helper.KEY, '/v', 'RelayInclude', '/t', 'REG_SZ',
                    '/d', self.relay.RELAY_INCLUDE, '/f'),
                   ('delete', self.helper.KEY, '/v', 'RelayInclude', '/f')}
        if arguments not in allowed or capture != (arguments[0] == 'query'):
            raise RuntimeError('Only the two fixed Wine Debug filter queries and own Include change are allowed')
        quiet = {key: value for key, value in self.environment.items() if not key.lower().startswith('citizenfx_')}
        quiet['WINEDEBUG'] = '-all'
        return subprocess.run([str(ENGINE / 'bin/wine'), 'reg.exe', *arguments],
                              cwd=STAGE, env=quiet, stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=20)

    def prepare(self):
        self._assert_held_context()
        self.verify_sources()
        for name in ('RelayInclude', 'RelayExclude'):
            value = self.registry('query', self.helper.KEY, '/v', name, capture=True)
            self.query_exit_codes.append({'value': name, 'exit': value.returncode})
            if name == 'RelayInclude':
                if value.returncode != 1:
                    raise RuntimeError('Source exit relay requires an absent RelayInclude setting')
            elif value.returncode == 1:
                self.exclude_state = 'absent'
            elif self.helper.is_default_exclude_query(value):
                self.exclude_state = 'unchanged_exact_wine_default'
            else:
                raise RuntimeError('Source exit relay refuses an unknown RelayExclude setting')
        # An interrupted/failed add may already have changed this one value.
        self.change_attempted = True
        value = self.registry('add', self.helper.KEY, '/v', 'RelayInclude', '/t', 'REG_SZ',
                              '/d', self.relay.RELAY_INCLUDE, '/f')
        if value.returncode != 0:
            raise RuntimeError('The fixed Source exit relay filter could not be configured')
        self.prepared = True

    def restore(self):
        if self.change_attempted and not self.restored and self.restore_failure is None:
            try:
                value = self.registry('delete', self.helper.KEY, '/v', 'RelayInclude', '/f')
                self.restored = value.returncode == 0
                if not self.restored:
                    self.restore_failure = 'RegistryDeleteFailed'
            except BaseException as error:
                self.restore_failure = type(error).__name__

    def start(self, binary_sink):
        if not self.prepared or self.process is not None:
            raise RuntimeError('Source exit relay must be prepared exactly once before Main')
        self._assert_held_context()
        self.verify_sources()
        self.process = subprocess.Popen([str(self.runtime.WINE), str(STAGE / 'FiveM.exe')],
                                        cwd=STAGE, env=self.environment,
                                        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        def drain():
            try:
                self.pump_summary = self.relay.pump(self.process.stderr, binary_sink,
                    stop_event=self.stop_event, timeout_seconds=min(3600, self.duration + 45))
            except BaseException as error:
                self.pump_failure = type(error).__name__
        self.thread = threading.Thread(target=drain, daemon=True)
        try:
            self.thread.start()
        finally:
            self.thread_started = self.thread.ident is not None
        return self.process

    @contextmanager
    def finishing_after_cleanup(self, output):
        try:
            yield
        finally:
            self.stop_event.set()
            if self.thread_started:
                self.thread.join(timeout=2)
            if self.thread is not None and self.thread.is_alive():
                self.pump_failure = 'RelayThreadDidNotStop'
            else:
                if self.process is not None and self.process.stderr is not None:
                    self.process.stderr.close()
                if output is not None:
                    output.close()

    def result(self):
        return {'enabled': True, 'source_selector': 'FiveM_ROSLauncher', 'code_inputs': self.inputs,
                'positive_own_control': CONTROL, 'debug_filter_query_exit_codes': self.query_exit_codes,
                'existing_relay_exclude_state': self.exclude_state, 'existing_relay_exclude_modified': False,
                'relay_include_change_attempted': self.change_attempted,
                'relay_include_restored': self.restored, 'restore_failure': self.restore_failure,
                'stream': self.pump_summary, 'stream_failure': self.pump_failure,
                'stream_thread_stopped': self.thread is None or not self.thread.is_alive(),
                'only_filtered_exit_numeric_records_persisted': True,
                'main_stdout_persisted': False, 'account_registry_or_profile_contents_accessed': False,
                'caller_module_rva_or_ros_cause_established': False,
                'authentication_or_integrity_decisions_modified': False}
