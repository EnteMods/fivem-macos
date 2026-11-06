#!/usr/bin/env python3
"""Positive exit-relay control using only the existing account-free own reader."""
import ast
import hashlib
import json
from pathlib import Path
import subprocess
import threading
import types

ROOT = Path(__file__).resolve().parents[2]
ADAPTER = ROOT / 'native/windows-ipc-read-loop/run.py'
ADAPTER_SHA = '80928e8c333a17416801e145f7f196230daea0432408692e165e3a4e97dc811f'
RELAY = ROOT / 'native/diagnostics/exit_relay.py'
LIFECYCLE = ROOT / 'native/wine-parity-probes/run.py'
LIFECYCLE_SHA = '476315318538c8db93712ba74848d636a5af587492d590a2e33e4b4d3aae6fe7'
KEY = r'HKCU\Software\Wine\Debug'
VALUE = 'RelayInclude'
DEFAULT_RELAY_EXCLUDE = ('ntdll.RtlEnterCriticalSection;ntdll.RtlTryEnterCriticalSection;'
    'ntdll.RtlLeaveCriticalSection;kernel32.48;kernel32.49;kernel32.94;kernel32.95;'
    'kernel32.96;kernel32.97;kernel32.98;kernel32.TlsGetValue;kernel32.TlsSetValue;'
    'kernel32.FlsGetValue;kernel32.FlsSetValue;kernel32.SetLastError')


def is_default_exclude_query(result):
    if result.returncode != 0 or type(result.stdout) is not bytes:
        return False
    try:
        lines = [line for line in result.stdout.decode('utf-8').splitlines() if line.strip()]
    except UnicodeDecodeError:
        return False
    return (len(lines) == 2 and lines[0].strip() == r'HKEY_CURRENT_USER\Software\Wine\Debug'
            and lines[1].lstrip().split(None, 2) == ['RelayExclude', 'REG_SZ', DEFAULT_RELAY_EXCLUDE])


def identity(path, raw=None):
    if path.resolve(strict=True) != path or not path.is_relative_to(ROOT):
        raise RuntimeError('Only direct project code inputs are allowed')
    raw = path.read_bytes() if raw is None else raw
    return {'path': str(path.relative_to(ROOT)), 'bytes': len(raw),
            'sha256': hashlib.sha256(raw).hexdigest()}


def load(path, expected=None):
    raw = path.read_bytes()
    value = identity(path, raw)
    if expected is not None and value['sha256'] != expected:
        raise RuntimeError('Existing own fixture adapter changed')
    module = types.ModuleType('own_exit_' + path.stem)
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module, value


class OwnProcessAdapter:
    def __init__(self, runner, binary, relay):
        self.runner, self.binary, self.relay = runner, binary, relay
        self.prepared = False
        self.restored = False
        self.pump_summary = None
        self.registry_used = False
        self.restore_failure = None
        self.query_exit_codes = []
        self.relay_exclude_state = None

    def __getattr__(self, name):
        return getattr(subprocess, name)

    def registry(self, env, *arguments, capture=False):
        if env.get('WINEPREFIX') != str(self.runner.PREFIX):
            raise RuntimeError('Registry operation belongs only to the selected own prefix')
        self.registry_used = True
        quiet = dict(env, WINEDEBUG='-all')
        return subprocess.run([str(self.runner.runtime.ENGINE / 'bin/wine'), 'reg.exe', *arguments],
            env=quiet, cwd=self.binary.parent,
            stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=20)

    def prepare(self, verified, env):
        # Preserve Wine's existing default exclusion; never overwrite either prior value.
        result = self.registry(env, 'query', KEY, '/v', VALUE, capture=True)
        self.query_exit_codes.append({'value': VALUE, 'exit': result.returncode})
        if result.returncode != 1:
            raise RuntimeError('Require an absent own-prefix RelayInclude setting')
        result = self.registry(env, 'query', KEY, '/v', 'RelayExclude', capture=True)
        self.query_exit_codes.append({'value': 'RelayExclude', 'exit': result.returncode})
        if result.returncode == 1:
            self.relay_exclude_state = 'absent'
        elif is_default_exclude_query(result):
            self.relay_exclude_state = 'unchanged_exact_wine_default'
        else:
            raise RuntimeError('Refusing an unknown own-prefix RelayExclude setting')
        self.prepared = True
        result = self.registry(env, 'add', KEY, '/v', VALUE, '/t', 'REG_SZ',
                               '/d', self.relay.RELAY_INCLUDE, '/f')
        if result.returncode:
            raise RuntimeError('Could not configure the own-prefix exit-only relay filter')
        return {'exit_only_filter_set': True, 'previous_relay_include_absent': True,
                'existing_relay_exclude_state': self.relay_exclude_state,
                'existing_relay_exclude_modified': False,
                'account_or_client_registry_read': False}

    def restore_on_cleanup(self, env):
        # Never prevent the existing lifecycle's server kill/wait on a restoration error.
        if self.prepared and not self.restored:
            try:
                result = self.registry(env, 'delete', KEY, '/v', VALUE, '/f')
                self.restored = result.returncode == 0
                if not self.restored:
                    self.restore_failure = 'RegistryDeleteFailed'
            except BaseException as error:
                self.restore_failure = type(error).__name__
        return self.registry_used

    def run(self, command, **options):
        expected = [str(self.runner.runtime.ENGINE / 'bin/wine'), str(self.binary)]
        if list(command) != expected:
            return subprocess.run(command, **options)
        if (not self.prepared or options.get('cwd') != self.binary.parent
                or options.get('timeout') != 45 or options.get('stderr') is None):
            raise RuntimeError('Only the exact own reader case can use the streaming adapter')
        env = options['env']
        if env['WINEDEBUG'] != self.relay.relay_debug('named_pipe_probe.exe'):
            raise RuntimeError('Unexpected own-image relay debug selector')
        stopped = threading.Event()
        failure = []
        sink = options['stderr'].buffer
        try:
            process = subprocess.Popen(command, cwd=options['cwd'], env=env,
                                       stdout=options['stdout'], stderr=subprocess.PIPE)
        except BaseException:
            self.restore_on_cleanup(env)
            raise

        def drain():
            try:
                self.pump_summary = self.relay.pump(process.stderr, sink,
                    stop_event=stopped, timeout_seconds=45)
            except BaseException as error:
                failure.append(type(error).__name__)

        thread = threading.Thread(target=drain, daemon=True)
        thread.start()
        try:
            try:
                code = process.wait(timeout=45)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
                raise
        finally:
            stopped.set()
            thread.join(timeout=2)
            self.restore_on_cleanup(env)
        if thread.is_alive() or failure or not self.restored:
            raise RuntimeError('Own exit stream or debug-setting restoration failed')
        process.stderr.close()
        sink.flush()
        return subprocess.CompletedProcess(command, code)


def parse_exit_events(lines, code):
    events = [json.loads(line) for line in lines]
    allowed = {'ExitProcess', 'RtlExitUserProcess', 'NtTerminateProcess'}
    fields = {'kind', 'api', 'pid', 'tid', 'status', 'caller_address'}
    valid = all(isinstance(row, dict) and set(row) == fields
                and row['kind'] == 'exit_api_call' and row['api'] in allowed
                and all(type(row[key]) is int for key in ('pid', 'tid', 'status', 'caller_address'))
                and 0 < row['pid'] <= 0xffffffff and 0 < row['tid'] <= 0xffffffff
                and 0 <= row['status'] <= 0xffffffff and 0 < row['caller_address'] <= 0xffffffffffffffff
                for row in events)
    statuses = sorted({row['status'] for row in events}) if valid else []
    parents = {row['pid'] for row in events if row['status'] == 0 and row['api'] != 'NtTerminateProcess'} if valid else set()
    children = {row['pid'] for row in events if row['status'] == 17 and row['api'] != 'NtTerminateProcess'} if valid else set()
    positive = any(parent != child for parent in parents for child in children)
    return {'passed': type(code) is int and code == 0 and valid and positive,
            'events': events if valid else [], 'observed_exit_statuses': statuses,
            'positive_parent0_and_child17_observed': valid and positive,
            'caller_module_or_ros_cause_established': False}


def install_cleanup_extension(runner, bridge):
    original = LIFECYCLE.read_bytes()
    original_identity = identity(LIFECYCLE, original)
    if original_identity['sha256'] != LIFECYCLE_SHA:
        raise RuntimeError('Require the unchanged existing account-free lifecycle')
    tree = ast.parse(original)
    node = next(item for item in tree.body if isinstance(item, ast.FunctionDef) and item.name == 'run_cases')
    source = ast.get_source_segment(original.decode(), node)
    before = '            finally:\n                if runtime_started:'
    after = '            finally:\n                runtime_started = _exit_relay_restore(env) or runtime_started\n                if runtime_started:'
    if source.count(before) != 1:
        raise RuntimeError('Unexpected own lifecycle cleanup anchor')
    rendered = source.replace(before, after)
    if rendered.count(after) != 1 or rendered.replace(after, before) != source:
        raise RuntimeError('The own cleanup extension must be exactly reversible')
    runner.__dict__['_exit_relay_restore'] = bridge.restore_on_cleanup
    exec(compile(rendered, str(LIFECYCLE), 'exec'), runner.__dict__)
    return {'unchanged_original': original_identity, 'exact_cleanup_insertion_count': 1,
            'extension_reversible': True, 'restoration_precedes_existing_server_cleanup': True}


def main():
    adapter, adapter_input = load(ADAPTER, ADAPTER_SHA)
    relay, relay_input = load(RELAY)
    own_input = identity(Path(__file__).resolve())
    fixture = adapter.verify_inputs()
    runner, verified, helper = adapter.select_runner('parity')
    binary = ROOT / adapter.BINARY
    bridge = OwnProcessAdapter(runner, binary, relay)
    runner.subprocess = bridge
    extension = install_cleanup_extension(runner, bridge)
    bound = [own_input, adapter_input, relay_input]

    def inputs():
        if [identity(ROOT / item['path']) for item in bound] != bound:
            raise RuntimeError('Own exit-relay code changed before or during execution')
        value = adapter.verify_inputs()
        if value != fixture:
            raise RuntimeError('The existing reader fixture changed')
        return {**fixture, 'exit_relay_sources': bound}

    def environment(value):
        env = runner.runtime.environment(value)
        env['WINEDEBUG'] = relay.relay_debug('named_pipe_probe.exe')
        return env

    case = adapter.cases(fixture, 'parity')[0]
    case['parse_diagnostics'] = parse_exit_events
    original_save = runner.save_result

    def save(path, result):
        result['exit_relay_stream'] = bridge.pump_summary
        result['own_debug_setting_restored'] = bridge.restored
        result['debug_setting_restore_failure'] = bridge.restore_failure
        result['debug_filter_query_exit_codes'] = bridge.query_exit_codes
        result['existing_relay_exclude_state'] = bridge.relay_exclude_state
        result['relay_include_change_attempted'] = bridge.prepared
        result['own_lifecycle_extension'] = extension
        result['only_filtered_exit_numeric_records_persisted'] = True
        result['passed'] = result['passed'] and bridge.restored and bridge.pump_summary is not None
        original_save(path, result)

    runner.save_result = save
    return runner.run_cases([case], verify_inputs=inputs, role='own-exit-relay',
        environment_factory=environment, prepare_prefix=bridge.prepare)


if __name__ == '__main__':
    raise SystemExit(main())
