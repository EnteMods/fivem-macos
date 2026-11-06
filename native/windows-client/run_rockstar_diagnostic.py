#!/usr/bin/env python3
"""Prepare/inspect a bounded original RGL comparison. Root reviews and starts `run` separately."""
import argparse
import datetime
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from run_main import ROOT, plain, sha
from process_observer_bridge import ProcessObserver, observer_artifact, ROCKSTAR_ROLE_PATHS

sys.path.insert(0, str(ROOT / 'scripts'))
from probe_environment import ProbePrefixError
from rockstar_code_policy import CODE_ROOTS, MANIFEST_NAME
from source_main_environment import (source_main_prefix, assert_source_main_prefix,
                                     _source_main_file_lock)

PREFIX = ROOT / 'prefixes/fivem-source-main'
LAUNCHER_RELATIVE = CODE_ROOTS[0] + '/Launcher.exe'
EXPECTED_CODE_FILES = 142
OBSERVED_FIVEM_ARGUMENTS = ('-skipPatcherCheck', '-fivem')
ARGUMENT_EVIDENCE = 'research/roslauncher-technical-log-review.json'


def observed_argument_provenance():
    path = ROOT / ARGUMENT_EVIDENCE
    plain(path)
    evidence = json.loads(path.read_text())
    matches = [item for log in evidence['startup_metadata'] for item in log['startup_commands']
               if item['local_time'] == '2026-11-01 20:34:41.161'
               and item['executable_basename'] == 'Launcher.exe'
               and item['flag_names_only'] == list(OBSERVED_FIVEM_ARGUMENTS)]
    if len(matches) != 1:
        raise ValueError('Require the exact observed original RGL coordinator arguments')
    return {'path': ARGUMENT_EVIDENCE, 'sha256': sha(path),
            'startup_local_time': matches[0]['local_time'],
            'startup_executable_root_classification': matches[0].get('executable_code_root', 'not_recorded'),
            'argument_names_observed_in_original_fivem_run': True,
            'published_standalone_argument_API_claim': False}


def plan(duration=90, observed_fivem_arguments=False, module_trace=False, observe_code_processes=False):
    if type(observed_fivem_arguments) is not bool:
        raise ValueError('Only the fixed boolean observed-argument variant is allowed')
    if type(module_trace) is not bool:
        raise ValueError('Only the fixed boolean module-trace variant is allowed')
    if type(observe_code_processes) is not bool:
        raise ValueError('Only the fixed boolean code-process observation is allowed')
    maximum = 180 if observed_fivem_arguments else 3600
    if not 1 <= duration <= maximum:
        raise ValueError(f'RGL observation must be between 1 and {maximum} seconds for this variant')
    provenance = observed_argument_provenance() if observed_fivem_arguments else None
    return {'scope': 'Original Rockstar Launcher SC/CEF initialization comparison only',
            'prefix': 'prefixes/fivem-source-main', 'prefix_is_account_free': False,
            'launcher': LAUNCHER_RELATIVE,
            'variant': 'observed_vendor_fivem_arguments' if observed_fivem_arguments else 'standalone_no_arguments',
            'arguments': list(OBSERVED_FIVEM_ARGUMENTS) if observed_fivem_arguments else [],
            'argument_provenance': provenance,
            'comparison_limit': 'No normal FiveM host/shared state/IPC graph is supplied; only original RGL initialization is compared',
            'fivem_legitimacy_callback_success_claim': False, 'observe_seconds': duration,
            'maximum_observe_seconds': maximum, 'expected_bound_code_files': EXPECTED_CODE_FILES,
            'user_library_registration_window': not observed_fivem_arguments and duration > 120,
            'wine_debug': '+loaddll,+seh' if module_trace else '-all,err+all',
            'module_trace': module_trace, 'cleanup_kill_and_wait_under_main_lock': True,
            'observe_code_processes': observe_code_processes,
            'observer_poll_ms': 10 if observe_code_processes else None,
            'observer_duration_seconds': min(duration + 30, 3600) if observe_code_processes else None,
            'agent_login_or_button_actions': False, 'screenshots_by_this_runner': False,
            'UI_success_claim': False, 'root_review_and_go_required_before_execution': True}


def code_identity(observe_code_processes=False):
    # This existing guard verifies the inode/marker binding, exact code inventory/hashes,
    # C: mapping, local Shell Folder bindings and the user's existing login enrollment.
    assert_source_main_prefix(PREFIX, root=ROOT)
    manifest_path = PREFIX / MANIFEST_NAME
    plain(manifest_path)
    manifest = json.loads(manifest_path.read_text())
    if manifest.get('roots') != list(CODE_ROOTS) or len(manifest.get('files', [])) != EXPECTED_CODE_FILES:
        raise ProbePrefixError('Require the exact reviewed 142-file Rockstar code binding')
    launcher = [item for item in manifest['files'] if item['path'] == LAUNCHER_RELATIVE]
    if len(launcher) != 1:
        raise ProbePrefixError('Bound original Launcher.exe is absent or ambiguous')
    if observe_code_processes:
        paths = {item['path'] for item in manifest['files']}
        if any('drive_c/Program Files/Rockstar Games/' + role not in paths for role in ROCKSTAR_ROLE_PATHS):
            raise ProbePrefixError('Require all five original observed roles in the 142-file code binding')
    return {'code_manifest': MANIFEST_NAME, 'code_manifest_sha256': sha(manifest_path),
            'code_files': EXPECTED_CODE_FILES, 'code_roots': list(CODE_ROOTS),
            'launcher': LAUNCHER_RELATIVE, 'launcher_sha256': launcher[0]['sha256']}


def inspect(duration=90, observed_fivem_arguments=False, module_trace=False, observe_code_processes=False):
    result = plan(duration, observed_fivem_arguments, module_trace, observe_code_processes)
    # Reuse the same nonblocking Main lock; do not seed folders or write a new prefix.
    assert_source_main_prefix(PREFIX, root=ROOT)
    with _source_main_file_lock(PREFIX):
        result['code_identity'] = code_identity(observe_code_processes)
        if observe_code_processes:
            result['observer_artifact'] = observer_artifact(rockstar_scope=True)
    result.update(inspection_passed=True, launcher_started=False, runtime_imported=False)
    return result


def load_runtime():
    spec = importlib.util.spec_from_file_location('standalone_rgl_existing_runtime', ROOT.parent / 'GTA-V-macOS/scripts/gta-macos.py')
    runtime = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runtime)
    return runtime


def run(duration=90, observed_fivem_arguments=False, module_trace=False, observe_code_processes=False):
    result = plan(duration, observed_fivem_arguments, module_trace, observe_code_processes)
    label_prefix = 'rockstar-source-observed-fivem-arguments-diagnostic-' if observed_fivem_arguments else 'rockstar-source-diagnostic-'
    label = label_prefix + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    error_log = ROOT / 'logs' / (label + '-wine-errors.log')
    result_path = ROOT / 'research' / (label + '-results.json')
    parent = None
    observer = None
    observer_start_attempted = False
    observer_result = None
    runtime = None
    environment = None
    started = None
    interrupted = False
    guard_failure = False
    failure_type = None
    cleanup = {'performed': False, 'kill_exit': None, 'wait_exit': None, 'wait_timed_out': False}
    parent_exit = None
    try:
        with source_main_prefix(PREFIX, root=ROOT):
            try:
                result['code_identity'] = code_identity(observe_code_processes)
                runtime = load_runtime()
                environment = runtime.environment()
                environment['WINEPREFIX'] = str(PREFIX)
                environment['WINEDEBUG'] = result['wine_debug']
                if any(key.lower().startswith('citizenfx_') for key in environment):
                    raise RuntimeError('Refusing inherited CitizenFX role variables')
                if observe_code_processes:
                    observer_start_attempted = True
                    observer = ProcessObserver(runtime, environment, ROOT / 'build/windows-source-integration', label,
                                               result['observer_duration_seconds'], rockstar_scope=True)
                    observer.wait_ready()
                executable = PREFIX / LAUNCHER_RELATIVE
                # The optional list is fixed from the original coordinator observation, never user-supplied arguments.
                print('Starting bound original Rockstar Launcher in source prefix; variant:', result['variant'], flush=True)
                descriptor = os.open(error_log, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(descriptor, 'w') as errors:
                    started = time.monotonic()
                    parent = subprocess.Popen([str(runtime.WINE), str(executable), *result['arguments']], cwd=executable.parent,
                                              env=environment, stdout=subprocess.DEVNULL, stderr=errors)
                    print('RGL native Wine PID:', parent.pid, '; observation seconds:', duration, flush=True)
                    next_guard = started
                    while time.monotonic() - started < duration:
                        if time.monotonic() >= next_guard:
                            assert_source_main_prefix(PREFIX, root=ROOT)
                            next_guard = time.monotonic() + 2
                        time.sleep(0.2)
                    assert_source_main_prefix(PREFIX, root=ROOT)
            except KeyboardInterrupt:
                interrupted = True
            except BaseException as error:
                guard_failure = isinstance(error, ProbePrefixError)
                failure_type = type(error).__name__
            finally:
                parent_exit = parent.poll() if parent is not None else None
                # No Wine process is started until this invocation has all three values.
                if (parent is not None or observer_start_attempted) and runtime is not None and environment is not None:
                    killed = subprocess.run([str(runtime.ENGINE / 'bin/wineserver'), '-k'], env=environment,
                                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    cleanup.update(performed=True, kill_exit=killed.returncode)
                    try:
                        waited = subprocess.run([str(runtime.ENGINE / 'bin/wineserver'), '-w'], env=environment,
                                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
                        cleanup['wait_exit'] = waited.returncode
                        if waited.returncode != 0:
                            failure_type = failure_type or 'WineServerWaitFailed'
                    except subprocess.TimeoutExpired:
                        cleanup['wait_timed_out'] = True
                    if parent is not None:
                        try:
                            parent.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            failure_type = failure_type or 'OwnWineParentWaitTimeout'
                    if observer is not None:
                        observer_result = observer.finish_after_wineserver_cleanup()
                        if not observer_result['reader_completed_without_error']:
                            failure_type = failure_type or 'ObserverMetadataReaderFailed'
    except BaseException as error:
        guard_failure = guard_failure or isinstance(error, ProbePrefixError)
        failure_type = failure_type or type(error).__name__
    result.update(at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  native_wine_pid=parent.pid if parent is not None else None,
                  elapsed_seconds=round(time.monotonic() - started, 2) if started is not None else 0,
                  native_wine_parent_exit_before_cleanup=parent_exit,
                  parent_exit_is_not_full_windows_child_or_UI_success=True,
                  operator_interrupted=interrupted, guard_failure=guard_failure, failure_type=failure_type,
                  cleanup=cleanup, launcher_started=parent is not None,
                  read_only_code_process_observer=observer_result,
                  error_log=str(error_log.relative_to(ROOT)) if parent is not None else None,
                  private_log_contents_read_hashed_or_copied=False,
                  no_additional_profile_ticket_cookie_or_browser_store_readers=True,
                  existing_guard_shell_folder_and_artifact_metadata_checked=True,
                  original_prefix_accessed_by_this_runner=False,
                  screenshot_taken=False, launcher_UI_status='unknown_requires_Root_current_PID_window_inspection',
                  account_authentication_success_claim=False,
                  agent_started_fivem_or_game=False, fivem_or_game_started=None,
                  child_startup_outcome_is_not_inferred_from_rgl_parent=True)
    result_path.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return 130 if interrupted else 1 if failure_type or cleanup['wait_timed_out'] else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'inspect', 'run'))
    parser.add_argument('--observe-seconds', type=int, default=90)
    parser.add_argument('--observed-fivem-arguments', action='store_true',
                        help='Only the fixed original -skipPatcherCheck/-fivem argument pair; no FiveM host is started')
    parser.add_argument('--module-trace', action='store_true',
                        help='Only child WINEDEBUG=+loaddll,+seh; raw output stays in the private log')
    parser.add_argument('--observe-code-processes', action='store_true',
                        help='Read-only fixed code-root process observer at 10ms; six metadata fields only')
    args = parser.parse_args()
    try:
        plan(args.observe_seconds, args.observed_fivem_arguments, args.module_trace, args.observe_code_processes)
    except ValueError as error:
        parser.error(str(error))
    if args.action == 'run':
        return run(args.observe_seconds, args.observed_fivem_arguments, args.module_trace, args.observe_code_processes)
    print(json.dumps(inspect(args.observe_seconds, args.observed_fivem_arguments, args.module_trace, args.observe_code_processes) if args.action == 'inspect'
                     else plan(args.observe_seconds, args.observed_fivem_arguments, args.module_trace, args.observe_code_processes), indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
