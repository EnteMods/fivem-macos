#!/usr/bin/env python3
"""Observe the explicit upstream source-developer client, limited to its launcher UI."""
import argparse
from contextlib import nullcontext
import datetime
import importlib.util
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import time

from run_main import ROOT, REVISION, plain, sha
from source_code_identity import validate_code_inputs, code_only_snapshot
from process_observer_bridge import ProcessObserver

STAGE = ROOT / "build/windows-source-integration"
PREFIX = ROOT / "prefixes/fivem-source-main"
MANIFEST = ROOT / "research/client-source-code-inputs-v12.json"
INITIAL_MANIFEST = ROOT / "research/client-source-integration-stage.json"
USER_LOGIN = ROOT / "research/manual-user-login.json"
PREFLIGHT = ROOT / "research/windows-viability-results.json"
GAME_ROOT = ROOT / "build/game-library/gta-v-legacy"
VIABILITY_SOURCE_SHA256 = "876b6df8b471f71e2ebf4318ec122ded60372347541525378545b0629b023c45"
sys.path.insert(0, str(ROOT / "scripts"))


def window_trace_support(runtime_profile, exit_relay=False, *, window_class=False):
    if runtime_profile != 'parity' or exit_relay:
        raise ValueError('Numeric window tracing requires parity without exit-relay')
    if window_class:
        role = 'window-class'
        control_label = 'wine-parity-window-class-20261104T180810511219Z'
        control_pin = (9754, '3389123ff691c276e54c6f5e10f954d73abf971b267c01bdc33fde17c12b26f4')
        parser_pin = ('window_class_trace.py', 6936, 'e70a70bb90628e0b4a3a6f4d01e2f8bff7be4002cba7fd937647d5446ffd7bb2')
    else:
        role = 'dxgi-windowtrace-control'
        control_label = 'wine-parity-dxgi-windowtrace-control-20261103T163426905785Z'
        control_pin = (29250, '4161b9ac505721816521be31eef1f55e733e7e6576190c5c06cb0099958e3dd5')
        parser_pin = ('window_creation_trace.py', 5070, 'bc3aa7429bae139d7ea5634da301b1a2d6a231fd2971491a33b2ef8321259e76')
    control = ROOT / 'research' / (control_label + '-results.json')
    providers = (parser_pin,
                 ('window_creation_stream.py', 6292, 'b797ad8b6963742fbc82099d71826e2360a79b259d9b74a5bff7e70cce21c66b'))
    inputs = []
    for name, length, digest in providers:
        path = ROOT / 'native/windows-client' / name
        plain(path)
        if path.stat().st_size != length or sha(path) != digest:
            raise RuntimeError('A reviewed numeric window-trace provider changed')
        inputs.append({'path': str(path.relative_to(ROOT)), 'bytes': length, 'sha256': digest})
    plain(control)
    digest = sha(control)
    if (control.stat().st_size, digest) != control_pin:
        raise RuntimeError('The actual own-window trace control changed')
    proof = json.loads(control.read_text())
    if (proof.get('probe_role') != role or proof.get('passed') is not True
            or proof.get('cleanup') != [{'flag': '-k', 'exit': 0}, {'flag': '-w', 'exit': 0}]
            or proof.get('client_cef_rockstar_game_or_account_code_started') is not False):
        raise RuntimeError('Require the completed account-free numeric own-window control')
    if window_class:
        from window_class_trace import Collector
    else:
        from window_creation_trace import Collector
    from window_creation_stream import WindowCreationStream
    return Collector, WindowCreationStream, {
        'code_inputs': inputs, 'actual_own_control': {'path': str(control.relative_to(ROOT)),
            'bytes': control.stat().st_size, 'sha256': digest},
        'wine_debug_additions': ['win', 'pid', 'class'] if window_class else ['win', 'pid'],
        'relay_or_registry_changes': False,
        'window_payload_filtered_before_persistence': True,
        'missing_created_event_proves_null': False,
    }


def game_mapping(check_executable_hashes=False):
    evidence = json.loads((ROOT / "research/game-library-clone.json").read_text())
    if evidence["target"] != str(GAME_ROOT.relative_to(ROOT)) or evidence["prefix"] != str(PREFIX.relative_to(ROOT)):
        raise RuntimeError("Unexpected user game-library mapping evidence")
    plain(GAME_ROOT)
    mapping = PREFIX / "dosdevices/g:"
    if not mapping.is_symlink() or mapping.resolve(strict=True) != GAME_ROOT.resolve(strict=True):
        raise RuntimeError("G: must retain the reviewed game-only CoW library mapping")
    if check_executable_hashes:
        for name, expected in evidence["executable_sha256"].items():
            path = GAME_ROOT / name
            plain(path)
            if sha(path) != expected:
                raise RuntimeError("Game library executable differs from the legal CoW-clone evidence: " + name)


def check_inputs(require_preflight, resume=False):
    # Validate only the declared immutable code/assets. Mutable user state stays opaque.
    record = validate_code_inputs(MANIFEST)
    game_mapping(check_executable_hashes=True)
    if require_preflight:
        preflight = json.loads(PREFLIGHT.read_text())
        if (not preflight.get("passed") or preflight.get("process_exit") != 0
                or preflight.get("original_verify_result") is not True
                or preflight.get("original_results", {}).get("verify") is not True
                or preflight.get("source_sha256") != VIABILITY_SOURCE_SHA256
                or "ORIGINAL_VERIFY_RESULT=1" not in preflight.get("original_diagnostic_lines", [])):
            raise RuntimeError("Require exact original VerifyViability return/exit/source/diagnostic evidence")
        if sha(ROOT / "port/fivem/code/client/launcher/ViabilityChecks.cpp") != VIABILITY_SOURCE_SHA256:
            raise RuntimeError("Original ViabilityChecks source differs from the pinned tested source")
    if not USER_LOGIN.is_file():
        raise RuntimeError("The Root-recorded manual-user-login controller context is required")
    return record


def process_exit_metadata(log):
    # Never return command lines or arbitrary process trace payloads.
    events = []
    functions = {"NtTerminateProcess", "RtlExitUserProcess", "ExitProcess", "ExitThread", "RtlExitUserThread"}
    if not log.is_file():
        return events
    pattern = re.compile(r"^(?:[0-9a-fA-F]+:)?([0-9a-fA-F]+):trace:process:([A-Za-z0-9_]+)\s+(.*)$")
    with log.open(errors="replace") as source:
        for line in source:
            match = pattern.match(line)
            if not match or match.group(2) not in functions:
                continue
            payload = match.group(3).strip()
            # These APIs print only numeric handle/exit fields; reject any other shape.
            if not re.fullmatch(r"[()0-9a-fA-FxX,; :=+\-]+", payload):
                continue
            events.append({"wine_thread_hex": match.group(1), "function": match.group(2),
                           "numeric_fields": re.findall(r"(?:0x)?[0-9a-fA-F]+", payload)})
    return events


def diagnostic_winedebug(version, process_trace=False):
    return "+loaddll,+seh" + (",+debugstr" if version in (5, 6, 7, 8, 9, 10, 11, 12) else "") + (",+process" if process_trace else "")


def mapping_metadata(log):
    # Accept only our complete fixed payload through the two normal Wine diagnostic channels.
    from mapping_diagnostic_identity import PHASES
    pattern = re.compile(
        r'^(?:[0-9a-fA-F]+:){1,2}warn:(?:debugstr:OutputDebugStringA|seh:dispatch_exception) '
        r'"\[CFX_MAPPING\] pid=([0-9]+) phase=([a-z.]+) provider_set=([01]) '
        r'provider_called=([01]) return_changed=([01])\\n"\s*$')
    events = []
    if log.is_file():
        with log.open(errors="replace") as source:
            for line in source:
                match = pattern.fullmatch(line)
                if match and match[2] in PHASES:
                    events.append({"pid": int(match[1]), "phase": match[2], "provider_set": int(match[3]),
                                   "provider_called": int(match[4]), "return_changed": int(match[5])})
    return events


def hook_metadata(log):
    from hook_diagnostic_identity import PHASES
    pattern = re.compile(
        r'^(?:[0-9a-fA-F]+:){1,2}warn:(?:debugstr:OutputDebugStringA|seh:dispatch_exception) '
        r'"\[CFX_MAPPING_HOOK\] pid=([0-9]+) phase=([A-Za-z0-9_.]+) status=(-1|[0-9]|1[012])\\n"\s*$')
    events = []
    if log.is_file():
        with log.open(errors="replace") as source:
            for line in source:
                match = pattern.fullmatch(line)
                if match and match[2] in PHASES:
                    events.append({"pid": int(match[1]), "phase": match[2], "status": int(match[3])})
    return events


def file_policy_metadata(log):
    pattern = re.compile(
        r'^(?:[0-9a-fA-F]+:){1,2}warn:(?:debugstr:OutputDebugStringA|seh:dispatch_exception) '
        r'"\[CFX_MAPPING_FILE\] pid=([0-9]+) operation=(create|open) allowed=([01]) '
        r'canonical_fragment=([01]) folded_fragment=([01]) nt_prefix=([01])\\n"\s*$')
    events = []
    if log.is_file():
        with log.open(errors="replace") as source:
            for line in source:
                match = pattern.fullmatch(line)
                if match:
                    events.append({"pid": int(match[1]), "operation": match[2], "allowed": int(match[3]),
                                   "canonical_fragment": int(match[4]), "folded_fragment": int(match[5]),
                                   "nt_prefix": int(match[6])})
    return events


def toolmode_diagnostic_report(log, enabled=True):
    from toolmode_diagnostic_identity import PHASES
    report = {"enabled": enabled, "scanned": False, "marker_lines": 0, "accepted_events": 0,
              "rejected_marker_lines": 0, "channels": {"debugstr": 0, "seh": 0}, "events": []}
    if not enabled or not log.is_file():
        return report
    pattern = re.compile(
        r'^(?:[0-9a-fA-F]+:){1,2}warn:(debugstr:OutputDebugStringA|seh:dispatch_exception) '
        r'"\[CFX_TOOLMODE\] pid=([0-9]+) phase=([a-z.-]+) value=([01])\\n"\s*$')
    report["scanned"] = True
    with log.open(errors="replace") as source:
        for line in source:
            if "[CFX_TOOLMODE]" not in line:
                continue
            report["marker_lines"] += 1
            match = pattern.fullmatch(line)
            if not match or match[3] not in PHASES or not 1 <= int(match[2]) <= 0xffffffff:
                report["rejected_marker_lines"] += 1
                continue
            channel = "debugstr" if match[1].startswith("debugstr:") else "seh"
            report["channels"][channel] += 1
            report["events"].append({"pid": int(match[2]), "phase": match[3], "value": int(match[4])})
    report["accepted_events"] = len(report["events"])
    return report


def toolmode_metadata(log):
    return toolmode_diagnostic_report(log)["events"]


def lifecycle_diagnostic_report(log, enabled=True):
    report = {"enabled": enabled, "scanned": False, "marker_lines": 0, "accepted_events": 0,
              "rejected_marker_lines": 0, "channels": {"debugstr": 0, "seh": 0}, "events": []}
    if not enabled or not log.is_file():
        return report
    pattern = re.compile(
        r'^(?:[0-9a-fA-F]+:){1,2}warn:(debugstr:OutputDebugStringA|seh:dispatch_exception) '
        r'"\[CFX_CORE_MH\] pid=([0-9]{1,10}) tid=([0-9]{1,10}) phase=([1-4]) '
        r'status_valid=([01]) status=(-1|[0-9]|1[012])\\n"\s*$')
    report["scanned"] = True
    with log.open(errors="replace") as source:
        for line in source:
            if "[CFX_CORE_MH]" not in line:
                continue
            report["marker_lines"] += 1
            match = pattern.fullmatch(line)
            if not match:
                report["rejected_marker_lines"] += 1
                continue
            pid, tid, phase, status_valid, status = map(int, match.group(2, 3, 4, 5, 6))
            if (not 1 <= pid <= 0xffffffff or not 1 <= tid <= 0xffffffff
                    or (phase in (1, 3) and (status_valid != 0 or status != -1))
                    or (phase in (2, 4) and status_valid != 1)):
                report["rejected_marker_lines"] += 1
                continue
            channel = "debugstr" if match[1].startswith("debugstr:") else "seh"
            report["channels"][channel] += 1
            report["events"].append({"pid": pid, "tid": tid, "phase": phase,
                                     "status_valid": status_valid, "status": status})
    report["accepted_events"] = len(report["events"])
    return report


def graphics_diagnostic_report(log, enabled=False):
    report = {"enabled": enabled, "events": [], "accepted": 0, "rejected": 0,
              "capped": False, "capture_error_type": None,
              "calls_paired": False, "exception_cause_established": False,
              "functional_success_established": False}
    if enabled:
        try:
            from graphics_swapchain_metadata import parse_log
            report.update(parse_log(log))
        except (ImportError, SyntaxError, OSError, ValueError) as error:
            report["capture_error_type"] = type(error).__name__
    return report


def graphics_window_diagnostic_report(log, enabled=False):
    report = {"enabled": enabled, "events": [], "accepted": 0, "rejected": 0,
              "capped": False, "capture_error_type": None,
              "calls_paired": False, "exception_cause_established": False,
              "functional_success_established": False, "top_level_windows_only": True}
    if enabled:
        try:
            from graphics_window_metadata import parse_log
            report.update(parse_log(log))
        except (ImportError, SyntaxError, OSError, ValueError) as error:
            report["capture_error_type"] = type(error).__name__
    return report


def observer_configuration(duration, rockstar_scope=False):
    if type(duration) is not int or not 1 <= duration <= 3600:
        raise ValueError("Controller duration must be between 1 and 3600 seconds")
    if type(rockstar_scope) is not bool:
        raise ValueError("Only the fixed boolean Rockstar code observer scope is allowed")
    return {"controller_duration_seconds": duration,
            "observer_requested_duration_seconds": min(duration, 600) if rockstar_scope else duration,
            "rockstar_scope_enabled": rockstar_scope,
            "poll_ms": 10 if rockstar_scope else 100,
            "scope": "source_stage_and_reviewed_rockstar_socialclub_code_roots" if rockstar_scope else "source_stage_code_only",
            "observer_completion_does_not_end_client_or_controller": True}


def source_runtime_environment(runtime, version, process_trace=False):
    environment = dict(runtime.environment())
    if any(key.lower().startswith("citizenfx_") for key in environment):
        raise RuntimeError("Refusing all inherited CitizenFX role variables, including empty values")
    debug = getattr(runtime, 'source_winedebug', None)
    if debug is not None:
        if debug != '-all,+cfxnum' or process_trace:
            raise RuntimeError('Only the fixed numeric source channel is allowed for the diagnostic runtime')
    else:
        debug = diagnostic_winedebug(version, process_trace)
    environment.update(WINEPREFIX=str(PREFIX), WINESERVER=str(runtime.ENGINE / "bin/wineserver"), WINEDEBUG=debug)
    for key in ("WINESERVERSOCKET", "WINELOADER", "WINELOADERNOEXEC"):
        environment.pop(key, None)
    environment["CitizenFX_NoTenUI"] = "1"
    return environment


def select_runtime_profile(name):
    if name not in ('matched', 'parity', 'numeric', 'read', 'session-proxy'):
        raise ValueError('Require an explicit reviewed runtime profile')
    spec = importlib.util.spec_from_file_location('existing_gta_environment', ROOT.parent / 'GTA-V-macOS/scripts/gta-macos.py')
    runtime = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runtime)
    if PREFIX.resolve() == runtime.PREFIX.resolve():
        raise RuntimeError('Refusing productive GTA prefix')
    if name == 'matched':
        return runtime, {'profile': 'matched', 'engine': str(runtime.ENGINE), 'explicit_parity_selection': False}
    if name == 'session-proxy':
        import session_proxy_runtime_profile
        selected = session_proxy_runtime_profile.select_runtime(runtime, PREFIX)
    elif name == 'read':
        import read_runtime_profile
        selected = read_runtime_profile.select_runtime(runtime, PREFIX)
    elif name == 'numeric':
        import numeric_runtime_profile
        selected = numeric_runtime_profile.select_runtime(runtime, PREFIX)
    else:
        import parity_runtime_profile
        selected = parity_runtime_profile.select_runtime(runtime, PREFIX)
    return selected, selected.source_runtime_profile


def validate_system_dyld_search(enabled, runtime_profile, exit_relay):
    if type(enabled) is not bool:
        raise ValueError('System dyld search must be an explicit boolean option')
    if enabled and (runtime_profile != 'parity' or exit_relay):
        raise ValueError('System dyld search requires parity without exit relay')


def use_system_dyld_search(env):
    override = env.get('DYLD_LIBRARY_PATH')
    if not override or env.get('DYLD_FALLBACK_LIBRARY_PATH') != override:
        raise RuntimeError('Expected matching parity dyld library paths')
    del env['DYLD_LIBRARY_PATH']


def validate_graphics_blit_selection(enabled, runtime_profile, system_dyld_search, exit_relay, *, gate_census=False,
                                     vertices=False, projection=False, y_probe=False, aligned=False, sharpness=False):
    if any(type(option) is not bool for option in (enabled, gate_census, vertices, projection, y_probe, aligned, sharpness)):
        raise ValueError('Graphics blit tracing must be an explicit boolean option')
    if sharpness and not aligned:
        raise ValueError('Sharpness measurement requires --blit-projection-align')
    if ((y_probe or aligned) and not projection) or (y_probe and aligned):
        raise ValueError('Choose one Y variant with --blit-projection-ab')
    if projection and not vertices:
        raise ValueError('Projection A/B requires --blit-vertices')
    if vertices and not gate_census:
        raise ValueError('Graphics vertex tracing requires --blit-gate-census')
    if gate_census and not enabled:
        raise ValueError('Graphics gate census requires --trace-graphics-blit')
    if enabled and (runtime_profile != 'parity' or not system_dyld_search or exit_relay):
        raise ValueError('Graphics blit tracing requires parity and system dyld search without exit relay')


def run(duration, resume=False, process_trace=False, observe_rockstar_processes=False, runtime_profile='matched',
        exit_relay=False, observe_ros_code=False, observe_ros_text=False, keep_open=False, observe_host_pids=False,
        observe_ros_windows=False, observe_ntdll_entries=False, trace_window_creation=False,
        trace_window_class=False, trace_window_registration=False, system_dyld_search=False,
        trace_graphics_blit=False, blit_gate_census=False, blit_vertices=False, blit_projection=False, blit_y_probe=False,
        blit_projection_align=False, blit_sharpness=False, blit_native_extents=False, blit_fast_extents=False,
        blit_fullscreen_y=False, retina_window=None, nui_resize_report=None, nui_quiet=False):
    from source_main_environment import source_main_prefix, assert_source_main_prefix
    from probe_environment import ProbePrefixError
    if type(keep_open) is not bool:
        raise ValueError('Keeping the Source client open must be an explicit boolean option')
    if type(exit_relay) is not bool:
        raise ValueError('Exit relay must be an explicit boolean option')
    validate_system_dyld_search(system_dyld_search, runtime_profile, exit_relay)
    validate_graphics_blit_selection(trace_graphics_blit, runtime_profile, system_dyld_search, exit_relay,
                                     gate_census=blit_gate_census, vertices=blit_vertices, projection=blit_projection,
                                     y_probe=blit_y_probe, aligned=blit_projection_align, sharpness=blit_sharpness)
    if blit_fast_extents and (not blit_native_extents or not blit_projection_align or blit_sharpness):
        raise ValueError('Fast extents require the aligned native projection without sharpness measurement')
    if blit_fullscreen_y and (not blit_fast_extents or retina_window is None):
        raise ValueError('Fullscreen Y correction requires fast native extents and Retina windowed startup')
    verified_nui_projection = blit_sharpness or blit_fast_extents
    if blit_native_extents and not verified_nui_projection:
        raise ValueError('Native menu extents trial requires a measurement or fast variant')
    if nui_quiet and (nui_resize_report is None or not trace_window_registration or process_trace
                      or observe_ntdll_entries):
        raise ValueError('Quiet NUI trial requires a resize build and the registration provider without extra traces')
    if retina_window is not None and (not resume or not verified_nui_projection or type(retina_window) is not tuple
            or len(retina_window) != 2 or any(type(value) is not int or not 320 <= value <= 4096 for value in retina_window)):
        raise ValueError('Retina trial requires resume, an admitted menu projection and a bounded logical window size')
    nui_timing = False
    if nui_resize_report is not None:
        if not resume or not verified_nui_projection:
            raise ValueError('NUI resize trial requires resume and an admitted menu projection')
        import nui_resize_launch
        nui_timing = nui_resize_launch.verify_candidate(nui_resize_report).get('timing_diagnostics', False)
        if nui_timing and not nui_quiet:
            raise ValueError('Menu timing diagnostics require the quiet NUI trial')
    if exit_relay:
        from source_exit_relay import SourceExitRelay, DEBUG as EXIT_DEBUG, validate_selection
        validate_selection(runtime_profile, process_trace)
    if type(observe_ros_code) is not bool:
        raise ValueError('ROS code observation must be an explicit boolean option')
    if observe_ros_code:
        from source_code_observer import SourceCodeObserver, validate_selection as validate_code_selection
        validate_code_selection(runtime_profile, exit_relay)
    if type(observe_ros_text) is not bool:
        raise ValueError('ROS Error text observation must be an explicit boolean option')
    if observe_ros_text:
        from source_text_observer import SourceTextObserver, validate_selection as validate_text_selection
        validate_text_selection(runtime_profile, exit_relay)
    if type(observe_host_pids) is not bool:
        raise ValueError('Host process mapping must be an explicit boolean option')
    if observe_host_pids:
        from source_pid_watch import SourcePidWatcher, validate_selection as validate_pid_selection
        validate_pid_selection(runtime_profile, exit_relay)
    if type(observe_ros_windows) is not bool:
        raise ValueError('ROS desktop metadata observation must be an explicit boolean option')
    if observe_ros_windows:
        from source_desktop_metadata import SourceDesktopMetadata, validate_selection as validate_window_selection
        validate_window_selection(runtime_profile, exit_relay)
    if type(observe_ntdll_entries) is not bool:
        raise ValueError('NTDLL entry observation must be an explicit boolean option')
    if observe_ntdll_entries:
        from source_ntdll_entry_observer import SourceNtdllEntryObserver, validate_selection as validate_entry_selection
        validate_entry_selection(runtime_profile, exit_relay)
    window_options = trace_window_creation, trace_window_class, trace_window_registration
    if any(type(value) is not bool for value in window_options):
        raise ValueError('Numeric window tracing must be an explicit boolean option')
    if sum(window_options) > 1 or ((trace_window_class or trace_window_registration) and process_trace):
        raise ValueError('Window class tracing must run without other window or process tracing')
    trace_class = trace_window_class or trace_window_registration
    trace_window = any(window_options)
    window_proof = None
    if trace_class:
        WindowCollector, WindowStream, window_proof = window_trace_support(runtime_profile, exit_relay, window_class=True)
    elif trace_window_creation:
        WindowCollector, WindowStream, window_proof = window_trace_support(runtime_profile, exit_relay)
    observer_config = observer_configuration(duration, observe_rockstar_processes)
    stage = check_inputs(require_preflight=True, resume=resume)
    input_manifest = MANIFEST
    runtime, runtime_context = select_runtime_profile(runtime_profile)
    env = source_runtime_environment(runtime, stage["developer_code_version"], process_trace)
    env.pop('CFX_NUI_TIMING_DIAGNOSTICS', None)
    if nui_timing:
        env['CFX_NUI_TIMING_DIAGNOSTICS'] = '1'
    if exit_relay:
        env['WINEDEBUG'] = EXIT_DEBUG
    if trace_window:
        env['WINEDEBUG'] += ',+win,+pid,+class' if trace_class else ',+win,+pid'
    if trace_window_registration:
        import window_registration_provider
        from window_registration_resolution_trace import Collector as WindowCollector
        window_proof['registration_provider'] = window_registration_provider.apply(env)
    if nui_quiet:
        env['WINEDEBUG'] = '-all,+debugstr,+cfxwndreg,+pid'
    if system_dyld_search:
        use_system_dyld_search(env)
    label = ("client-source-ui-resume-" if resume else "client-source-ui-") + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    log = ROOT / "logs" / (label + ".log")
    output_record = ROOT / "research" / (label + "-results.json")
    parent = None
    started = None
    operator_stop = False
    failure = None
    isolation_failure = None
    observer = None
    exit_capture = None
    relay_output = None
    ros_code_observer = None
    ros_text_observer = None
    host_pid_observer = None
    desktop_observer = None
    entry_observer = None
    entry_observer_failure = None
    window_stream = None
    window_output = None
    blit_run = None
    nui_resize_run = None
    nui_resize_cleanup = {'baseline_restored': False}
    natural_idle = False
    retina_evidence = {}
    retina_context = nullcontext()
    if retina_window is not None:
        from source_retina_profile import profile
        retina_context = profile(runtime, env, retina_window, retina_evidence)
    with source_main_prefix(PREFIX, root=ROOT), retina_context:
        if trace_graphics_blit:
            import graphics_blit_launch
            check_inputs(require_preflight=True, resume=resume)
            blit_run = graphics_blit_launch.activate(MANIFEST, runtime, env, gate_census=blit_gate_census,
                                                     vertices=blit_vertices, projection=blit_projection, y_probe=blit_y_probe,
                                                     aligned=blit_projection_align, sharpness=blit_sharpness,
                                                     native_extents=blit_native_extents, fast_extents=blit_fast_extents,
                                                     fullscreen_y=blit_fullscreen_y)
            blit_run['gate_census'] = blit_gate_census
            blit_run['vertices_enabled'] = blit_vertices
            blit_run['projection_ab_enabled'] = blit_projection
            blit_run['projection_y_probe_enabled'] = blit_y_probe
            blit_run['projection_align_enabled'] = blit_projection_align
            blit_run['sharpness_texture_measurement_enabled'] = blit_sharpness
            blit_run['native_extents_enabled'] = blit_native_extents
            blit_run['fast_extents_enabled'] = blit_fast_extents
            blit_run['fullscreen_y_enabled'] = blit_fullscreen_y
            blit_run['baseline_restored'] = False
        try:
            if nui_resize_report is not None:
                nui_resize_run = nui_resize_launch.activate(nui_resize_report, runtime, env)
            assert_source_main_prefix(PREFIX, root=ROOT)
            game_mapping()
            # Validate again after acquiring the shared prefix/run lock.
            if blit_run is None:
                check_inputs(require_preflight=True, resume=resume)
            if hasattr(runtime, 'before_source_spawn'):
                runtime.before_source_spawn()
            if exit_relay:
                exit_capture = SourceExitRelay(runtime, env, PREFIX, STAGE, duration)
                exit_capture.prepare()
            print("Starting the verified read-only code-process observer before Main", flush=True)
            print("Observer scope:", observer_config["scope"], "; requested seconds:",
                  observer_config["observer_requested_duration_seconds"], flush=True)
            if observe_rockstar_processes:
                observer = ProcessObserver(runtime, env, STAGE, label,
                                           observer_config["observer_requested_duration_seconds"], rockstar_scope=True)
            else:
                observer = ProcessObserver(runtime, env, STAGE, label, duration)
            observer.wait_ready()
            if observe_ros_code:
                ros_code_observer = SourceCodeObserver(runtime, env, STAGE, label, duration, exit_capture)
                ros_code_observer.start()
                ros_code_observer.wait_ready()
            if observe_ros_text:
                ros_text_observer = SourceTextObserver(runtime, env, STAGE, label, duration, exit_capture)
                ros_text_observer.start()
                ros_text_observer.wait_ready()
            if observe_host_pids:
                host_pid_observer = SourcePidWatcher(runtime, env, STAGE, label, duration, exit_capture)
                host_pid_observer.start()
                host_pid_observer.wait_ready()
            if observe_ros_windows:
                desktop_observer = SourceDesktopMetadata(runtime, env, STAGE, label, duration, exit_capture)
                desktop_observer.start()
                desktop_observer.wait_ready()
            if observe_ntdll_entries:
                entry_observer = SourceNtdllEntryObserver(runtime, env, STAGE, label, duration)
                entry_observer.start()
                entry_observer.wait_ready()
            if hasattr(runtime, 'before_source_spawn'):
                runtime.before_source_spawn()
            if trace_window_registration and window_registration_provider.verify() != window_proof['registration_provider']:
                raise RuntimeError('User32 registration trace provider changed before the client start')
            if blit_run is not None:
                graphics_blit_launch.require_prefix(blit_run['source_prefix_identity'])
                artifact = blit_run['artifact']
                graphics_blit_launch.require(graphics_blit_launch.TARGET, (artifact['bytes'], artifact['sha256']))
            if nui_resize_run is not None:
                nui_resize_launch.require_active(nui_resize_run)
            print("Explicit source-developer MAIN, launcher UI only:", STAGE / "FiveM.exe", flush=True)
            print("Original developer output marker: FiveM.exe.formaldev; no application arguments", flush=True)
            print("Runner PID:", os.getpid(), "; observation seconds:", duration, flush=True)
            if keep_open:
                print('Controller auto-close disabled; application stays open until an explicit stop or its own exit', flush=True)
            print("Log:", log, "; result:", output_record, flush=True)
            descriptor = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            output = os.fdopen(descriptor, "w")
            if exit_relay:
                relay_output = output
            if trace_window:
                window_output = output
                window_stream = WindowStream(WindowCollector())
            with (nullcontext(output) if exit_relay or trace_window else output):
                started = time.monotonic()
                if exit_relay:
                    parent = exit_capture.start(output.buffer)
                else:
                    parent = subprocess.Popen([str(runtime.WINE), str(STAGE / "FiveM.exe")], cwd=STAGE, env=env,
                                              stdout=subprocess.PIPE if trace_window else output,
                                              stderr=subprocess.STDOUT)
                    if trace_window:
                        window_stream.attach(parent, output)
                print("MAIN native Wine PID:", parent.pid, flush=True)
                next_guard = started
                while keep_open or time.monotonic() - started < duration:
                    if time.monotonic() >= next_guard:
                        assert_source_main_prefix(PREFIX, root=ROOT)
                        game_mapping()
                        next_guard = time.monotonic() + 2
                        if blit_run is not None and keep_open and parent.poll() is not None:
                            graphics_blit_launch.require_prefix(blit_run['source_prefix_identity'])
                            if graphics_blit_launch.session_idle(runtime, env):
                                natural_idle = True
                                break
                    time.sleep(0.2)
            assert_source_main_prefix(PREFIX, root=ROOT)
            game_mapping()
        except KeyboardInterrupt:
            operator_stop = True
        except BaseException as error:
            detail = {"type": type(error).__name__, "message": str(error)}
            if isinstance(error, ProbePrefixError):
                isolation_failure = detail
            else:
                failure = detail
            raise
        finally:
            if parent is None and exit_capture is not None:
                parent = exit_capture.process
            parent_exit_before_cleanup = parent.poll() if parent is not None else None
            if exit_capture is not None:
                exit_capture.restore()
            finish = exit_capture.finishing_after_cleanup(relay_output) if exit_capture is not None else nullcontext()
            code_finish = ros_code_observer.finishing_after_cleanup() if ros_code_observer is not None else nullcontext()
            text_finish = ros_text_observer.finishing_after_cleanup() if ros_text_observer is not None else nullcontext()
            pid_finish = host_pid_observer.finishing_after_cleanup() if host_pid_observer is not None else nullcontext()
            desktop_finish = desktop_observer.finishing_after_cleanup() if desktop_observer is not None else nullcontext()
            cleanup_confirmed = False
            cleanup = {'kill_exit': None, 'wait_exit': None, 'wait_timed_out': False}
            try:
                with desktop_finish, pid_finish, text_finish, code_finish, finish:
                    if blit_run is not None:
                        graphics_blit_launch.require_prefix(blit_run['source_prefix_identity'])
                    if natural_idle:
                        cleanup['wait_exit'] = 0
                        cleanup['natural_wine_idle_observed'] = True
                    else:
                        killed = subprocess.run([str(runtime.ENGINE / "bin/wineserver"), "-k"], env=env,
                                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        cleanup['kill_exit'] = killed.returncode
                        if blit_run is not None:
                            graphics_blit_launch.require_prefix(blit_run['source_prefix_identity'])
                        try:
                            stopped = subprocess.run([str(runtime.ENGINE / "bin/wineserver"), "-w"], env=env,
                                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
                            cleanup['wait_exit'] = stopped.returncode
                        except subprocess.TimeoutExpired:
                            cleanup['wait_timed_out'] = True
                    if parent is not None:
                        try:
                            parent.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            parent.terminate()
                            parent.wait(timeout=5)
                    if blit_run is not None:
                        graphics_blit_launch.require_prefix(blit_run['source_prefix_identity'])
                    cleanup_confirmed = cleanup['wait_exit'] == 0
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
                if blit_run is None:
                    raise
                cleanup['failure_type'] = type(error).__name__
            finally:
                if nui_resize_run is not None and cleanup_confirmed:
                    try:
                        nui_resize_launch.restore_locked(nui_resize_run)
                    except (OSError, RuntimeError) as error:
                        nui_resize_cleanup['restore_failure_type'] = type(error).__name__
                    else:
                        nui_resize_cleanup['baseline_restored'] = True
                if blit_run is not None and cleanup_confirmed:
                    try:
                        graphics_blit_launch.restore_locked(lambda: check_inputs(require_preflight=True, resume=resume))
                    except (OSError, RuntimeError) as error:
                        blit_run['restore_failure_type'] = type(error).__name__
                    else:
                        blit_run['baseline_restored'] = True
                if window_stream is not None:
                    window_stream.finish_after_wineserver_cleanup()
                if (window_output is not None and not window_output.closed
                        and (window_stream is None or window_stream.output is not window_output)):
                    window_output.close()
            observer_result = observer.finish_after_wineserver_cleanup() if observer is not None else None
            if entry_observer is not None:
                try:
                    entry_observer.finish_after_wineserver_cleanup()
                except Exception as error:
                    entry_observer_failure = type(error).__name__
            toolmode_report = toolmode_diagnostic_report(log, stage["developer_code_version"] in (8, 9, 10, 11, 12) and not exit_relay)
            lifecycle_report = lifecycle_diagnostic_report(log, stage["developer_code_version"] in (9, 10, 11, 12) and not exit_relay)
            graphics_report = graphics_diagnostic_report(log, stage["developer_code_version"] in (11, 12) and not exit_relay)
            window_graphics_report = graphics_window_diagnostic_report(log, stage["developer_code_version"] == 12 and not exit_relay)
            record = {
                "at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "source_revision": REVISION, "stage": str(STAGE.relative_to(ROOT)),
                "runtime_engine_profile": runtime_profile, "runtime_engine_proof_context": runtime_context,
                "system_dyld_search": system_dyld_search,
                "input_manifest": str(input_manifest.relative_to(ROOT)), "input_manifest_sha256": sha(input_manifest),
                "initial_source_manifest": str(INITIAL_MANIFEST.relative_to(ROOT)), "initial_source_manifest_sha256": sha(INITIAL_MANIFEST),
                "developer_code_version": stage["developer_code_version"],
                "user_manual_login_confirmed": True, "prefix_is_account_free": False,
                "manual_login_controller_evidence": str(USER_LOGIN.relative_to(ROOT)),
                "manual_login_controller_evidence_sha256": sha(USER_LOGIN),
                "source_client_authentication_acceptance_claim": False,
                "resumed_existing_user_authorized_session": resume,
                "full_runtime_checkpoint_used_for_identity": False,
                "original_verify_viability_evidence": str(PREFLIGHT.relative_to(ROOT)),
                "original_verify_viability_evidence_sha256": sha(PREFLIGHT),
                "arguments": [], "self_set_environment": {"CitizenFX_NoTenUI": "1"},
                "developer_role": "exact original premake postbuild label, explicit source output",
                "copied_account_or_profile_inputs": False, "official_stage_modified": False,
                "agent_issued_story_mode_gameplay_or_connect_arguments": False,
                "sdk_or_tool_role_selected": False, "runtime_security_branches_modified": False,
                "prefix": str(PREFIX.relative_to(ROOT)), "wine_pid": parent.pid if parent is not None else None,
                "parent_exit_before_cleanup": parent_exit_before_cleanup,
                "observed_seconds": round(time.monotonic() - started, 2) if started else 0,
                "controller_auto_close_disabled": keep_open,
                "operator_requested_stop": operator_stop, "isolation_guard_failure": isolation_failure,
                "runner_failure": failure, "prefix_cleanup": cleanup,
                "log": str(log.relative_to(ROOT)), "log_contents_hashed_or_copied": False,
                "private_wine_process_trace_enabled": process_trace,
                "process_exit_numeric_metadata_only": process_exit_metadata(log) if process_trace else [],
                "wine_debug_channels": env["WINEDEBUG"],
                "mapping_diagnostics_enabled": stage["developer_code_version"] in (5, 6, 7, 8, 9, 10, 11, 12) and not exit_relay,
                "mapping_diagnostic_fixed_metadata_only": mapping_metadata(log) if stage["developer_code_version"] in (5, 6, 7, 8, 9, 10, 11, 12) and not exit_relay else [],
                "hook_diagnostics_enabled": stage["developer_code_version"] in (6, 7, 8, 9, 10, 11, 12) and not exit_relay,
                "hook_diagnostic_fixed_metadata_only": hook_metadata(log) if stage["developer_code_version"] in (6, 7, 8, 9, 10, 11, 12) and not exit_relay else [],
                "file_policy_diagnostics_enabled": stage["developer_code_version"] in (7, 8, 9, 10, 11, 12) and not exit_relay,
                "file_policy_diagnostic_fixed_metadata_only": file_policy_metadata(log) if stage["developer_code_version"] in (7, 8, 9, 10, 11, 12) and not exit_relay else [],
                "toolmode_diagnostics_enabled": toolmode_report["enabled"],
                "toolmode_diagnostic_fixed_metadata_only": toolmode_report["events"],
                "toolmode_diagnostic_channel_state": {key: value for key, value in toolmode_report.items() if key != "events"},
                "lifecycle_diagnostics_enabled": lifecycle_report["enabled"],
                "lifecycle_diagnostic_fixed_metadata_only": lifecycle_report["events"],
                "lifecycle_diagnostic_channel_state": {key: value for key, value in lifecycle_report.items() if key != "events"},
                "graphics_swapchain_diagnostics": graphics_report,
                "graphics_window_diagnostics": window_graphics_report,
                "read_only_code_process_observer": observer_result,
                "process_observer_configuration": observer_config,
                "code_assets_after": code_only_snapshot(stage),
                "runtime_sessions_profiles_tickets_browser_caches_inspected_or_copied": False,
                "launcher_ui_reached": False,
                "ui_status_note": "Actual UI success requires Root's window inspection; process exit alone is insufficient",
                "full_client_auth_gameplay_server_anticheat_success_claim": False,
            }
            if exit_relay:
                record['source_exit_relay'] = exit_capture.result() if exit_capture is not None else {
                    'enabled': True, 'capture_not_prepared': True}
            if observe_ros_code:
                record['ros_executable_code_observer'] = ros_code_observer.result() if ros_code_observer is not None else {
                    'enabled': True, 'observer_not_prepared': True}
            if observe_ros_text:
                record['ros_error_text_observer'] = ros_text_observer.result() if ros_text_observer is not None else {
                    'enabled': True, 'observer_not_prepared': True}
            if observe_host_pids:
                record['source_host_pid_observer'] = host_pid_observer.result() if host_pid_observer is not None else {
                    'enabled': True, 'observer_not_prepared': True}
            if observe_ros_windows:
                record['ros_desktop_metadata_observer'] = desktop_observer.result() if desktop_observer is not None else {
                    'enabled': True, 'observer_not_prepared': True}
            if observe_ntdll_entries:
                try:
                    entry_result = entry_observer.result() if entry_observer is not None else {
                        'enabled': True, 'observer_not_prepared': True}
                    if type(entry_result) is not dict:
                        raise TypeError('Entry observer result must be a metadata object')
                except Exception as error:
                    entry_observer_failure = type(error).__name__
                    entry_result = {'enabled': True, 'result_unavailable': True}
                record['ntdll_entry_code_observer'] = entry_result
                record['ntdll_entry_observer_finalization_error_type'] = entry_observer_failure
            if trace_window:
                trace_key = ('window_registration_trace' if trace_window_registration else
                             'window_class_trace' if trace_window_class else 'window_creation_trace')
                record[trace_key] = {**window_proof,
                    'stream': window_stream.result() if window_stream is not None else None}
            if blit_run is not None:
                from graphics_blit_metadata import parse_log
                try:
                    blit_run['measurement'] = parse_log(log) if log.is_file() else None
                except (OSError, ValueError) as error:
                    blit_run['measurement_error_type'] = type(error).__name__
                if blit_gate_census and log.is_file():
                    from graphics_blit_gate_metadata import parse_log as parse_blit_gates
                    try:
                        blit_run['gate_measurement'] = parse_blit_gates(log)
                    except (OSError, ValueError) as error:
                        blit_run['gate_measurement_error_type'] = type(error).__name__
                if blit_vertices and log.is_file():
                    from graphics_blit_vertex_metadata import parse_log as parse_blit_vertices
                    try:
                        blit_run['vertex_measurement'] = parse_blit_vertices(log)
                    except (OSError, ValueError) as error:
                        blit_run['vertex_measurement_error_type'] = type(error).__name__
                record['graphics_blit_diagnostics'] = blit_run
            if retina_evidence:
                record['retina_trial'] = retina_evidence
            if nui_resize_run is not None:
                record['nui_resize_trial'] = {**nui_resize_run, **nui_resize_cleanup, 'quiet': nui_quiet}
            output_record.write_text(json.dumps(record, indent=2) + "\n")
            (ROOT / "research/client-source-ui-latest.json").write_text(json.dumps({
                "at": record["at"], "result": str(output_record.relative_to(ROOT))}, indent=2) + "\n")
    print("Source MAIN observation ended; prefix cleanup:", cleanup, flush=True)
    relay_failed = exit_capture is not None and (exit_capture.restore_failure is not None
        or exit_capture.pump_failure is not None or (exit_capture.change_attempted and not exit_capture.restored))
    code_failed = ros_code_observer is not None and (ros_code_observer.reader_error is not None
        or ros_code_observer.lifecycle_error is not None or ros_code_observer.start_error is not None)
    text_failed = ros_text_observer is not None and (ros_text_observer.reader_error is not None
        or ros_text_observer.lifecycle_error is not None or ros_text_observer.start_error is not None)
    pid_failed = host_pid_observer is not None and (host_pid_observer.reader_error is not None
        or host_pid_observer.lifecycle_error is not None or host_pid_observer.start_error is not None)
    desktop_failed = desktop_observer is not None and (desktop_observer.reader_error is not None
        or desktop_observer.lifecycle_error is not None or desktop_observer.start_error is not None)
    entry_failed = entry_observer_failure is not None or (entry_observer is not None and (
        entry_observer.reader_error is not None or entry_observer.lifecycle_error is not None
        or entry_observer.start_error is not None))
    window_failed = trace_window and (window_stream is None or not window_stream.result()['capture_complete'])
    blit_failed = blit_run is not None and (not blit_run['baseline_restored'] or 'measurement_error_type' in blit_run)
    nui_resize_failed = nui_resize_run is not None and not nui_resize_cleanup['baseline_restored']
    if blit_failed or nui_resize_failed:
        return 1
    return 130 if operator_stop else (1 if cleanup["wait_timed_out"] or relay_failed or code_failed or text_failed or pid_failed or desktop_failed or entry_failed or window_failed else 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("inspect", "run", "inspect-resume", "resume"))
    parser.add_argument("--observe-seconds", type=int, default=3600)
    parser.add_argument('--keep-open', action='store_true',
                        help='Disable controller auto-close; diagnostic helpers remain independently bounded')
    parser.add_argument("--process-exit-trace", action="store_true",
                        help="Private Wine process trace; report numeric exit fields only, never command lines")
    parser.add_argument('--exit-relay', action='store_true',
                        help='Parity only: capture three ordinary ROS exit calls through the tested numeric stream filter')
    parser.add_argument('--system-dyld-search', action='store_true',
                        help='Parity without exit relay: retain the fallback paths and remove DYLD_LIBRARY_PATH')
    parser.add_argument('--trace-graphics-blit', action='store_true',
                        help='Temporarily measure the original graphics submission on the parity runtime')
    parser.add_argument('--blit-gate-census', action='store_true',
                        help='With blit tracing, also log each bounded diagnostic path once per process')
    parser.add_argument('--blit-vertices', action='store_true',
                        help='With gate tracing, measure up to eight Glue rectangles and their rasterizer state')
    parser.add_argument('--blit-projection-ab', action='store_true',
                        help='With vertex tracing, explicitly test the scoped menu projection correction')
    parser.add_argument('--blit-y-probe', action='store_true',
                        help='With projection A/B, translate the admitted menu quad by +90 raw Y units')
    parser.add_argument('--blit-projection-align', action='store_true',
                        help='With projection A/B, offset Y by the measured target height minus the logical reference')
    parser.add_argument('--blit-sharpness', action='store_true',
                        help='With the aligned projection, measure the admitted menu texture and render target')
    parser.add_argument('--blit-native-extents', action='store_true',
                        help='Preserve menu geometry above the original projection extent')
    parser.add_argument('--blit-fast-extents', action='store_true',
                        help='With the aligned native projection, skip high-resolution graphics state diagnostics')
    parser.add_argument('--blit-fullscreen-y', action='store_true',
                        help='With fast native extents and Retina startup, trial dynamic fullscreen menu geometry')
    parser.add_argument('--retina-window', nargs=2, type=int, metavar=('WIDTH', 'HEIGHT'),
                        help='Retina trial in the existing windowed Source profile, using macOS logical points')
    parser.add_argument('--nui-resize-report', type=Path,
                        help='With resume and sharpness measurement, trial the admitted M103 software resize DLL')
    parser.add_argument('--nui-quiet', action='store_true',
                        help='With the NUI resize trial, reduce Wine logging to debug markers and class registration')
    parser.add_argument('--observe-ros-code', action='store_true',
                        help='Parity plus exit-relay only: bounded executable ROS code window, no data/account reads')
    parser.add_argument('--observe-ros-text', action='store_true',
                        help='Parity plus exit-relay only: bounded Error-dialog STATIC text after separate own controls')
    parser.add_argument('--observe-host-pids', action='store_true',
                        help='Parity plus exit-relay only: map fixed client/Rockstar roles to native PIDs before Main')
    parser.add_argument('--observe-ros-windows', action='store_true',
                        help='Parity plus exit-relay only: role2 desktop/window class metadata; no child text or input')
    parser.add_argument('--observe-ntdll-entries', action='store_true',
                        help='Parity without exit-relay: compare three fixed NTDLL export entries; metadata only')
    window_tracing = parser.add_mutually_exclusive_group()
    window_tracing.add_argument('--trace-window-creation', action='store_true',
                        help='Parity without exit-relay: retain only numeric Wine window checkpoints')
    window_tracing.add_argument('--trace-window-class', action='store_true',
                        help='Parity only: observe grcWindow registration and lookup without persisting raw trace lines')
    window_tracing.add_argument('--trace-window-registration', action='store_true',
                        help='Parity only: trace wide registration entry and return using the tested User32 provider')
    parser.add_argument("--observe-rockstar-processes", action="store_true",
                        help="Fixed reviewed RGL/Social Club code scope at 10ms; observer capped at 600s, controller unchanged")
    parser.add_argument('--runtime', choices=('matched', 'parity', 'numeric', 'read', 'session-proxy'), default='matched',
                        help='Explicit runtime selection; numeric/read additionally require their own regression evidence')
    args = parser.parse_args()
    if not 1 <= args.observe_seconds <= 3600:
        parser.error("Launcher UI observation must be between 1 and 3600 seconds")
    verified_nui_projection = args.blit_sharpness or args.blit_fast_extents
    if args.retina_window is not None and (args.action != 'resume' or not verified_nui_projection
            or any(not 320 <= value <= 4096 for value in args.retina_window)):
        parser.error('Retina trial requires resume, an admitted menu projection and two logical dimensions from 320 to 4096')
    if args.nui_resize_report is not None and (args.action != 'resume' or not verified_nui_projection):
        parser.error('NUI resize trial requires resume and an admitted menu projection')
    if args.nui_quiet and (args.nui_resize_report is None or not args.trace_window_registration
                           or args.process_exit_trace or args.observe_ntdll_entries):
        parser.error('Quiet NUI trial requires a resize build and the registration provider without extra traces')
    if args.blit_fast_extents and (not args.blit_native_extents or not args.blit_projection_align or args.blit_sharpness):
        parser.error('Fast extents require --blit-projection-align and --blit-native-extents without --blit-sharpness')
    if args.blit_fullscreen_y and (not args.blit_fast_extents or args.retina_window is None):
        parser.error('Fullscreen Y correction requires --blit-fast-extents and --retina-window')
    if args.blit_native_extents and not verified_nui_projection:
        parser.error('Native menu extents trial requires --blit-sharpness or --blit-fast-extents')
    try:
        validate_system_dyld_search(args.system_dyld_search, args.runtime, args.exit_relay)
        validate_graphics_blit_selection(args.trace_graphics_blit, args.runtime, args.system_dyld_search, args.exit_relay,
                                         gate_census=args.blit_gate_census, vertices=args.blit_vertices,
                                         projection=args.blit_projection_ab, y_probe=args.blit_y_probe,
                                         aligned=args.blit_projection_align, sharpness=args.blit_sharpness)
    except ValueError as error:
        parser.error(str(error))
    if args.exit_relay:
        from source_exit_relay import validate_selection
        try:
            validate_selection(args.runtime, args.process_exit_trace)
        except ValueError as error:
            parser.error(str(error))
    if args.observe_ros_code:
        from source_code_observer import validate_selection
        try:
            validate_selection(args.runtime, args.exit_relay)
        except ValueError as error:
            parser.error(str(error))
    if args.observe_ros_text:
        from source_text_observer import validate_selection
        try:
            validate_selection(args.runtime, args.exit_relay)
        except ValueError as error:
            parser.error(str(error))
    if args.observe_host_pids:
        from source_pid_watch import validate_selection
        try:
            validate_selection(args.runtime, args.exit_relay)
        except ValueError as error:
            parser.error(str(error))
    if args.observe_ros_windows:
        from source_desktop_metadata import validate_selection
        try:
            validate_selection(args.runtime, args.exit_relay)
        except ValueError as error:
            parser.error(str(error))
    if args.observe_ntdll_entries:
        from source_ntdll_entry_observer import validate_selection
        try:
            validate_selection(args.runtime, args.exit_relay)
        except ValueError as error:
            parser.error(str(error))
    if args.trace_window_creation:
        try:
            window_trace_support(args.runtime, args.exit_relay)
        except ValueError as error:
            parser.error(str(error))
    if args.trace_window_class or args.trace_window_registration:
        if args.process_exit_trace:
            parser.error('Window class tracing must run without process tracing')
        try:
            window_trace_support(args.runtime, args.exit_relay, window_class=True)
        except ValueError as error:
            parser.error(str(error))
    if args.trace_window_registration and args.action in ('inspect', 'inspect-resume'):
        from window_registration_provider import verify
        verify()
    if args.action in ("inspect", "inspect-resume"):
        from source_main_environment import assert_source_main_prefix
        resumed = args.action == "inspect-resume"
        record = check_inputs(require_preflight=False, resume=resumed)
        if args.trace_graphics_blit:
            from graphics_blit_launch import verify_candidate
            verify_candidate(MANIFEST, gate_census=args.blit_gate_census, vertices=args.blit_vertices,
                             projection=args.blit_projection_ab, y_probe=args.blit_y_probe,
                             aligned=args.blit_projection_align, sharpness=args.blit_sharpness,
                             native_extents=args.blit_native_extents, fast_extents=args.blit_fast_extents,
                             fullscreen_y=args.blit_fullscreen_y)
            print('Read-only V12 baseline and graphics blit candidate verification PASS')
        assert_source_main_prefix(PREFIX, root=ROOT)
        count = len(record["files"])
        if args.runtime in ('parity', 'numeric', 'read', 'session-proxy'):
            runtime, context = select_runtime_profile(args.runtime)
            env = source_runtime_environment(runtime, record['developer_code_version'], args.process_exit_trace)
            if args.system_dyld_search:
                use_system_dyld_search(env)
            if args.exit_relay:
                from source_exit_relay import load_helpers
                load_helpers()
            if args.observe_ros_code:
                from source_code_observer import load_binding
                load_binding()
            if args.observe_ros_text:
                from source_text_observer import load_binding
                load_binding()
            if args.observe_host_pids:
                from source_pid_watch import load_binding
                load_binding()
            if args.observe_ros_windows:
                from source_desktop_metadata import load_binding
                load_binding()
            if args.observe_ntdll_entries:
                from source_ntdll_entry_observer import load_binding
                load_binding()
            print('Read-only engine, renderer and fixed own-probe prerequisite verification PASS; no runtime started')
            proof = context['live_components']['engine'] if args.runtime == 'parity' else context['engine']
            print('Engine manifest:', proof['manifest_sha256'])
        print("Read-only code/assets, prefix and game-mapping inspection PASS:", count, "immutable inputs")
        print("Original VerifyViability proof will be validated again before a coordinated runtime start")
        return 0
    options = dict(resume=args.action == 'resume', process_trace=args.process_exit_trace,
                   observe_rockstar_processes=args.observe_rockstar_processes)
    if args.runtime in ('parity', 'numeric', 'read', 'session-proxy'):
        options['runtime_profile'] = args.runtime
    if args.exit_relay:
        options['exit_relay'] = True
    if args.observe_ros_code:
        options['observe_ros_code'] = True
    if args.observe_ros_text:
        options['observe_ros_text'] = True
    if args.keep_open:
        options['keep_open'] = True
    if args.observe_host_pids:
        options['observe_host_pids'] = True
    if args.observe_ros_windows:
        options['observe_ros_windows'] = True
    if args.observe_ntdll_entries:
        options['observe_ntdll_entries'] = True
    if args.trace_window_creation:
        options['trace_window_creation'] = True
    if args.trace_window_class:
        options['trace_window_class'] = True
    if args.trace_window_registration:
        options['trace_window_registration'] = True
    if args.system_dyld_search:
        options['system_dyld_search'] = True
    if args.trace_graphics_blit:
        options['trace_graphics_blit'] = True
    if args.blit_gate_census:
        options['blit_gate_census'] = True
    if args.blit_vertices:
        options['blit_vertices'] = True
    if args.blit_projection_ab:
        options['blit_projection'] = True
    if args.blit_y_probe:
        options['blit_y_probe'] = True
    if args.blit_projection_align:
        options['blit_projection_align'] = True
    if args.blit_sharpness:
        options['blit_sharpness'] = True
    if args.blit_native_extents:
        options['blit_native_extents'] = True
    if args.blit_fast_extents:
        options['blit_fast_extents'] = True
    if args.blit_fullscreen_y:
        options['blit_fullscreen_y'] = True
    if args.retina_window is not None:
        options['retina_window'] = tuple(args.retina_window)
    if args.nui_resize_report is not None:
        options['nui_resize_report'] = args.nui_resize_report.absolute()
    if args.nui_quiet:
        options['nui_quiet'] = True
    return run(args.observe_seconds, **options)


if __name__ == "__main__":
    raise SystemExit(main())
