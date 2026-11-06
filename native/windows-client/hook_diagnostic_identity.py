"""Fixed v6 own-Core diagnostics identity; never follow user-data references."""
import hashlib
import json
from pathlib import PurePosixPath
import re
import stat

import source_code_identity as identity
from run_main import ROOT, REVISION, plain, sha

CORE_SHA256 = "b8830fa5bc6103a976d217dba418d9cbf7f27fed5e2cdf4db4587447f5eb17b8"
PREVIOUS_CORE_SHA256 = "de1d88338377a1463cf9107656ba4a9669f1da087a136f2bcfad2a4eee031377"
ORDINARY_CORE_SHA256 = "a9f4262d7f0d35b7e87e89d84cb00ed2007ca2dd297a0ae802d2c6877738f0a0"
ORDINARY_TBB_SHA256 = "facbb8c13497defb47191774081fba51fb421991da7eecbb828f9eb493b1d97c"
TBB_SHA256 = "7692b31578fa9c390cf253ee6ecdabaea63839327f054d3ed179ab60eb64096c"
SOURCE = "build/windows-core-hook-diagnostic/CoreRT.dll"
TBB = "build/windows-core-hook-diagnostic/clang_23.1_cxx17_64_md_relwithdebinfo/tbb12.dll"
ORDINARY_CORE = "build/windows-core/CoreRT.dll"
ORDINARY_TBB = "build/windows-core/clang_23.1_cxx17_64_md_relwithdebinfo/tbb12.dll"
PREVIOUS_CORE = "build/windows-core-mapping-diagnostic/CoreRT.dll"
PREVIOUS_MANIFEST = "research/client-source-code-inputs-v5.json"
MANIFEST = "research/client-source-code-inputs-v6.json"
TRANSACTION = "research/client-source-hook-diagnostic-update-v6.json"
BACKUP = "build/checkpoints/source-code-updates/hook-v6/CoreRT.dll.previous"
BUILD_RECORD = "research/core-hook-diagnostic-build.json"
V5_BUILD_RECORD = "research/core-mapping-diagnostic-build.json"
FIXTURE_BUILD_RECORD = "research/windows-hook-diagnostic-fixture-build.json"
FIXTURE_RESULTS = "research/windows-hook-diagnostic-fixture-results.json"
POLICY_BUILD_RECORD = "research/windows-mapping-policy-build.json"
RUNNER_SOURCE = "native/windows-mapping-policy/run_hook.py"
POLICY_RUNNER_SOURCE = "native/windows-mapping-policy/run.py"
HEADER_TEST = "native/windows-core-hook-diagnostic/test_hook_diagnostics.py"
HEADER_TEST_COUNT = 5
ORIGIN = "public-source-Core-v6-fixed-field-hook-status-diagnostics"
PINNED_SOURCES = {
    "port/fivem/code/client/citicore/FileMapping.Win32.cpp": "1e2e23846410586e27117716ba8ea4ee8be3681469d50015391c4f10ce2e3053",
    "port/fivem/code/client/citicore/MappingDiagnostics.h": "9cab07670dfcbd4134d5d60af5d28e745c753576c12107b270b0a8f3df033b31",
    "native/windows-core/CMakeLists.txt": "37ed38171fcaf4b02ead24e53ac05a7f7579f360cb74343ce9abab164f79bbac",
}
EXPECTED_SOURCES = {"native/windows-core-hook-diagnostic/" + name for name in
                    ("build.py", "HookDiagnostics.h", "test_hook_diagnostics.py")}
EXPECTED_OVERLAY = {"build/windows-core-hook-diagnostic/overlay/" + name for name in
                    ("CMakeLists.txt", "FileMapping.Win32.cpp", "HookDiagnostics.h")}
EXPECTED_ARTIFACTS = {"build/windows-mapping-policy/" + name for name in
                      ("mapping_policy_probe.exe", "consumer.dll", "socialclub.dll", "mapping-target.dll")}
BUILD_FILES = {
    "toolchain": "native/windows-core/toolchain.cmake",
    "log": "build/windows-core-hook-diagnostic/build.log",
    "compile_commands": "build/windows-core-hook-diagnostic/compile_commands.json",
    "source_scope": "build/windows-core-hook-diagnostic/source-scope.txt",
}
HEADER_LOG = "build/windows-core-hook-diagnostic/header-tests.log"
PRESERVED_INPUTS = set(PINNED_SOURCES) | {V5_BUILD_RECORD, ORDINARY_CORE, ORDINARY_TBB, PREVIOUS_CORE}
ALLOWED_INPUTS = (EXPECTED_SOURCES | EXPECTED_OVERLAY | EXPECTED_ARTIFACTS | PRESERVED_INPUTS
                  | set(BUILD_FILES.values()) | {SOURCE, TBB, BUILD_RECORD, HEADER_LOG,
                     FIXTURE_BUILD_RECORD, FIXTURE_RESULTS, POLICY_BUILD_RECORD,
                     PREVIOUS_MANIFEST, TRANSACTION, BACKUP, RUNNER_SOURCE, POLICY_RUNNER_SOURCE})
PHASES = frozenset({"create.ntdll." + name for name in (
    "NtCreateFile", "NtOpenFile", "NtDeleteFile", "NtQueryAttributesFile", "NtQueryFullAttributesFile",
    "NtSetInformationFile", "LdrLoadDll", "LdrGetProcedureAddress", "RtlGetFullPathName_U")}
    | {"create.version." + name for name in ("GetFileVersionInfoSizeW", "GetFileVersionInfoSizeA",
          "GetFileVersionInfoW", "GetFileVersionInfoA", "VerQueryValueW")}
    | {"create.kernelbase." + name for name in ("RegOpenKeyExW", "GetFileAttributesExW", "GetProcAddressForCaller", "CreateThread")}
    | {"create.kernel32.CreateThread", "create.combase.CoUninitialize", "enable.all"})
MODES = ("--baseline-explicit", "--mapped-explicit", "--baseline-import", "--mapped-import")
CASES = tuple((location, mode) for location in ("foreign", "canonical") for mode in MODES)
METADATA = re.compile(
    r"MAPPING_POLICY_FIXTURE location=(canonical|foreign) route=(explicit|import) mapped=([01]) "
    r"preloaded_before=([01]) preloaded_after=([01]) callback_count=(0|[1-9][0-9]*) "
    r"fixed_path_hits=(0|[1-9][0-9]*) load_error=(0|[1-9][0-9]*) marker=(0x[0-9a-f]{8})")


def allowed_input(root, name):
    if type(name) is not str or name not in ALLOWED_INPUTS:
        raise RuntimeError("Refusing an undeclared hook diagnostic input")
    relative = PurePosixPath(name)
    if relative.is_absolute() or str(relative) != name or any(part in (".", "..") for part in relative.parts):
        raise RuntimeError("Hook input must be a canonical project-relative code path")
    path = root / relative
    plain(path)
    metadata = path.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
            or path.resolve(strict=True) != path or not path.is_relative_to(root)):
        raise RuntimeError("Hook input must be a local regular unaliased code/evidence file")
    return path


def _identity_shape(item, path):
    if (not isinstance(item, dict) or item.get("path") != path
            or type(item.get("bytes")) is not int or item["bytes"] <= 0
            or type(item.get("sha256")) is not str or not re.fullmatch("[0-9a-f]{64}", item["sha256"])):
        raise RuntimeError("Unexpected hook diagnostic code/evidence identity")


def _group(items, expected):
    if (not isinstance(items, list) or len(items) != len(expected)
            or any(not isinstance(item, dict) or type(item.get("path")) is not str for item in items)
            or len({item["path"] for item in items}) != len(items)
            or {item["path"] for item in items} != set(expected)):
        raise RuntimeError("Unexpected hook diagnostic input path set")
    for item in items:
        _identity_shape(item, item["path"])


def _reference(item, expected):
    if (not isinstance(item, dict) or item.get("path") != expected
            or type(item.get("sha256")) is not str or not re.fullmatch("[0-9a-f]{64}", item["sha256"])):
        raise RuntimeError("Unexpected fixed hook diagnostic reference")


def _case_contract(case, location, mode):
    mapped = mode.startswith("--mapped-")
    route = "import" if mode.endswith("-import") else "explicit"
    should_map = mapped and (route == "explicit" or location == "canonical")
    metadata = case.get("metadata")
    if not isinstance(metadata, list) or len(metadata) != 1 or type(metadata[0]) is not str:
        return False
    match = METADATA.fullmatch(metadata[0])
    if match is None:
        return False
    actual_location, actual_route, actual_mapped, before, after, callbacks, hits, error, marker = match.groups()
    if (actual_location, actual_route, actual_mapped, before, after, error) != (
            location, route, str(int(mapped)), "0", "0", "0"):
        return False
    if marker != ("0x46585232" if should_map else "0x46585231") or int(hits) > int(callbacks):
        return False
    if not (int(hits) > 0 if should_map else int(hits) == 0 and int(callbacks) == 0):
        return False
    events = case.get("hook_events")
    if not isinstance(events, list):
        return False
    for event in events:
        if (not isinstance(event, dict) or set(event) != {"pid", "phase", "status"}
                or type(event["pid"]) is not int or not 1 <= event["pid"] <= 0xffffffff
                or type(event["phase"]) is not str or event["phase"] not in PHASES
                or type(event["status"]) is not int or not -1 <= event["status"] <= 12):
            return False
    if (not events if mapped else bool(events)):
        return False
    if mapped and {event["phase"] for event in events} != PHASES:
        return False
    # Wine may report OutputDebugString through two channels; duplicate events are valid.
    all_ok = all(event["status"] == 0 for event in events) if mapped else True
    return (case.get("location") == location and case.get("mode") == mode
            and type(case.get("exit")) is int and case["exit"] == 0 and case.get("passed") is True
            and case.get("hook_phase_contract") is True and type(case.get("all_hooks_ok")) is bool
            and case["all_hooks_ok"] == all_ok)


def validate_evidence(root):
    references = []

    def bind(name):
        path = allowed_input(root, name)
        references.append({"path": name, "sha256": sha(path)})
        return path

    def bound_identity(item):
        path = bind(item["path"])
        if sha(path) != item["sha256"] or path.stat().st_size != item["bytes"]:
            raise RuntimeError("Bound hook diagnostic code/evidence bytes changed")
        return path

    build_path = bind(BUILD_RECORD)
    build = json.loads(build_path.read_text())
    fixture_path = bind(FIXTURE_BUILD_RECORD)
    fixture = json.loads(fixture_path.read_text())
    # Admit every path-bearing group before hashing any path supplied by either record.
    _identity_shape(build.get("artifact"), SOURCE)
    _identity_shape(build.get("tbb_artifact"), TBB)
    _group(build.get("source_evidence"), EXPECTED_SOURCES)
    _group(build.get("generated_overlay"), EXPECTED_OVERLAY)
    _identity_shape(build.get("base_v5_build_record"), V5_BUILD_RECORD)
    for key, name in BUILD_FILES.items():
        _identity_shape(build.get("build", {}).get(key), name)
    _identity_shape(build.get("header_and_overlay_tests", {}).get("log"), HEADER_LOG)
    preserved = build.get("preserved_original_input_and_artifact_sha256")
    if not isinstance(preserved, dict) or set(preserved) != PRESERVED_INPUTS:
        raise RuntimeError("Unexpected preserved v5 input path set")
    _reference(fixture.get("build_record"), BUILD_RECORD)
    _reference(fixture.get("policy_build_evidence"), POLICY_BUILD_RECORD)
    _identity_shape(fixture.get("runner_source"), RUNNER_SOURCE)
    _identity_shape(fixture.get("policy_runner_source"), POLICY_RUNNER_SOURCE)
    _identity_shape(fixture.get("diagnostic_core_input"), SOURCE)
    _identity_shape(fixture.get("tbb_input"), ORDINARY_TBB)
    _group(fixture.get("artifacts"), EXPECTED_ARTIFACTS)
    if (fixture["diagnostic_core_input"] != build["artifact"] or build["artifact"]["sha256"] != CORE_SHA256
            or build["tbb_artifact"]["sha256"] != TBB_SHA256
            or fixture["tbb_input"]["sha256"] != ORDINARY_TBB_SHA256
            or fixture["build_record"]["sha256"] != sha(build_path)
            or type(fixture.get("hook_phases")) is not list or len(fixture["hook_phases"]) != len(PHASES)
            or set(fixture["hook_phases"]) != PHASES):
        raise RuntimeError("Require the exact built hook Core, original fixture TBB and fixed phases")
    if (build.get("compiled") is not True or build.get("source_revision") != REVISION
            or build.get("wine_client_or_game_started") is not False or build.get("stage_or_prefix_accessed") is not False
            or build.get("existing_patch_queue_changed") is not False or build.get("runtime_tested") is not False):
        raise RuntimeError("Unexpected separate compile-only hook build scope")
    settings = build["build"]
    if any(settings.get(key) != value for key, value in {
            "directory": "build/windows-core-hook-diagnostic", "exit": 0,
            "CFX_SOURCE_DIR": "port/fivem", "CFX_CORE_MAPPING_DIAGNOSTICS": "ON",
            "CFX_CORE_ACCOUNT_FREE_TESTS": "OFF", "runtime": "/MD", "target": "AMD64 Windows CoreRT"}.items()):
        raise RuntimeError("Require the full separate /MD diagnostic Core build")
    scope = build.get("scope_proof", {})
    if any(scope.get(key) != value for key, value in {
            "original_sources_pinned": PINNED_SOURCES,
            "stripped_mapping_sha256": PINNED_SOURCES["port/fivem/code/client/citicore/FileMapping.Win32.cpp"],
            "stripped_mapping_equals_exact_v5_bytes": True, "stripped_cmake_equals_exact_v5_bytes": True,
            "create_hook_api_wrappers": 20, "enable_all_wrappers": 1,
            "original_hook_expressions_unchanged_and_evaluated_once": True, "status_controls_original_flow": False,
            "mapping_callback_filter_or_return_changed": False, "additional_getmodulehandle_probes": False}.items()):
        raise RuntimeError("Require the reversible status-only overlay scope")
    payload = build.get("payload", {})
    if any(payload.get(key) != value for key, value in {
            "fixed_prefix": "CFX_MAPPING_HOOK", "fields": ["pid", "phase", "status"],
            "phase_source": "fixed enum only", "status_range": [-1, 12], "out_of_range_status_logged_as": -1,
            "paths_pointers_auth_or_profile_values_logged": False, "last_error_preserved": True}.items()):
        raise RuntimeError("Unexpected hook diagnostic payload scope")
    checks = build["header_and_overlay_tests"]
    if checks.get("exit") != 0:
        raise RuntimeError("Require the actual header and reversible-overlay tests")
    for item in [build["artifact"], build["tbb_artifact"], build["base_v5_build_record"],
                 *build["source_evidence"], *build["generated_overlay"],
                 *(settings[key] for key in BUILD_FILES), checks["log"]]:
        bound_identity(item)
    header_log = allowed_input(root, HEADER_LOG).read_text()
    if not re.search(r"\bRan 5 tests\b", header_log) or not re.search(r"(?m)^OK\s*$", header_log):
        raise RuntimeError("Require the five real ON/OFF/header/overlay checks")
    expected_preserved = {**PINNED_SOURCES, ORDINARY_CORE: ORDINARY_CORE_SHA256,
                          ORDINARY_TBB: ORDINARY_TBB_SHA256, PREVIOUS_CORE: PREVIOUS_CORE_SHA256,
                          V5_BUILD_RECORD: build["base_v5_build_record"]["sha256"]}
    if preserved != expected_preserved:
        raise RuntimeError("Preserved v5 code identity differs")
    for name in sorted(preserved):
        if sha(bind(name)) != preserved[name]:
            raise RuntimeError("An original v5 code/evidence input changed")
    policy_path = bind(POLICY_BUILD_RECORD)
    if sha(policy_path) != fixture["policy_build_evidence"]["sha256"]:
        raise RuntimeError("Own policy fixture build evidence changed")
    for item in [fixture["runner_source"], fixture["policy_runner_source"], fixture["tbb_input"], *fixture["artifacts"]]:
        bound_identity(item)
    results = json.loads(bind(FIXTURE_RESULTS).read_text())
    if (results.get("passed") is not True or results.get("core_sha256") != CORE_SHA256
            or results.get("fixture_build_sha256") != sha(fixture_path)
            or results.get("only_own_marker_dlls") is not True or results.get("client_started") is not False
            or results.get("real_rockstar_code_staged") is not False
            or results.get("cleanup") != [{"flag": "-k", "exit": 0}, {"flag": "-w", "exit": 0}]):
        raise RuntimeError("Require real own-marker hook diagnostics with successful cleanup")
    cases = results.get("cases")
    if (not isinstance(cases, list) or len(cases) != len(CASES)
            or any(not isinstance(case, dict) or not _case_contract(case, *expected)
                   for case, expected in zip(cases, CASES))):
        raise RuntimeError("Require the exact eight own policy and hook-diagnostic cases")
    return references


def validate_version(record):
    """Admit all v6 metadata before the common validator follows any record paths."""
    for key, expected in (("hook_previous_manifest", PREVIOUS_MANIFEST), ("hook_update_transaction", TRANSACTION)):
        if record.get(key) != expected:
            raise RuntimeError("Unexpected v6 hook evidence reference")
        path = allowed_input(ROOT, expected)
        if sha(path) != record.get(key + "_sha256"):
            raise RuntimeError("Bound v6 hook evidence changed")
    previous = json.loads((ROOT / PREVIOUS_MANIFEST).read_text())
    transaction = json.loads((ROOT / TRANSACTION).read_text())
    if previous.get("developer_code_version") != 5:
        raise RuntimeError("Hook diagnostics require exact previous v5 metadata")
    identity.validate_mapping_version(previous)
    additions = {"hook_previous_manifest", "hook_previous_manifest_sha256", "hook_update_transaction", "hook_update_transaction_sha256"}
    if set(record) != set(previous) | additions:
        raise RuntimeError("Unexpected v6 role or metadata fields")
    for key, value in previous.items():
        if key not in ("at", "developer_code_version", "files") and record.get(key) != value:
            raise RuntimeError("v6 must preserve existing v5 role and provenance: " + key)
    old = previous.get("files")
    new = record.get("files")
    if (not isinstance(old, list) or not isinstance(new, list) or len(old) != len(new)
            or any(not isinstance(item, dict) or type(item.get("name")) is not str for item in old + new)
            or len({item["name"] for item in old}) != len(old)
            or sum(item["name"] == "CoreRT.dll" for item in old) != 1):
        raise RuntimeError("Unexpected v5/v6 code inventory")
    for before, after in zip(old, new):
        if before["name"] != "CoreRT.dll":
            if before != after:
                raise RuntimeError("v6 may update only its own CoreRT code input")
        else:
            expected = dict(before, sha256=CORE_SHA256, bytes=allowed_input(ROOT, SOURCE).stat().st_size, origin=ORIGIN)
            if before.get("sha256") != PREVIOUS_CORE_SHA256 or after != expected:
                raise RuntimeError("Unexpected v6 own CoreRT delta")
    if (record.get("developer_code_version") != 6 or transaction.get("developer_code_version") != 6
            or transaction.get("source_revision") != REVISION
            or transaction.get("hook_previous_manifest") != PREVIOUS_MANIFEST
            or transaction.get("hook_previous_manifest_sha256") != record["hook_previous_manifest_sha256"]
            or transaction.get("previous_sha256") != PREVIOUS_CORE_SHA256
            or transaction.get("new_sha256") != CORE_SHA256
            or transaction.get("target") != "build/windows-source-integration/CoreRT.dll"
            or transaction.get("source") != SOURCE or transaction.get("previous_code_backup") != BACKUP
            or transaction.get("header_checks", {}).get("exit") != 0
            or transaction.get("header_checks", {}).get("passed") != HEADER_TEST_COUNT
            or transaction.get("only_own_core_file_updated") is not True
            or transaction.get("main_citigame_and_original_modules_unchanged") is not True
            or transaction.get("original_conditions_returns_mapping_authentication_and_security_decisions_preserved") is not True
            or transaction.get("profiles_sessions_tickets_read_copied_or_reset") is not False):
        raise RuntimeError("Unexpected hook-only Core transaction")
    backup = allowed_input(ROOT, BACKUP)
    if sha(backup) != PREVIOUS_CORE_SHA256:
        raise RuntimeError("Previous v5 own Core backup changed")
    if transaction.get("diagnostic_evidence") != validate_evidence(ROOT):
        raise RuntimeError("Exact hook diagnostic build/header/fixture evidence changed")
