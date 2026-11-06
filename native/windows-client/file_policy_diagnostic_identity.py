"""Fixed v7 file-policy diagnostic identity, with v5/v6 evidence preserved."""
import hashlib
import json
from pathlib import PurePosixPath
import re
import stat

import hook_diagnostic_identity as hook
from hook_diagnostic_identity import _group, _identity_shape, _reference
from run_main import ROOT, REVISION, plain, sha

CORE_SHA256 = "6b895ac942eee539ece652462558144c4a10f8b7e22b4965ba1270008ceca16f"
PREVIOUS_CORE_SHA256 = "b8830fa5bc6103a976d217dba418d9cbf7f27fed5e2cdf4db4587447f5eb17b8"
TBB_SHA256 = "4751126ff5387794ab99dc5ed4caeb0a0e33ab409623edc37728347ca310150e"
SOURCE = "build/windows-core-file-policy-diagnostic/CoreRT.dll"
TBB = "build/windows-core-file-policy-diagnostic/clang_23.1_cxx17_64_md_relwithdebinfo/tbb12.dll"
PREVIOUS_MANIFEST = "research/client-source-code-inputs-v6.json"
MANIFEST = "research/client-source-code-inputs-v7.json"
TRANSACTION = "research/client-source-file-policy-diagnostic-update-v7.json"
BACKUP = "build/checkpoints/source-code-updates/file-policy-v7/CoreRT.dll.previous"
BUILD_RECORD = "research/core-file-policy-diagnostic-build.json"
FIXTURE_BUILD_RECORD = "research/windows-file-policy-diagnostic-fixture-build.json"
FIXTURE_RESULTS = "research/windows-file-policy-diagnostic-fixture-results.json"
RUNNER_SOURCE = "native/windows-mapping-policy/run_file_policy.py"
POLICY_RUNNER_SOURCE = "native/windows-mapping-policy/run.py"
HOOK_RUNNER_SOURCE = "native/windows-mapping-policy/run_hook.py"
PROFILE = "file-policy-diagnostic-v7"
NT_PROFILE = "direct-nt-file-policy-v7"
NT_BUILD_RECORD = "research/windows-mapping-nt-policy-build.json"
NT_RESULTS = "research/windows-mapping-nt-policy-results.json"
NT_PROBE = "build/windows-mapping-nt-policy/mapping_nt_policy_probe.exe"
NT_SOURCES = {"native/windows-mapping-nt-policy/" + name for name in
              ("CMakeLists.txt", "probe.cpp", "build.py", "run.py")}
NT_HELPERS = {RUNNER_SOURCE, POLICY_RUNNER_SOURCE, HOOK_RUNNER_SOURCE}
NT_INPUTS = {NT_PROBE: "mapping_nt_policy_probe.exe",
             "build/windows-mapping-policy/socialclub.dll": "socialclub.dll",
             "build/windows-mapping-policy/mapping-target.dll": "mapping-target.dll",
             SOURCE: "CoreRT.dll", hook.ORDINARY_TBB: "tbb12.dll"}
NT_CASES = tuple((location, operation, mapped) for location in ("foreign", "canonical")
                 for operation in ("open", "create") for mapped in (False, True))
NT_METADATA = re.compile(
    r"MAPPING_NT_POLICY_FIXTURE location=(foreign|canonical) operation=(open|create) mapped=([01]) "
    r"status=(0x[0-9a-f]{8}) source_identity=([01]) target_identity=([01]) "
    r"callback_count=(0|[1-9][0-9]*) fixed_path_hits=(0|[1-9][0-9]*)")
ORIGIN = "public-source-Core-v7-fixed-field-file-policy-diagnostics"
HEADER_TEST = "native/windows-core-file-policy-diagnostic/test_file_policy_diagnostics.py"
HEADER_TEST_COUNT = 6
BASE_MAPPING = "build/windows-core-hook-diagnostic/overlay/FileMapping.Win32.cpp"
BASE_CMAKE = "build/windows-core-hook-diagnostic/overlay/CMakeLists.txt"
BASE_HEADER = "build/windows-core-hook-diagnostic/overlay/HookDiagnostics.h"
BASE_MAPPING_SHA256 = "00cf57d5fe758d61ca67ebb1e6778bc28c240a26d66824c210aaa47c10e2a3c4"
EXPECTED_SOURCES = {"native/windows-core-file-policy-diagnostic/" + name for name in
                    ("build.py", "FilePolicyDiagnostics.h", "test_file_policy_diagnostics.py")}
EXPECTED_OVERLAY = {"build/windows-core-file-policy-diagnostic/overlay/" + name for name in
                    ("CMakeLists.txt", "FileMapping.Win32.cpp", "HookDiagnostics.h", "FilePolicyDiagnostics.h")}
BUILD_FILES = {"toolchain": "native/windows-core/toolchain.cmake", **{
    key: "build/windows-core-file-policy-diagnostic/" + name for key, name in (
        ("log", "build.log"), ("compile_commands", "compile_commands.json"), ("source_scope", "source-scope.txt"))}}
HEADER_LOG = "build/windows-core-file-policy-diagnostic/header-tests.log"
PRESERVED_INPUTS = hook.PRESERVED_INPUTS | {hook.BUILD_RECORD, hook.SOURCE, hook.TBB} | hook.EXPECTED_SOURCES | hook.EXPECTED_OVERLAY
ALLOWED_INPUTS = (set(hook.ALLOWED_INPUTS) | EXPECTED_SOURCES | EXPECTED_OVERLAY | PRESERVED_INPUTS
                  | set(BUILD_FILES.values()) | {SOURCE, TBB, BUILD_RECORD, HEADER_LOG,
                     FIXTURE_BUILD_RECORD, FIXTURE_RESULTS, RUNNER_SOURCE, PREVIOUS_MANIFEST, TRANSACTION, BACKUP,
                     NT_BUILD_RECORD, NT_RESULTS, NT_PROBE} | NT_SOURCES | NT_HELPERS | set(NT_INPUTS))
FILE_FIELDS = ("pid", "operation", "allowed", "canonical_fragment", "folded_fragment", "nt_prefix")
FILE_OPERATIONS = ("create", "open")
INCLUDE = b'#include "FilePolicyDiagnostics.h"\r\n'
PREDICATE = b'IsMappedFilename(moduleNameStr)'
WRAPPERS = {operation: (b'cfx::compat::TraceMappingFilePolicy(cfx::compat::MappingFileOperation::'
                        + operation.encode() + b', moduleNameStr, ' + PREDICATE + b')') for operation in ("Create", "Open")}


def allowed_input(root, name):
    if type(name) is not str or name not in ALLOWED_INPUTS:
        raise RuntimeError("Refusing an undeclared file-policy diagnostic input")
    relative = PurePosixPath(name)
    if relative.is_absolute() or str(relative) != name or any(part in (".", "..") for part in relative.parts):
        raise RuntimeError("File-policy input must be canonical and project-relative")
    path = root / relative
    plain(path)
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or path.resolve(strict=True) != path
            or not path.is_relative_to(root)):
        raise RuntimeError("Require a local regular unaliased file-policy code/evidence input")
    return path


def _valid_file_events(events):
    if not isinstance(events, list):
        return False
    for event in events:
        if (not isinstance(event, dict) or set(event) != set(FILE_FIELDS)
                or type(event["pid"]) is not int or not 1 <= event["pid"] <= 0xffffffff
                or type(event["operation"]) is not str or event["operation"] not in FILE_OPERATIONS
                or any(type(event[key]) is not int or event[key] not in (0, 1) for key in FILE_FIELDS[2:])):
            return False
    return True


def _file_contract(case, location, mode):
    events = case.get("file_events")
    if not _valid_file_events(events):
        return False
    if mode.startswith("--baseline-"):
        return not events and case.get("file_event_contract") is True
    if mode == "--mapped-import" and location == "foreign":
        expected = (0, 0, 0)
        if not any(tuple(event[key] for key in ("allowed", "canonical_fragment", "folded_fragment")) == expected
                   for event in events):
            return False
    return case.get("file_event_contract") is True


def _nt_contract(case, location, operation, mapped):
    if (case.get("location") != location or case.get("operation") != operation
            or type(case.get("mapped")) is not bool or case["mapped"] != mapped
            or type(case.get("exit")) is not int or case["exit"] != 0
            or any(case.get(key) is not True for key in ("nt_contract", "hook_phase_contract", "file_event_contract"))
            or any(type(case.get(key)) is not int or case[key] != 0
                   for key in ("unparsed_hook_event_lines", "unparsed_file_event_lines"))):
        return False
    metadata = case.get("metadata")
    if not isinstance(metadata, list) or len(metadata) != 1 or type(metadata[0]) is not str:
        return False
    match = NT_METADATA.fullmatch(metadata[0])
    if match is None:
        return False
    loc, op, map_bit, status, source_bit, target_bit, callbacks, hits = match.groups()
    redirected = mapped and location == "canonical"
    if (loc, op, map_bit, status, source_bit, target_bit) != (
            location, operation, str(int(mapped)), "0x00000000", str(int(not redirected)), str(int(redirected))):
        return False
    if int(hits) > int(callbacks) or not (int(hits) > 0 if redirected else int(hits) == 0 and int(callbacks) == 0):
        return False
    hook_events = case.get("hook_events")
    if not isinstance(hook_events, list):
        return False
    for event in hook_events:
        if (not isinstance(event, dict) or set(event) != {"pid", "phase", "status"}
                or type(event["pid"]) is not int or not 1 <= event["pid"] <= 0xffffffff
                or type(event["phase"]) is not str or event["phase"] not in hook.PHASES
                or type(event["status"]) is not int or not -1 <= event["status"] <= 12):
            return False
    file_events = case.get("file_events")
    if not _valid_file_events(file_events):
        return False
    if not mapped:
        return not hook_events and not file_events
    bit = int(location == "canonical")
    return ({event["phase"] for event in hook_events} == hook.PHASES
            and any(event["operation"] == operation and event["nt_prefix"] == 1
                    and all(event[key] == bit for key in ("allowed", "canonical_fragment", "folded_fragment"))
                    for event in file_events))


def validate_nt_evidence(root):
    references = []

    def bind(name):
        path = allowed_input(root, name)
        references.append({"path": name, "sha256": sha(path)})
        return path

    build_path = bind(NT_BUILD_RECORD)
    build = json.loads(build_path.read_text())
    _group(build.get("artifacts"), {NT_PROBE})
    _group(build.get("runtime_inputs"), set(NT_INPUTS))
    _group(build.get("source_evidence"), NT_SOURCES)
    _group(build.get("helper_sources"), NT_HELPERS)
    _identity_shape(build.get("core_build_evidence"), BUILD_RECORD)
    _identity_shape(build.get("policy_build_evidence"), hook.POLICY_BUILD_RECORD)
    if (type(build.get("schema_version")) is not int or build["schema_version"] != 1
            or build.get("profile") != NT_PROFILE or build.get("compiled") is not True
            or build.get("cases") != [{"location": loc, "operation": op, "mapped": mapped}
                                     for loc, op, mapped in NT_CASES]):
        raise RuntimeError("Require the compiled direct-NT positive/control matrix")
    inputs = {item["path"]: item for item in build["runtime_inputs"]}
    if (any(item.get("runtime_name") != NT_INPUTS[item["path"]] for item in build["runtime_inputs"])
            or inputs[SOURCE]["sha256"] != CORE_SHA256
            or inputs[hook.ORDINARY_TBB]["sha256"] != hook.ORDINARY_TBB_SHA256
            or any(build["artifacts"][0].get(key) != inputs[NT_PROBE].get(key) for key in ("path", "bytes", "sha256"))):
        raise RuntimeError("Unexpected direct-NT probe/Core/original-TBB identities")
    for item in [*build["artifacts"], *build["runtime_inputs"], *build["source_evidence"],
                 *build["helper_sources"], build["core_build_evidence"], build["policy_build_evidence"]]:
        path = bind(item["path"])
        if sha(path) != item["sha256"] or path.stat().st_size != item["bytes"]:
            raise RuntimeError("A direct-NT fixture code/evidence input changed")
    result = json.loads(bind(NT_RESULTS).read_text())
    if (type(result.get("schema_version")) is not int or result["schema_version"] != 1
            or result.get("core_profile") != NT_PROFILE or result.get("core_sha256") != CORE_SHA256
            or result.get("build_evidence_sha256") != sha(build_path) or result.get("passed") is not True
            or result.get("cleanup") != [{"flag": "-k", "exit": 0}, {"flag": "-w", "exit": 0}]):
        raise RuntimeError("Require real direct-NT tests and successful cleanup")
    cases = result.get("cases")
    if (not isinstance(cases, list) or len(cases) != len(NT_CASES)
            or any(not isinstance(case, dict) or not _nt_contract(case, *expected)
                   for case, expected in zip(cases, NT_CASES))):
        raise RuntimeError("Require all eight direct-NT identity, hook and file-event contracts")
    return references


def validate_evidence(root):
    references = list(hook.validate_evidence(root))

    def bind(name):
        path = allowed_input(root, name)
        references.append({"path": name, "sha256": sha(path)})
        return path

    def bound_identity(item):
        path = bind(item["path"])
        if sha(path) != item["sha256"] or path.stat().st_size != item["bytes"]:
            raise RuntimeError("Bound file-policy diagnostic bytes changed")
        return path

    build_path = bind(BUILD_RECORD)
    build = json.loads(build_path.read_text())
    fixture_path = bind(FIXTURE_BUILD_RECORD)
    fixture = json.loads(fixture_path.read_text())
    _identity_shape(build.get("artifact"), SOURCE)
    _identity_shape(build.get("tbb_artifact"), TBB)
    _identity_shape(build.get("base_v6_build_record"), hook.BUILD_RECORD)
    _identity_shape(build.get("base_v6_overlay"), BASE_MAPPING)
    _group(build.get("source_evidence"), EXPECTED_SOURCES)
    _group(build.get("generated_overlay"), EXPECTED_OVERLAY)
    for key, name in BUILD_FILES.items():
        _identity_shape(build.get("build", {}).get(key), name)
    _identity_shape(build.get("header_and_overlay_tests", {}).get("log"), HEADER_LOG)
    preserved = build.get("preserved_original_and_v6_input_sha256")
    if not isinstance(preserved, dict) or set(preserved) != PRESERVED_INPUTS:
        raise RuntimeError("Unexpected preserved original/v6 path set")
    _reference(fixture.get("build_record"), BUILD_RECORD)
    _reference(fixture.get("policy_build_evidence"), hook.POLICY_BUILD_RECORD)
    _identity_shape(fixture.get("diagnostic_core_input"), SOURCE)
    _identity_shape(fixture.get("tbb_input"), hook.ORDINARY_TBB)
    _group(fixture.get("artifacts"), hook.EXPECTED_ARTIFACTS)
    for key, path in (("runner_source", RUNNER_SOURCE), ("policy_runner_source", POLICY_RUNNER_SOURCE),
                      ("hook_runner_source", HOOK_RUNNER_SOURCE)):
        _identity_shape(fixture.get(key), path)
    if (fixture["diagnostic_core_input"] != build["artifact"] or build["artifact"]["sha256"] != CORE_SHA256
            or build["tbb_artifact"]["sha256"] != TBB_SHA256
            or fixture["tbb_input"]["sha256"] != hook.ORDINARY_TBB_SHA256
            or fixture["build_record"]["sha256"] != sha(build_path)
            or type(fixture.get("schema_version")) is not int or fixture["schema_version"] != 1
            or fixture.get("profile") != PROFILE or fixture.get("file_event_fields") != list(FILE_FIELDS)
            or fixture.get("file_operations") != list(FILE_OPERATIONS)
            or fixture.get("cases") != [{"location": location, "mode": mode} for location, mode in hook.CASES]
            or type(fixture.get("hook_phases")) is not list or len(fixture["hook_phases"]) != len(hook.PHASES)
            or set(fixture["hook_phases"]) != hook.PHASES):
        raise RuntimeError("Unexpected file-policy Core/profile/fixed-field contract")
    if (build.get("compiled") is not True or build.get("source_revision") != REVISION
            or any(build.get(key) is not False for key in ("wine_client_or_game_started", "stage_or_prefix_accessed",
                                                          "existing_patch_queue_changed", "runtime_tested"))):
        raise RuntimeError("Require the separate compile-only file-policy Core build")
    settings = build["build"]
    if any(settings.get(key) != value for key, value in {
            "directory": "build/windows-core-file-policy-diagnostic", "exit": 0, "CFX_SOURCE_DIR": "port/fivem",
            "CFX_CORE_MAPPING_DIAGNOSTICS": "ON", "CFX_CORE_ACCOUNT_FREE_TESTS": "OFF", "runtime": "/MD",
            "target": "AMD64 Windows CoreRT"}.items()):
        raise RuntimeError("Require the full /MD diagnostic build with ordinary client definitions")
    if any(build.get("scope_proof", {}).get(key) != value for key, value in {
            "wrapper_count": 2, "operations": list(FILE_OPERATIONS), "original_predicate_evaluated_once": True,
            "original_boolean_return_preserved": True, "stripped_mapping_sha256": BASE_MAPPING_SHA256,
            "stripped_mapping_equals_exact_v6_bytes": True, "cmake_equals_exact_v6_bytes": True,
            "hook_header_equals_exact_v6_bytes": True, "existing_hook_expressions_tls_gates_callbacks_or_returns_changed": False,
            "mapping_filename_policy_changed": False, "additional_module_or_file_api_probes": False}.items()):
        raise RuntimeError("Require the original predicate and exact reversible two-wrapper scope")
    if any(build.get("payload", {}).get(key) != value for key, value in {
            "fixed_prefix": "CFX_MAPPING_FILE", "fields": list(FILE_FIELDS), "operations": list(FILE_OPERATIONS),
            "filename_filter": "exact socialclub.dll basename, ASCII case-insensitive",
            "canonical_fragment_literal": "Files\\Rockstar Games\\Social Club", "folding": "ASCII A-Z only",
            "nt_prefix_literal": "\\??\\", "paths_pointers_auth_or_profile_values_logged": False,
            "last_error_after_original_predicate_preserved": True, "default": "OFF"}.items()):
        raise RuntimeError("Unexpected file-policy diagnostic payload")
    checks = build["header_and_overlay_tests"]
    if checks.get("exit") != 0 or checks.get("passed") != HEADER_TEST_COUNT:
        raise RuntimeError("Require all six real header and overlay tests")
    for item in [build["artifact"], build["tbb_artifact"], build["base_v6_build_record"], build["base_v6_overlay"],
                 *build["source_evidence"], *build["generated_overlay"],
                 *(settings[key] for key in BUILD_FILES), checks["log"]]:
        bound_identity(item)
    header_log = allowed_input(root, HEADER_LOG).read_text()
    if not re.search(r"\bRan 6 tests\b", header_log) or not re.search(r"(?m)^OK\s*$", header_log):
        raise RuntimeError("Require the six native ON/OFF and reversible-overlay checks")
    v6 = json.loads(allowed_input(root, hook.BUILD_RECORD).read_text())
    expected_preserved = {**v6["preserved_original_input_and_artifact_sha256"],
                          hook.BUILD_RECORD: sha(allowed_input(root, hook.BUILD_RECORD)),
                          hook.SOURCE: PREVIOUS_CORE_SHA256, hook.TBB: hook.TBB_SHA256,
                          **{item["path"]: item["sha256"] for item in v6["source_evidence"] + v6["generated_overlay"]}}
    if preserved != expected_preserved:
        raise RuntimeError("Preserved original/v6 source and artifact identity changed")
    for name in sorted(preserved):
        if sha(bind(name)) != preserved[name]:
            raise RuntimeError("Original or v6 bytes changed")
    overlay = allowed_input(root, "build/windows-core-file-policy-diagnostic/overlay/FileMapping.Win32.cpp").read_bytes()
    if overlay.count(INCLUDE) != 1 or overlay.count(b'cfx::compat::TraceMappingFilePolicy(') != 2:
        raise RuntimeError("Unexpected generated file-policy overlay inventory")
    stripped = overlay.replace(INCLUDE, b'', 1)
    for wrapper in WRAPPERS.values():
        if stripped.count(wrapper) != 1:
            raise RuntimeError("Unexpected file-policy predicate wrapper")
        stripped = stripped.replace(wrapper, PREDICATE, 1)
    if (hashlib.sha256(stripped).hexdigest() != BASE_MAPPING_SHA256
            or stripped != allowed_input(root, BASE_MAPPING).read_bytes()):
        raise RuntimeError("Removing the two wrappers and include must reproduce exact v6 bytes")
    for filename, previous in (("CMakeLists.txt", BASE_CMAKE), ("HookDiagnostics.h", BASE_HEADER)):
        if sha(allowed_input(root, "build/windows-core-file-policy-diagnostic/overlay/" + filename)) != sha(allowed_input(root, previous)):
            raise RuntimeError("Existing CMake or hook header changed in the new overlay")
    policy_path = bind(hook.POLICY_BUILD_RECORD)
    if sha(policy_path) != fixture["policy_build_evidence"]["sha256"]:
        raise RuntimeError("Own policy fixture evidence changed")
    for item in [fixture["runner_source"], fixture["policy_runner_source"], fixture["hook_runner_source"],
                 fixture["tbb_input"], *fixture["artifacts"]]:
        bound_identity(item)
    results = json.loads(bind(FIXTURE_RESULTS).read_text())
    if (type(results.get("schema_version")) is not int or results["schema_version"] != 1
            or results.get("core_profile") != PROFILE or results.get("passed") is not True
            or results.get("core_sha256") != CORE_SHA256 or results.get("fixture_build_sha256") != sha(fixture_path)
            or results.get("only_own_marker_dlls") is not True or results.get("client_started") is not False
            or results.get("real_rockstar_code_staged") is not False
            or results.get("cleanup") != [{"flag": "-k", "exit": 0}, {"flag": "-w", "exit": 0}]):
        raise RuntimeError("Require the real isolated file-policy fixture and successful cleanup")
    cases = results.get("cases")
    if (not isinstance(cases, list) or len(cases) != len(hook.CASES)
            or any(not isinstance(case, dict) or case.get("mapping_contract") is not True
                   or any(type(case.get(key)) is not int or case[key] != 0
                          for key in ("unparsed_hook_event_lines", "unparsed_file_event_lines"))
                   or not hook._case_contract(case, *expected)
                   or not _file_contract(case, *expected) for case, expected in zip(cases, hook.CASES))):
        raise RuntimeError("Require all eight real mapping, hook and file-policy contracts")
    references.extend(validate_nt_evidence(root))
    return references


def validate_version(record):
    for key, expected in (("file_policy_previous_manifest", PREVIOUS_MANIFEST),
                          ("file_policy_update_transaction", TRANSACTION)):
        if record.get(key) != expected:
            raise RuntimeError("Unexpected v7 file-policy evidence reference")
        if sha(allowed_input(ROOT, expected)) != record.get(key + "_sha256"):
            raise RuntimeError("Bound v7 file-policy evidence changed")
    previous = json.loads(allowed_input(ROOT, PREVIOUS_MANIFEST).read_text())
    transaction = json.loads(allowed_input(ROOT, TRANSACTION).read_text())
    if previous.get("developer_code_version") != 6:
        raise RuntimeError("File-policy diagnostics require exact previous v6 metadata")
    hook.validate_version(previous)
    additions = {"file_policy_previous_manifest", "file_policy_previous_manifest_sha256",
                 "file_policy_update_transaction", "file_policy_update_transaction_sha256"}
    if set(record) != set(previous) | additions:
        raise RuntimeError("Unexpected v7 role or metadata fields")
    for key, value in previous.items():
        if key not in ("at", "developer_code_version", "files") and record.get(key) != value:
            raise RuntimeError("v7 must preserve existing v6 role and provenance: " + key)
    old, new = previous.get("files"), record.get("files")
    if (not isinstance(old, list) or not isinstance(new, list) or len(old) != len(new)
            or any(not isinstance(item, dict) or type(item.get("name")) is not str for item in old + new)
            or len({item["name"] for item in old}) != len(old)
            or sum(item["name"] == "CoreRT.dll" for item in old) != 1):
        raise RuntimeError("Unexpected v6/v7 code inventory")
    for before, after in zip(old, new):
        if before["name"] != "CoreRT.dll":
            if before != after:
                raise RuntimeError("v7 may update only its own CoreRT code input")
        elif (before.get("sha256") != PREVIOUS_CORE_SHA256 or after != dict(
                before, sha256=CORE_SHA256, bytes=allowed_input(ROOT, SOURCE).stat().st_size, origin=ORIGIN)):
            raise RuntimeError("Unexpected v7 own-Core delta")
    if (record.get("developer_code_version") != 7 or transaction.get("developer_code_version") != 7
            or transaction.get("source_revision") != REVISION
            or transaction.get("file_policy_previous_manifest") != PREVIOUS_MANIFEST
            or transaction.get("file_policy_previous_manifest_sha256") != record["file_policy_previous_manifest_sha256"]
            or transaction.get("previous_sha256") != PREVIOUS_CORE_SHA256 or transaction.get("new_sha256") != CORE_SHA256
            or transaction.get("target") != "build/windows-source-integration/CoreRT.dll"
            or transaction.get("source") != SOURCE or transaction.get("previous_code_backup") != BACKUP
            or transaction.get("header_checks", {}).get("exit") != 0
            or transaction.get("header_checks", {}).get("passed") != HEADER_TEST_COUNT
            or transaction.get("only_own_core_file_updated") is not True
            or transaction.get("main_citigame_and_original_modules_unchanged") is not True
            or transaction.get("original_conditions_returns_mapping_authentication_and_security_decisions_preserved") is not True
            or transaction.get("profiles_sessions_tickets_read_copied_or_reset") is not False):
        raise RuntimeError("Unexpected file-policy-only Core transaction")
    if sha(allowed_input(ROOT, BACKUP)) != PREVIOUS_CORE_SHA256:
        raise RuntimeError("Previous v6 own Core backup changed")
    if transaction.get("diagnostic_evidence") != validate_evidence(ROOT):
        raise RuntimeError("Exact file-policy diagnostic evidence changed")
