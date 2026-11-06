"""Fixed inputs for the opt-in mapping diagnostic Core; no runtime or prefix access."""
import hashlib
import json
from pathlib import PurePosixPath
import re
import stat

from run_main import plain, sha

CORE_SHA256 = "de1d88338377a1463cf9107656ba4a9669f1da087a136f2bcfad2a4eee031377"
PREVIOUS_CORE_SHA256 = "a9f4262d7f0d35b7e87e89d84cb00ed2007ca2dd297a0ae802d2c6877738f0a0"
PRETRACE_SOURCE_SHA256 = "71c853b9205e14033e5d79b3fe4ede5b3c61a42d4ebb6a1127ee509771ad8c9c"
SOURCE = "build/windows-core-mapping-diagnostic/CoreRT.dll"
PREVIOUS_MANIFEST = "research/client-source-code-inputs-v4.json"
MANIFEST = "research/client-source-code-inputs-v5.json"
TRANSACTION = "research/client-source-mapping-diagnostic-update-v5.json"
BACKUP = "build/checkpoints/source-code-updates/mapping-v5/CoreRT.dll.previous"
PHASES = {"setup.enter", "provider.assigned", "setup.complete", "ldr.enter", "map.enter",
          "provider.before", "provider.after", "ldr.mapped"}
BUILD_RECORD = "research/core-mapping-diagnostic-build.json"
FIXTURE_BUILD_RECORD = "research/windows-mapping-diagnostic-fixture-build.json"
FIXTURE_RESULTS = "research/windows-mapping-diagnostic-fixture-results.json"
HEADER_TEST = "tests/test_mapping_diagnostics.py"
EXPECTED_SOURCES = {"port/fivem/code/client/citicore/FileMapping.Win32.cpp",
                    "port/fivem/code/client/citicore/MappingDiagnostics.h", "native/windows-core/CMakeLists.txt"}
EXPECTED_ARTIFACTS = {"build/windows-mapping-diagnostics/mapping_diag_probe.exe",
                      "build/windows-mapping-diagnostics/socialclub.dll",
                      "build/windows-mapping-diagnostics/mapping-target.dll"}
ALLOWED_INPUTS = EXPECTED_SOURCES | EXPECTED_ARTIFACTS | {
    SOURCE, "build/windows-core/CoreRT.dll", BUILD_RECORD, FIXTURE_BUILD_RECORD, FIXTURE_RESULTS, HEADER_TEST}


def allowed_input(root, name):
    if type(name) is not str or name not in ALLOWED_INPUTS:
        raise RuntimeError("Refusing an undeclared mapping diagnostic input")
    relative = PurePosixPath(name)
    if relative.is_absolute() or str(relative) != name or any(part in (".", "..") for part in relative.parts):
        raise RuntimeError("Mapping input must be a canonical project-relative code path")
    path = root / relative
    plain(path)
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise RuntimeError("Mapping input must be a regular unaliased code/evidence file")
    if path.resolve(strict=True) != path or not path.is_relative_to(root):
        raise RuntimeError("Mapping input must remain inside the canonical project root")
    return path


def validate_evidence(root):
    references = []

    def bind(name):
        path = allowed_input(root, name)
        references.append({"path": name, "sha256": sha(path)})
        return path

    build_path = bind(BUILD_RECORD)
    build = json.loads(build_path.read_text())
    core = bind(SOURCE)
    artifact = build["diagnostic_artifact"]
    if (artifact != {"path": SOURCE, "bytes": core.stat().st_size, "sha256": CORE_SHA256}
            or sha(core) != CORE_SHA256 or build["source_revision"] != "9f0e34e1cbdfc34fd05079416791f01938279097"
            or build["build"]["exit"] != 0 or build["build"]["CFX_CORE_MAPPING_DIAGNOSTICS"] != "ON"
            or build["build"]["CFX_CORE_ACCOUNT_FREE_TESTS"] != "OFF"):
        raise RuntimeError("Require the exact ordinary full Core build with only mapping diagnostics enabled")
    if sha(bind("build/windows-core/CoreRT.dll")) != PREVIOUS_CORE_SHA256:
        raise RuntimeError("The unchanged ordinary Core input no longer matches")
    source_evidence = build["source_evidence"]
    if (not isinstance(source_evidence, list) or len(source_evidence) != len(EXPECTED_SOURCES)
            or any(not isinstance(item, dict) or type(item.get("path")) is not str for item in source_evidence)
            or {item["path"] for item in source_evidence} != EXPECTED_SOURCES):
        raise RuntimeError("Unexpected mapping diagnostic source scope")
    for item in source_evidence:
        if sha(bind(item["path"])) != item["sha256"]:
            raise RuntimeError("Mapping diagnostic build sources changed")
    mapping = allowed_input(root, "port/fivem/code/client/citicore/FileMapping.Win32.cpp").read_bytes()
    stripped, includes = re.subn(rb'^#include "MappingDiagnostics.h"\r?\n', b'', mapping, flags=re.M)
    stripped, calls = re.subn(rb'^[ \t]*cfx::compat::Trace(?:SocialClubMapping|MappingProvider)\([^;]+;\r?\n',
                              b'', stripped, flags=re.M)
    if includes != 1 or calls != 8 or hashlib.sha256(stripped).hexdigest() != PRETRACE_SOURCE_SHA256:
        raise RuntimeError("Removing exactly eight trace calls and one include must recover the previous mapping source")
    checks = build["header_tests"]
    if (checks["passed"] != 2 or checks["source"] != HEADER_TEST
            or sha(bind(HEADER_TEST)) != checks["source_sha256"]):
        raise RuntimeError("Require the exact two mapping diagnostic header checks")
    fixture_build_path = bind(FIXTURE_BUILD_RECORD)
    fixture_build = json.loads(fixture_build_path.read_text())
    if fixture_build["diagnostic_core_input"] != artifact or fixture_build["diagnostic_build_evidence"] != {
            "path": str(build_path.relative_to(root)), "sha256": sha(build_path)}:
        raise RuntimeError("Fixture build must bind this diagnostic Core build")
    artifacts = fixture_build["artifacts"]
    if (not isinstance(artifacts, list) or len(artifacts) != len(EXPECTED_ARTIFACTS)
            or any(not isinstance(item, dict) or type(item.get("path")) is not str for item in artifacts)
            or {item["path"] for item in artifacts} != EXPECTED_ARTIFACTS):
        raise RuntimeError("Unexpected own mapping fixture artifact scope")
    for item in artifacts:
        path = bind(item["path"])
        if sha(path) != item["sha256"] or path.stat().st_size != item["bytes"]:
            raise RuntimeError("The tested own mapping fixture artifacts changed")
    fixture = json.loads(bind(FIXTURE_RESULTS).read_text())
    if (fixture.get("passed") is not True or fixture.get("core_sha256") != CORE_SHA256
            or fixture.get("fixture_build_sha256") != sha(fixture_build_path)
            or fixture.get("only_own_marker_dlls") is not True or fixture.get("client_started") is not False
            or fixture.get("real_rockstar_code_staged") is not False
            or fixture.get("cleanup") != [{"flag": "-k", "exit": 0}, {"flag": "-w", "exit": 0}]):
        raise RuntimeError("Require the real own-marker diagnostic fixture and successful prefix cleanup")
    cases = fixture["cases"]
    if len(cases) != 2 or [case["mode"] for case in cases] != ["baseline", "mapped"]:
        raise RuntimeError("Require both baseline and redirected own-marker cases")
    for case, marker in zip(cases, ("0x46585231", "0x46585232")):
        if (case.get("passed") is not True or case.get("exit") != 0
                or case.get("diagnostic_phase_contract") is not True
                or not any(re.search(r"\bmarker=" + marker + r"\b", line) for line in case["own_fixture_metadata"])):
            raise RuntimeError("An actual own marker or diagnostic contract failed")
    if cases[0]["diagnostic_events"] or {event["phase"] for event in cases[1]["diagnostic_events"]} != PHASES:
        raise RuntimeError("Require silent baseline and all eight real diagnostic phases")
    if not any(re.search(r"\bfixed_path_hits=[1-9][0-9]*\b", line) for line in cases[1]["own_fixture_metadata"]):
        raise RuntimeError("Require a real exact own-path provider hit")
    return references
