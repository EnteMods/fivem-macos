#!/usr/bin/env python3
"""One verified HEAD on the exact pinned public CEF URL through existing MAIN /MT vendors."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
from urllib.parse import quote, urlsplit

import run as abi

ROOT, LLVM = abi.ROOT, abi.LLVM
SOURCE = ROOT / "port/fivem"
BUILD = abi.BUILD / "https"
SNAPSHOTS = BUILD / "archives"
BUILD_RECORD = BUILD / "build-record.json"
RESULT = ROOT / "research/main-https-results.json"
TARGETS = ("cpr", "curl", "openssl_ssl", "openssl_crypto", "nghttp2", "compiler_rt")


def original_input(path, repository, revision, git_path):
    data = path.read_bytes()
    original = subprocess.run(["git", "-C", str(repository), "show", revision + ":" + git_path], capture_output=True, check=True).stdout
    if data != original:
        raise SystemExit("HTTPS policy source differs from pinned original: " + str(path))
    return {"path": abi.relative(path), "revision": revision, "sha256": hashlib.sha256(data).hexdigest()}


def policy_sources():
    lock = json.loads((ROOT / "config/native-port.json").read_text())
    records = [original_input(SOURCE / "code/client/launcher/Download.cpp", SOURCE,
                              lock["base_revision"], "code/client/launcher/Download.cpp")]
    for vendor, name in (("curl", "lib/vtls/openssl.c"), ("curl", "lib/url.c"), ("cpr", "cpr/session.cpp")):
        records.append(original_input(SOURCE / "vendor" / vendor / name, SOURCE / "vendor" / vendor,
                                      lock["submodule_pins"]["vendor/" + vendor], name))
    return {"pinned_original_inputs": records,
            "main_download": {"path": records[0]["path"], "lines": [63, 69, 70],
                              "http_version": "CURL_HTTP_VERSION_2TLS", "tls_min_max": "TLSv1.2 only",
                              "openssl_custom_ssl_context_callback": False,
                              "mbedtls_roots_callback_branch_used": False},
            "curl_default_verification": {"path": records[2]["path"], "lines": [542, 543], "peer": True, "hostname": True},
            "curl_windows_root_import": {"path": records[1]["path"], "lines": [3149, 3155],
                                         "when": "no explicit CAfile or CApath", "store": "Windows ROOT",
                                         "separate_curl_native_ca_option_path": True},
            "cpr_head_and_ca": {"path": records[3]["path"], "lines": [469, 645, 801, 826, 839],
                                "nobody": True, "native_ca_option": "CURLSSLOPT_NATIVE_CA",
                                "curl_error_buffer_exposed_by": "CurlHolder.error and Session.Complete(CURLcode)"},
            "probe_scope_overrides": {"method": "HEAD", "redirects": False, "proxy": "disabled for unauthenticated direct exact-URL probe",
                                      "body_callback": "reject any body bytes", "response_header_limit": 32768,
                                      "custom_ca_or_ssl_context_callback": False, "client_cert_or_credentials": False}}


def cef_target():
    config_path = ROOT / "config/cef-package.json"
    config = json.loads(config_path.read_text())
    for name, digest in config["verified_source_pin_sha256"].items():
        if abi.sha256(SOURCE / name) != digest:
            raise SystemExit("Original CEF package URL source pin changed: " + name)
    name = (SOURCE / "vendor/cef/cef_build_name.txt").read_text().strip()
    if name != config["build_name"]:
        raise SystemExit("CEF package build name differs from original source")
    expected = "https://content.cfx.re/mirrors/vendor/cef/v144/" + quote(name, safe="") + ".zip"
    parts = urlsplit(config["requested_url"])
    if config["requested_url"] != expected or parts.username or parts.password or parts.query or parts.fragment:
        raise SystemExit("Refusing a changed, authenticated or non-pinned HTTPS probe target")
    return {"url": config["requested_url"], "expected_archive_bytes": config["archive_bytes"],
            "config": abi.relative(config_path), "config_sha256": abi.sha256(config_path),
            "original_package_source_pins": config["verified_source_pin_sha256"]}


def archive_snapshot(name, vendor_record):
    entry = next(item for item in vendor_record["archives"] if item["target"] == "cfx_main_" + name)
    original = ROOT / entry["path"]
    digest = abi.sha256(original)
    if digest != entry["sha256"]:
        raise SystemExit("Existing vendor archive differs from verified build record: " + name)
    inspection = abi.command_output([LLVM / "llvm-readobj", "--file-headers", "--coff-directives", original])
    machines = re.findall(r"Machine: ([^\n]+)", inspection)
    defaults = {item.lower().strip('"') for item in re.findall(r"/DEFAULTLIB:([^\s]+)", inspection, re.IGNORECASE)}
    allowed = {"libcmt.lib", "oldnames.lib", "libcpmt.lib", "uuid.lib", "bcrypt.lib"}
    if len(machines) != entry["object_count"] or any(item != "IMAGE_FILE_MACHINE_AMD64 (0x8664)" for item in machines):
        raise SystemExit("HTTPS vendor has unexpected object count or non-AMD64 member: " + name)
    if "libcmt.lib" not in defaults or defaults - allowed:
        raise SystemExit("HTTPS vendor has unexpected or non-/MT runtime directives: " + name)
    log = BUILD / (name + "-inspection.log")
    log.write_text(inspection)
    snapshot = SNAPSHOTS / original.name
    abi.write_if_changed(snapshot, original.read_bytes())
    if abi.sha256(snapshot) != digest or abi.sha256(original) != digest:
        raise SystemExit("HTTPS vendor changed during snapshot: " + name)
    return {"original": abi.relative(original), "sha256": digest, "snapshot": abi.relative(snapshot),
            "snapshot_sha256": abi.sha256(snapshot), "bytes": original.stat().st_size,
            "amd64_objects": len(machines), "default_libraries": sorted(defaults), "inspection": abi.relative(log)}


def build():
    BUILD.mkdir(parents=True, exist_ok=True)
    SNAPSHOTS.mkdir(exist_ok=True)
    policy, target = policy_sources(), cef_target()
    record_path = ROOT / "research/main-vendor-build.json"
    vendor_record = json.loads(record_path.read_text())
    if not vendor_record["passed"]:
        raise SystemExit("Verify the MAIN vendor build before constructing this API probe")
    archives = {name: archive_snapshot(name, vendor_record) for name in TARGETS}
    header = ("static constexpr char HTTPS_TARGET_URL[] = " + json.dumps(target["url"]) + ";\n" +
              "static constexpr curl_off_t HTTPS_EXPECTED_BYTES = " + str(target["expected_archive_bytes"]) + ";\n")
    abi.write_if_changed(BUILD / "https-target.h", header.encode())
    cmake_source = abi.BUILD / "https-source"
    cmake_source.mkdir(exist_ok=True)
    abi.write_if_changed(cmake_source / "CMakeLists.txt", (ROOT / "native/windows-client-tests/https.cmake").read_bytes())
    subprocess.run(["cmake", "-S", str(cmake_source), "-B", str(BUILD), "-G", "Ninja",
                    "-DCMAKE_TOOLCHAIN_FILE=" + str(ROOT / "native/windows-core/toolchain.cmake"),
                    "-DCMAKE_BUILD_TYPE=RelWithDebInfo", "-DCFX_PROJECT_ROOT=" + str(ROOT),
                    "-DCFX_MAIN_SNAPSHOT_DIR=" + str(SNAPSHOTS)], check=True)
    subprocess.run(["cmake", "--build", str(BUILD), "--parallel", "2"], check=True)
    artifact = BUILD / "main_https_probe.exe"
    obj = BUILD / "CMakeFiles/main_https_probe.dir" / Path(*((ROOT / "native/windows-client-tests/https.cpp").parts[1:]))
    obj = Path(str(obj) + ".obj")
    directives = abi.command_output([LLVM / "llvm-readobj", "--coff-directives", obj])
    defaults = {item.lower().strip('"') for item in re.findall(r"/DEFAULTLIB:([^\s]+)", directives, re.IGNORECASE)}
    if "libcmt.lib" not in defaults or defaults - {"libcmt.lib", "oldnames.lib", "libcpmt.lib"}:
        raise SystemExit("HTTPS consumer does not consistently select the static MSVC runtime")
    binary = abi.command_output([LLVM / "llvm-readobj", "--file-headers", "--coff-imports", artifact])
    imported = re.findall(r"  Name: ([^\n]+)", binary)
    if "IMAGE_FILE_MACHINE_AMD64 (0x8664)" not in binary or any(
            re.match(r"(?i)(?:msvc(?:p|r)|vcruntime|ucrtbase|api-ms-win-crt-|libcrypto|libssl|libcurl)", name) for name in imported):
        raise SystemExit("HTTPS probe has unexpected architecture or dynamic runtime/library imports")
    (BUILD / "consumer-inspection.log").write_text(directives + binary)
    map_path = BUILD / "main-https-probe.map"
    map_lines = map_path.read_text().splitlines()
    link_symbols = {}
    for symbol, origin in (("?PrepareHead@Session@cpr@@", "cfx_main_cpr:"), ("curl_easy_perform", "cfx_main_curl:"),
                           ("SSL_connect", "cfx_main_openssl_ssl:"), ("X509_verify_cert", "cfx_main_openssl_crypto:"),
                           ("nghttp2_session_client_new2", "cfx_main_nghttp2:")):
        line = next((line for line in map_lines if symbol in line and origin in line), "")
        if not line:
            raise SystemExit("HTTPS link-map origin missing: " + symbol)
        link_symbols[symbol] = line.strip()
    if any(abi.sha256(ROOT / entry["original"]) != entry["sha256"] for entry in archives.values()):
        raise SystemExit("Original HTTPS vendor archive changed during consumer build")
    record = {"target": target, "source_policy": policy, "archives": archives,
              "main_vendor_build_record": abi.relative(record_path), "main_vendor_build_record_sha256": abi.sha256(record_path),
              "artifact": abi.relative(artifact), "artifact_sha256": abi.sha256(artifact),
              "consumer_object_default_libraries": sorted(defaults), "imports": imported,
              "dynamic_crt_or_tls_library_import_found": False, "link_map": abi.relative(map_path), "link_map_origins": link_symbols,
              "own_source_sha256": {abi.relative(path): abi.sha256(path) for path in
                                    (ROOT / "native/windows-client-tests/https.cpp", ROOT / "native/windows-client-tests/https.cmake")}}
    BUILD_RECORD.write_text(json.dumps(record, indent=2) + "\n")
    print("MAIN /MT HTTPS HEAD probe built; no network request executed")


def test():
    record = json.loads(BUILD_RECORD.read_text())
    if cef_target() != record["target"] or abi.sha256(ROOT / record["artifact"]) != record["artifact_sha256"]:
        raise SystemExit("HTTPS probe or pinned target changed after build")
    for entry in record["archives"].values():
        if abi.sha256(ROOT / entry["snapshot"]) != entry["sha256"]:
            raise SystemExit("HTTPS vendor snapshot changed after build")
    cleared = ("CURL_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR", "SSLKEYLOGFILE", "OPENSSL_CONF",
               "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")
    timeout = False
    with abi.probe_prefix(abi.PREFIX, root=ROOT):
        spec = importlib.util.spec_from_file_location("gta_runtime", ROOT.parent / "GTA-V-macOS/scripts/gta-macos.py")
        runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runtime)
        env = runtime.environment()
        env["WINEPREFIX"] = str(abi.PREFIX)
        for name in cleared:
            env.pop(name, None)
        try:
            abi.assert_account_free_prefix(abi.PREFIX, root=ROOT)
            try:
                process = subprocess.run([str(runtime.WINE), str(ROOT / record["artifact"])], cwd=BUILD,
                                         env=env, capture_output=True, text=True, timeout=60)
                output, returncode = process.stdout + process.stderr, process.returncode
            except subprocess.TimeoutExpired as error:
                def text(value): return value.decode(errors="replace") if isinstance(value, bytes) else (value or "")
                output, returncode, timeout = text(error.stdout) + text(error.stderr), None, True
            abi.assert_account_free_prefix(abi.PREFIX, root=ROOT)
        finally:
            subprocess.run([str(runtime.ENGINE / "bin/wineserver"), "-k"], env=env,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
            subprocess.run([str(runtime.ENGINE / "bin/wineserver"), "-w"], env=env,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15, check=True)
    at = datetime.now(timezone.utc)
    log = ROOT / ("logs/main-https-head-" + at.strftime("%Y%m%d-%H%M%S") + ".log")
    log.write_text(output)
    lines = [line[len("HTTPS_HEAD_RESULT "):] for line in output.splitlines() if line.startswith("HTTPS_HEAD_RESULT ")]
    response = json.loads(lines[0]) if len(lines) == 1 else None
    record.update({"at": at.isoformat(), "process_returncode": returncode, "process_timeout": timeout,
                   "passed": returncode == 0 and bool(response and response["passed"]), "response": response,
                   "tls_http_stack_verified": bool(response and response["tls_verified"] and response["http_response_received"]),
                   "single_head_attempt": True, "retry_after_ca_or_api_error": False,
                   "account_free": True, "shared_guard_and_lock": True, "prefix": abi.relative(abi.PREFIX),
                   "child_environment_names_cleared": list(cleared), "log": abi.relative(log),
                   "custom_ca_added": False, "peer_or_host_check_disabled": False,
                   "main_or_client_executed": False, "auth_or_gui_started": False,
                   "scope": "Own unauthenticated HEAD on exact pinned public CEF URL, actual MAIN /MT CPR/curl/OpenSSL/nghttp2 archives; no client/auth/updater integrity claim"})
    RESULT.write_text(json.dumps(record, indent=2) + "\n")
    print(output[-3000:])
    if not record["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "test", "all"))
    action = parser.parse_args().action
    if action in ("build", "all"):
        build()
    if action in ("test", "all"):
        test()
