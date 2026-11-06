#!/usr/bin/env python3
"""Run original OpenSSL known-answer data against the existing MAIN /MT crypto archive."""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import re
import subprocess

import run as abi

ROOT, BUILD, LLVM = abi.ROOT, abi.BUILD, abi.LLVM
SOURCE = ROOT / "port/fivem"
VECTORS = SOURCE / "vendor/openssl/test/recipes/30-test_evp_data"
BUILD_RECORD = BUILD / "openssl-build.json"
RESULT = ROOT / "research/main-openssl-kat-results.json"
ALGORITHMS = ("SHA1", "SHA224", "SHA256", "SHA384", "SHA512")


def entries(path):
    entry = []
    for number, line in enumerate(path.read_text().splitlines() + [""], 1):
        line = line.strip()
        if not line:
            if entry:
                yield entry
                entry = []
        elif not line.startswith("#"):
            key, value = line.split("=", 1)
            entry.append((key.strip(), value.strip(), number))


def binary(value):
    if value.startswith('"') and value.endswith('"'):
        return value[1:-1].encode("ascii")
    return bytes.fromhex(value)


def original_vectors():
    digest_rows, mac_rows, cipher_rows, provenance = [], [], [], []
    counts = {name: 0 for name in ALGORITHMS}
    for entry in entries(VECTORS / "evpdigest.txt"):
        fields = {key: value for key, value, _ in entry}
        name = fields.get("Digest")
        if name not in counts or counts[name] >= 3:
            continue
        parts = []
        for key, value, _ in entry:
            if key == "Input":
                parts.append([binary(value), 1])
            elif key == "Ncopy":
                parts[-1][0] *= int(value)
            elif key == "Count":
                parts[-1][1] = int(value)
        if not 1 <= len(parts) <= 2 or any(len(data) > 4096 for data, _ in parts):
            raise SystemExit("Review changed digest vector structure")
        output = binary(fields["Output"]).hex()
        padded = parts + [(b"", 0)] * (2 - len(parts))
        c_parts = "{" + ",".join('{"%s",%d}' % (data.hex(), count) for data, count in padded) + "}"
        digest_rows.append('{"%s",%s,%d,"%s"}' % (name, c_parts, len(parts), output))
        provenance.append({"kind": "EVP_Digest", "algorithm": name, "file": abi.relative(VECTORS / "evpdigest.txt"),
                           "line": entry[0][2], "input_bytes": sum(len(data) * count for data, count in parts),
                           "expected_hex": output})
        counts[name] += 1
    if set(counts.values()) != {3}:
        raise SystemExit("Expected abc, multi-block, and million-a vectors for each original SHA algorithm")
    counts = {name: 0 for name in ALGORITHMS}
    for entry in entries(VECTORS / "evpmac.txt"):
        fields = {key: value for key, value, _ in entry}
        name = fields.get("Algorithm")
        if fields.get("MAC") != "HMAC" or name not in counts or counts[name] >= 3:
            continue
        mac_rows.append('{"%s","%s","%s","%s"}' %
                        (name, binary(fields["Key"]).hex(), binary(fields["Input"]).hex(), binary(fields["Output"]).hex()))
        provenance.append({"kind": "HMAC", "algorithm": name, "file": abi.relative(VECTORS / "evpmac.txt"),
                           "line": entry[0][2], "expected_hex": binary(fields["Output"]).hex()})
        counts[name] += 1
    if set(counts.values()) != {3}:
        raise SystemExit("Expected original HMAC short/equal/long-block-key vectors")
    selected = {"AES-%d-%s" % (size, mode): 0 for size in (128, 192, 256) for mode in ("ECB", "CBC")}
    for entry in entries(VECTORS / "evpciph.txt"):
        fields = {key: value for key, value, _ in entry}
        name = fields.get("Cipher")
        if name not in selected or selected[name]:
            continue
        cipher_rows.append('{"%s","%s","%s","%s","%s"}' %
                           (name, binary(fields["Key"]).hex(), binary(fields.get("IV", "")).hex(),
                            binary(fields["Plaintext"]).hex(), binary(fields["Ciphertext"]).hex()))
        provenance.append({"kind": "EVP_Cipher_encrypt_and_decrypt", "algorithm": name,
                           "file": abi.relative(VECTORS / "evpciph.txt"), "line": entry[0][2],
                           "expected_ciphertext_hex": binary(fields["Ciphertext"]).hex()})
        selected[name] += 1
    if set(selected.values()) != {1}:
        raise SystemExit("Expected original FIPS-197 ECB and SP800-38A CBC vectors")
    include = BUILD / "openssl-vectors.inc"
    abi.write_if_changed(include, ("static const struct DigestVector digest_vectors[] = {\n" + ",\n".join(digest_rows) +
                       "\n};\nstatic const struct MacVector mac_vectors[] = {\n" + ",\n".join(mac_rows) +
                       "\n};\nstatic const struct CipherVector cipher_vectors[] = {\n" + ",\n".join(cipher_rows) + "\n};\n").encode())
    return {"digest": len(digest_rows), "hmac": len(mac_rows), "aes_encrypt": len(cipher_rows),
            "aes_decrypt": len(cipher_rows), "original_test_cases": provenance, "include_sha256": abi.sha256(include),
            "original_files_sha256": {abi.relative(VECTORS / name): abi.sha256(VECTORS / name)
                                      for name in ("evpdigest.txt", "evpmac.txt", "evpciph.txt")}}


def inspect_static(archive, expected_objects):
    headers = abi.command_output([LLVM / "llvm-readobj", "--file-headers", "--coff-directives", archive])
    machines = re.findall(r"Machine: ([^\n]+)", headers)
    directives = re.findall(r"Directive\(s\): ([^\n]+)", headers)
    defaults = [{lib.lower().strip('"') for lib in re.findall(r"/DEFAULTLIB:([^\s]+)", line, re.IGNORECASE)}
                for line in directives]
    if len(machines) != expected_objects or any(machine != "IMAGE_FILE_MACHINE_AMD64 (0x8664)" for machine in machines):
        raise SystemExit("Unexpected original OpenSSL object count or machine in " + archive.name)
    if any(not {"libcmt.lib", "oldnames.lib"} <= row or
           row - {"libcmt.lib", "oldnames.lib", "bcrypt.lib"} for row in defaults):
        raise SystemExit("Unexpected CRT directive in " + archive.name)
    log = BUILD / (archive.stem + "-inspection.log")
    log.write_text(headers)
    return {"object_count": len(machines), "machine": "AMD64", "objects_with_mt_directives": len(defaults),
            "objects_without_defaultlib_directives": len(machines) - len(defaults),
            "additional_system_defaultlibs": sorted(set().union(*defaults) - {"libcmt.lib", "oldnames.lib"}),
            "md_defaultlib_found": False, "inspection_log": abi.relative(log)}


def build():
    if not abi.BUILD_RECORD.is_file():
        abi.build(abi.DEFAULT_ARCHIVE)
    builtins = json.loads(abi.BUILD_RECORD.read_text())
    if abi.sha256(ROOT / builtins["snapshot"]) != builtins["archive_sha256"]:
        raise SystemExit("Run the arithmetic build before consuming changed MAIN compiler builtins")
    archives = {}
    for name, expected in (("crypto", 625), ("ssl", 44)):
        original = ROOT / ("build/windows-client-vendor/cfx_main_openssl_%s.lib" % name)
        digest = abi.sha256(original)
        inspection = inspect_static(original, expected)
        snapshot = BUILD / ("main-openssl-%s.lib" % name)
        abi.write_if_changed(snapshot, original.read_bytes())
        if abi.sha256(snapshot) != digest or abi.sha256(original) != digest:
            raise SystemExit("OpenSSL archive changed during snapshot")
        archives[name] = {"original": abi.relative(original), "sha256": digest,
                          "snapshot": abi.relative(snapshot), "snapshot_sha256": abi.sha256(snapshot),
                          "static_inspection": inspection, "selected_for_runtime_kat": name == "crypto"}
    vectors = original_vectors()
    args = ["cmake", "-S", str(ROOT / "native/windows-client-tests"), "-B", str(BUILD), "-G", "Ninja",
            "-DCMAKE_TOOLCHAIN_FILE=" + str(ROOT / "native/windows-core/toolchain.cmake"),
            "-DCMAKE_BUILD_TYPE=RelWithDebInfo", "-DCFX_MAIN_OPENSSL_TESTS=ON",
            "-DCFX_MAIN_BUILTINS_ARCHIVE=" + str(ROOT / builtins["snapshot"]),
            "-DCFX_MAIN_CRYPTO_ARCHIVE=" + str(ROOT / archives["crypto"]["snapshot"])]
    subprocess.run(args, check=True)
    subprocess.run(["cmake", "--build", str(BUILD), "--target", "main_openssl_probe", "--parallel", "2"], check=True)
    artifact = BUILD / "main_openssl_probe.exe"
    obj = BUILD / "CMakeFiles/main_openssl_probe.dir/openssl_probe.c.obj"
    object_directives = abi.command_output([LLVM / "llvm-readobj", "--coff-directives", obj])
    object_defaults = {item.lower().strip('"') for item in re.findall(r"/DEFAULTLIB:([^\s]+)", object_directives, re.IGNORECASE)}
    if object_defaults != {"libcmt.lib", "oldnames.lib"}:
        raise SystemExit("OpenSSL API consumer object does not select the /MT CRT")
    imports = abi.command_output([LLVM / "llvm-readobj", "--file-headers", "--coff-imports", artifact])
    imported_dlls = re.findall(r"  Name: ([^\n]+)", imports)
    if "IMAGE_FILE_MACHINE_AMD64 (0x8664)" not in imports or any(
            re.match(r"(?i)(?:msvc(?:p|r)|vcruntime|ucrtbase|api-ms-win-crt-|libcrypto|libssl)", dll) for dll in imported_dlls):
        raise SystemExit("Unexpected machine or dynamic CRT/OpenSSL dependency")
    inspection = BUILD / "main-openssl-probe-inspection.log"
    inspection.write_text(object_directives + imports)
    link_map = BUILD / "main-openssl-probe.map"
    map_lines = link_map.read_text().splitlines()
    for symbol in ("EVP_DigestInit_ex", "HMAC", "EVP_CipherInit_ex"):
        line = next((line for line in map_lines if re.search(r"\b" + symbol + r"\b", line)), "")
        if "main-openssl-crypto:" not in line:
            raise SystemExit("Known-answer API did not resolve from exact MAIN crypto snapshot: " + symbol)
    for entry in archives.values():
        if abi.sha256(ROOT / entry["original"]) != entry["sha256"]:
            raise SystemExit("OpenSSL original archive changed during consumer build")
    record = {"archives": archives, "compiler_rt_archive_sha256": builtins["archive_sha256"],
              "vectors": vectors, "artifact": abi.relative(artifact), "artifact_sha256": abi.sha256(artifact),
              "consumer_object_defaultlibs": sorted(object_defaults),
              "imports": imported_dlls, "dynamic_crt_or_openssl_import_found": False,
              "link_map": abi.relative(link_map), "probe_source_sha256": abi.sha256(ROOT / "native/windows-client-tests/openssl_probe.c"),
              "openssl_source_commit": abi.command_output(["git", "-C", SOURCE / "vendor/openssl", "rev-parse", "HEAD"]).strip(),
              "headers_sha256": {abi.relative(path): abi.sha256(path) for path in
                                  (SOURCE / "code/vendor/openssl/openssl/opensslconf.h", SOURCE / "vendor/openssl/include/openssl/opensslv.h")}}
    BUILD_RECORD.write_text(json.dumps(record, indent=2) + "\n")
    print("MAIN /MT OpenSSL KAT build ready: " + archives["crypto"]["sha256"])


def test():
    record = json.loads(BUILD_RECORD.read_text())
    if abi.sha256(ROOT / record["artifact"]) != record["artifact_sha256"]:
        raise SystemExit("OpenSSL known-answer probe changed after inspection")
    for entry in record["archives"].values():
        if abi.sha256(ROOT / entry["snapshot"]) != entry["sha256"]:
            raise SystemExit("OpenSSL snapshot changed after inspection")
    cases = []
    with abi.probe_prefix(abi.PREFIX, root=ROOT):
        spec = importlib.util.spec_from_file_location("gta_runtime", ROOT.parent / "GTA-V-macOS/scripts/gta-macos.py")
        runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runtime)
        try:
            for name, mask in (("default_cpu_dispatch", None), ("cpu_capabilities_masked_zero", "0")):
                env = runtime.environment()
                env["WINEPREFIX"] = str(abi.PREFIX)
                env.pop("OPENSSL_ia32cap", None)
                if mask is not None:
                    env["OPENSSL_ia32cap"] = mask
                abi.assert_account_free_prefix(abi.PREFIX, root=ROOT)
                result = subprocess.run([str(runtime.WINE), str(ROOT / record["artifact"])], cwd=BUILD,
                                        env=env, capture_output=True, text=True, timeout=60)
                abi.assert_account_free_prefix(abi.PREFIX, root=ROOT)
                output = result.stdout + result.stderr
                log = ROOT / ("logs/main-openssl-kat-%s.log" % name)
                log.write_text(output)
                expected = "OPENSSL_MAIN_KAT_OK digest=15 hmac=15 aes_encrypt=6 aes_decrypt=6 mt=1"
                cases.append({"name": name, "openssl_ia32cap": mask, "returncode": result.returncode,
                              "passed": result.returncode == 0 and expected in output, "log": abi.relative(log)})
                print(name + ": " + output[-1200:])
        finally:
            subprocess.run([str(runtime.ENGINE / "bin/wineserver"), "-k"], env=env,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
            subprocess.run([str(runtime.ENGINE / "bin/wineserver"), "-w"], env=env,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15, check=True)
        record.update({"at": datetime.now(timezone.utc).isoformat(), "passed": len(cases) == 2 and all(case["passed"] for case in cases),
                       "cases": cases, "kat_count_per_process": 42, "account_free": True, "prefix": abi.relative(abi.PREFIX),
                       "shared_guard_and_lock": True, "tls_or_network_tested": False, "main_or_client_executed": False,
                       "auth_or_gui_started": False,
                       "scope": "Original EVP SHA1/2, HMAC SHA1/2 and AES ECB/CBC known answers against exact MAIN /MT Crypto archive; SSL archive static inspection only"})
        for name, archive in record["archives"].items():
            archive["runtime_verified"] = name == "crypto" and record["passed"]
        RESULT.write_text(json.dumps(record, indent=2) + "\n")
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
