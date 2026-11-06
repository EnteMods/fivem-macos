#!/usr/bin/env python3
"""Validate real GameProcess PE layout and TLS build outputs without executing them."""
import datetime
import hashlib
import json
from pathlib import Path
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build/windows-client"


class PE:
    def __init__(self, path):
        self.path = path
        self.data = path.read_bytes()
        if self.data[:2] != b"MZ":
            raise ValueError("Missing MZ header")
        offset = struct.unpack_from("<I", self.data, 60)[0]
        if self.data[offset:offset + 4] != b"PE\0\0":
            raise ValueError("Missing PE signature")
        machine, count, _, _, _, optional_size, _ = struct.unpack_from("<HHIIIHH", self.data, offset + 4)
        self.optional = offset + 24
        if machine != 0x8664 or self.u16(self.optional) != 0x20b:
            raise ValueError("Require genuine Windows AMD64 PE32+")
        self.image_base = self.u64(self.optional + 24)
        self.entry = self.u32(self.optional + 16)
        self.alignment = self.u32(self.optional + 32)
        self.image_size = self.u32(self.optional + 56)
        self.stack = self.u64(self.optional + 72)
        self.sections = []
        for index in range(count):
            start = self.optional + optional_size + index * 40
            name, size, rva, raw_size, raw_offset = struct.unpack_from("<8sIIII", self.data, start)
            self.sections.append({"name": name.rstrip(b"\0").decode("ascii"), "rva": rva,
                                  "virtual_bytes": size, "raw_bytes": raw_size, "raw_offset": raw_offset,
                                  "characteristics": self.u32(start + 36)})

    def u16(self, offset): return struct.unpack_from("<H", self.data, offset)[0]
    def u32(self, offset): return struct.unpack_from("<I", self.data, offset)[0]
    def u64(self, offset): return struct.unpack_from("<Q", self.data, offset)[0]

    def directory(self, index):
        return struct.unpack_from("<II", self.data, self.optional + 112 + index * 8)

    def file_offset(self, rva, length):
        for section in self.sections:
            delta = rva - section["rva"]
            if delta >= 0 and delta + length <= section["raw_bytes"]:
                offset = section["raw_offset"] + delta
                if offset + length <= len(self.data): return offset
        raise ValueError("RVA has no complete raw-data mapping")

    def tls(self):
        rva, size = self.directory(9)
        if not rva: return None
        offset = self.file_offset(rva, 40)
        start, end, index, callbacks, zero, flags = struct.unpack_from("<QQQQII", self.data, offset)
        return {"template_bytes": end - start, "index_rva": index - self.image_base,
                "callbacks_rva": callbacks - self.image_base, "zero_fill": zero, "flags": flags}


def main():
    revision = subprocess.run(["git", "-C", str(ROOT / "port/fivem"), "rev-parse", "HEAD"],
                              capture_output=True, text=True, check=True).stdout.strip()
    if revision != "9f0e34e1cbdfc34fd05079416791f01938279097":
        raise SystemExit("Review the GameProcess source/layout contract after changing source revision")
    game = PE(BUILD / "CitizenFX_SubProcess_game_3889_aslr.bin")
    tls = PE(BUILD / "CitiLaunch_TLSDummy.dll")
    expected_names = [".cdummy", ".pdata", ".cld", ".clr", ".zdata", ".rsrc", ".reloc", ".tls"]
    names = [section["name"] for section in game.sections]
    dummy = game.sections[0]
    reserve_end = dummy["rva"] + dummy["virtual_bytes"]
    exception_rva, exception_bytes = game.directory(3)
    if exception_bytes % 12: raise ValueError("Partial runtime-function table entry")
    offset = game.file_offset(exception_rva, exception_bytes)
    functions = [struct.unpack_from("<III", game.data, offset + index * 12)
                 for index in range(exception_bytes // 12)]
    executable_entry = any(section["rva"] <= game.entry < section["rva"] + section["virtual_bytes"]
                           and section["characteristics"] & 0x20000000 for section in game.sections)
    checks = {
        "only_explicitly_reviewed_sections": names == expected_names,
        "game_reserve_starts_at_first_aligned_rva": dummy["name"] == ".cdummy" and dummy["rva"] == game.alignment,
        "original_dummy_and_stub_capacity": dummy["virtual_bytes"] == 0x6000000 + 0x100000,
        "all_native_sections_after_game_reserve": all(section["rva"] >= reserve_end for section in game.sections[1:]),
        "entrypoint_after_game_reserve_and_executable": game.entry >= reserve_end and executable_entry,
        "original_game_stack_reserve": game.stack == 0x180000,
        "native_function_records_after_game_reserve": bool(functions) and all(reserve_end <= begin < end <= game.image_size for begin, end, _ in functions),
        "native_function_records_sorted": functions == sorted(functions, key=lambda entry: entry[0]),
        "tls_dummy_contains_original_capacity": tls.tls()["template_bytes"] >= 7096 * 4,
    }
    raw_dummy = game.data[dummy["raw_offset"]:dummy["raw_offset"] + dummy["raw_bytes"]]
    record = {
        "at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "checks": checks,
        "passed": all(checks.values()), "game_executed": False, "tls_dll_loaded": False,
        "source_revision": revision,
        "source_diff_sha256": hashlib.sha256(subprocess.run(["git", "-C", str(ROOT / "port/fivem"), "diff", "HEAD"],
                                                             capture_output=True, check=True).stdout).hexdigest(),
        "game": {"path": str(game.path.relative_to(ROOT)), "sha256": hashlib.sha256(game.data).hexdigest(),
                 "file_bytes": len(game.data), "image_base": game.image_base, "image_bytes": game.image_size,
                 "entry_rva": game.entry, "stack_bytes": game.stack, "sections": game.sections,
                 "runtime_function_count": len(functions), "tls": game.tls(),
                 "dummy_raw_bytes_all_zero": not any(raw_dummy)},
        "tls_dummy": {"path": str(tls.path.relative_to(ROOT)), "sha256": hashlib.sha256(tls.data).hexdigest(),
                      "file_bytes": len(tls.data), "tls": tls.tls()},
        "layout_method": "LLD23 supported declarative /sectionlayout file; no fixed-address or post-link code patch",
        "dump_retarget_applied": False, "private_signing_applied": False,
        "limits": ["Game dump and proprietary signing tools unavailable",
                   "clang emits the named .cdummy as initialized zero bytes; larger file than original compact BSS",
                   "TLS slot index and actual game loading remain runtime tests, not established by PE metadata"],
    }
    (ROOT / "research/client-game-build-results.json").write_text(json.dumps(record, indent=2) + "\n")
    print("Actual Game3889 PE layout", "PASS" if record["passed"] else "FAIL",
          "; runtime functions", len(functions), "; TLS dummy bytes", tls.tls()["template_bytes"])
    if not record["passed"]: raise SystemExit(1)


if __name__ == "__main__":
    main()
