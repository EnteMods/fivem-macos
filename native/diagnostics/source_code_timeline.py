#!/usr/bin/env python3
"""Extract only fixed code basenames and numeric mapping markers from one source run."""
import argparse
import collections
import datetime
import json
import os
from pathlib import Path
import re
import stat

ROOT = Path(__file__).resolve().parents[2]
LABEL = re.compile(r"client-source-ui-resume-[0-9]{8}T[0-9]{12}Z")
NAMES = frozenset({"socialclub.dll", "corert.dll", "legitimacy.dll", "game_mtl.bin",
                   "steam_api64.dll", "citizen-resources-core.dll"})
LOAD = re.compile(r'^(?:[0-9A-Fa-f]+:)?([0-9A-Fa-f]+):trace:loaddll:build_module '
                  r'Loaded L"([^"\r\n]*)" at [0-9A-Fa-f]+: (builtin|native)\s*$')
MAPPING = re.compile(r'^(?:[0-9A-Fa-f]+:)?([0-9A-Fa-f]+):warn:'
                     r'(?:debugstr:OutputDebugStringA|seh:dispatch_exception) '
                     r'"\[CFX_MAPPING\] pid=([0-9]+) phase=(setup.enter|provider.assigned|setup.complete) '
                     r'provider_set=([01]) provider_called=([01]) return_changed=([01])\\n"\s*$')


def code_location(path, basename):
    normalized = path.replace("\\\\", "\\").replace("\\", "/").lower()
    stage = ("Z:" + str(ROOT / "build/windows-source-integration")).lower()
    known = {
        stage + "/corert.dll": "source-core",
        stage + "/data/game-storage/ros_2090/socialclub.dll": "source-staged-ros2090",
        "c:/program files/rockstar games/social club/socialclub.dll": "source-rockstar-installed",
    }
    return known.get(normalized, "other-code-location-not-retained")


def extract(lines):
    events = []
    for number, line in enumerate(lines, 1):
        match = LOAD.fullmatch(line)
        if match:
            basename = match[2].replace("\\", "/").rsplit("/", 1)[-1].lower()
            if basename in NAMES:
                events.append({"line": number, "wine_thread_hex": match[1].lower(),
                               "kind": "code_load", "basename": basename, "provider": match[3],
                               "code_location_class": code_location(match[2], basename)})
            continue
        match = MAPPING.fullmatch(line)
        if match:
            events.append({"line": number, "wine_thread_hex": match[1].lower(),
                           "kind": "mapping_setup", "pid": int(match[2]), "phase": match[3],
                           "provider_set": int(match[4]), "provider_called": int(match[5]),
                           "return_changed": int(match[6])})
    return events


def read_plain(path):
    current = path
    while current != ROOT.parent:
        if current.is_symlink():
            raise RuntimeError("Refusing redirected diagnostic input")
        current = current.parent
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        os.close(descriptor)
        raise RuntimeError("Require an ordinary single-link run log")
    return os.fdopen(descriptor, errors="replace")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("label")
    args = parser.parse_args()
    if not LABEL.fullmatch(args.label):
        parser.error("Require an exact source-resume run label, not an arbitrary path")
    source = ROOT / "logs" / (args.label + ".log")
    with read_plain(source) as lines:
        events = extract(lines)
    counts = collections.Counter(e["basename"] for e in events if e["kind"] == "code_load")
    record = {"at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "source_label": args.label, "fixed_code_load_counts": dict(counts), "events": events,
              "paths_arguments_exception_payloads_and_other_log_fields_retained": False,
              "log_contents_hashed_or_copied": False,
              "limit": "Global log order and Wine thread identifiers only. No automatic cross-thread process attribution, failed-load detection or cause claim."}
    output = ROOT / "research" / (args.label + "-code-timeline.json")
    with output.open("x") as target:
        json.dump(record, target, indent=2)
        target.write("\n")
    print(json.dumps({"result": str(output.relative_to(ROOT)), "counts": dict(counts),
                      "events": len(events)}, indent=2))


if __name__ == "__main__":
    main()
