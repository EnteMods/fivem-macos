#!/usr/bin/env python3
"""Offline metadata/syntax checks only; no downloads, extraction, build or Wine."""
import argparse
import ast
import hashlib
import json
from pathlib import Path

from common import PINS, PROJECT, RECIPE, WORK


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--audit-cache", type=Path)
    parser.add_argument("--prepared-source", type=Path)
    args = parser.parse_args()
    if WORK == PROJECT / "build/wine-job-query":
        raise RuntimeError("Recipe must not target the tested candidate directory")
    patch = PROJECT / PINS["query_patch"]["path"]
    if digest(patch) != PINS["query_patch"]["sha256"]:
        raise RuntimeError("Tracked patch differs from the tested patch")
    headers = [line for line in patch.read_text().splitlines() if line.startswith("+++ b/")]
    if sorted(line[6:] for line in headers) != sorted(item["path"] for item in PINS["query_patch"]["source_files"]):
        raise RuntimeError("Tracked patch has an unexpected source scope")
    expected = ["0001", "0002", "0003"] + [str(i).zfill(4) for i in range(5, 25)]
    if PINS["highball"]["applied_patch_numbers"] != expected:
        raise RuntimeError("Original baseline patch set differs")
    files = PINS["highball"]["files"]
    patch_numbers = [item["path"].split("/")[-1].split("-")[0] for item in files if item["path"].startswith("patches/")]
    if patch_numbers != expected or len(files) != 25:
        raise RuntimeError("Pinned baseline blobs differ")
    for item in files:
        expected_url = "https://raw.githubusercontent.com/gauthierpiarrette/highball-engine/" + PINS["highball"]["commit"] + "/" + item["path"]
        if item["url"] != expected_url:
            raise RuntimeError("Original source URL is not immutable/pinned")
        if args.audit_cache:
            path = args.audit_cache / item["path"]
            if path.stat().st_size != item["bytes"] or digest(path) != item["sha256"]:
                raise RuntimeError("Cached original blob differs")
            blob = hashlib.sha1(b"blob " + str(path.stat().st_size).encode() + b"\0" + path.read_bytes()).hexdigest()
            if blob != item["git_blob_sha1"]:
                raise RuntimeError("Cached original Git blob differs")
    if args.prepared_source:
        for item in PINS["query_patch"]["source_files"]:
            if digest(args.prepared_source / item["path"]) != item["proposed_sha256"]:
                raise RuntimeError("Existing reviewed query source differs")
        for name, expected_hash in PINS["original_generator"]["generated_after_sha256"].items():
            if digest(args.prepared_source / name) != expected_hash:
                raise RuntimeError("Existing original generator output differs")
    for path in RECIPE.glob("*.py"):
        ast.parse(path.read_text(), filename=str(path))
    print(json.dumps({"passed": True, "patch_source_files": len(headers),
                      "pinned_original_blobs": len(files),
                      "cached_original_blobs_checked": bool(args.audit_cache),
                      "existing_query_and_generator_outputs_checked": bool(args.prepared_source),
                      "default_build_output": str(WORK.relative_to(PROJECT)),
                      "downloads_builds_runtime_or_prefix_actions": False}, indent=2))


if __name__ == "__main__":
    main()
