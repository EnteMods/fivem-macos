#!/usr/bin/env python3
"""Exercise output-path rejection with own temporary host files only."""
import os
from pathlib import Path
import shutil
import tempfile

def main():
    os.environ["CFX_WINE_QUERY_BUILD_NAME"] = "wine-job-query-rebuild-guard-qa-" + str(os.getpid())
    from common import PROJECT, WORK, owned_path

    if WORK.exists():
        raise RuntimeError("Refusing to reuse an existing own QA directory")
    WORK.mkdir()
    checked = []
    try:
        with tempfile.TemporaryDirectory(prefix="wine-query-own-outside-", dir=PROJECT / "build") as temporary:
            outside = Path(temporary) / "own.txt"
            outside.write_text("own fixture remains unchanged\n")
            normal = WORK / "normal.txt"
            normal.write_text("own normal file\n")
            for path, label in [(WORK, "directory"), (normal, "single-link regular file"),
                                (WORK / "new.txt", "new output file")]:
                owned_path(path)
                checked.append(label)
            hardlink = WORK / "hardlink.txt"
            os.link(outside, hardlink)
            symlink = WORK / "symlink.txt"
            symlink.symlink_to(outside)
            fifo = WORK / "pipe"
            os.mkfifo(fifo)
            for path, label in [(hardlink, "hardlink"), (symlink, "symlink"),
                                (fifo, "FIFO"), (WORK / ".." / "outside.txt", "traversal")]:
                try:
                    owned_path(path)
                except RuntimeError:
                    checked.append(label + " rejected")
                else:
                    raise RuntimeError("Unsafe own fixture was accepted: " + label)
            if outside.read_text() != "own fixture remains unchanged\n":
                raise RuntimeError("Own outside fixture changed")
    finally:
        shutil.rmtree(WORK)
    print("PASS {} host-only path cases; no downloads, build, Wine or prefix".format(len(checked)))


if __name__ == "__main__":
    main()
