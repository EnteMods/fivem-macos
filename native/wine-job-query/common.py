"""Shared paths/pins for build-only recipes; imports have no filesystem side effects."""
import json
import os
from pathlib import Path
import re
import stat

RECIPE = Path(__file__).resolve().parent
PROJECT = RECIPE.parents[1]
PINS = json.loads((RECIPE / "pins.json").read_text())
BUILD_NAME = os.environ.get("CFX_WINE_QUERY_BUILD_NAME", PINS["default_build_name"])
if not re.fullmatch(r"wine-job-query-rebuild(?:-[A-Za-z0-9._-]+)?", BUILD_NAME):
    raise RuntimeError("Build name must select an isolated wine-job-query-rebuild directory")
WORK = PROJECT / "build" / BUILD_NAME


def owned_path(path):
    """Reject symlinks/escapes before writes into an ignored build directory."""
    if path != WORK and WORK not in path.parents:
        raise RuntimeError("Output path is outside the isolated build")
    for ancestor in [path] + list(path.parents):
        if ancestor.is_symlink():
            raise RuntimeError("Writable build paths must not contain symlinks")
        if ancestor.exists():
            info = ancestor.lstat()
            if not stat.S_ISDIR(info.st_mode):
                if ancestor != path or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise RuntimeError("Writable build files must be regular files with one link")
        if ancestor == PROJECT / "build":
            break
    if path != WORK and WORK.resolve() not in path.resolve().parents:
        raise RuntimeError("Output path escapes the isolated build")
    return path


owned_path(WORK)
