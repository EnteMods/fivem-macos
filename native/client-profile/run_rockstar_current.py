#!/usr/bin/env python3
"""Open the original Rockstar Launcher in the rebound candidate prefix."""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import doctor
import run_current

ROOT = doctor.ROOT
MANUAL = ROOT / 'build/source-update-candidate-nqwlz36g/manual-rockstar-session.py'
MANUAL_SHA = '18a2a842cd66a1e584f3a26f9d5164c1fb809daee629d6b0df1ddfd052f9fd21'
LAST_FAILED_SESSION = ROOT / 'build/source-update-candidate-nqwlz36g/sessions/20261106T133945050607Z/status.json'


def no_related_processes():
    names = ('wine', 'wineserver', 'fivem', 'rockstar', 'socialclub', 'gta5', 'playgtav')
    result = subprocess.run(['/bin/ps', '-axo', 'comm='], check=True, capture_output=True, text=True)
    for line in result.stdout.splitlines():
        command = Path(line.strip())
        if command.parts[-4:] == ('FiveM.app', 'Contents', 'MacOS', 'FiveMLauncher'):
            continue
        if any(term in command.name.casefold() for term in names):
            return False
    return True


def load_manual():
    data = run_current.checked(MANUAL, MANUAL_SHA)
    spec = importlib.util.spec_from_file_location('current_pinned_manual_rockstar', MANUAL)
    module = importlib.util.module_from_spec(spec)
    exec(compile(data, str(MANUAL), 'exec'), module.__dict__)
    return module


def preflight():
    helper = run_current.load_helper()
    run_current.check_binding(helper)
    previous = json.loads(LAST_FAILED_SESSION.read_text())
    if (previous.get('phase') != 'ended' or previous.get('stop_requested') is not True
            or previous.get('cleanup', {}).get('-w') != 0
            or previous.get('verified_code_assets_after') != 422
            or previous.get('core_sha256') != helper.identity.FIXED_CORE
            or previous.get('net_sha256') != helper.identity.ORIGINAL_NET):
        raise RuntimeError('Previous candidate session is not terminal and verified')
    if not no_related_processes():
        raise RuntimeError('A related Wine or Rockstar process is still running')
    manual = load_manual()
    if (manual.game.PREFIX != helper.game.PREFIX or manual.game.STAGE != helper.game.STAGE
            or manual.game.WINDOWS_ENTRYPOINT != helper.game.WINDOWS_ENTRYPOINT):
        raise RuntimeError('Manual Rockstar helper targets another candidate')
    manual.reuse.MANIFEST = ROOT / doctor.VENDOR_MANIFEST
    manual.reuse.MANIFEST_SHA = doctor.VENDOR_SHA
    manual.reuse.verify(manual.game.PREFIX, manual.reuse.inventory())
    return helper, manual


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='Check identities and terminal state without Wine')
    args = parser.parse_args()
    helper, manual = preflight()
    if args.check:
        print(json.dumps({'status': 'OK', 'rockstar_program_files': 145,
                          'prefix_binding': 'current', 'prior_session_terminal': True,
                          'client_started': False}))
        return 0
    manual.game.first.prelogin_lock = lambda old_record: run_current.current_prelogin_lock(helper, old_record)
    return manual.main()


if __name__ == '__main__':
    raise SystemExit(main())
