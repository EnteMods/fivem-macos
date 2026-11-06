"""Forward a normal Cfx browser return to the already running Wine candidate.

The URL arrives on standard input and is never printed or written to disk.
The original FiveM executable handles its own normal protocol and authentication.
"""
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import parse_qsl, urlsplit

ROOT = Path(__file__).resolve().parents[2]
CANDIDATE = ROOT / 'build/source-update-candidate-nqwlz36g'
MAX_BYTES = 65536
GAME_PROCESS = re.compile(
    r'C:\\source-update-game-client\\(?:data\\cache\\subprocess\\)?'
    r'(?:FiveM\.exe|FiveM_b[0-9]{1,6}_GameProcess(?:\.exe)?)', re.IGNORECASE)


def valid_uri(raw):
    if not raw or len(raw) > MAX_BYTES:
        return False
    try:
        value = raw.decode('utf-8', errors='strict')
        if (not value.startswith('fivem://accept-auth?payload=')
                or any(ord(char) <= 32 or ord(char) == 127 for char in value)
                or re.search(r'%(?![0-9a-fA-F]{2})', value)):
            return False
        parts = urlsplit(value)
        if (parts.scheme != 'fivem' or parts.netloc != 'accept-auth'
                or parts.path or parts.fragment):
            return False
        # Match the unchanged stock LinkProtocolIPC message capacity.
        if len(parts.query.encode('utf-16-le')) // 2 > 4096:
            return False
        fields = parse_qsl(parts.query, keep_blank_values=True, strict_parsing=True)
        return len(fields) == 1 and fields[0][0] == 'payload' and bool(fields[0][1])
    except (ValueError, UnicodeError):
        return False


def load_candidate():
    spec = importlib.util.spec_from_file_location('protocol_candidate', CANDIDATE / 'resume-candidate.py')
    candidate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(candidate)
    return candidate


def active_candidate(candidate):
    game = candidate.game
    prelogin = game.verify_finished_prelogin()
    prefix_info = game.PREFIX.stat()
    binding = {'device': prefix_info.st_dev, 'inode': prefix_info.st_ino}
    marker = game.PREFIX / '.source-update-prelogin'
    if (marker.is_symlink() or marker.stat().st_nlink != 1
            or prelogin['prefix_binding'] != binding
            or json.loads(marker.read_text()) != binding):
        raise RuntimeError('Candidate prefix binding differs')
    candidate.identity.verify_input(game)
    lock = game.PREFIX.parent / ('.' + game.PREFIX.name + '.probe.lock')
    descriptor = os.open(lock, os.O_RDWR | os.O_NOFOLLOW)
    try:
        if os.fstat(descriptor).st_nlink != 1:
            raise RuntimeError('Candidate lock identity differs')
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            pass
        else:
            return False
    finally:
        os.close(descriptor)
    sessions = CANDIDATE / 'sessions'
    records = sorted((p for p in sessions.glob('*/status.json')
                      if re.fullmatch(r'[0-9]{8}T[0-9]{12}Z', p.parent.name)), reverse=True)
    if not records:
        return False
    latest = records[0]
    if latest.is_symlink() or latest.resolve() != latest:
        raise RuntimeError('Candidate status identity differs')
    state = json.loads(latest.read_text())
    if (state['phase'] not in ('running', 'parent-exited-awaiting-scoped-observation')
            or state['stage'] != str(game.STAGE.relative_to(ROOT))
            or state['prefix'] != str(game.PREFIX.relative_to(ROOT))
            or (latest.parent / 'stop').exists()):
        return False
    try:
        os.kill(state['controller_pid'], 0)
    except ProcessLookupError:
        return False
    processes = subprocess.run(['/bin/ps', '-axo', 'comm='], check=True,
                               capture_output=True, text=True).stdout.splitlines()
    return any(GAME_PROCESS.fullmatch(name.strip()) for name in processes)


def dispatch(raw):
    if not valid_uri(raw):
        return 2
    candidate = load_candidate()
    if not active_candidate(candidate):
        return 3
    game = candidate.game
    graphics, runtime, renderer, env = game.first.configure()
    env.update(CitizenFX_NoTenUI='1', CFX_NUI_SOFTWARE_144='1', WINEDEBUG='-all')
    # The stock secondary instance delivers the unchanged URL through its IPC.
    process = subprocess.Popen(
        [graphics.runtime.ENGINE / 'bin/wine', game.WINDOWS_ENTRYPOINT, raw.decode('utf-8')],
        env=env, cwd=game.STAGE, stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        code = process.wait(timeout=30)
    except subprocess.TimeoutExpired:
        # Do not terminate a legitimate client while it handles the return.
        return 0
    return 0 if code == 0 else 5


def main():
    try:
        if sys.argv[1:] == ['--check']:
            result = 0 if active_candidate(load_candidate()) else 3
        elif len(sys.argv) == 1:
            result = dispatch(sys.stdin.buffer.read(MAX_BYTES + 1))
        else:
            result = 2
    except Exception:
        # Errors may otherwise include a credential-bearing URL or command line.
        result = 4
    print('CFX_PROTOCOL_HANDOFF code=' + str(result))
    return result


if __name__ == '__main__':
    sys.exit(main())
