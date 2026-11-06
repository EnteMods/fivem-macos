"""Start the tested read-only Windows observer; persist only its fixed metadata schema."""
import json
import os
import re
import subprocess
import threading

from run_main import ROOT, plain, sha

OBSERVER_PATH = "build/windows-process-observer/process_observer.exe"
OBSERVER_SHA256 = "776137400dfe36ab720426009b4bfe8500e815a1413cfb89d762088fb0ac70f3"
ROCKSTAR_WINDOWS_ROOT = "C:\\Program Files\\Rockstar Games"
ROCKSTAR_ROLE_PATHS = ("Launcher/Launcher.exe", "Launcher/LauncherPatcher.exe", "Launcher/RockstarService.exe",
                       "Launcher/RockstarSteamHelper.exe", "Social Club/SocialClubHelper.exe")


def observer_artifact(rockstar_scope=False):
    if type(rockstar_scope) is not bool:
        raise ValueError("Only the fixed boolean Rockstar observer scope is allowed")
    build_path = ROOT / "research/windows-process-observer-build.json"
    fixture_path = ROOT / "research/windows-process-observer-source-filter-results.json"
    build = json.loads(build_path.read_text())
    fixture = json.loads(fixture_path.read_text())
    binary = build["binaries"]["process_observer"]
    executable = ROOT / binary["path"]
    plain(executable)

    def require_fixture(record):
        tested = record["build"]["binaries"]["process_observer"]
        if (tested["path"] != OBSERVER_PATH or tested["sha256"] != OBSERVER_SHA256
                or not record["passed"] or not record["full_uint32_exit_codes_and_parentage_passed"]
                or not record["outside_root_and_unlisted_basename_excluded"]
                or not record["minimal_ndjson_schema_passed"]):
            raise RuntimeError("Require fixture evidence for the exact reviewed read-only observer")

    def require_fixture_copies(record, expected_roles):
        copies = record["own_fixture_copy_sha256"]
        for copy_name, fixture_role in expected_roles.items():
            tested_source = record["build"]["binaries"][fixture_role]
            if (tested_source != build["binaries"][fixture_role]
                    or copies.get(copy_name) != tested_source["sha256"]):
                raise RuntimeError("Fixture copy differs from its tested own child/driver artifact")

    if binary["path"] != OBSERVER_PATH or binary["sha256"] != OBSERVER_SHA256 or sha(executable) != OBSERVER_SHA256:
        raise RuntimeError("Require the exact reviewed read-only observer executable")
    require_fixture(fixture)
    require_fixture_copies(fixture, {"FiveM.exe": "observer_fixture_driver",
                                      "FiveM_b3258_GameProcess.exe": "observer_fixture_child"})
    if not fixture["source_client_filter_tested_with_own_fixture_copies"] or fixture["poll_ms"] != 100:
        raise RuntimeError("Require the unchanged default FiveM filter regression")
    identity = {"path": binary["path"], "sha256": binary["sha256"],
                "build_evidence": str(build_path.relative_to(ROOT)),
                "fixture_evidence": str(fixture_path.relative_to(ROOT)),
                "rockstar_code_scope": rockstar_scope, "poll_ms": 10 if rockstar_scope else 100}
    if rockstar_scope:
        path = ROOT / "research/windows-process-observer-rockstar-filter-results.json"
        rockstar = json.loads(path.read_text())
        require_fixture(rockstar)
        require_fixture_copies(rockstar, {"observer_fixture_driver.exe": "observer_fixture_driver",
                                          **{role: "observer_fixture_child" for role in ROCKSTAR_ROLE_PATHS}})
        if (not rockstar["rockstar_code_filter_tested_with_own_fixture_copies"] or rockstar["poll_ms"] != 10
                or len(rockstar["expected_children"]) != 5
                or not all(role in rockstar["own_fixture_copy_sha256"] for role in ROCKSTAR_ROLE_PATHS)
                or not rockstar["invalid_option_cases"] or not all(case["passed"] for case in rockstar["invalid_option_cases"])):
            raise RuntimeError("Require all five fixed Rockstar roles and negative-option fixture evidence")
        identity.update(rockstar_fixture_evidence=str(path.relative_to(ROOT)), rockstar_windows_root=ROCKSTAR_WINDOWS_ROOT)
    return identity


class ProcessObserver:
    def __init__(self, runtime, environment, stage, label, duration, *, rockstar_scope=False):
        self.identity = observer_artifact(rockstar_scope)
        if type(duration) is not int or not 1 <= duration <= 3600:
            raise ValueError("Observer duration must be between 1 and 3600 seconds")
        executable = ROOT / self.identity["path"]
        self.path = ROOT / "logs" / (label + "-observer.ndjson")
        self.error_path = ROOT / "logs" / (label + "-observer-wine.log")
        self.events = []
        self.ready = threading.Event()
        self.reader_error = None
        self.stdout_file = os.fdopen(os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "w")
        self.error_file = os.fdopen(os.open(self.error_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "w")
        observer_env = dict(environment)
        observer_env["WINEDEBUG"] = "-all,err+all"
        windows_stage = "Z:" + str(stage).replace("/", "\\")
        command = [str(runtime.WINE), str(executable), "--source-root", windows_stage, "--duration-ms", str(duration * 1000)]
        if rockstar_scope:
            command += ["--rockstar-code-root", ROCKSTAR_WINDOWS_ROOT, "--poll-ms", "10"]
        self.process = subprocess.Popen(command, cwd=stage, env=observer_env,
                                        stdout=subprocess.PIPE, stderr=self.error_file, text=True, errors="replace")
        self.identity["native_observer_pid"] = self.process.pid
        self.thread = threading.Thread(target=self._read, daemon=True)
        self.thread.start()

    def _read(self):
        try:
            self._read_events()
        except Exception as error:
            self.reader_error = type(error).__name__

    def _read_events(self):
        fields = {"event", "time_ms", "pid", "parent_pid", "basename", "exit_hex"}
        for line in self.process.stdout:
            try:
                event = json.loads(line)
            except (ValueError, TypeError):
                continue
            if not isinstance(event, dict) or set(event) != fields:
                continue
            if not isinstance(event["event"], str) or not re.fullmatch(r"[a-z_-]{1,40}", event["event"]):
                continue
            if not isinstance(event["basename"], str) or not re.fullmatch(r"[A-Za-z0-9_.-]{0,100}", event["basename"]):
                continue
            if event["exit_hex"] is not None and (not isinstance(event["exit_hex"], str) or
                    not re.fullmatch(r"(?:0x)?[0-9A-Fa-f]{0,8}", event["exit_hex"])):
                continue
            if any(type(event[key]) is not int or event[key] < 0 for key in ("time_ms", "pid", "parent_pid")):
                continue
            self.events.append(event)
            self.stdout_file.write(json.dumps(event) + "\n")
            self.stdout_file.flush()
            if event["event"] in ("ready", "observed", "exited"):
                print("Code-process observer:", json.dumps(event), flush=True)
            if event["event"] == "ready":
                self.ready.set()

    def wait_ready(self):
        if not self.ready.wait(30) or self.reader_error or self.process.poll() is not None:
            raise RuntimeError("The read-only process observer did not signal ready before Main")

    def finish_after_wineserver_cleanup(self):
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            # This is our own observer process, never a client/game/account process.
            self.process.terminate()
            self.process.wait(timeout=5)
        self.thread.join(timeout=5)
        reader_alive = self.thread.is_alive()
        if not reader_alive:
            self.stdout_file.close()
        self.error_file.close()
        return {"identity": self.identity, "ready_before_main": self.ready.is_set(),
                "exit": self.process.returncode, "events": self.events,
                "reader_error_type": self.reader_error, "reader_still_running": reader_alive,
                "reader_completed_without_error": not reader_alive and self.reader_error is None,
                "metadata_file": str(self.path.relative_to(ROOT)),
                "commandlines_profile_or_ticket_data_collected": False}
