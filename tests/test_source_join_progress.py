import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'native/windows-client'))
import source_join_progress as progress


def line(tick, message):
    return f'[{tick:>10}] [b3258_GameProc]        CrBrowserMain/ {message}\r\n'.encode()


class SourceJoinProgressTests(unittest.TestCase):
    def test_keeps_cache_phases_and_an_exact_percentage(self):
        raw = io.BytesIO(b''.join((
            line(1, 'OnConnectionProgress: Requesting server variables...'),
            line(2, 'OnConnectionProgress: Verifying game content... (100%)'),
            line(3, 'OnConnectionProgress: Updating game storage... (41%)'),
            line(4, 'OnConnectionProgress: Updating game storage... (105%)'),
        )))
        self.assertEqual(progress.summarize(raw), {
            'counts': {'server_variables': 1, 'game_cache_verify': 1, 'game_cache_update': 1},
            'latest': {'tick_ms': 3, 'phase': 'game_cache_update', 'percent': 41},
        })

    def test_identifiers_and_untrusted_progress_are_never_returned(self):
        raw = io.BytesIO(b''.join((
            line(1, 'OnConnectionProgress: token=example https://example.test/account'),
            line(2, '^2Received connectOK: ServerID 345, SlotID 234, HostID 123'),
            line(3, 'OnConnectionError: account example at 192.0.2.1'),
        )))
        self.assertEqual(progress.summarize(raw), {
            'counts': {'server_protocol_ack': 1, 'connection_error': 1},
            'latest': {'tick_ms': 3, 'phase': 'connection_error'},
        })

    def test_build_switch_is_distinct_from_server_admission(self):
        raw = io.BytesIO(line(10, 'Switching from build 3258 to build 3889 (exe 3889)...'))
        self.assertEqual(progress.summarize(raw), {
            'counts': {'game_build_switch_requested': 1},
            'latest': {'tick_ms': 10, 'phase': 'game_build_switch_requested',
                       'from_build': 3258, 'to_build': 3889, 'exe_build': 3889},
        })

    def test_exact_missing_ticket_rejection_is_distinct_from_other_errors(self):
        raw = io.BytesIO(line(11, 'OnConnectionError: Connection rejected by server: '
                                 'No authentication ticket was specified.'))
        self.assertEqual(progress.summarize(raw), {
            'counts': {'server_rejected_missing_auth_ticket': 1},
            'latest': {'tick_ms': 11, 'phase': 'server_rejected_missing_auth_ticket'},
        })

    def test_ignores_partial_lines_other_processes_and_overlong_fragments(self):
        raw = io.BytesIO(b''.join((
            b'a' * progress.MAX_LINE_BYTES + line(1, 'Downloading completed'),
            line(2, 'OnConnectionError: external').replace(b'b3258_GameProc', b'Launcher'),
            line(3, '^2Network connected, triggering initial game load...'),
            line(4, 'OnConnectionError: partial')[:-2],
        )))
        self.assertEqual(progress.summarize(raw), {
            'counts': {'network_active_game_load_requested': 1},
            'latest': {'tick_ms': 3, 'phase': 'network_active_game_load_requested'},
        })

    def test_resource_error_is_distinct_when_wrapped_by_connection_error(self):
        raw = io.BytesIO(b''.join((
            line(100, 'OnConnectionProgress: Downloading content'),
            line(101, 'Could not get resource mounter for resource mapmanager.'),
            line(102, 'OnConnectionError: ^1Could not get resource mounter for resource mapmanager.'),
        )))
        self.assertEqual(progress.summarize(raw), {
            'counts': {'server_resource_download_started': 1, 'resource_mounter_error': 2},
            'latest': {'tick_ms': 102, 'phase': 'resource_mounter_error'},
        })

    def test_mounter_diagnostics_export_only_a_fixed_scheme_class(self):
        for scheme, expected in (('ci', 'ci'), ('global', 'global'), ('PRIVATE-IDENTIFIER', 'other')):
            with self.subTest(scheme=scheme):
                raw = io.BytesIO(line(200, 'Resource URI ' + scheme +
                    '://private-user/private-path?ticket=private-ticket#private-fragment has no mounter.'))
                self.assertEqual(progress.summarize(raw), {
                    'counts': {'resource_uri_without_mounter': 1},
                    'latest': {'tick_ms': 200, 'phase': 'resource_uri_without_mounter',
                               'scheme_class': expected},
                })


class StandaloneLogSelectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.script = self.root / 'source_join_progress.py'
        shutil.copyfile(progress.__file__, self.script)
        self.logs = self.root / 'chosen-installation' / 'logs'
        self.logs.mkdir(parents=True)
        self.log = self.logs / 'CitizenFX_log_2026-11-06T000000.log'
        self.log.write_bytes(line(1, 'OnConnectionProgress: Handshaking with server...'))

    def run_reader(self, *args):
        return subprocess.run([sys.executable, '-B', str(self.script), *map(str, args)],
                              cwd=self.root, capture_output=True, text=True, timeout=5)

    def test_copied_standalone_cli_uses_only_the_explicit_installation(self):
        for args in (('--log', self.log), ('--logs-dir', self.logs, self.log.name)):
            with self.subTest(args=args):
                result = self.run_reader(*args)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), {
                    'counts': {'handshake_started': 1},
                    'latest': {'tick_ms': 1, 'phase': 'handshake_started'},
                })
                self.assertNotIn(str(self.root), result.stdout)

    def test_no_implicit_developer_installation_and_no_ambiguous_file_selection(self):
        for args in ((self.log.name,), ('--log', self.log, self.log.name),
                     ('--logs-dir', self.logs, '../' + self.log.name)):
            with self.subTest(args=args):
                self.assertEqual(self.run_reader(*args).returncode, 2)

    def test_redirected_directory_or_file_is_refused_without_exporting_paths(self):
        alias = self.root / 'redirected'
        alias.symlink_to(self.logs, target_is_directory=True)
        file_alias = self.logs / 'CitizenFX_log_2026-11-06T000001.log'
        file_alias.symlink_to(self.log)
        for selected in (alias / self.log.name, file_alias):
            with self.subTest(selected=selected):
                result = self.run_reader('--log', selected)
                self.assertEqual(result.returncode, 1)
                self.assertNotIn(str(self.root), result.stderr)
                self.assertEqual(result.stdout, '')

    def test_a_named_pipe_cannot_block_the_diagnostic_reader(self):
        fifo = self.logs / 'CitizenFX_log_2026-11-06T000002.log'
        os.mkfifo(fifo)
        result = self.run_reader('--log', fifo)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, '')
