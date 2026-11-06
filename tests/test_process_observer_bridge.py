"""Artifact admission and exact observer scope using own bytes and mocked processes only."""
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / 'native/windows-client'))
import process_observer_bridge as bridge


class ProcessObserverBridgeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        (self.root / 'research').mkdir()
        (self.root / 'logs').mkdir()
        binary = self.root / bridge.OBSERVER_PATH
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b'Own inert observer artifact fixture, never executed')
        self.digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        self.binary = {'path': bridge.OBSERVER_PATH, 'sha256': self.digest}
        child = {'path': 'build/windows-process-observer/observer_fixture_child.exe', 'sha256': 'a' * 64}
        driver = {'path': 'build/windows-process-observer/observer_fixture_driver.exe', 'sha256': 'b' * 64}
        build = {'binaries': {'process_observer': self.binary, 'observer_fixture_child': child,
                               'observer_fixture_driver': driver}}
        common = {'build': build, 'passed': True, 'full_uint32_exit_codes_and_parentage_passed': True,
                  'outside_root_and_unlisted_basename_excluded': True, 'minimal_ndjson_schema_passed': True}
        self.source = dict(common, source_client_filter_tested_with_own_fixture_copies=True, poll_ms=100,
                           own_fixture_copy_sha256={'FiveM.exe': driver['sha256'],
                                                    'FiveM_b3258_GameProcess.exe': child['sha256']})
        self.rockstar = dict(common, rockstar_code_filter_tested_with_own_fixture_copies=True, poll_ms=10,
                             expected_children=[{} for _ in range(5)],
                             own_fixture_copy_sha256={'observer_fixture_driver.exe': driver['sha256'],
                                 **{name: child['sha256'] for name in bridge.ROCKSTAR_ROLE_PATHS}},
                             invalid_option_cases=[{'passed': True}])
        self.write('build', build)
        self.write('source-filter-results', self.source)
        self.write('rockstar-filter-results', self.rockstar)
        self.patches = [mock.patch.object(bridge, 'ROOT', self.root),
                        mock.patch.object(bridge, 'OBSERVER_SHA256', self.digest),
                        mock.patch.dict(bridge.plain.__globals__, ROOT=self.root)]
        for patch in self.patches:
            patch.start()

    def tearDown(self):
        for patch in reversed(self.patches):
            patch.stop()
        self.temporary.cleanup()

    def write(self, suffix, value):
        (self.root / ('research/windows-process-observer-' + suffix + '.json')).write_text(json.dumps(value))

    def test_mismatched_source_or_rockstar_fixture_hash_refuses_before_spawn(self):
        for name, record, scope in [('source-filter-results', self.source, False),
                                    ('rockstar-filter-results', self.rockstar, True)]:
            changed = json.loads(json.dumps(record))
            changed['build']['binaries']['process_observer']['sha256'] = '0' * 64
            self.write(name, changed)
            with mock.patch.object(bridge.subprocess, 'Popen') as start, self.assertRaises(RuntimeError):
                bridge.ProcessObserver(SimpleNamespace(), {}, self.root, 'reject', 1, rockstar_scope=scope)
            start.assert_not_called()
            self.write(name, record)

    def test_default_command_unchanged_and_rockstar_scope_is_fixed_with_six_fields(self):
        runtime = SimpleNamespace(WINE=self.root / 'wine')
        event = {'event': 'ready', 'time_ms': 1, 'pid': 32, 'parent_pid': 0,
                 'basename': 'process_observer.exe', 'exit_hex': None}
        for scope in (False, True):
            process = SimpleNamespace(pid=123, returncode=0, stdout=io.StringIO(json.dumps(event) + '\n'),
                                      poll=lambda: None, wait=lambda timeout: 0)
            with mock.patch.object(bridge.subprocess, 'Popen', return_value=process) as start:
                observed = bridge.ProcessObserver(runtime, {'WINEPREFIX': 'OwnPrefix'}, self.root,
                                                  'rockstar' if scope else 'default', 90, rockstar_scope=scope)
                observed.wait_ready()
                result = observed.finish_after_wineserver_cleanup()
            command = start.call_args.args[0]
            expected = [str(runtime.WINE), str(self.root / bridge.OBSERVER_PATH), '--source-root',
                        'Z:' + str(self.root).replace('/', '\\'), '--duration-ms', '90000']
            if scope:
                expected += ['--rockstar-code-root', 'C:\\Program Files\\Rockstar Games', '--poll-ms', '10']
            self.assertEqual(command, expected)
            self.assertNotIn('--fixture', command)
            self.assertEqual(start.call_args.kwargs['env']['WINEDEBUG'], '-all,err+all')
            self.assertEqual(set(result['events'][0]), {'event', 'time_ms', 'pid', 'parent_pid', 'basename', 'exit_hex'})
            self.assertTrue(result['reader_completed_without_error'])

    def test_wrong_own_child_or_driver_copy_hash_refuses_before_spawn(self):
        cases = [('source-filter-results', self.source, False, 'FiveM.exe'),
                 ('source-filter-results', self.source, False, 'FiveM_b3258_GameProcess.exe'),
                 ('rockstar-filter-results', self.rockstar, True, 'observer_fixture_driver.exe')]
        cases += [('rockstar-filter-results', self.rockstar, True, role) for role in bridge.ROCKSTAR_ROLE_PATHS]
        for name, original, scope, role in cases:
            with self.subTest(fixture=name, copy=role):
                changed = json.loads(json.dumps(original))
                changed['own_fixture_copy_sha256'][role] = '0' * 64
                self.write(name, changed)
                with mock.patch.object(bridge.subprocess, 'Popen') as start, self.assertRaises(RuntimeError):
                    bridge.ProcessObserver(SimpleNamespace(), {}, self.root, 'reject-copy', 1, rockstar_scope=scope)
                start.assert_not_called()
                self.write(name, original)
