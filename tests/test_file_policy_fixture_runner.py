"""Verify file-policy binding, staging and failure evidence without Wine."""
from contextlib import nullcontext, redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


PROJECT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'own_file_policy_fixture_under_test', PROJECT / 'native/windows-mapping-policy/run_file_policy.py')
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class FilePolicyFixtureRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve() / 'project'
        self.here = self.root / 'native/windows-mapping-policy'
        self.build = self.root / 'build/windows-mapping-policy'
        self.stage = self.build / 'runtime-file-policy'
        self.manifest = self.root / runner.FIXTURE_BUILD
        self.latest = self.root / runner.FIXTURE_RESULTS
        (self.root / 'research').mkdir(parents=True)
        (self.root / 'logs').mkdir()
        self.here.mkdir(parents=True)
        self.runtime = SimpleNamespace(WINE=Path('/own-test/wine'), ENGINE=Path('/own-test/engine'))
        for module, values in ((runner, {'ROOT': self.root, 'HERE': self.here, 'STAGE': self.stage}),
                               (runner.policy, {'ROOT': self.root, 'BUILD': self.build, 'STAGE': self.stage,
                                                'PREFIX': self.root / 'prefixes/own-unused-test'})):
            for key, value in values.items():
                patch = mock.patch.object(module, key, value)
                patch.start()
                self.addCleanup(patch.stop)
        inputs = runner.policy.expected_inputs()
        sources = runner.policy.expected_sources()
        for relative in list(inputs) + sorted(sources) + [runner.CORE, 'native/windows-mapping-policy/run_file_policy.py', 'native/windows-mapping-policy/run_hook.py',
                                                        'native/windows-mapping-policy/run.py']:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(('own temporary bytes: ' + relative).encode())
        ordinary_core_sha = self.identity('build/windows-core/CoreRT.dll')['sha256']
        for module, key, value in ((runner.policy, 'CORE_SHA', ordinary_core_sha),
                                   (runner, 'CORE_SHA', self.identity(runner.CORE)['sha256']),
                                   (runner, 'TBB_SHA', self.identity(runner.TBB)['sha256'])):
            patch = mock.patch.object(module, key, value)
            patch.start()
            self.addCleanup(patch.stop)
        self.policy_report = {
            'compiled': True, 'ordinary_core_sha256': ordinary_core_sha,
            'runtime_inputs': [dict(self.identity(path), runtime_name=name) for path, name in inputs.items()],
            'source_evidence': [self.identity(path) for path in sorted(sources)],
        }
        self.core_report = json.loads((PROJECT / runner.BUILD_RECORD).read_text())
        self.core_report['artifact'] = self.identity(runner.CORE)
        self.write_json(runner.POLICY_BUILD, self.policy_report)
        self.write_json(runner.BUILD_RECORD, self.core_report)

    def identity(self, relative):
        data = (self.root / relative).read_bytes()
        return {'path': relative, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}

    def write_json(self, relative, value):
        (self.root / relative).write_text(json.dumps(value))

    def prepare(self):
        with redirect_stdout(io.StringIO()):
            runner.prepare()
        return json.loads(self.manifest.read_text())

    def update_manifest(self, value):
        self.manifest.write_text(json.dumps(value))

    def assert_scope_refused_before_dynamic_read(self, value):
        self.update_manifest(value)
        with mock.patch.object(runner.policy, 'read_regular', wraps=runner.policy.read_regular) as read:
            with mock.patch.object(runner.policy, 'atomic_replace') as replace:
                with self.assertRaises(RuntimeError):
                    runner.stage()
        self.assertEqual([call.args[0] for call in read.call_args_list], [self.manifest])
        replace.assert_not_called()
        self.assertFalse(self.stage.exists())

    def policy_line(self, location, mode):
        mapped = mode.startswith('--mapped-')
        imported = mode.endswith('-import')
        should_map = mapped and (not imported or location == 'canonical')
        return ('MAPPING_POLICY_FIXTURE location={} route={} mapped={} preloaded_before=0 '
                'preloaded_after=0 callback_count={} fixed_path_hits={} load_error=0 marker={}\n').format(
                    location, 'import' if imported else 'explicit', int(mapped), int(should_map),
                    int(should_map), '0x46585232' if should_map else '0x46585231')

    def fake_process(self, command, **kwargs):
        if command[0] == str(self.runtime.WINE):
            location, mode = command[-2][2:], command[-1]
            output = kwargs['stdout']
            output.write(self.policy_line(location, mode))
            if mode.startswith('--mapped-'):
                for phase in runner.HOOK_PHASES:
                    output.write('0020:0030:warn:debugstr:OutputDebugStringA '
                                 '"[CFX_MAPPING_HOOK] pid=42 phase={} status=0\\n"\n'.format(phase))
                if mode.endswith('-import'):
                    bit = int(location == 'canonical')
                    output.write('0020:0030:warn:debugstr:OutputDebugStringA '
                                 '"[CFX_MAPPING_FILE] pid=42 operation=open allowed={} canonical_fragment={} '
                                 'folded_fragment={} nt_prefix=1\\n"\n'.format(bit, bit, bit))
        return SimpleNamespace(returncode=0)

    def run_main(self, *, process=None, runtime_error=None, lock_error=None, stage_error=None,
                 final_guard_error=None):
        account_calls = 0

        def account_guard(*args, **kwargs):
            nonlocal account_calls
            account_calls += 1
            if final_guard_error is not None and account_calls == 9:
                raise final_guard_error

        context = mock.MagicMock()
        context.__enter__.side_effect = lock_error
        context.__exit__.return_value = False
        with mock.patch.object(runner.policy, 'load_runtime') as runtime:
            runtime.side_effect = runtime_error
            runtime.return_value = (self.runtime, {})
            with mock.patch.object(runner.policy, 'probe_prefix', return_value=context if lock_error else nullcontext()):
                with mock.patch.object(runner.policy, 'assert_account_free_prefix', side_effect=account_guard):
                    with mock.patch.object(runner, 'stage', return_value='0' * 64, side_effect=stage_error):
                        with mock.patch.object(runner.subprocess, 'run', side_effect=process or self.fake_process) as run:
                            with redirect_stdout(io.StringIO()):
                                result = runner.main()
        return result, json.loads(self.latest.read_text()), run

    def test_prepare_and_stage_bind_only_own_four_pes_exact_core_and_original_tbb(self):
        value = self.prepare()
        self.assertEqual(value['diagnostic_core_input'], self.identity(runner.CORE))
        self.assertEqual(value['tbb_input'], self.identity(runner.TBB))
        self.assertEqual({item['path'] for item in value['artifacts']}, set(runner.ARTIFACTS))
        digest = runner.stage()
        self.assertEqual(digest, hashlib.sha256(self.manifest.read_bytes()).hexdigest())
        expected = value['artifacts'] + [value['diagnostic_core_input'], value['tbb_input']]
        for relative in runner.policy.STAGE_PATHS.values():
            directory = self.stage / relative
            self.assertEqual({path.name for path in directory.iterdir()}, {Path(item['path']).name for item in expected})
            for item in expected:
                self.assertEqual((directory / Path(item['path']).name).read_bytes(), (self.root / item['path']).read_bytes())

    def test_prepare_refuses_existing_binding_without_replacing_it(self):
        self.prepare()
        previous = self.manifest.read_bytes()
        with self.assertRaises(RuntimeError):
            runner.prepare()
        self.assertEqual(self.manifest.read_bytes(), previous)

    def test_prepare_policy_scope_precedes_any_manifest_selected_payload_read(self):
        self.policy_report['runtime_inputs'][-1]['path'] = '../unreviewed-private.bin'
        self.write_json(runner.POLICY_BUILD, self.policy_report)
        with mock.patch.object(runner.policy, 'read_regular', wraps=runner.policy.read_regular) as read:
            with self.assertRaises(RuntimeError):
                runner.prepare()
        self.assertEqual([call.args[0] for call in read.call_args_list], [self.root / runner.POLICY_BUILD])
        self.assertFalse(self.manifest.exists())

    def test_prepare_unreviewed_core_path_is_not_opened(self):
        self.core_report['artifact']['path'] = '../unreviewed-private.bin'
        self.write_json(runner.BUILD_RECORD, self.core_report)
        with mock.patch.object(runner.policy, 'read_regular', wraps=runner.policy.read_regular) as read:
            with self.assertRaises(RuntimeError):
                runner.prepare()
        self.assertNotIn(self.root / '../unreviewed-private.bin', [call.args[0] for call in read.call_args_list])
        self.assertFalse(self.manifest.exists())

    def test_stage_rejects_all_unreviewed_manifest_paths_before_hash_or_read(self):
        original = self.prepare()
        for field in ('build_record', 'policy_build_evidence', 'diagnostic_core_input', 'tbb_input',
                      'runner_source', 'policy_runner_source', 'hook_runner_source'):
            value = json.loads(json.dumps(original))
            value[field]['path'] = '../unreviewed-private.bin'
            with self.subTest(field=field):
                self.assert_scope_refused_before_dynamic_read(value)
        value = json.loads(json.dumps(original))
        value['artifacts'][-1]['path'] = '../unreviewed-private.bin'
        self.assert_scope_refused_before_dynamic_read(value)

    def test_stage_rejects_changed_phase_inventory_before_payload_reads(self):
        value = self.prepare()
        value['hook_phases'] = list(reversed(value['hook_phases']))
        self.assert_scope_refused_before_dynamic_read(value)

    def test_late_canonical_stage_hardlink_is_rejected_before_manifest_read_or_copy(self):
        self.prepare()
        canonical = self.stage / runner.policy.STAGE_PATHS['canonical']
        canonical.mkdir(parents=True)
        sentinel = self.root.parent / 'unrelated.bin'
        sentinel.write_bytes(b'preserve')
        os.link(sentinel, canonical / 'tbb12.dll')
        with mock.patch.object(runner.policy, 'read_regular') as read:
            with mock.patch.object(runner.policy, 'atomic_replace') as replace:
                with self.assertRaises(RuntimeError):
                    runner.stage()
        read.assert_not_called()
        replace.assert_not_called()
        self.assertEqual(sentinel.read_bytes(), b'preserve')
        self.assertFalse((self.stage / runner.policy.STAGE_PATHS['foreign']).exists())

    def test_changed_bound_runner_source_prevents_all_staging(self):
        self.prepare()
        (self.here / 'run_file_policy.py').write_bytes(b'changed after binding')
        with mock.patch.object(runner.policy, 'atomic_replace') as replace:
            with self.assertRaises(RuntimeError):
                runner.stage()
        replace.assert_not_called()
        self.assertFalse(self.stage.exists())

    def test_changed_bound_policy_runner_source_prevents_all_staging(self):
        self.prepare()
        (self.here / 'run.py').write_bytes(b'changed after binding')
        with mock.patch.object(runner.policy, 'atomic_replace') as replace:
            with self.assertRaises(RuntimeError):
                runner.stage()
        replace.assert_not_called()
        self.assertFalse(self.stage.exists())

    def test_changed_bound_hook_helper_prevents_all_staging(self):
        self.prepare()
        (self.here / 'run_hook.py').write_bytes(b'changed after binding')
        with mock.patch.object(runner.policy, 'atomic_replace') as replace:
            with self.assertRaises(RuntimeError):
                runner.stage()
        replace.assert_not_called()
        self.assertFalse(self.stage.exists())

    def test_wrong_profile_fields_operations_or_cases_refused_before_payload_reads(self):
        original = self.prepare()
        for key, invalid in (('profile', 'ordinary'), ('file_event_fields', ['path']),
                             ('file_operations', ['read']), ('cases', list(reversed(original['cases'])))):
            value = json.loads(json.dumps(original))
            value[key] = invalid
            with self.subTest(key=key):
                self.assert_scope_refused_before_dynamic_read(value)

    def test_prepare_refuses_changed_policy_or_failed_header_test_report(self):
        self.core_report['scope_proof']['mapping_filename_policy_changed'] = True
        self.write_json(runner.BUILD_RECORD, self.core_report)
        with self.assertRaises(RuntimeError):
            runner.prepare()
        self.core_report['scope_proof']['mapping_filename_policy_changed'] = False
        self.core_report['header_and_overlay_tests']['exit'] = 1
        self.write_json(runner.BUILD_RECORD, self.core_report)
        with self.assertRaises(RuntimeError):
            runner.prepare()
        self.assertFalse(self.manifest.exists())

    def test_file_metadata_accepts_exact_fields_in_both_wine_channels(self):
        lines = [
            '0020:0030:warn:debugstr:OutputDebugStringA "[CFX_MAPPING_FILE] pid=42 operation=open allowed=1 canonical_fragment=1 folded_fragment=1 nt_prefix=1\\n"',
            '0030:warn:seh:dispatch_exception "[CFX_MAPPING_FILE] pid=43 operation=create allowed=0 canonical_fragment=0 folded_fragment=0 nt_prefix=0\\n"',
        ]
        self.assertEqual(runner.file_metadata(lines), [
            {'pid': 42, 'operation': 'open', 'allowed': 1, 'canonical_fragment': 1, 'folded_fragment': 1, 'nt_prefix': 1},
            {'pid': 43, 'operation': 'create', 'allowed': 0, 'canonical_fragment': 0, 'folded_fragment': 0, 'nt_prefix': 0},
        ])

    def test_file_metadata_rejects_arbitrary_operations_bits_fields_and_text(self):
        line = ('0020:0030:warn:debugstr:OutputDebugStringA "[CFX_MAPPING_FILE] pid=42 operation=open '
                'allowed=1 canonical_fragment=1 folded_fragment=1 nt_prefix=1\\n"')
        invalid = [line.replace('operation=open', 'operation=read'), line.replace('allowed=1', 'allowed=2'),
                   line.replace('canonical_fragment=1', 'canonical_fragment=-1'),
                   line.replace('folded_fragment=1', 'folded_fragment=true'),
                   line.replace('nt_prefix=1', 'nt_prefix=01'), line.replace('pid=42', 'pid=-1'),
                   line.replace(' operation=', ' path=private operation='), line + ' extra',
                   line.replace('warn:', 'trace:')]
        self.assertEqual(runner.file_metadata(invalid), [])

    def test_file_contract_requires_exact_import_bits_but_explicit_has_no_positive_requirement(self):
        canonical = {'pid': 42, 'operation': 'open', 'allowed': 1,
                     'canonical_fragment': 1, 'folded_fragment': 1, 'nt_prefix': 1}
        foreign = dict(canonical, allowed=0, canonical_fragment=0, folded_fragment=0)
        for location, mode in runner.policy.CASES:
            with self.subTest(location=location, mode=mode):
                if not mode.startswith('--mapped-'):
                    self.assertTrue(runner.file_event_contract([], location, mode))
                    self.assertFalse(runner.file_event_contract([foreign], location, mode))
                elif mode.endswith('-explicit'):
                    self.assertTrue(runner.file_event_contract([], location, mode))
                else:
                    expected, wrong = (canonical, foreign) if location == 'canonical' else (foreign, canonical)
                    self.assertTrue(runner.file_event_contract([expected], location, mode))
                    self.assertEqual(runner.file_event_contract([], location, mode), location == 'canonical')
                    self.assertFalse(runner.file_event_contract([wrong], location, mode))

    def test_wrong_canonical_event_is_preserved_as_failure_without_relabeling(self):
        def process(command, **kwargs):
            result = self.fake_process(command, **kwargs)
            if command[0] == str(self.runtime.WINE) and command[-2:] == ['--canonical', '--mapped-import']:
                output = kwargs['stdout']
                output.flush()
                content = Path(output.name).read_text()
                content = content.replace('allowed=1 canonical_fragment=1 folded_fragment=1',
                                          'allowed=0 canonical_fragment=1 folded_fragment=1')
                output.seek(0)
                output.truncate()
                output.write(content)
            return result

        status, record, _ = self.run_main(process=process)
        case = record['cases'][-1]
        self.assertEqual(status, 1)
        self.assertFalse(record['passed'])
        self.assertTrue(case['mapping_contract'])
        self.assertFalse(case['file_event_contract'])
        self.assertEqual(case['file_events'][0]['allowed'], 0)
        self.assertEqual(case['file_events'][0]['canonical_fragment'], 1)

    def test_unparsed_baseline_file_marker_fails_instead_of_disappearing(self):
        def process(command, **kwargs):
            result = self.fake_process(command, **kwargs)
            if command[0] == str(self.runtime.WINE) and command[-1] == '--baseline-explicit':
                kwargs['stdout'].write('0020:warn:debugstr:OutputDebugStringA '
                                       '"[CFX_MAPPING_FILE] pid=42 operation=read allowed=1\\n"\n')
            return result

        status, record, _ = self.run_main(process=process)
        self.assertEqual(status, 1)
        self.assertFalse(record['cases'][0]['file_event_contract'])
        self.assertEqual(record['cases'][0]['unparsed_file_event_lines'], 1)

    def test_hook_metadata_accepts_both_fixed_wine_channels_and_bounded_statuses(self):
        lines = [
            '0020:0030:warn:debugstr:OutputDebugStringA "[CFX_MAPPING_HOOK] pid=42 phase=enable.all status=-1\\n"',
            '0030:warn:seh:dispatch_exception "[CFX_MAPPING_HOOK] pid=43 phase=create.ntdll.NtOpenFile status=12\\n"',
        ]
        self.assertEqual(runner.hook_metadata(lines), [
            {'pid': 42, 'phase': 'enable.all', 'status': -1},
            {'pid': 43, 'phase': 'create.ntdll.NtOpenFile', 'status': 12},
        ])

    def test_hook_metadata_rejects_arbitrary_phases_statuses_fields_and_wrappers(self):
        line = '0020:0030:warn:debugstr:OutputDebugStringA "[CFX_MAPPING_HOOK] pid=42 phase=enable.all status=0\\n"'
        invalid = [line.replace('enable.all', 'private.path'), line.replace('status=0', 'status=13'),
                   line.replace('status=0', 'status=-2'), line.replace('status=0', 'status=00'),
                   line.replace('pid=42', 'pid=-1'), line.replace(' status=0', ' extra=value status=0'),
                   line + ' appended', line.replace('warn:', 'trace:'), line[10:]]
        self.assertEqual(runner.hook_metadata(invalid), [])

    def test_full_mock_matrix_records_all_eight_cases_and_both_cleanup_calls(self):
        status, record, process = self.run_main()
        self.assertEqual(status, 0)
        self.assertTrue(record['passed'])
        self.assertEqual(len(record['cases']), 8)
        self.assertEqual(process.call_count, 10)
        self.assertEqual(record['cleanup'], [{'flag': '-k', 'exit': 0}, {'flag': '-w', 'exit': 0}])
        self.assertEqual([len(case['hook_events']) for case in record['cases']], [0, 21, 0, 21, 0, 21, 0, 21])

    def test_stage_failure_saves_evidence_without_killing_any_unstarted_process(self):
        status, record, process = self.run_main(stage_error=RuntimeError('stage refused'))
        self.assertEqual(status, 1)
        self.assertEqual(record['failure']['message'], 'stage refused')
        self.assertEqual(record['cleanup'], [])
        process.assert_not_called()

    def test_owned_process_timeout_saves_failure_and_attempts_both_cleanup_steps(self):
        def process(command, **kwargs):
            if command[0] == str(self.runtime.WINE):
                raise subprocess.TimeoutExpired(command, 45)
            return SimpleNamespace(returncode=0)

        status, record, calls = self.run_main(process=process)
        self.assertEqual(status, 1)
        self.assertEqual(record['failure']['type'], 'TimeoutExpired')
        self.assertEqual(record['cleanup'], [{'flag': '-k', 'exit': 0}, {'flag': '-w', 'exit': 0}])
        self.assertEqual(calls.call_count, 3)

    def test_cleanup_failure_does_not_skip_second_cleanup_or_evidence(self):
        def process(command, **kwargs):
            if command[-1] == '-k':
                raise subprocess.TimeoutExpired(command, 15)
            return self.fake_process(command, **kwargs)

        status, record, _ = self.run_main(process=process)
        self.assertEqual(status, 1)
        self.assertEqual(record['cleanup'], [
            {'flag': '-k', 'exit': None, 'failure_type': 'TimeoutExpired'}, {'flag': '-w', 'exit': 0}])

    def test_runtime_load_failure_still_saves_failure_evidence(self):
        status, record, process = self.run_main(runtime_error=RuntimeError('runtime refused'))
        self.assertEqual(status, 1)
        self.assertFalse(record['passed'])
        self.assertEqual(record['failure']['message'], 'runtime refused')
        process.assert_not_called()

    def test_prefix_lock_enter_failure_still_saves_failure_evidence(self):
        status, record, process = self.run_main(lock_error=RuntimeError('lock refused'))
        self.assertEqual(status, 1)
        self.assertFalse(record['passed'])
        self.assertEqual(record['failure']['message'], 'lock refused')
        process.assert_not_called()

    def test_final_prefix_guard_failure_after_cleanup_still_saves_failure_evidence(self):
        status, record, _ = self.run_main(final_guard_error=RuntimeError('final guard refused'))
        self.assertEqual(status, 1)
        self.assertFalse(record['passed'])
        self.assertEqual(record['failure']['message'], 'final guard refused')
        self.assertEqual(record['cleanup'], [{'flag': '-k', 'exit': 0}, {'flag': '-w', 'exit': 0}])


if __name__ == '__main__':
    unittest.main()
