"""Direct NT identity/diagnostic contracts and guarded staging, without Wine."""
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
SPEC = importlib.util.spec_from_file_location('own_direct_nt_under_test', PROJECT/'native/windows-mapping-nt-policy/run.py')
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class DirectNtPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()/'project'
        self.stage = self.root/'build/windows-mapping-nt-policy/runtime'
        (self.root/'research').mkdir(parents=True)
        for module, values in ((runner, {'ROOT': self.root, 'STAGE': self.stage}),
                               (runner.file_policy, {'ROOT': self.root}),
                               (runner.policy, {'ROOT': self.root, 'STAGE': self.stage,
                                                'PREFIX': self.root/'prefixes/unused-own-test'})):
            for key, value in values.items():
                patch = mock.patch.object(module, key, value)
                patch.start()
                self.addCleanup(patch.stop)
        for relative in set(runner.INPUTS)|runner.SOURCES|runner.HELPERS|{
                runner.file_policy.BUILD_RECORD, runner.file_policy.POLICY_BUILD}:
            path = self.root/relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'{}' if relative.endswith('.json') else ('own test '+relative).encode())
        patch = mock.patch.object(runner.file_policy, 'validate_core_report')
        patch.start()
        self.addCleanup(patch.stop)
        for module, name, value in ((runner, 'CORE_SHA', self.identity(runner.file_policy.CORE)['sha256']),
                                    (runner.file_policy, 'TBB_SHA', self.identity(runner.file_policy.TBB)['sha256'])):
            patch = mock.patch.object(module, name, value)
            patch.start()
            self.addCleanup(patch.stop)
        self.record = {
            'schema_version': 1, 'profile': runner.PROFILE, 'compiled': True, 'core_sha256': runner.CORE_SHA,
            'runtime_inputs': [dict(self.identity(path), runtime_name=name) for path, name in runner.INPUTS.items()],
            'source_evidence': [self.identity(path) for path in sorted(runner.SOURCES)],
            'helper_sources': [self.identity(path) for path in sorted(runner.HELPERS)],
            'core_build_evidence': self.identity(runner.file_policy.BUILD_RECORD),
            'policy_build_evidence': self.identity(runner.file_policy.POLICY_BUILD),
            'cases': [{'location': location, 'operation': operation, 'mapped': mapped}
                      for location, operation, mapped in runner.CASES],
        }
        self.manifest = self.root/runner.BUILD_RECORD
        self.save_manifest()

    def identity(self, relative):
        payload = (self.root/relative).read_bytes()
        return {'path': relative, 'bytes': len(payload), 'sha256': hashlib.sha256(payload).hexdigest()}

    def save_manifest(self):
        self.manifest.write_text(json.dumps(self.record))

    def metadata(self, location, operation, mapped):
        target = location == 'canonical' and mapped
        return ('MAPPING_NT_POLICY_FIXTURE location={} operation={} mapped={} status=0x00000000 '
                'source_identity={} target_identity={} callback_count={} fixed_path_hits={}').format(
                    location, operation, int(mapped), int(not target), int(target), int(target), int(target))

    def file_event(self, location, operation):
        bit = int(location == 'canonical')
        return {'pid': 42, 'operation': operation, 'allowed': bit, 'canonical_fragment': bit,
                'folded_fragment': bit, 'nt_prefix': 1}

    def test_all_eight_nt_identity_contracts(self):
        for location, operation, mapped in runner.CASES:
            with self.subTest(location=location, operation=operation, mapped=mapped):
                line = self.metadata(location, operation, mapped)
                self.assertTrue(runner.case_contract([line], location, operation, mapped, 0))
                self.assertFalse(runner.case_contract([line], location, operation, mapped, 10))
                self.assertFalse(runner.case_contract([line, line], location, operation, mapped, 0))

    def test_wrong_status_identity_or_callback_hit_is_rejected(self):
        line = self.metadata('canonical', 'open', True)
        for changed in (line.replace('status=0x00000000', 'status=0xc0000001'),
                        line.replace('source_identity=0', 'source_identity=1'),
                        line.replace('target_identity=1', 'target_identity=0'),
                        line.replace('fixed_path_hits=1', 'fixed_path_hits=0'),
                        line.replace('callback_count=1', 'callback_count=0'), line+' path=private'):
            self.assertFalse(runner.case_contract([changed], 'canonical', 'open', True, 0))

    def test_mapped_nt_calls_require_matching_positive_file_event(self):
        for location, operation, mapped in runner.CASES:
            event = self.file_event(location, operation)
            self.assertEqual(runner.file_contract([], location, operation, mapped), not mapped)
            self.assertEqual(runner.file_contract([event], location, operation, mapped), mapped)
            if mapped:
                self.assertFalse(runner.file_contract([dict(event, nt_prefix=0)], location, operation, mapped))
                self.assertFalse(runner.file_contract([dict(event, operation='other')], location, operation, mapped))
                self.assertFalse(runner.file_contract([dict(event, allowed=1-event['allowed'])], location, operation, mapped))

    def test_stage_copies_only_five_verified_runtime_inputs_to_both_locations(self):
        digest = runner.stage()
        self.assertEqual(digest, hashlib.sha256(self.manifest.read_bytes()).hexdigest())
        for relative in runner.policy.STAGE_PATHS.values():
            destination = self.stage/relative
            self.assertEqual({path.name for path in destination.iterdir()}, set(runner.INPUTS.values()))
            for source, name in runner.INPUTS.items():
                self.assertEqual((destination/name).read_bytes(), (self.root/source).read_bytes())

    def test_all_manifest_scopes_are_admitted_before_any_selected_payload_is_read(self):
        original = json.loads(json.dumps(self.record))
        for key in ('runtime_inputs', 'source_evidence', 'helper_sources'):
            self.record = json.loads(json.dumps(original))
            self.record[key][-1]['path'] = '../private.bin'
            self.save_manifest()
            with mock.patch.object(runner.policy, 'read_regular', wraps=runner.policy.read_regular) as read:
                with mock.patch.object(runner.policy, 'atomic_replace') as replace:
                    with self.assertRaises(RuntimeError):
                        runner.stage()
            self.assertEqual([call.args[0] for call in read.call_args_list], [self.manifest])
            replace.assert_not_called()

    def test_late_destination_hardlink_blocks_reads_and_all_writes(self):
        destination = self.stage/runner.policy.STAGE_PATHS['canonical']
        destination.mkdir(parents=True)
        sentinel = self.root.parent/'unrelated.bin'
        sentinel.write_bytes(b'preserve')
        os.link(sentinel, destination/'tbb12.dll')
        with mock.patch.object(runner.policy, 'read_regular') as read:
            with self.assertRaises(RuntimeError):
                runner.stage()
        read.assert_not_called()
        self.assertEqual(sentinel.read_bytes(), b'preserve')

    def test_helper_change_refuses_staging(self):
        path = self.root/next(iter(runner.HELPERS))
        path.write_bytes(b'changed helper')
        with mock.patch.object(runner.policy, 'atomic_replace') as replace:
            with self.assertRaises(RuntimeError):
                runner.stage()
        replace.assert_not_called()

    def run_main(self, failure=None, runtime_error=None):
        runtime = SimpleNamespace(WINE=Path('/own/wine'), ENGINE=Path('/own/engine'))

        def process(command, **kwargs):
            if command[0] == str(runtime.WINE):
                if failure:
                    raise failure
                location, operation, mode = (arg[2:] for arg in command[-3:])
                mapped = mode == 'mapped'
                output = kwargs['stdout']
                output.write(self.metadata(location, operation, mapped)+'\n')
                if mapped:
                    for phase in runner.file_policy.HOOK_PHASES:
                        output.write('0020:0030:warn:debugstr:OutputDebugStringA '
                                     '"[CFX_MAPPING_HOOK] pid=42 phase={} status=0\\n"\n'.format(phase))
                    event = self.file_event(location, operation)
                    output.write('0020:0030:warn:debugstr:OutputDebugStringA '
                                 '"[CFX_MAPPING_FILE] pid=42 operation={operation} allowed={allowed} '
                                 'canonical_fragment={canonical_fragment} folded_fragment={folded_fragment} '
                                 'nt_prefix=1\\n"\n'.format(**event))
            return SimpleNamespace(returncode=0)

        with mock.patch.object(runner.policy, 'load_runtime', return_value=(runtime, {}), side_effect=runtime_error):
            with mock.patch.object(runner.policy, 'probe_prefix', return_value=nullcontext()):
                with mock.patch.object(runner.policy, 'assert_account_free_prefix'):
                    with mock.patch.object(runner, 'stage', return_value='0'*64):
                        with mock.patch.object(runner.subprocess, 'run', side_effect=process) as calls:
                            with redirect_stdout(io.StringIO()):
                                status = runner.main()
        return status, json.loads((self.root/runner.RESULTS).read_text()), calls

    def test_mock_matrix_retains_eight_cases_and_both_cleanup_steps(self):
        status, result, calls = self.run_main()
        self.assertEqual(status, 0)
        self.assertTrue(result['passed'])
        self.assertEqual(len(result['cases']), 8)
        self.assertEqual(calls.call_count, 10)
        self.assertEqual(result['cleanup'], [{'flag': '-k', 'exit': 0}, {'flag': '-w', 'exit': 0}])

    def test_timeout_still_cleans_up_and_saves_failure(self):
        status, result, calls = self.run_main(failure=subprocess.TimeoutExpired(['own'], 45))
        self.assertEqual(status, 1)
        self.assertEqual(result['failure']['type'], 'TimeoutExpired')
        self.assertEqual(result['cleanup'], [{'flag': '-k', 'exit': 0}, {'flag': '-w', 'exit': 0}])
        self.assertEqual(calls.call_count, 3)

    def test_runtime_loader_error_saves_evidence_without_processes(self):
        status, result, calls = self.run_main(runtime_error=RuntimeError('runtime refused'))
        self.assertEqual(status, 1)
        self.assertEqual(result['failure']['message'], 'runtime refused')
        self.assertEqual(result['cleanup'], [])
        calls.assert_not_called()


if __name__ == '__main__':
    unittest.main()
