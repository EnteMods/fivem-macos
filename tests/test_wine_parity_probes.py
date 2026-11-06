"""Temporary-inventory and mocked-process tests; never start Wine."""
from contextlib import redirect_stdout
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
SPEC = importlib.util.spec_from_file_location('own_parity_runner_under_test', PROJECT/'native/wine-parity-probes/run.py')
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)
envmod = runner.runtime


class ParityProbeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()/'project'
        self.engine = self.root/'runtime/wine-job-query-parity/engine'
        self.build = self.root/'build/windows-job-tests'
        self.prefix = self.root/'prefixes/wine-parity-regression'
        self.manifest = self.root/'build/wine-job-query-parity/full-x86_64/engine-manifest.json'
        self.build.mkdir(parents=True)
        for module, values in ((runner, {'ROOT': self.root, 'BUILD': self.build, 'PREFIX': self.prefix}),
                               (envmod, {'ROOT': self.root, 'ENGINE': self.engine, 'PREFIX': self.prefix,
                                         'MANIFEST': self.manifest})):
            for key, value in values.items():
                patch = mock.patch.object(module, key, value)
                patch.start()
                self.addCleanup(patch.stop)

    def event(self, name='one', ok=True):
        return {'actor': 'query' if name == 'all_query_cases_passed' else 'parent',
                'case': 'complete' if name.startswith('all_') else 'setup',
                'kind': 'result' if name == 'all_cases_passed' else 'assertion',
                'name': name, 'pid': 42, 'ok': ok, 'value': 0, 'last_error': None}

    def test_environment_discards_all_inherited_loader_graphics_client_and_plugin_roles(self):
        inherited = {'WINEPREFIX': '/private', 'WineServerSocket': 'private', 'DYLD_INSERT_LIBRARIES': '/private.dylib',
                     'LD_PRELOAD': '/other', 'DXMT_CONFIG': 'old', 'DXVK_LOG_PATH': '/other',
                     'CitizenFX_ToolMode': '1', 'CX_ROOT': '/old', 'VK_ICD_FILENAMES': '/old',
                     'GST_PLUGIN_PATH': '/private', 'PATH': '/unsafe', 'LANG': 'de_DE.UTF-8'}
        result = envmod.environment({'manifest_sha256': envmod.MANIFEST_SHA, 'protocol_version': 1810}, inherited)
        self.assertEqual(result['WINEPREFIX'], str(self.prefix))
        self.assertEqual(result['WINELOADER'], str(self.engine/'bin/wine'))
        self.assertEqual(result['WINESERVER'], str(self.engine/'bin/wineserver'))
        self.assertEqual(result['PATH'], '/usr/bin:/bin:/usr/sbin:/sbin')
        self.assertEqual(result['LANG'], inherited['LANG'])
        for key in ('WineServerSocket', 'DYLD_INSERT_LIBRARIES', 'LD_PRELOAD', 'DXMT_CONFIG',
                    'DXVK_LOG_PATH', 'CitizenFX_ToolMode', 'CX_ROOT', 'VK_ICD_FILENAMES'):
            self.assertNotIn(key, result)
        for key in ('GST_PLUGIN_PATH', 'GST_PLUGIN_PATH_1_0', 'GST_PLUGIN_SYSTEM_PATH', 'GST_PLUGIN_SYSTEM_PATH_1_0'):
            self.assertEqual(result[key], '')

    def test_unverified_runtime_reference_cannot_construct_environment(self):
        with self.assertRaises(RuntimeError):
            envmod.environment({'manifest_sha256': '0'*64, 'protocol_version': 1810}, {})

    def test_manifest_digest_refused_before_parsing_or_selected_reads(self):
        self.manifest.parent.mkdir(parents=True)
        self.manifest.write_bytes(b'not a manifest')
        with mock.patch.object(envmod, 'validate_manifest') as validate:
            with self.assertRaisesRegex(RuntimeError, 'manifest differs'):
                envmod.verify_runtime()
        validate.assert_not_called()

    def minimal_inventory(self):
        self.engine.mkdir(parents=True)
        entries = []
        for name in ('bin/wine', 'bin/wineserver', 'share/wine/test.nls'):
            path = self.engine/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(('own '+name).encode())
            entries.append({'path': name, 'bytes': path.stat().st_size,
                            'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                            'kind': 'data', 'executable': False})
        self.manifest.parent.mkdir(parents=True)
        self.manifest.write_text(json.dumps({'entries': entries, 'successful_phases': []}))
        molten = self.root/'own-molten.dylib'
        molten.write_bytes(b'own molten')
        value = json.loads(self.manifest.read_text())
        value['pinned_moltenvk'] = {'path': str(molten), 'bytes': len(b'own molten'),
                                   'sha256': hashlib.sha256(b'own molten').hexdigest()}
        self.manifest.write_text(json.dumps(value))
        return entries, molten

    def verify_minimal(self, entries, molten):
        with mock.patch.object(envmod, 'MANIFEST_SHA', hashlib.sha256(self.manifest.read_bytes()).hexdigest()):
            with mock.patch.object(envmod, 'validate_manifest', return_value=(entries, [], [])):
                with mock.patch.object(envmod, 'verify_provenance', return_value=[]):
                    with mock.patch.object(envmod, 'MOLTENVK', molten):
                        return envmod.verify_runtime()

    def test_exact_inventory_accepts_only_all_bound_files(self):
        entries, molten = self.minimal_inventory()
        self.assertEqual(self.verify_minimal(entries, molten)['entries'], 3)
        (self.engine/'extra.dll').write_bytes(b'unbound')
        with self.assertRaisesRegex(RuntimeError, 'unbound code/data'):
            self.verify_minimal(entries, molten)

    def test_inventory_hardlink_or_symlink_is_rejected_before_code_read(self):
        entries, molten = self.minimal_inventory()
        path = self.engine/'bin/wine'
        sentinel = self.root/'unrelated.bin'
        sentinel.write_bytes(path.read_bytes())
        path.unlink()
        os.link(sentinel, path)
        with self.assertRaisesRegex(RuntimeError, 'alias/special'):
            self.verify_minimal(entries, molten)
        path.unlink()
        path.symlink_to(sentinel)
        with self.assertRaises(SystemExit):
            self.verify_minimal(entries, molten)

    def test_provenance_layer_scope_is_checked_before_any_file_read(self):
        allowed = self.root/'own.json'
        item = {'path': str(allowed), 'bytes': 2, 'sha256': hashlib.sha256(b'{}').hexdigest()}
        foreign = Path(self.temporary.name).resolve()/'outside.bin'
        with mock.patch.object(envmod, 'read_regular') as read:
            with self.assertRaises(RuntimeError):
                envmod.verify_provenance([(item, allowed, self.root), (dict(item, path=str(foreign)), foreign, self.root)])
        read.assert_not_called()

    def test_only_exact_sdk_settings_alias_is_resolved_and_recorded(self):
        sdk_root = self.root/'SDKs'
        actual = sdk_root/'MacOSX.sdk'
        actual.mkdir(parents=True)
        target = actual/'SDKSettings.json'
        target.write_bytes(b'{}')
        version = sdk_root/'MacOSX27.2.sdk'
        version.symlink_to(actual, target_is_directory=True)
        alias = version/'SDKSettings.json'
        item = {'path': str(alias), 'bytes': 2, 'sha256': hashlib.sha256(b'{}').hexdigest()}
        with mock.patch.object(envmod, 'SDK_ROOT', sdk_root), mock.patch.object(envmod, 'SDK_SETTINGS_ALIAS', alias):
            verified = envmod.verify_provenance([(item, alias, sdk_root)])
            self.assertEqual(verified[0]['path'], str(alias))
            self.assertEqual(verified[0]['resolved_path'], str(target))
            other = sdk_root/'Other.sdk'
            other.symlink_to(actual, target_is_directory=True)
            with self.assertRaises(SystemExit):
                envmod.verify_provenance([(dict(item, path=str(other/'SDKSettings.json')), other/'SDKSettings.json', sdk_root)])

    def test_sdk_alias_cannot_escape_declared_sdk_tree(self):
        sdk_root = self.root/'SDKs'
        sdk_root.mkdir()
        outside = self.root/'unrelated'
        outside.mkdir()
        (outside/'SDKSettings.json').write_bytes(b'{}')
        version = sdk_root/'MacOSX27.2.sdk'
        version.symlink_to(outside, target_is_directory=True)
        alias = version/'SDKSettings.json'
        item = {'path': str(alias), 'bytes': 2, 'sha256': hashlib.sha256(b'{}').hexdigest()}
        with mock.patch.object(envmod, 'SDK_ROOT', sdk_root), mock.patch.object(envmod, 'SDK_SETTINGS_ALIAS', alias):
            with mock.patch.object(envmod, 'read_regular') as read:
                with self.assertRaises(RuntimeError):
                    envmod.verify_provenance([(item, alias, sdk_root)])
            read.assert_not_called()

    def test_font_before_is_historical_while_after_and_output_are_live_bound(self):
        work = self.root/'build/wine-job-query-parity'
        build = work/'full-x86_64'
        tool = build/'tools/sfnt2fon/sfnt2fon'
        tool.parent.mkdir(parents=True)
        tool.write_bytes(b'after')
        font = build/'font-helper-smoke.fon'
        font.write_bytes(b'font')
        def item(path, payload):
            return {'path': str(path), 'bytes': len(payload), 'sha256': hashlib.sha256(payload).hexdigest()}
        value = {'before': item(tool, b'before'), 'after': item(tool, b'after'), 'font_output': item(font, b'font'),
                 'passed': True, 'font_conversion_exit': 0, 'only_own_native_build_helper_modified': True,
                 'original_dependency_modified': False}
        report = build/'font-helper-20261102T081649505809Z-results.json'
        report.write_text(json.dumps(value))
        identity = item(report, report.read_bytes())
        with mock.patch.object(envmod, 'WORK', work), mock.patch.object(envmod, 'BUILD', build):
            verified = envmod.verify_provenance([(identity, report, self.root)])
            claims = [entry for entry in verified if 'historical_artifact_claim' in entry]
            self.assertEqual(len(claims), 1)
            self.assertEqual(claims[0]['sha256'], value['before']['sha256'])
            self.assertIn(value['after'], verified)
            self.assertIn(value['font_output'], verified)
            tool.write_bytes(b'changed')
            with self.assertRaisesRegex(RuntimeError, 'Bound artifact changed'):
                envmod.verify_provenance([(identity, report, self.root)])

    def test_only_fixed_build_compiler_roles_allow_hardlinks_in_provenance(self):
        tool = self.root/'own-compiler'
        tool.write_bytes(b'compiler')
        alias = self.root/'other-name'
        os.link(tool, alias)
        item = {'path': str(tool), 'bytes': 8, 'sha256': hashlib.sha256(b'compiler').hexdigest()}
        with mock.patch.object(envmod, 'MULTILINK_BUILD_TOOLS', {tool}):
            verified = envmod.verify_provenance([(item, tool, self.root)])
            self.assertEqual(verified[0]['link_count'], 2)
            self.assertEqual(verified[0]['path_role'], 'fixed_historical_mingw_build_compiler')
            with self.assertRaises(RuntimeError):
                envmod.read_regular(tool)
            with self.assertRaises(RuntimeError):
                envmod.verify_provenance([(dict(item, path=str(alias)), alias, self.root)])
            with self.assertRaisesRegex(RuntimeError, 'compiler changed'):
                envmod.verify_provenance([(dict(item, sha256='0'*64), tool, self.root)])

    def test_fresh_prefix_binding_refuses_old_directory_or_changed_inode(self):
        self.prefix.mkdir(parents=True)
        with self.assertRaises(RuntimeError):
            runner.bind_prefix(True)
        original = runner.bind_prefix(False)
        self.assertEqual(runner.bind_prefix(True), original)
        value = json.loads(runner.binding_path().read_text())
        value['inode'] += 1
        runner.binding_path().write_text(json.dumps(value))
        with self.assertRaises(RuntimeError):
            runner.bind_prefix(True)

    def test_event_contract_requires_exact_counts_no_failures_and_one_final(self):
        events = [self.event() for _ in range(78)]+[self.event('all_cases_passed')]
        lines = [json.dumps(event) for event in events]
        self.assertTrue(runner.event_contract(lines, 79, 'all_cases_passed', 0, final_kind='result')['passed'])
        self.assertFalse(runner.event_contract(lines[:-1], 79, 'all_cases_passed', 0, final_kind='result')['passed'])
        self.assertFalse(runner.event_contract(lines, 79, 'all_cases_passed', 1, final_kind='result')['passed'])
        events[0]['ok'] = False
        self.assertFalse(runner.event_contract([json.dumps(event) for event in events], 79, 'all_cases_passed', 0, final_kind='result')['passed'])
        events[0]['ok'] = 1
        with self.assertRaises(RuntimeError):
            runner.event_contract([json.dumps(event) for event in events], 79, 'all_cases_passed', 0, final_kind='result')

    def test_query_terminal_is_assertion_and_does_not_accept_result(self):
        events = [self.event() for _ in range(169)]+[self.event('all_query_cases_passed')]
        lines = [json.dumps(event) for event in events]
        self.assertTrue(runner.event_contract(lines, 170, 'all_query_cases_passed', 0, final_kind='assertion')['passed'])
        events[-1]['kind'] = 'result'
        self.assertFalse(runner.event_contract([json.dumps(event) for event in events], 170,
                         'all_query_cases_passed', 0, final_kind='assertion')['passed'])
        with self.assertRaises(RuntimeError):
            runner.event_contract(lines, 170, 'all_query_cases_passed', 0, final_kind='result')

    def test_parent_terminal_does_not_accept_assertion_or_wrong_actor(self):
        events = [self.event() for _ in range(78)]+[self.event('all_cases_passed')]
        events[-1]['kind'] = 'assertion'
        self.assertFalse(runner.event_contract([json.dumps(event) for event in events], 79,
                         'all_cases_passed', 0, final_kind='result')['passed'])
        events[-1]['kind'] = 'result'
        events[-1]['actor'] = 'query'
        self.assertFalse(runner.event_contract([json.dumps(event) for event in events], 79,
                         'all_cases_passed', 0, final_kind='result')['passed'])

    def historical_reassessment_inputs(self):
        (self.root/'research').mkdir()
        (self.root/'logs').mkdir()
        source = self.root/'native/wine-parity-probes/run.py'
        source.parent.mkdir(parents=True)
        source.write_bytes(b'own parser source fixture')
        original = {'profile': envmod.ROLE, 'probe_role': 'jobs', 'protocol_version': 1810,
                    'runtime_started': True, 'runtime_verification': {'manifest_sha256': envmod.MANIFEST_SHA},
                    'cleanup': [{'flag': '-k', 'exit': 0}, {'flag': '-w', 'exit': 0}],
                    'quarantine_cleared_after_confirmed_cleanup': True, 'prefix_binding': {'inode': 42},
                    'passed': False, 'runs': []}
        for case in runner.job_cases():
            events = [self.event() for _ in range(case['expected_events']-1)]+[self.event(case['final_event'])]
            log = 'logs/'+runner.ORIGINAL_JOB_LABEL+'-'+case['name']+'.ndjson'
            (self.root/log).write_text(''.join(json.dumps(event)+'\n' for event in events))
            original['runs'].append({'name': case['name'], 'binary': 'build/windows-job-tests/'+case['name']+'.exe',
                                    'log': log, 'exit': 0, 'events': events, 'passed': case['name']=='job_parent'})
        result_path = 'research/'+runner.ORIGINAL_JOB_LABEL+'-results.json'
        (self.root/result_path).write_text(json.dumps(original))
        inputs = {}
        for name in [result_path]+[run['log'] for run in original['runs']]:
            raw = (self.root/name).read_bytes()
            inputs[name] = (len(raw), hashlib.sha256(raw).hexdigest())
        return inputs, {name: (self.root/name).read_bytes() for name in inputs}

    def test_reassessment_uses_only_fixed_logs_and_preserves_original_files(self):
        inputs, before = self.historical_reassessment_inputs()
        with mock.patch.object(runner, 'REASSESS_INPUTS', inputs):
            with mock.patch.object(runner.subprocess, 'run') as process:
                with mock.patch.object(envmod, 'verify_runtime') as verify:
                    with mock.patch.object(runner, 'probe_prefix') as prefix:
                        with redirect_stdout(io.StringIO()):
                            self.assertEqual(runner.reassess_jobs(), 0)
        process.assert_not_called()
        verify.assert_not_called()
        prefix.assert_not_called()
        for name, payload in before.items():
            self.assertEqual((self.root/name).read_bytes(), payload)
        result = json.loads(next((self.root/'research').glob('wine-parity-jobs-reassessment-*-results.json')).read_text())
        self.assertTrue(result['passed'])
        self.assertTrue(result['reassessment_only'])
        self.assertTrue(result['no_new_wine_run'])
        self.assertFalse(result['runtime_started'])
        self.assertFalse(result['prefix_or_engine_accessed'])
        self.assertEqual([run['event_count'] for run in result['runs']], [79, 170])
        self.assertEqual([run['final_kind'] for run in result['runs']], ['result', 'assertion'])
        self.assertEqual([run['original_reported_passed'] for run in result['runs']], [True, False])

    def test_reassessment_refuses_changed_old_log_before_writing_report(self):
        inputs, before = self.historical_reassessment_inputs()
        changed = next(name for name in before if name.endswith('job_query_contract.ndjson'))
        (self.root/changed).write_bytes(b'changed')
        with mock.patch.object(runner, 'REASSESS_INPUTS', inputs):
            with self.assertRaisesRegex(RuntimeError, 'input changed'):
                runner.reassess_jobs()
        self.assertEqual(list((self.root/'research').glob('wine-parity-jobs-reassessment-*-results.json')), [])

    def mock_run(self, *, cleanup_error=False, runtime_error=None, post_guard_error=False):
        binaries = []
        for name in ('job_parent', 'job_child', 'job_query_contract'):
            path = self.build/(name+'.exe')
            path.write_bytes(b'own code')
            binaries.append({'path': str(path.relative_to(self.root)), 'bytes': 8,
                             'sha256': hashlib.sha256(b'own code').hexdigest()})
        fixture = {'runtime_inputs': binaries}
        verification = {'manifest_sha256': envmod.MANIFEST_SHA, 'protocol_version': 1810}
        verify_calls = 0

        def verify_runtime():
            nonlocal verify_calls
            verify_calls += 1
            if runtime_error:
                raise runtime_error
            if post_guard_error and verify_calls == 4:
                raise RuntimeError('post-runtime guard')
            return verification

        def process(command, **kwargs):
            # A second lock acquisition must fail for initialization, probes and cleanup.
            with self.assertRaises(SystemExit):
                with runner.probe_prefix(self.prefix, root=self.root):
                    self.fail('Prefix lock was released while an owned process was live')
            if command[-1] == '-k' and cleanup_error:
                raise subprocess.TimeoutExpired(command, 15)
            if command[-1] == '-i':
                (self.prefix/'system.reg').write_text('own initialization')
                devices = self.prefix/'dosdevices'
                devices.mkdir()
                (devices/'c:').symlink_to('../drive_c', target_is_directory=True)
            elif command[-1].endswith('.exe'):
                name = Path(command[-1]).stem
                count, final = (79, 'all_cases_passed') if name=='job_parent' else (170, 'all_query_cases_passed')
                for i in range(count):
                    kwargs['stdout'].write(json.dumps(self.event(final if i == count-1 else 'one'))+'\n')
            return SimpleNamespace(returncode=0)

        with mock.patch.object(envmod, 'verify_runtime', side_effect=verify_runtime):
            with mock.patch.object(runner.subprocess, 'run', side_effect=process) as calls:
                with redirect_stdout(io.StringIO()):
                    status = runner.run_cases(runner.job_cases(), verify_inputs=lambda: fixture)
        results = sorted((self.root/'research').glob('wine-parity-jobs-*-results.json'))
        return status, json.loads(results[-1].read_text()), calls

    def test_mock_jobs_hold_lock_through_cleanup_and_clear_quarantine_only_when_clean(self):
        status, result, calls = self.mock_run()
        self.assertEqual(status, 0)
        self.assertEqual([run['event_count'] for run in result['runs']], [79, 170])
        self.assertEqual(calls.call_count, 5)
        self.assertFalse(runner.quarantine_path().exists())
        self.assertTrue(result['quarantine_cleared_after_confirmed_cleanup'])

    def test_cleanup_error_attempts_wait_and_retains_quarantine(self):
        status, result, calls = self.mock_run(cleanup_error=True)
        self.assertEqual(status, 1)
        self.assertEqual(result['cleanup'][1], {'flag': '-w', 'exit': 0})
        self.assertTrue(runner.quarantine_path().exists())
        self.assertTrue(result['prefix_terminal_state_uncertain'])
        with self.assertRaises(RuntimeError):
            runner.refuse_quarantine()

    def test_post_runtime_guard_error_retains_quarantine_and_evidence(self):
        status, result, _ = self.mock_run(post_guard_error=True)
        self.assertEqual(status, 1)
        self.assertEqual(result['post_run_guard_failure']['message'], 'post-runtime guard')
        self.assertTrue(runner.quarantine_path().exists())

    def test_runtime_guard_failure_saves_evidence_without_prefix_or_process(self):
        status, result, calls = self.mock_run(runtime_error=RuntimeError('engine differs'))
        self.assertEqual(status, 1)
        self.assertFalse(self.prefix.exists())
        self.assertFalse(result['runtime_started'])
        calls.assert_not_called()


if __name__ == '__main__':
    unittest.main()
