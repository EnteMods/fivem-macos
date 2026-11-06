"""No-Wine fixtures for candidate binding, cleanup and preserved failure evidence."""
from contextlib import contextmanager, redirect_stdout
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
SPEC = importlib.util.spec_from_file_location('own_job_query_runner', PROJECT / 'native/windows-job-tests/run_query.py')
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class JobQueryRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve() / 'project'
        self.root.mkdir()
        self.build = self.root / 'build/windows-job-tests'
        self.build.mkdir(parents=True)
        for name in ('logs', 'research'):
            (self.root / name).mkdir()
        self.patch_root = mock.patch.object(runner, 'ROOT', self.root); self.patch_root.start()
        self.patch_build = mock.patch.object(runner, 'BUILD', self.build); self.patch_build.start()
        self.prefix = self.root / 'prefixes/corert-regression'
        with runner.probe_prefix(self.prefix, root=self.root, create=True):
            (self.prefix / 'drive_c').mkdir()
            (self.prefix / 'dosdevices').mkdir()
            (self.prefix / 'dosdevices/c:').symlink_to('../drive_c')
            (self.prefix / 'system.reg').write_text('Own fixture registry; no user data.\n')
        self.query = self.build / 'job_query_contract.exe'
        self.query.write_bytes(b'MZ own inert query fixture; never executed')
        source = self.root / 'native/windows-job-tests'; source.mkdir(parents=True)
        for name in ('job_query_contract.cpp', 'events.h', 'CMakeLists.txt'):
            (source / name).write_text('Own source metadata fixture: ' + name)
        self.query_evidence = {'passed': True, 'runtime_started': False,
                              'binary': str(self.query.relative_to(self.root)),
                              'sha256': runner.sha(self.query), 'bytes': self.query.stat().st_size,
                              **{key: runner.sha(source / name) for key, name in (
                                  ('source_sha256', 'job_query_contract.cpp'),
                                  ('events_header_sha256', 'events.h'), ('cmake_sha256', 'CMakeLists.txt'))}}
        self.write_json('research/windows-job-query-build.json', self.query_evidence)
        self.wine = self.build / 'own-fake-wine'; self.wine.write_bytes(b'Own inert loader fixture')
        self.server = self.build / 'own-fake-server'; self.server.write_bytes(b'Own inert server fixture')

    def tearDown(self):
        self.patch_build.stop(); self.patch_root.stop(); self.temp.cleanup()

    def write_json(self, relative, value):
        p = self.root / relative; p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(value, indent=2) + '\n')
        return self.identity(p)

    def identity(self, p):
        return {'path': str(p.relative_to(self.root)), 'sha256': runner.sha(p), 'bytes': p.stat().st_size}

    def latest(self):
        paths = sorted((self.root / 'research').glob('windows-job-query-baseline-*-results.json'))
        return json.loads(paths[-1].read_text())

    def exercise(self, cleanup_failure=None, post_guard_failure=False, query_failure=False):
        calls=[]; held=[False]
        original_guard=runner.probe_prefix
        @contextmanager
        def tracked_guard(*args, **kwargs):
            with original_guard(*args, **kwargs):
                held[0]=True
                try: yield self.prefix
                finally: held[0]=False
        def run(command, **kwargs):
            self.assertTrue(held[0]); self.assertTrue(runner.quarantine_path(self.prefix).is_file())
            self.assertEqual(kwargs['env']['WINEPREFIX'], str(self.prefix))
            calls.append(command)
            if command[1] in ('-k','-w'):
                if command[1] == cleanup_failure: raise subprocess.TimeoutExpired(command,10)
            else:
                if query_failure: raise subprocess.TimeoutExpired(command,45)
                kwargs['stdout'].write(json.dumps({'name':'all_query_cases_passed','ok':True})+'\n')
            return SimpleNamespace(returncode=0)
        runtime=(self.wine,self.server,{},self.prefix,None)
        with mock.patch.object(runner,'runtime',return_value=runtime), \
                mock.patch.object(runner,'probe_prefix',tracked_guard), \
                mock.patch.object(runner.subprocess,'run',side_effect=run), redirect_stdout(io.StringIO()):
            if post_guard_failure:
                with mock.patch.object(runner,'assert_account_free_prefix',side_effect=RuntimeError('own injected post-guard failure')):
                    code=runner.test('baseline')
            else: code=runner.test('baseline')
        return code,calls,self.latest()

    def test_success_uses_held_lock_then_clears_owned_marker_after_both_cleanup_steps(self):
        code,calls,result=self.exercise()
        self.assertEqual(code,0)
        self.assertEqual([c[1] for c in calls],[str(self.query),'-k','-w'])
        self.assertTrue(result['passed'])
        self.assertTrue(result['quarantine_marker_cleared_after_confirmed_cleanup'])
        self.assertFalse(runner.quarantine_path(self.prefix).exists())

    def test_kill_timeout_still_attempts_wait_preserves_evidence_and_blocks_reuse(self):
        code,calls,result=self.exercise(cleanup_failure='-k')
        self.assertEqual(code,1); self.assertEqual([c[1] for c in calls][-2:],['-k','-w'])
        self.assertEqual(result['cleanup'][0]['failure_type'],'TimeoutExpired')
        self.assertEqual(result['cleanup'][1]['exit'],0)
        self.assertTrue(result['prefix_terminal_state_uncertain'])
        self.assertTrue(runner.quarantine_path(self.prefix).is_file())
        with mock.patch.object(runner,'runtime',return_value=(self.wine,self.server,{},self.prefix,None)), \
                mock.patch.object(runner.subprocess,'run') as execute, redirect_stdout(io.StringIO()):
            self.assertEqual(runner.test('baseline'),1)
            execute.assert_not_called()

    def test_wait_timeout_and_post_guard_failure_leave_refusal_marker_and_result(self):
        for mode in ('wait','guard'):
            with self.subTest(mode=mode):
                code,_,result=self.exercise(cleanup_failure='-w' if mode=='wait' else None,
                                             post_guard_failure=mode=='guard')
                self.assertEqual(code,1); self.assertTrue(result['prefix_terminal_state_uncertain'])
                if mode=='guard': self.assertIn('post_run_guard_failure',result)
                self.assertTrue(runner.quarantine_path(self.prefix).is_file())
                runner.quarantine_path(self.prefix).unlink()

    def test_fixture_timeout_still_cleans_and_keeps_failure_evidence(self):
        code,calls,result=self.exercise(query_failure=True)
        self.assertEqual(code,1); self.assertEqual([c[1] for c in calls][-2:],['-k','-w'])
        self.assertEqual(result['failure']['type'],'TimeoutExpired')
        self.assertFalse(runner.quarantine_path(self.prefix).exists())

    def test_wrong_fixture_path_or_changed_source_refuses_before_runtime(self):
        other=self.build/'other.exe'; other.write_bytes(self.query.read_bytes())
        self.query_evidence.update(binary=str(other.relative_to(self.root)))
        self.write_json('research/windows-job-query-build.json',self.query_evidence)
        with mock.patch.object(runner,'runtime') as runtime, redirect_stdout(io.StringIO()):
            self.assertEqual(runner.test('baseline'),1); runtime.assert_not_called()
        self.assertFalse(self.latest()['runtime_started'])
        self.query_evidence['binary']=str(self.query.relative_to(self.root))
        self.write_json('research/windows-job-query-build.json',self.query_evidence)
        (self.root/'native/windows-job-tests/events.h').write_text('own changed source')
        with mock.patch.object(runner,'runtime') as runtime, redirect_stdout(io.StringIO()):
            self.assertEqual(runner.test('baseline'),1); runtime.assert_not_called()

    def test_bootstrap_seeds_nonempty_local_crossover_personal_folder_targets(self):
        with mock.patch.object(runner.getpass,'getuser',return_value='own-fixture-user'):
            runner.seed_personal_directories(self.prefix)
        for user in ('own-fixture-user','Public'):
            for name in (*runner.PERSONAL_FOLDERS,'Desktop/My Mac Desktop',
                         'AppData/Roaming/Microsoft/Windows/Templates'):
                path=self.prefix/'drive_c/users'/user/name
                self.assertTrue(path.is_dir()); self.assertFalse(path.is_symlink())
                self.assertTrue((path/'.local-api-fixture-directory').is_file())
    def candidate(self):
        full=self.root/runner.CANDIDATE_REL; files=[]
        for name in ('loader/wine','server/wineserver','dlls/ntdll/ntdll.so',
                     'dlls/ntdll/x86_64-windows/ntdll.dll','dlls/kernel32/x86_64-windows/kernel32.dll',
                     'dlls/kernelbase/x86_64-windows/kernelbase.dll',
                     'programs/wineboot/x86_64-windows/wineboot.exe','loader/wine.inf',
                     'dlls/win32u/libMoltenVK.dylib'):
            p=full/name; p.parent.mkdir(parents=True,exist_ok=True)
            p.write_bytes((b'own INF data' if name.endswith('.inf') else b'MZ own inert code')+name.encode())
            files.append(p)
        nls=self.root/runner.WORK_REL/'source/nls/c_own.nls'; nls.parent.mkdir(parents=True)
        nls.write_bytes(b'own inert NLS data')
        link=full/'nls/c_own.nls'; link.parent.mkdir(); link.symlink_to(nls); files.append(link)
        frontend=full/'tools/wine/wine'; frontend.parent.mkdir(parents=True)
        frontend.write_bytes(b'MZ own inert frontend fixture'); files.append(frontend)
        frontend_link=full/'wine'; frontend_link.symlink_to('tools/wine/wine'); files.append(frontend_link)
        placed=full/'dlls/win32u/libMoltenVK.dylib'
        original=self.root/runner.WORK_REL/'dependencies/moltenvk/libMoltenVK.dylib'
        original.parent.mkdir(parents=True); original.write_bytes(placed.read_bytes())
        self.own_dependency_sha=runner.sha(placed)
        records={}
        values=[('source_preparation_record','source-preparation.json',{'original_generator_executed':True}),
                ('configure_record','wine-moltenvk-configure-results.json',{'passed':True,'timeout':False,'protocol_version':1810,'variant':'moltenvk'}),
                ('build_record','wine-moltenvk-all-results.json',{'passed':True,'timeout':False,'protocol_version':1810,'variant':'moltenvk','artifacts':[self.identity(full/'loader/wine')]}),
                ('dependency_record','moltenvk-build-dependency.json',{'sha256':self.own_dependency_sha,'archive_sha256':runner.MOLTENVK_ARCHIVE_SHA})]
        for key,name,value in values: records[key]=self.write_json(str(runner.WORK_REL/name),value)
        inventory=[]
        for p in files:
            item=dict(self.identity(p),kind='data' if p.suffix=='.nls' or p.name=='wine.inf' else 'code')
            if p.is_symlink():item.update(symlink_target=str(p.readlink()),resolved_path=str(p.resolve().relative_to(self.root)))
            inventory.append(item)
        manifest={'schema_version':1,'build_passed':True,'runtime_tested':False,'protocol_version':1810,
                  'build_dir':str(runner.CANDIDATE_REL),'intended_prefix':'prefixes/wine-job-query-regression',
                  'loader':self.identity(full/'loader/wine'),'server':self.identity(full/'server/wineserver'),
                  'ntdll_unix':self.identity(full/'dlls/ntdll/ntdll.so'),**records,
                  'runtime_files':inventory,'runtime_file_count':len(inventory),
                  'external_code_dependencies':[dict(self.identity(placed),original_snapshot=self.identity(original),
                       original_archive_sha256=runner.MOLTENVK_ARCHIVE_SHA)]}
        self.save_candidate(manifest)
        return manifest,link,original

    def save_candidate(self,manifest):
        self.write_json(str(runner.WORK_REL/'candidate-manifest.json'),manifest)

    def test_real_generator_schema_exact_nls_binding_dependency_and_fixed_environment(self):
        manifest,_,_=self.candidate()
        with mock.patch.object(runner,'MOLTENVK_SHA',self.own_dependency_sha), \
                mock.patch.dict(os.environ,{'DYLD_LIBRARY_PATH':'old','WINEDLLPATH':'old','WINESERVERSOCKET':'old','DXMT_OLD':'old'}):
            wine,server,env,prefix,reference=runner.candidate_runtime()
        self.assertEqual(env['WINESERVER'],str(server));self.assertEqual(wine,self.root/manifest['loader']['path'])
        self.assertEqual(prefix,self.root/'prefixes/wine-job-query-regression')
        self.assertEqual(env['WINEDLLOVERRIDES'],'winemenubuilder.exe,mscoree,mshtml=d')
        for key in ('DYLD_LIBRARY_PATH','WINEDLLPATH','WINESERVERSOCKET','DXMT_OLD'):self.assertNotIn(key,env)
        self.assertEqual(reference['sha256'],runner.sha(self.root/runner.WORK_REL/'candidate-manifest.json'))

    def test_candidate_rejects_partial_schema_inventory_external_changes_and_unbound_links(self):
        manifest,link,original=self.candidate()
        with mock.patch.object(runner,'MOLTENVK_SHA',self.own_dependency_sha):
            for changes in ({'schema_version':0},{'build_passed':False},{'runtime_tested':True},
                            {'runtime_files':manifest['runtime_files'][:-1],'runtime_file_count':len(manifest['runtime_files'])-1}):
                with self.subTest(changes=list(changes)):
                    self.save_candidate(dict(manifest,**changes))
                    with self.assertRaises(RuntimeError):runner.candidate_runtime()
            self.save_candidate(manifest)
            original.write_bytes(b'own changed dependency')
            with self.assertRaises(RuntimeError):runner.candidate_runtime()
            original.write_bytes((self.root/manifest['external_code_dependencies'][0]['path']).read_bytes())
            outside=self.root/'outside.nls'; outside.write_bytes(b'own outside fixture')
            link.unlink();link.symlink_to(outside)
            with self.assertRaises(RuntimeError):runner.candidate_runtime()

    def test_candidate_prefix_requires_fresh_or_exact_manifest_inode_binding(self):
        prefix=self.root/'prefixes/wine-job-query-regression';prefix.mkdir()
        reference={'path':str(runner.WORK_REL/'candidate-manifest.json'),'sha256':'a'*64}
        with self.assertRaises(RuntimeError):runner.candidate_prefix_binding(prefix,reference,True)
        runner.candidate_prefix_binding(prefix,reference,False)
        runner.candidate_prefix_binding(prefix,reference,True)
        with self.assertRaises(RuntimeError):runner.candidate_prefix_binding(prefix,dict(reference,sha256='b'*64),True)
