import copy
import errno
import hashlib
import importlib.util
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('own_rockstar_update', ROOT / 'native/windows-client/run_user_rockstar_update.py')
update = importlib.util.module_from_spec(spec)
spec.loader.exec_module(update)


def manifest():
    return {'files': [{'path': update.code_policy.CODE_ROOTS[0] + '/own-%03d.dll' % index,
                       'bytes': 4, 'sha256': 'a' * 64} for index in range(142)]}


class UpdateControlTests(unittest.TestCase):
    def test_removed_walk_descendant_is_normal_but_root_or_outside_enoent_is_not(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / 'code'
            directory.mkdir()
            def walk_error(path):
                def walk(_directory, **kwargs):
                    kwargs['onerror'](FileNotFoundError(errno.ENOENT, 'own removed directory', str(path)))
                    return iter(())
                return walk
            with patch.object(update, 'PREFIX', root), patch.object(update.os, 'walk', side_effect=walk_error(directory / 'retired')):
                self.assertEqual(update.walk_local(directory), {})
            for path in (directory, root / 'outside'):
                with patch.object(update, 'PREFIX', root), patch.object(update.os, 'walk', side_effect=walk_error(path)):
                    with self.subTest(path=path), self.assertRaises(FileNotFoundError):
                        update.walk_local(directory)

    def test_checkpoint_scope_is_only_142_code_and_two_own_metadata_files(self):
        items = update.checkpoint_items(manifest())
        self.assertEqual(len(items), 144)
        self.assertEqual([row['path'] for row in items[-2:]],
                         ['.source-main-probe', '.source-main-rockstar-code.json'])
        for bad in ('user.reg', 'drive_c/users/own/Documents/Rockstar Games/Launcher/session.dat',
                    update.ZERO_STAGE, update.code_policy.CODE_ROOTS[0] + '/Profiles/cookies'):
            record = manifest()
            record['files'][0]['path'] = bad
            with self.subTest(path=bad), self.assertRaises(update.ProbePrefixError):
                update.checkpoint_items(record)

    def test_checkpoint_rejects_aliases_and_invalid_identities(self):
        record = manifest()
        record['files'][1]['path'] = record['files'][0]['path'].upper()
        with self.assertRaises(update.ProbePrefixError):
            update.checkpoint_items(record)
        record = manifest()
        record['files'][0]['bytes'] = True
        with self.assertRaises(update.ProbePrefixError):
            update.checkpoint_items(record)

    def test_frozen_report_cannot_select_another_stage_before_prefix_access(self):
        record = json.loads((ROOT / update.FROZEN).read_bytes())
        record['unclassified_additional_files_metadata_only'][0]['path'] = 'drive_c/users/own/private.dat'
        raw = json.dumps(record).encode()
        with patch.object(update, 'read_metadata', return_value=raw), \
                patch.object(update, 'FROZEN_BYTES', len(raw)), \
                patch.object(update, 'FROZEN_SHA', hashlib.sha256(raw).hexdigest()), \
                patch.object(update, '_location') as location:
            with self.assertRaises(update.ProbePrefixError):
                update.preflight()
            location.assert_not_called()

    def test_citizenfx_even_empty_or_mixed_case_is_rejected_before_cleanup(self):
        engine = ROOT / 'runtime/wine-job-query-parity/engine'
        for key in ('CitizenFX_ToolMode', 'CITIZENFX_'):
            runtime = SimpleNamespace(ENGINE=engine, WINE=engine / 'bin/wine', environment=lambda: {key: ''})
            with self.subTest(key=key), self.assertRaises(update.ProbePrefixError):
                update.runtime_environment(runtime)
        runtime = SimpleNamespace(ENGINE=engine, WINE=engine / 'bin/wine', environment=lambda: {
            'WINEPREFIX': '/unrelated', 'WINELOADER': '/wrong', 'WINESERVERSOCKET': '/wrong'})
        env = update.runtime_environment(runtime)
        self.assertEqual(env['WINEPREFIX'], str(update.PREFIX))
        self.assertEqual(env['WINESERVER'], str(engine / 'bin/wineserver'))
        self.assertNotIn('WINELOADER', env)
        self.assertNotIn('WINESERVERSOCKET', env)
        self.assertEqual(env['WINEDEBUG'], '-all')

    def supervise(self, isolation, sleep):
        engine = ROOT / 'runtime/wine-job-query-parity/engine'
        runtime = SimpleNamespace(ENGINE=engine, WINE=engine / 'bin/wine', before_source_spawn=Mock())
        env = {'WINEPREFIX': str(update.PREFIX), 'WINESERVER': str(engine / 'bin/wineserver')}
        context = {'prefix_identity': [1, 2], 'code_manifest_sha256': 'a' * 64,
                   'staging_review': {'path': update.FROZEN}, 'identity': {}}
        process = Mock(pid=12345)
        process.poll.return_value = 0
        process.wait.return_value = 0
        saved = []
        def capture(_path, record, new=False):
            saved.append(copy.deepcopy(record))
        with patch.object(update, 'save', side_effect=capture), \
                patch.object(update, 'isolation', side_effect=isolation), \
                patch.object(update, 'cleanup_identity'), \
                patch.object(update.subprocess, 'Popen', return_value=process) as launch, \
                patch.object(update.subprocess, 'run', return_value=SimpleNamespace(returncode=0)) as cleanup, \
                patch.object(update.time, 'sleep', side_effect=sleep) as wait, \
                patch('builtins.print'):
            result = update.supervise(runtime, env, context, {'complete': True}, ROOT / 'research/own-test.json')
        return result, saved, launch, cleanup, wait

    def test_natural_launcher_exit_does_not_end_update_and_sigint_cleans_exact_prefix(self):
        metadata = {'metadata_boundaries_passed': True, 'runtime_code_immutability_enforced': False}
        result, saved, launch, cleanup, wait = self.supervise([metadata] * 3, [None, KeyboardInterrupt()])
        self.assertEqual(wait.call_count, 2)
        self.assertEqual(result['original_launcher_exit'], 0)
        self.assertEqual(result['cleanup_reason'], 'root-sigint-requested-stop')
        self.assertEqual(result['status'], 'root-stopped-pending-final-code-review')
        self.assertTrue(result['cleanup_confirmed'])
        self.assertFalse(result['updater_success_claim'])
        self.assertTrue(result['final_code_binding_pending'])
        self.assertIsNone(result['automatic_time_limit_seconds'])
        self.assertEqual(launch.call_args.args[0], [str(ROOT / 'runtime/wine-job-query-parity/engine/bin/wine'),
            str(update.PREFIX / update.code_policy.CODE_ROOTS[0] / 'Launcher.exe')])
        self.assertEqual([call.args[0][-1] for call in cleanup.call_args_list], ['-k', '-w'])
        self.assertTrue(all(call.kwargs['env']['WINEPREFIX'] == str(update.PREFIX) for call in cleanup.call_args_list))
        self.assertEqual(saved[-1]['status'], result['status'])

    def test_real_isolation_failure_cleans_without_waiting_for_operator(self):
        metadata = {'metadata_boundaries_passed': True}
        result, saved, _launch, cleanup, wait = self.supervise(
            [metadata, update.ProbePrefixError('own boundary failure')], [])
        wait.assert_not_called()
        self.assertEqual(cleanup.call_count, 2)
        self.assertEqual(result['cleanup_reason'], 'isolation-or-controller-failure')
        self.assertEqual(result['failure_type'], 'ProbePrefixError')
        self.assertEqual(saved[-1]['status'], 'stopped-or-detached-needs-review')
        self.assertNotIn('own boundary failure', json.dumps(result))

    def test_actual_cleanup_failure_remains_needs_review(self):
        metadata = {'metadata_boundaries_passed': True}
        engine = ROOT / 'runtime/wine-job-query-parity/engine'
        runtime = SimpleNamespace(ENGINE=engine, WINE=engine / 'bin/wine', before_source_spawn=Mock())
        context = {'prefix_identity': [1, 2], 'code_manifest_sha256': 'a' * 64, 'staging_review': {}, 'identity': {}}
        env = {'WINEPREFIX': str(update.PREFIX), 'WINESERVER': str(engine / 'bin/wineserver')}
        for kill_exit, wait_failure, changed_inode in ((1, None, False), (0, update.subprocess.TimeoutExpired('own wait', 10), False), (0, None, True)):
            process = Mock(pid=12)
            process.poll.return_value = None
            process.wait.return_value = 0
            process.wait.side_effect = wait_failure
            with self.subTest(kill_exit=kill_exit, parent_wait_timeout=wait_failure is not None, changed_inode=changed_inode), \
                    patch.object(update, 'save'), patch.object(update, 'isolation', return_value=metadata), \
                    patch.object(update.subprocess, 'Popen', return_value=process), \
                    patch.object(update.subprocess, 'run', side_effect=[SimpleNamespace(returncode=kill_exit), SimpleNamespace(returncode=0)]) as cleanup, \
                    patch.object(update, '_location', return_value=(update.PREFIX, ROOT)), \
                    patch.object(Path, 'stat', return_value=SimpleNamespace(st_dev=1, st_ino=3 if changed_inode else 2)), \
                    patch.object(update.time, 'sleep', side_effect=KeyboardInterrupt()), patch('builtins.print'):
                result = update.supervise(runtime, env, context, {}, ROOT / 'research/own-test.json')
            self.assertFalse(result['cleanup_confirmed'])
            if changed_inode:
                cleanup.assert_not_called()
                self.assertEqual(result['cleanup'], [])
                self.assertEqual(result['cleanup_failure_type'], 'ProbePrefixError')
            else:
                self.assertEqual(result['cleanup'][0]['exit'], kill_exit)
            self.assertEqual(result['status'], 'stopped-or-detached-needs-review')
            self.assertEqual(result.get('original_launcher_wait_timed_out', False), wait_failure is not None)


if __name__ == '__main__':
    unittest.main()
