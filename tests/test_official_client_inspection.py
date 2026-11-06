"""Fresh-prefix metadata and controller fixtures; all target processes are mocked."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('official_inspection_test', PROJECT/'native/official-client-inspection/run.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class OfficialInspectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.inspection = runner.Inspection(self.root)
        self.inspection.client.mkdir(parents=True)
        self.inspection.original.parent.mkdir()
        own = b'Own inert fixture bytes; never executable or launched'
        for name, value in (('EXECUTABLE_SHA256', hashlib.sha256(own).hexdigest()), ('EXECUTABLE_BYTES', len(own))):
            patch = mock.patch.object(runner, name, value)
            patch.start()
            self.addCleanup(patch.stop)
        self.inspection.original.write_bytes(own)
        self.inspection.executable.write_bytes(own)
        self.metadata = {'path': str(self.inspection.original.relative_to(self.root)),
                         'client_path': str(self.inspection.executable.relative_to(self.root)),
                         'requested_url': 'https://runtime.fivem.net/client/FiveM.exe',
                         'final_url': 'https://content.cfx.re/mirrors/client_download/FiveM.exe',
                         'official_download_page': 'https://fivem.net/', 'http_status': 200, 'format': 'PE',
                         'machine': '0x8664', 'executed': False,
                         'tls_verification': 'Python default certificate and hostname verification',
                         'copied_existing_client_or_authentication_state': False,
                         'existing_installation_overwritten': False,
                         'bytes': len(own), 'sha256': hashlib.sha256(own).hexdigest()}
        self.save_metadata(self.metadata)

    def save_metadata(self, metadata):
        self.inspection.reference_record.parent.mkdir(parents=True, exist_ok=True)
        for path in (self.inspection.download_record, self.inspection.reference_record):
            path.write_text(json.dumps(metadata))

    def tearDown(self):
        self.temporary.cleanup()

    def test_exclusive_fresh_creation_nonempty_personal_dirs_and_inode_binding(self):
        with self.inspection.session(create=True):
            identity = self.inspection.assert_prefix()
            self.assertEqual(identity['inode'], self.inspection.prefix.stat().st_ino)
            for user in (runner.username(), 'Public'):
                for folder in runner.LOCAL_FOLDERS:
                    personal = self.inspection.prefix/'drive_c/users'/user/folder
                    self.assertTrue(list(personal.iterdir()))
                    self.assertFalse(personal.is_symlink())
        with self.assertRaises(runner.ProbePrefixError):
            with self.inspection.session(create=True):
                self.fail('Existing prefix must not be reused')
        original = self.inspection.prefix.with_name('own-original-fixture-prefix')
        self.inspection.prefix.rename(original)
        shutil.copytree(original, self.inspection.prefix)
        with self.assertRaises(runner.ProbePrefixError):
            self.inspection.assert_prefix()

    def test_host_c_mapping_personal_symlink_and_hardlinked_registry_are_refused(self):
        with self.inspection.session(create=True):
            devices = self.inspection.prefix/'dosdevices'
            (devices/'c:').unlink()
            (devices/'c:').symlink_to(self.root)
            with self.assertRaises(runner.ProbePrefixError):
                self.inspection.assert_prefix()
            (devices/'c:').unlink()
            (devices/'c:').symlink_to('../drive_c', target_is_directory=True)
            personal = self.inspection.prefix/'drive_c/users'/runner.username()/'Documents'
            shutil.rmtree(personal)
            personal.symlink_to(self.root, target_is_directory=True)
            with self.assertRaises(runner.ProbePrefixError):
                self.inspection.assert_prefix()
            personal.unlink()
            personal.mkdir()
            own_registry = self.root/'own-private-sentinel'
            own_registry.write_text('Own private sentinel; must never be interpreted')
            os.link(own_registry, self.inspection.prefix/'user.reg')
            with self.assertRaises(runner.ProbePrefixError):
                self.inspection.assert_prefix()

    def test_c_mapping_precedes_wineboot_and_early_system_registry_never_weakens_guard(self):
        with self.inspection.session(create=True):
            mapping = self.inspection.prefix/'dosdevices/c:'
            self.assertEqual(mapping.readlink(), Path('../drive_c'))
            self.assertEqual(mapping.resolve(), self.inspection.prefix/'drive_c')
            self.inspection.assert_prefix()
            (self.inspection.prefix/'system.reg').write_text('Own early wineboot registry fixture\n')
            self.inspection.assert_prefix()
            mapping.unlink()
            with self.assertRaisesRegex(runner.ProbePrefixError, 'missing its C: mapping'):
                self.inspection.assert_prefix()
            mapping.symlink_to(self.root)
            with self.assertRaisesRegex(runner.ProbePrefixError, 'exactly to this prefix'):
                self.inspection.assert_prefix()

    def test_fixed_download_paths_and_no_source_role_files(self):
        self.inspection.inputs()
        invalid = copy.deepcopy(self.metadata)
        invalid['path'] = 'prefixes/other/user.reg'
        self.save_metadata(invalid)
        with mock.patch.object(runner, 'sha') as hashed, self.assertRaises(runner.ProbePrefixError):
            self.inspection.inputs()
        hashed.assert_not_called()
        self.save_metadata(self.metadata)
        (self.inspection.client/'FiveM.exe.formaldev').write_text('own unwanted role fixture')
        with self.assertRaises(runner.ProbePrefixError):
            self.inspection.inputs()

    def test_agreeing_download_records_cannot_replace_the_pinned_executable(self):
        invalid = copy.deepcopy(self.metadata)
        invalid['sha256'] = '0'*64
        self.save_metadata(invalid)
        with mock.patch.object(runner, 'sha') as hashed, self.assertRaises(runner.ProbePrefixError):
            self.inspection.inputs()
        hashed.assert_not_called()

    def test_renderer_roles_and_complete_filename_set_are_admitted_before_code_hashes(self):
        reviewed = json.loads((PROJECT/runner.DXMT_PIN_RECORD).read_text())
        for defect in ('provider-root', 'filename', 'archive-root'):
            invalid = copy.deepcopy(reviewed)
            if defect == 'provider-root': invalid['provider_relative_root'] = 'prefixes/private'
            elif defect == 'filename': invalid['files'][0]['relative_path'] = '../../prefixes/private/user.reg'
            else: invalid['source_archive']['relative_path'] = 'prefixes/private/user.reg'
            (self.root/runner.DXMT_PIN_RECORD).write_text(json.dumps(invalid))
            with self.subTest(defect=defect), mock.patch.object(runner, 'sha') as hashed, self.assertRaises(runner.ProbePrefixError):
                runner.renderer_binding(self.inspection)
            hashed.assert_not_called()

    def test_replaced_code_directories_or_lock_refused_before_new_lock_or_private_reads(self):
        with self.inspection.session(create=True):
            old = self.inspection.base.with_name(self.inspection.base.name+'-own-old')
            self.inspection.base.rename(old)
            shutil.copytree(old, self.inspection.base)
            replacement = runner.Inspection(self.root)
            with mock.patch.object(runner.os, 'open') as opened, \
                    mock.patch.object(runner, '_check_shell_folders') as registry, self.assertRaises(runner.ProbePrefixError):
                with replacement.session(): self.fail('Replaced base acquired a different lock')
            opened.assert_not_called()
            registry.assert_not_called()

    def test_replaced_client_download_and_lock_inodes_are_detected(self):
        with self.inspection.session(create=True):
            for directory in (self.inspection.client, self.inspection.original.parent):
                renamed = directory.with_name(directory.name+'-own-old')
                directory.rename(renamed)
                shutil.copytree(renamed, directory)
                with self.assertRaises(runner.ProbePrefixError): self.inspection.assert_prefix()
                shutil.rmtree(directory)
                renamed.rename(directory)
            self.inspection.lock.rename(self.inspection.base/'own-old-lock')
            self.inspection.lock.write_text('own replacement lock')
            with self.assertRaises(runner.ProbePrefixError): self.inspection.assert_prefix()

    def test_result_appearing_during_lock_acquisition_is_preserved_before_prefix_creation(self):
        def intervening(*args):
            self.inspection.result.write_text('own intervening result')

        with mock.patch.object(runner.fcntl, 'flock', side_effect=intervening), self.assertRaises(runner.ProbePrefixError):
            with self.inspection.session(create=True): self.fail('Intervening output was overwritten')
        self.assertEqual(self.inspection.result.read_text(), 'own intervening result')
        self.assertFalse(self.inspection.prefix.exists())

    def test_initialization_write_failure_rolls_back_only_new_owned_objects(self):
        with mock.patch.object(runner.os, 'fsync', side_effect=OSError('own write failure')), self.assertRaises(OSError):
            with self.inspection.session(create=True): self.fail('Partial initialization yielded')
        self.assertFalse(self.inspection.prefix.exists())
        self.inspection.inputs()

    def test_initialization_rollback_preserves_unexpected_objects_for_review(self):
        def injected_failure(*args):
            (self.inspection.prefix/'own-unexpected-sentinel').write_text('must remain')
            raise OSError('own write failure')

        with mock.patch.object(runner.os, 'fsync', side_effect=injected_failure), \
                self.assertRaisesRegex(runner.ProbePrefixError, 'rollback incomplete'):
            with self.inspection.session(create=True): self.fail('Partial initialization yielded')
        self.assertEqual((self.inspection.prefix/'own-unexpected-sentinel').read_text(), 'must remain')

    def test_failed_result_dump_or_replace_is_retryable_and_preserves_previous_result(self):
        self.inspection.write_result({'label': runner.LABEL, 'status': 'own-old'})
        before = self.inspection.result.read_bytes()
        for operation in ('dump', 'replace'):
            patched = mock.patch.object(runner.json if operation == 'dump' else runner.os, operation,
                                        side_effect=OSError('own '+operation+' failure'))
            with patched, self.assertRaises(OSError): self.inspection.write_result({'status': 'own-new'})
            self.assertEqual(self.inspection.result.read_bytes(), before)
            self.assertFalse(list(self.inspection.base.glob('.session-*.json.pending')))
        self.inspection.write_result({'status': 'own-next'})
        self.assertEqual(json.loads(self.inspection.result.read_text())['status'], 'own-next')

    def test_only_this_fresh_game_clone_can_be_bound_to_g(self):
        self.inspection.game.mkdir(parents=True)
        for name in ('GTA5.exe', 'PlayGTAV.exe', 'GTAVLauncher.exe'):
            (self.inspection.game/name).write_bytes(b'Own inert game-name fixture; never executed')
        info = self.inspection.game.stat()
        record = {'target': str(self.inspection.game.relative_to(self.root)), 'target_device': info.st_dev,
                  'target_inode': info.st_ino, 'file_count': 443, 'logical_bytes': 128918230441,
                  'copied_client_account_profiles_or_tickets': False, 'source_game_or_existing_client_files_written': False,
                  'known_game_executable_checks': {'GTA5.exe': True, 'PlayGTAV.exe': True, 'GTAVLauncher.exe': True}}
        for path in (self.inspection.game_record, self.inspection.game_reference):
            path.write_text(json.dumps(record))
        with self.inspection.session(create=True):
            mapping = self.inspection.prefix/'dosdevices/g:'
            self.assertEqual(mapping.resolve(), self.inspection.game)
            mapping.unlink()
            mapping.symlink_to(self.root)
            with self.assertRaises(runner.ProbePrefixError):
                self.inspection.assert_prefix()

    def runtime(self):
        engine = self.root/'own-engine'
        (engine/'bin').mkdir(parents=True, exist_ok=True)
        for name in ('wine', 'wineserver'):
            (engine/'bin'/name).write_bytes(b'Own inert runtime stand-in, never executed')
        inherited = {'WINEPREFIX': '/old/production', 'WINESERVER': '/old/server', 'WINESERVERSOCKET': '/old/socket',
                     'WINELOADER': '/old/loader', 'WINELOADERNOEXEC': '1', '__WINE_SERVER_DIR': '/old/socket2',
                     'CitizenFX_NoTenUI': '1', 'CitizenFX_ToolMode': '1', 'USERPROFILE': 'Z:\\host',
                     'DYLD_INSERT_LIBRARIES': '/own-unwanted-injection', 'WINEDLLOVERRIDES': 'mscoree,mshtml=d',
                     'WINEDLLPATH_PREPEND': str(self.root/'own-dxmt'),
                     'DXMT_ALLOW_CROSS_PROCESS_SWAPCHAIN': '1', 'HOME': '/own-home',
                     'DYLD_FALLBACK_FRAMEWORK_PATH': '/own-support/Frameworks',
                     'DYLD_FALLBACK_LIBRARY_PATH': '/own-support/libraries', 'GST_PLUGIN_PATH': '/own-support/plugins'}
        return SimpleNamespace(ENGINE=engine, WINE=engine/'bin/wine', DXMT=self.root/'own-dxmt', environment=lambda: dict(inherited))

    def test_environment_drops_old_loader_socket_profile_and_client_modes(self):
        runtime = self.runtime()
        env = runner.environment(runtime, self.inspection.prefix)
        self.assertEqual(env['WINEPREFIX'], str(self.inspection.prefix))
        self.assertEqual(env['WINESERVER'], str(runtime.ENGINE/'bin/wineserver'))
        self.assertEqual({key for key in env if key.startswith('WINE')},
                         {'WINEPREFIX', 'WINESERVER', 'WINEARCH', 'WINEDEBUG', 'WINEDLLOVERRIDES',
                          'WINEDLLPATH_PREPEND', 'WINEESYNC', 'WINEMSYNC'})
        self.assertEqual(env['WINEDLLOVERRIDES'], 'dxgi,d3d11,d3d10core=b;winemenubuilder.exe=d')
        self.assertFalse(any(key.lower().startswith('citizenfx_') for key in env))
        for name in ('USERPROFILE', 'DYLD_INSERT_LIBRARIES', '__WINE_SERVER_DIR'):
            self.assertNotIn(name, env)
        self.assertEqual(env['DYLD_FALLBACK_LIBRARY_PATH'], '/own-support/libraries')
        self.assertEqual(env['HOME'], '/own-home')
        self.assertEqual(env['WINEDLLPATH_PREPEND'], str(runtime.DXMT))
        self.assertEqual(env['DXMT_ALLOW_CROSS_PROCESS_SWAPCHAIN'], '1')

    def test_cleanup_requires_exact_fresh_prefix_and_absolute_own_server(self):
        runtime = self.runtime()
        env = runner.environment(runtime, self.inspection.prefix)
        with self.inspection.session(create=True), mock.patch.object(runner.subprocess, 'run', return_value=SimpleNamespace(returncode=0)) as process:
            with self.assertRaises(runner.ProbePrefixError):
                runner.cleanup(self.inspection, runtime, dict(env, WINEPREFIX='/old/production'))
            process.assert_not_called()
            self.assertEqual(runner.cleanup(self.inspection, runtime, env), [{'flag': '-k', 'exit': 0}, {'flag': '-w', 'exit': 0}])
            self.assertEqual([call.args[0] for call in process.call_args_list],
                             [[str(runtime.ENGINE/'bin/wineserver'), '-k'], [str(runtime.ENGINE/'bin/wineserver'), '-w']])
            self.assertTrue(all(call.kwargs['env']['WINEPREFIX'] == str(self.inspection.prefix) for call in process.call_args_list))

    def test_both_cleanup_steps_run_after_nonzero_or_timeout_and_incomplete_stop_is_not_success(self):
        runtime = self.runtime()
        env = runner.environment(runtime, self.inspection.prefix)
        for first in (SimpleNamespace(returncode=9), runner.subprocess.TimeoutExpired('own-server', 20)):
            with self.subTest(first=type(first).__name__), self.inspection.session(create=not self.inspection.prefix.exists()), \
                    mock.patch.object(runner.subprocess, 'run', side_effect=[first, SimpleNamespace(returncode=0)]) as process:
                result = runner.cleanup(self.inspection, runtime, env)
                self.assertEqual(process.call_count, 2)
                self.assertEqual(result[-1], {'flag': '-w', 'exit': 0})
                self.assertFalse(runner.cleanup_complete(result))

    def test_600_second_mark_and_explicit_detach_do_not_terminate_wine(self):
        runtime = self.runtime()
        env = runner.environment(runtime, self.inspection.prefix)
        handlers = {}

        def install_handler(number, handler):
            previous = handlers.get(number)
            handlers[number] = handler
            return previous

        def own_spawn(command, **kwargs):
            self.assertEqual(kwargs['env'], env)
            if 'wineboot.exe' in command:
                return SimpleNamespace(pid=1001, poll=lambda: 0, returncode=0)
            self.assertEqual(command, [str(runtime.WINE), str(self.inspection.executable)])
            handlers[signal.SIGUSR1](signal.SIGUSR1, None)
            return SimpleNamespace(pid=1002, poll=lambda: None)

        with mock.patch.object(runner, 'runtime_and_environment', return_value=(runtime, env)), \
                mock.patch.object(runner.signal, 'signal', side_effect=install_handler), \
                mock.patch.object(runner.subprocess, 'Popen', side_effect=own_spawn), \
                mock.patch.object(runner, 'cleanup') as cleanup, \
                mock.patch.object(runner.time, 'monotonic', side_effect=[0, 601, 602]):
            self.assertEqual(runner.run(self.inspection), 0)
        cleanup.assert_not_called()
        result = json.loads(self.inspection.result.read_text())
        self.assertTrue(result['observation_mark_reached'])
        self.assertEqual(result['status'], 'root-requested-detach-without-termination')
        self.assertEqual(result['client_arguments'], [])
        self.assertIsNone(result['cleanup'])

    def controller(self, stop=False, persist_failure=False, mutate_code=False):
        runtime = self.runtime()
        env = runner.environment(runtime, self.inspection.prefix)
        handlers, restored = {}, []
        real_write = self.inspection.write_result

        def install(number, handler):
            if isinstance(handler, str): restored.append(number)
            handlers[number] = handler
            return 'own-previous-'+str(number)

        def spawn(command, **kwargs):
            if 'wineboot.exe' in command:
                if mutate_code: self.inspection.executable.write_bytes(b'own changed code')
                return SimpleNamespace(pid=1001, poll=lambda: 0, returncode=0)
            handlers[signal.SIGTERM if stop else signal.SIGUSR1](0, None)
            return SimpleNamespace(pid=1002, poll=lambda: None)

        def write(record):
            if persist_failure and record['status'].startswith('root-requested-detach'):
                raise OSError('own terminal persistence failure')
            real_write(record)

        patches = (mock.patch.object(runner, 'runtime_and_environment', return_value=(runtime, env)),
                   mock.patch.object(runner.signal, 'signal', side_effect=install),
                   mock.patch.object(runner.subprocess, 'Popen', side_effect=spawn),
                   mock.patch.object(self.inspection, 'write_result', side_effect=write),
                   mock.patch.object(runner.time, 'monotonic', side_effect=[0, 1, 2]))
        from contextlib import ExitStack
        with ExitStack() as stack:
            for patch in patches: stack.enter_context(patch)
            if persist_failure:
                with self.assertRaises(OSError): runner.run(self.inspection)
            elif mutate_code:
                with self.assertRaises(runner.ProbePrefixError): runner.run(self.inspection)
            else:
                self.assertEqual(runner.run(self.inspection), 1)
        return restored

    def test_terminal_persistence_failure_still_restores_all_signal_handlers(self):
        restored = self.controller(persist_failure=True)
        self.assertEqual(set(restored), {signal.SIGINT, signal.SIGTERM, signal.SIGUSR1})

    def test_stop_with_nonzero_cleanup_is_persisted_as_needing_review(self):
        with mock.patch.object(runner.subprocess, 'run', side_effect=[SimpleNamespace(returncode=8), SimpleNamespace(returncode=0)]):
            self.controller(stop=True)
        result = json.loads(self.inspection.result.read_text())
        self.assertEqual(result['status'], 'root-requested-stop-needs-review')
        self.assertEqual(result['cleanup'], [{'flag': '-k', 'exit': 8}, {'flag': '-w', 'exit': 0}])

    def test_changed_executable_after_wineboot_is_refused_before_bootstrap_spawn(self):
        self.controller(mutate_code=True)
        result = json.loads(self.inspection.result.read_text())
        self.assertEqual([item['role'] for item in result['processes']], ['wineboot'])

    def stopped_session(self, runtime, reviewed=False):
        env = runner.environment(runtime, self.inspection.prefix)
        with self.inspection.session(create=True):
            mono = self.inspection.prefix/'drive_c/own-installed-mono-sentinel'
            mono.write_text('own existing component must survive restart')
            record = {'label': runner.LABEL, 'prefix': str(self.inspection.prefix.relative_to(self.root)),
                'original_download_sha256': runner.EXECUTABLE_SHA256, 'client_arguments': [],
                'source_core_or_client_override_used': False, 'old_prefix_cache_profile_or_account_data_copied': False,
                'engine_wine_sha256': runner.sha(runtime.WINE), 'engine_server_sha256': runner.sha(runtime.ENGINE/'bin/wineserver'),
                'status': 'root-requested-stop-needs-review' if reviewed else 'root-requested-stop-complete',
                'cleanup': [{'flag': '-k', 'exit': 1 if reviewed else 0}, {'flag': '-w', 'exit': 0}],
                'processes': [{'role': 'wineboot', 'exit': 0}, {'role': 'official-bootstrap', 'exit': -11}]}
            self.inspection.write_result(record)
            (self.inspection.base/'runtime-private.log').write_text('OWN OPAQUE LOG; never read/hash/copy it')
        return env, mono

    def terminal_review(self, runtime):
        info = self.inspection.prefix.stat()
        review = {'schema': 1, 'session_sha256': runner.sha(self.inspection.result),
                  'prefix_device': info.st_dev, 'prefix_inode': info.st_ino,
                  'server_absolute_path': str(runtime.ENGINE/'bin/wineserver'), 'wait_exit': 0,
                  'no_scoped_code_processes': True, 'controller_absent': True, 'explicitly_reviewed_by_root': True}
        self.inspection.terminal_review.write_text(json.dumps(review))
        return review

    def test_restart_reuses_prefix_and_mono_without_wineboot_reset_or_automatic_stop(self):
        runtime = self.runtime()
        env, mono = self.stopped_session(runtime)
        inode = self.inspection.prefix.stat().st_ino
        handlers = {}

        def install(number, handler):
            handlers[number] = handler
            return None

        def spawn(command, **kwargs):
            self.assertEqual(command, [str(runtime.WINE), str(self.inspection.executable)])
            self.assertNotIn('wineboot.exe', command)
            handlers[signal.SIGUSR1](0, None)
            return SimpleNamespace(pid=2002, poll=lambda: None)

        with mock.patch.object(runner, 'runtime_and_environment', return_value=(runtime, env)), \
                mock.patch.object(self.inspection, 'create_prefix') as initialized, \
                mock.patch.object(runner.signal, 'signal', side_effect=install), \
                mock.patch.object(runner.subprocess, 'Popen', side_effect=spawn) as launched, \
                mock.patch.object(runner, 'cleanup') as cleanup, \
                mock.patch.object(runner.time, 'monotonic', side_effect=[0, 1]):
            self.assertEqual(runner.run(self.inspection, restart=True), 0)
        initialized.assert_not_called()
        cleanup.assert_not_called()
        self.assertEqual(launched.call_count, 1)
        self.assertEqual(self.inspection.prefix.stat().st_ino, inode)
        self.assertEqual(mono.read_text(), 'own existing component must survive restart')
        record = json.loads(self.inspection.result.read_text())
        self.assertTrue(record['restart_existing_prefix'])
        self.assertEqual([item['role'] for item in record['processes']], ['official-bootstrap'])
        self.assertEqual(record['status'], 'root-requested-detach-without-termination')
        self.assertIsNotNone(record['previous_session_archive'])

    def test_restart_archive_renames_opaque_log_without_opening_or_hashing_it(self):
        runtime = self.runtime()
        env, _ = self.stopped_session(runtime)
        opaque = self.inspection.base/'runtime-private.log'
        old_inode = opaque.stat().st_ino
        original_open = Path.open

        def no_log_open(path, *args, **kwargs):
            self.assertNotEqual(path, opaque, 'Opaque log content was opened')
            return original_open(path, *args, **kwargs)

        with self.inspection.session(), mock.patch.object(Path, 'open', no_log_open), \
                mock.patch.object(runner, 'sha', wraps=runner.sha) as hashed:
            archived = self.inspection.archive_stopped_session(runtime, env)
        self.assertNotIn(mock.call(opaque), hashed.call_args_list)
        checkpoint = self.root/archived['path']
        self.assertEqual((checkpoint/'runtime-private.log').stat().st_ino, old_inode)
        self.assertFalse(self.inspection.result.exists())
        self.assertFalse(opaque.exists())

    def test_needs_review_requires_exact_root_terminal_evidence_and_preserves_old_nonzero_cleanup(self):
        runtime = self.runtime()
        env, _ = self.stopped_session(runtime, reviewed=True)
        with self.inspection.session(), self.assertRaises((OSError, runner.ProbePrefixError)):
            self.inspection.archive_stopped_session(runtime, env)
        review = self.terminal_review(runtime)
        self.inspection.terminal_review.write_text(json.dumps(dict(review, session_sha256='0'*64)))
        with self.inspection.session(), self.assertRaises(runner.ProbePrefixError):
            self.inspection.archive_stopped_session(runtime, env)
        self.inspection.terminal_review.write_text(json.dumps(review))
        with self.inspection.session(): archived = self.inspection.archive_stopped_session(runtime, env)
        self.assertTrue(archived['root_terminal_review_used'])
        previous = json.loads((self.root/archived['path']/'session.json').read_text())
        self.assertEqual(previous['cleanup'], [{'flag': '-k', 'exit': 1}, {'flag': '-w', 'exit': 0}])
        self.assertEqual(previous['processes'][-1]['exit'], -11)

    def test_partial_archive_rename_failure_restores_original_objects_without_copy(self):
        runtime = self.runtime()
        env, _ = self.stopped_session(runtime)
        objects = [self.inspection.result, self.inspection.base/'runtime-private.log']
        inodes = [path.stat().st_ino for path in objects]
        original_rename = os.rename
        count = 0

        def rename(source, destination):
            nonlocal count
            count += 1
            if count == 2: raise OSError('own rename failure')
            return original_rename(source, destination)

        with self.inspection.session(), mock.patch.object(runner.os, 'rename', side_effect=rename), self.assertRaises(OSError):
            self.inspection.archive_stopped_session(runtime, env)
        self.assertEqual([path.stat().st_ino for path in objects], inodes)
        self.assertFalse(list(self.inspection.base.glob('restart-checkpoint-*')))

    def test_restart_refuses_changed_client_directory_identity_before_spawn_or_archival(self):
        runtime = self.runtime()
        env, _ = self.stopped_session(runtime)
        previous = self.inspection.client.with_name('own-prior-client')
        self.inspection.client.rename(previous)
        shutil.copytree(previous, self.inspection.client)
        with mock.patch.object(runner, 'runtime_and_environment', return_value=(runtime, env)), \
                mock.patch.object(runner.subprocess, 'Popen') as process, self.assertRaises(runner.ProbePrefixError):
            runner.run(self.inspection, restart=True)
        process.assert_not_called()
        self.assertTrue(self.inspection.result.exists())
        self.assertFalse(list(self.inspection.base.glob('restart-checkpoint-*')))

    def test_user_discard_record_blocks_first_run_and_restart_before_input_or_runtime_access(self):
        marker = self.root/'research/official-client-inspection-abandoned-20261102.json'
        marker.write_text('{"status":"discarded-by-user"}')
        for restart in (False, True):
            with self.subTest(restart=restart), mock.patch.object(self.inspection, 'inputs') as inputs, \
                    mock.patch.object(runner, 'runtime_and_environment') as runtime, \
                    self.assertRaisesRegex(runner.ProbePrefixError, 'user discarded'):
                runner.run(self.inspection, restart=restart)
            inputs.assert_not_called()
            runtime.assert_not_called()
        self.assertFalse(self.inspection.prefix.exists())


if __name__ == '__main__':
    unittest.main()
