import hashlib
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('own_update_finalizer', ROOT / 'native/windows-client/finalize_user_rockstar_update.py')
finalizer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(finalizer)


class FinalizationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.prefix = self.root / 'prefixes/fivem-source-main'
        self.checkpoint = self.root / 'build/checkpoints/rockstar-official-update-20261103'
        self.checkpoint.mkdir(parents=True)
        (self.root / 'research').mkdir()
        self.patches = [patch.object(finalizer, name, value) for name, value in (
            ('ROOT', self.root), ('PREFIX', self.prefix), ('CHECKPOINT', self.checkpoint),
            ('STAGED', self.checkpoint / 'finalization-x86-complete'))]
        for value in self.patches:
            value.start()
        self.launcher = self.prefix / finalizer.policy.CODE_ROOTS[0] / 'Launcher.exe'
        self.launcher.parent.mkdir(parents=True)
        self.launcher.write_bytes(b'own vendor-updated bytes')
        social = self.prefix / finalizer.policy.CODE_ROOTS[1]
        social.mkdir()
        (social / 'socialclub.dll').write_bytes(b'own inert social code')
        self.old = self.launcher.with_name('Launcher.exe.old')
        self.old.write_bytes(b'own original bytes')
        self.original_item = {'path': str(self.launcher.relative_to(self.prefix)), 'bytes': self.old.stat().st_size,
                             'sha256': hashlib.sha256(self.old.read_bytes()).hexdigest()}
        service = self.launcher.with_name('RockstarService.exe')
        service.write_bytes(b'own updated service bytes')
        service_old = service.with_name('RockstarService.exe.old')
        service_old.write_bytes(b'own original service bytes')
        self.original_items = [self.original_item, {'path': str(service.relative_to(self.prefix)),
            'bytes': service_old.stat().st_size, 'sha256': hashlib.sha256(service_old.read_bytes()).hexdigest()}]
        x86 = self.prefix / finalizer.policy.UPDATE_X86_CODE_ROOT
        x86.mkdir(parents=True)
        for name in finalizer.policy.UPDATE_X86_BASENAMES:
            (x86 / name).write_bytes(b'own inert x86 vendor code')

    def tearDown(self):
        for value in reversed(self.patches):
            value.stop()
        self.temporary.cleanup()

    def test_inventory_only_relocates_verified_old_parent_bytes_and_rejects_staging_or_accounts(self):
        files, moves = finalizer.inventory({'files': self.original_items})
        self.assertEqual(len(files), 8)
        self.assertEqual({row['path'] for row in moves}, set(finalizer.OLD_FILES))
        self.old.write_bytes(b'wrong original bytes')
        with self.assertRaises(finalizer.ProbePrefixError):
            finalizer.inventory({'files': self.original_items})
        self.old.write_bytes(b'own original bytes')
        for name in ('unfinished.swap', 'unexpected.old', 'cookies'):
            path = self.launcher.parent / name
            path.write_bytes(b'own data')
            with self.subTest(name=name), self.assertRaises(finalizer.ProbePrefixError):
                finalizer.inventory({'files': self.original_items})
            path.unlink()

    def state(self):
        marker = self.prefix / finalizer.main_policy.MARKER_NAME
        manifest = self.prefix / finalizer.policy.MANIFEST_NAME
        marker.write_bytes(b'{"own":"old-marker"}\n')
        manifest.write_bytes(b'{"own":"old-manifest"}\n')
        stat = self.prefix.stat()
        files, moves = finalizer.inventory({'files': self.original_items})
        plan = {'code_backup_relocations': moves, 'new_code_manifest': {'path': finalizer.policy.MANIFEST_NAME, 'sha256': 'a' * 64},
                'new_code_files': len(files)}
        return {'context': {'prefix_identity': [stat.st_dev, stat.st_ino]}, 'observation': {'known_native_pids_gone': [69967, 70009]},
                'old_marker': marker.read_bytes(), 'old_manifest': manifest.read_bytes(), 'plan': plan,
                'payloads': {'plan.json': finalizer.encoded(plan), 'new-code-manifest.json': b'{"own":"new-manifest"}\n',
                             'new-marker.json': b'{"own":"new-marker"}\n', 'update-origin.json': b'{"own":"proof"}\n'}}

    def helper(self):
        def save(path, record, new=False):
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open('x' if new else 'w') as target:
                json.dump(record, target)
        return SimpleNamespace(save=save, read_metadata=lambda path: path.read_bytes())

    def test_wait_uses_only_bound_w_15_seconds_without_k_or_client(self):
        state = self.state()
        engine = self.root / 'runtime/wine-job-query-parity/engine'
        runtime = SimpleNamespace(ENGINE=engine, before_source_spawn=Mock())
        env = {'WINEPREFIX': str(self.prefix), 'WINESERVER': str(engine / 'bin/wineserver')}
        helper = SimpleNamespace(runtime_environment=lambda _runtime: env, cleanup_identity=Mock())
        source = SimpleNamespace(select_runtime_profile=Mock(return_value=(runtime, {})))
        with patch.dict('sys.modules', {'run_source': source}), patch.object(os, 'kill', side_effect=ProcessLookupError()), \
                patch.object(finalizer.subprocess, 'run', side_effect=finalizer.subprocess.TimeoutExpired('own wait', 15)) as run:
            with self.assertRaises(finalizer.subprocess.TimeoutExpired):
                finalizer.quiescent(helper, state)
        self.assertEqual(run.call_args.args[0], [str(engine / 'bin/wineserver'), '-w'])
        self.assertEqual(run.call_args.kwargs['timeout'], 15)
        self.assertEqual(run.call_args.kwargs['env'], env)

    def test_unconfirmed_quiescence_preserves_all_prefix_bytes_and_old_file_locations(self):
        state = self.state()
        before = (state['old_marker'], state['old_manifest'], self.old.read_bytes(), self.launcher.read_bytes())
        with patch.object(finalizer, 'quiescent', side_effect=finalizer.subprocess.TimeoutExpired('own wait', 15)), \
                patch.object(finalizer.policy, '_write_bytes') as writes:
            result = finalizer.commit(self.helper(), state)
        writes.assert_not_called()
        self.assertFalse(result['code_binding_finalized'])
        self.assertEqual(result['failure_type'], 'TimeoutExpired')
        self.assertEqual(before, ((self.prefix / finalizer.main_policy.MARKER_NAME).read_bytes(),
            (self.prefix / finalizer.policy.MANIFEST_NAME).read_bytes(), self.old.read_bytes(), self.launcher.read_bytes()))

    def test_normal_assert_failure_restores_only_bindings_and_old_locations_not_vendor_code(self):
        state = self.state()
        vendor_before = self.launcher.read_bytes()
        with patch.object(finalizer, 'quiescent', return_value={'flag': '-w', 'exit': 0}), \
                patch.object(finalizer, 'plan', return_value=state), patch.object(finalizer, 'stage'), \
                patch.object(finalizer.policy, '_verify_code'), \
                patch.object(finalizer.main_policy, 'assert_source_main_prefix', side_effect=finalizer.ProbePrefixError('own reject')):
            result = finalizer.commit(self.helper(), state)
        self.assertFalse(result['code_binding_finalized'])
        self.assertEqual((self.prefix / finalizer.main_policy.MARKER_NAME).read_bytes(), state['old_marker'])
        self.assertEqual((self.prefix / finalizer.policy.MANIFEST_NAME).read_bytes(), state['old_manifest'])
        self.assertTrue(self.old.is_file())
        self.assertEqual(self.old.read_bytes(), b'own original bytes')
        self.assertEqual(self.launcher.read_bytes(), vendor_before)
        self.assertTrue(all(row['restored'] for row in result['rollback']))
        self.assertFalse(result['vendor_code_rollback_or_downgrade'])
        self.assertTrue((self.root / finalizer.policy.UPDATE_EVIDENCE_PATH).is_file())


if __name__ == '__main__':
    unittest.main()
