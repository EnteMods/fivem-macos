"""Exercise own-code staging guards using temporary files, without Wine."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


PROJECT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'mapping_import_runner_under_test', PROJECT / 'native/windows-mapping-imports/run.py')
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class MappingImportStagingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve() / 'project'
        self.build = self.root / 'build/windows-mapping-imports'
        self.stage = self.build / 'runtime'
        self.manifest = self.root / 'research/windows-mapping-imports-build.json'
        self.inputs = [
            ('build/windows-mapping-imports/mapping_import_probe.exe', 'mapping_import_probe.exe'),
            ('build/windows-mapping-imports/consumer.dll', 'consumer.dll'),
            ('build/windows-mapping-imports/socialclub.dll', 'socialclub.dll'),
            ('build/windows-mapping-imports/mapping-target.dll', 'mapping-target.dll'),
            ('build/windows-core/CoreRT.dll', 'CoreRT.dll'),
            ('build/windows-core/clang_23.1_cxx17_64_md_relwithdebinfo/tbb12.dll', 'tbb12.dll'),
        ]
        sources = ['native/windows-mapping-imports/' + name
                   for name in ('CMakeLists.txt', 'build.py', 'probe.cpp', 'consumer.cpp')]
        sources.append('native/windows-mapping-fixture/marker.cpp')
        for relative in [path for path, _ in self.inputs] + sources:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(('own temporary fixture: ' + relative).encode())

        def evidence(relative):
            data = (self.root / relative).read_bytes()
            return {'path': relative, 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}

        core_sha = evidence('build/windows-core/CoreRT.dll')['sha256']
        self.value = {
            'compiled': True,
            'runtime_inputs_not_yet_staged': [dict(evidence(path), runtime_name=name)
                                             for path, name in self.inputs],
            'source_evidence': [evidence(path) for path in sources],
            'ordinary_core_sha256': core_sha,
            'rockstar_security_or_client_binaries_staged': False,
            'cases_to_run_in_separate_processes': [
                {'argument': argument, 'expected_marker': marker} for argument, marker in runner.CASES],
        }
        self.manifest.parent.mkdir(parents=True)
        self.write_manifest()
        for key, value in (('ROOT', self.root), ('BUILD', self.build), ('STAGE', self.stage),
                           ('CORE_SHA', core_sha)):
            patch = mock.patch.object(runner, key, value)
            patch.start()
            self.addCleanup(patch.stop)

    def write_manifest(self):
        self.manifest.write_text(json.dumps(self.value))

    def refuse_without_copy(self, error=RuntimeError):
        with mock.patch.object(runner.shutil, 'copyfile') as copy:
            with self.assertRaises(error):
                runner.stage()
        copy.assert_not_called()

    def assert_only_manifest_hashed_on_refusal(self):
        with mock.patch.object(runner, 'sha', wraps=runner.sha) as digest:
            self.refuse_without_copy()
        self.assertEqual([call.args[0] for call in digest.call_args_list], [self.manifest])
        self.assertFalse(self.stage.exists())

    def test_verified_inventory_stages_and_replaces_regular_previous_files(self):
        self.stage.mkdir()
        for _, name in self.inputs:
            (self.stage / name).write_bytes(b'previous own fixture')
        evidence, manifest_sha = runner.stage()
        self.assertEqual(evidence, self.value)
        self.assertEqual(manifest_sha, hashlib.sha256(self.manifest.read_bytes()).hexdigest())
        self.assertEqual({path.name for path in self.stage.iterdir()}, {name for _, name in self.inputs})
        for relative, name in self.inputs:
            self.assertEqual((self.stage / name).read_bytes(), (self.root / relative).read_bytes())

    def test_late_destination_hardlink_rejected_before_first_copy(self):
        self.stage.mkdir()
        sentinel = self.root.parent / 'unrelated.bin'
        sentinel.write_bytes(b'preserve unrelated content')
        os.link(sentinel, self.stage / self.inputs[-1][1])
        self.refuse_without_copy()
        self.assertEqual(sentinel.read_bytes(), b'preserve unrelated content')
        self.assertFalse((self.stage / self.inputs[0][1]).exists())

    def test_destination_symlinks_including_broken_links_rejected_before_copy(self):
        self.stage.mkdir()
        sentinel = self.root.parent / 'unrelated.bin'
        sentinel.write_bytes(b'preserve unrelated content')
        for target in (sentinel, self.root.parent / 'missing.bin'):
            with self.subTest(target=target.name):
                destination = self.stage / self.inputs[-1][1]
                destination.symlink_to(target)
                self.refuse_without_copy(SystemExit)
                destination.unlink()
        self.assertEqual(sentinel.read_bytes(), b'preserve unrelated content')

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'Requires POSIX FIFO support')
    def test_fifo_destination_rejected_before_copy_or_blocking_open(self):
        self.stage.mkdir()
        os.mkfifo(self.stage / self.inputs[-1][1])
        self.refuse_without_copy()

    def test_stage_regular_file_or_redirect_is_rejected_before_copy(self):
        self.stage.write_bytes(b'not a directory')
        self.refuse_without_copy()
        self.stage.unlink()
        external = self.root.parent / 'external'
        external.mkdir()
        self.stage.symlink_to(external, target_is_directory=True)
        self.refuse_without_copy(SystemExit)
        self.assertEqual(list(external.iterdir()), [])

    def test_unknown_stage_file_is_not_deleted_or_overwritten(self):
        self.stage.mkdir()
        unknown = self.stage / 'unreviewed.dll'
        unknown.write_bytes(b'preserve')
        self.refuse_without_copy()
        self.assertEqual(unknown.read_bytes(), b'preserve')

    def test_unreviewed_code_path_rejected_before_payload_hash_or_read(self):
        self.value['runtime_inputs_not_yet_staged'][-1]['path'] = '../unrelated.bin'
        self.write_manifest()
        self.assert_only_manifest_hashed_on_refusal()

    def test_unreviewed_runtime_name_rejected_before_payload_hash_or_read(self):
        self.value['runtime_inputs_not_yet_staged'][-1]['runtime_name'] = '../unrelated.bin'
        self.write_manifest()
        self.assert_only_manifest_hashed_on_refusal()

    def test_unreviewed_source_path_rejected_before_payload_hash_or_read(self):
        self.value['source_evidence'][-1]['path'] = '../unrelated.cpp'
        self.write_manifest()
        self.assert_only_manifest_hashed_on_refusal()

    def test_only_four_reviewed_modes_and_markers_are_accepted(self):
        cases = self.value['cases_to_run_in_separate_processes']
        invalid = [cases[:-1], cases + [cases[0]], list(reversed(cases)),
                   [dict(case, argument='--other') if i == 0 else case for i, case in enumerate(cases)],
                   [dict(case, expected_marker='0x00000000') if i == 0 else case for i, case in enumerate(cases)],
                   [dict(case, extra=True) if i == 0 else case for i, case in enumerate(cases)]]
        for number, value in enumerate(invalid):
            with self.subTest(number=number):
                self.value['cases_to_run_in_separate_processes'] = value
                self.write_manifest()
                self.assert_only_manifest_hashed_on_refusal()

    def test_hardlinked_manifest_rejected_before_reading_content(self):
        alias = self.root.parent / 'manifest-alias.json'
        os.link(self.manifest, alias)
        with mock.patch.object(Path, 'read_text', side_effect=AssertionError('Unsafe manifest read')):
            self.refuse_without_copy()

    def test_corrupt_last_source_prevents_all_staging(self):
        source = self.root / self.value['source_evidence'][-1]['path']
        source.write_bytes(b'changed')
        self.refuse_without_copy()
        self.assertFalse(self.stage.exists())

    def test_changed_copy_is_rejected_before_becoming_runtime_input(self):
        def changed_copy(source, destination):
            Path(destination).write_bytes(b'changed during copy')

        with mock.patch.object(runner.shutil, 'copyfile', side_effect=changed_copy):
            with self.assertRaisesRegex(RuntimeError, 'Own staged code differs'):
                runner.stage()
        self.assertEqual(list(self.stage.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
