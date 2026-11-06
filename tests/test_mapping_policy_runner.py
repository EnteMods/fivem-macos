"""Verify mapping policy staging and orchestration without starting Wine."""
from contextlib import contextmanager, redirect_stdout
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
SPEC = importlib.util.spec_from_file_location('mapping_policy_runner_under_test',
                                           PROJECT / 'native/windows-mapping-policy/run.py')
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


def metadata(location, mode, *, callbacks=None, hits=None, marker=None):
    mapped = mode.startswith('--mapped-')
    route = 'import' if mode.endswith('-import') else 'explicit'
    should_map = mapped and (route == 'explicit' or location == 'canonical')
    hit_count = int(should_map) if hits is None else hits
    callback_count = hit_count if callbacks is None else callbacks
    value = marker or ('0x46585232' if should_map else '0x46585231')
    return (f'MAPPING_POLICY_FIXTURE location={location} route={route} mapped={int(mapped)} '
            f'preloaded_before=0 preloaded_after=0 callback_count={callback_count} '
            f'fixed_path_hits={hit_count} load_error=0 marker={value}')


class MappingPolicyRunnerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve() / 'project'
        self.build = self.root / 'build/windows-mapping-policy'
        self.stage = self.build / 'runtime'
        self.prefix = self.root / 'prefixes/corert-regression'
        self.manifest = self.root / 'research/windows-mapping-policy-build.json'
        for key, value in (('ROOT', self.root), ('BUILD', self.build), ('STAGE', self.stage), ('PREFIX', self.prefix)):
            patch = mock.patch.object(runner, key, value)
            patch.start()
            self.addCleanup(patch.stop)
        inputs = runner.expected_inputs()
        sources = runner.expected_sources()
        for relative in [*inputs, *sources]:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(('Own inert temporary fixture: ' + relative).encode())

        def identity(relative):
            payload = (self.root / relative).read_bytes()
            return {'path': relative, 'bytes': len(payload), 'sha256': hashlib.sha256(payload).hexdigest()}

        core_sha = identity('build/windows-core/CoreRT.dll')['sha256']
        patch = mock.patch.object(runner, 'CORE_SHA', core_sha)
        patch.start()
        self.addCleanup(patch.stop)
        self.value = {'compiled': True, 'ordinary_core_sha256': core_sha,
                      'runtime_inputs': [dict(identity(path), runtime_name=name) for path, name in inputs.items()],
                      'source_evidence': [identity(path) for path in sorted(sources)]}
        self.manifest.parent.mkdir(parents=True)
        self.write_manifest()

    def write_manifest(self):
        self.manifest.write_text(json.dumps(self.value))

    def reject_without_replacement(self, error=RuntimeError):
        with mock.patch.object(runner, 'atomic_replace') as replace:
            with self.assertRaises(error):
                runner.stage()
        replace.assert_not_called()

    def test_exact_six_inputs_are_staged_identically_in_both_locations(self):
        for relative in runner.STAGE_PATHS.values():
            directory = self.stage / relative
            directory.mkdir(parents=True)
            for name in runner.expected_inputs().values():
                (directory / name).write_bytes(b'previous own input')
        evidence, digest = runner.stage()
        self.assertEqual(evidence, self.value)
        self.assertEqual(digest, hashlib.sha256(self.manifest.read_bytes()).hexdigest())
        for relative in runner.STAGE_PATHS.values():
            directory = self.stage / relative
            self.assertEqual({file.name for file in directory.iterdir()}, set(runner.expected_inputs().values()))
            for source, name in runner.expected_inputs().items():
                self.assertEqual((directory / name).read_bytes(), (self.root / source).read_bytes())

    def test_final_canonical_hardlink_is_rejected_before_any_input_read(self):
        directory = self.stage / runner.STAGE_PATHS['canonical']
        directory.mkdir(parents=True)
        sentinel = self.root.parent / 'unrelated.bin'
        sentinel.write_bytes(b'preserve')
        os.link(sentinel, directory / 'tbb12.dll')
        with mock.patch.object(runner, 'read_regular', side_effect=AssertionError('Input read before destination preflight')):
            self.reject_without_replacement()
        self.assertEqual(sentinel.read_bytes(), b'preserve')
        self.assertFalse((self.stage / 'foreign').exists())

    def test_destination_symlinks_and_fifo_are_rejected_without_opening(self):
        directory = self.stage / runner.STAGE_PATHS['canonical']
        directory.mkdir(parents=True)
        destination = directory / 'tbb12.dll'
        for target in ('missing.bin', str(self.manifest)):
            with self.subTest(target=target):
                destination.symlink_to(target)
                self.reject_without_replacement(SystemExit)
                destination.unlink()
        if hasattr(os, 'mkfifo'):
            os.mkfifo(destination)
            self.reject_without_replacement()

    def test_redirected_intermediate_directory_or_stage_file_is_rejected(self):
        self.stage.mkdir()
        external = self.root.parent / 'external'
        external.mkdir()
        (self.stage / 'Program Files').symlink_to(external, target_is_directory=True)
        self.reject_without_replacement(SystemExit)
        self.assertEqual(list(external.iterdir()), [])
        (self.stage / 'Program Files').unlink()
        self.stage.rmdir()
        self.stage.write_bytes(b'not a directory')
        self.reject_without_replacement()

    def test_unknown_files_at_every_stage_level_are_preserved(self):
        for relative in (Path('.'), Path('Program Files'), Path('Program Files/Rockstar Games'),
                         runner.STAGE_PATHS['canonical'], runner.STAGE_PATHS['foreign']):
            with self.subTest(relative=str(relative)):
                directory = self.stage / relative
                directory.mkdir(parents=True, exist_ok=True)
                unknown = directory / 'unreviewed.dll'
                unknown.write_bytes(b'preserve')
                self.reject_without_replacement()
                self.assertEqual(unknown.read_bytes(), b'preserve')
                unknown.unlink()

    def test_all_inventory_scopes_are_validated_before_payload_reads(self):
        mutations = (
            lambda value: value['runtime_inputs'][-1].update(path='../foreign.dll'),
            lambda value: value['runtime_inputs'][-1].update(runtime_name='../foreign.dll'),
            lambda value: value['source_evidence'][-1].update(path='../foreign.cpp'),
            lambda value: value['runtime_inputs'].append(value['runtime_inputs'][0]),
            lambda value: value['source_evidence'].__setitem__(-1, value['source_evidence'][0]),
            lambda value: value.update(ordinary_core_sha256='0' * 64),
            lambda value: value.update(compiled=1),
            lambda value: value['runtime_inputs'][0].update(bytes=True),
            lambda value: value['runtime_inputs'][0].update(sha256='not-a-hash'),
        )
        original = json.loads(json.dumps(self.value))
        for number, mutate in enumerate(mutations):
            with self.subTest(number=number):
                self.value = json.loads(json.dumps(original))
                mutate(self.value)
                self.write_manifest()
                with mock.patch.object(runner, 'read_regular', wraps=runner.read_regular) as read:
                    self.reject_without_replacement()
                self.assertEqual([call.args[0] for call in read.call_args_list], [self.manifest])

    def test_hardlinked_manifest_and_source_refuse_before_staging(self):
        alias = self.root.parent / 'alias'
        os.link(self.manifest, alias)
        self.reject_without_replacement()
        alias.unlink()
        source = self.root / self.value['source_evidence'][-1]['path']
        os.link(source, alias)
        with mock.patch.object(runner, 'read_regular', wraps=runner.read_regular) as read:
            self.reject_without_replacement()
        self.assertEqual([call.args[0] for call in read.call_args_list], [self.manifest])

    def test_changed_last_source_prevents_all_payload_replacements(self):
        (self.root / self.value['source_evidence'][-1]['path']).write_bytes(b'changed')
        self.reject_without_replacement()
        self.assertFalse(self.stage.exists())

    def test_atomic_replace_failure_keeps_prior_input_and_removes_temporary(self):
        directory = self.stage / 'foreign'
        directory.mkdir(parents=True)
        destination = directory / 'consumer.dll'
        destination.write_bytes(b'previous')
        with mock.patch.object(runner.os, 'replace', side_effect=OSError('own injected replace failure')):
            with self.assertRaises(OSError):
                runner.atomic_replace(destination, b'new verified payload')
        self.assertEqual(destination.read_bytes(), b'previous')
        self.assertEqual([path.name for path in directory.iterdir()], ['consumer.dll'])

    def exercise(self, *, timeout=False, cleanup_failure=None, bad_case=False):
        held = [False]
        calls = []
        environment = {'WINEPREFIX': str(self.prefix), 'WINESERVER': '/own/engine/bin/wineserver'}
        runtime = SimpleNamespace(WINE=Path('/own/wine'), ENGINE=Path('/own/engine'))

        @contextmanager
        def locked(prefix, *, root):
            self.assertEqual((prefix, root), (self.prefix, self.root))
            held[0] = True
            try:
                yield prefix
            finally:
                held[0] = False

        def execute(command, **kwargs):
            self.assertTrue(held[0])
            self.assertEqual(kwargs['env'], environment)
            calls.append(command)
            if command[1] in ('-k', '-w'):
                if command[1] == cleanup_failure:
                    raise subprocess.TimeoutExpired(command, 15)
            else:
                if timeout:
                    raise subprocess.TimeoutExpired(command, 45)
                location, mode = command[-2][2:], command[-1]
                self.assertEqual(kwargs['cwd'], self.stage / runner.STAGE_PATHS[location])
                self.assertEqual(command[1], str(kwargs['cwd'] / 'mapping_policy_probe.exe'))
                line = metadata(location, mode)
                if bad_case and location == 'canonical' and mode == '--mapped-import':
                    line = line.replace('marker=0x46585232', 'marker=0x46585231')
                kwargs['stdout'].write(line + '\n')
            return SimpleNamespace(returncode=0)

        with mock.patch.object(runner, 'load_runtime', return_value=(runtime, environment)), \
                mock.patch.object(runner, 'probe_prefix', side_effect=locked), \
                mock.patch.object(runner, 'assert_account_free_prefix'), \
                mock.patch.object(runner.subprocess, 'run', side_effect=execute), redirect_stdout(io.StringIO()):
            code = runner.main()
        result = json.loads((self.root / 'research/windows-mapping-policy-results.json').read_text())
        unique = list((self.root / 'research').glob('windows-mapping-policy-*-results.json'))
        self.assertEqual(len(unique), 1)
        self.assertEqual(json.loads(unique[0].read_text()), result)
        return code, calls, result

    def test_eight_fresh_processes_and_cleanup_run_with_the_probe_lock_held(self):
        old_import = self.root / 'research/windows-mapping-imports-results.json'
        old_import.write_bytes(b'preserve prior failed experiment')
        code, calls, result = self.exercise()
        self.assertEqual(code, 0)
        self.assertEqual(len(calls), 10)
        self.assertEqual([(call[-2][2:], call[-1]) for call in calls[:-2]], list(runner.CASES))
        self.assertEqual([call[1] for call in calls[-2:]], ['-k', '-w'])
        self.assertTrue(result['passed'])
        self.assertEqual(old_import.read_bytes(), b'preserve prior failed experiment')

    def test_failing_metadata_is_preserved_and_does_not_skip_remaining_cases(self):
        code, calls, result = self.exercise(bad_case=True)
        self.assertEqual(code, 1)
        self.assertEqual(len(calls), 10)
        self.assertEqual(sum(not case['passed'] for case in result['cases']), 1)
        self.assertFalse(result['passed'])

    def test_fixture_timeout_still_attempts_both_cleanup_steps_and_saves_evidence(self):
        code, calls, result = self.exercise(timeout=True)
        self.assertEqual(code, 1)
        self.assertEqual(len(calls), 3)
        self.assertEqual([call[1] for call in calls[-2:]], ['-k', '-w'])
        self.assertEqual(result['failure']['type'], 'TimeoutExpired')

    def test_cleanup_timeout_preserves_failure_and_still_attempts_wait(self):
        code, calls, result = self.exercise(cleanup_failure='-k')
        self.assertEqual(code, 1)
        self.assertEqual(calls[-1][1], '-w')
        self.assertEqual(result['cleanup'][0]['failure_type'], 'TimeoutExpired')
        self.assertFalse(result['passed'])

    def test_results_refuse_to_overwrite_a_previous_unique_run(self):
        runner.save_results('windows-mapping-policy-own-timestamp', {'run': 1})
        with self.assertRaises(FileExistsError):
            runner.save_results('windows-mapping-policy-own-timestamp', {'run': 2})
        self.assertEqual(json.loads((self.root / 'research/windows-mapping-policy-results.json').read_text()), {'run': 1})

    def test_results_refuse_linked_latest_before_creating_unique_evidence(self):
        sentinel = self.root.parent / 'unrelated-result.json'
        sentinel.write_bytes(b'preserve unrelated result')
        latest = self.root / 'research/windows-mapping-policy-results.json'
        os.link(sentinel, latest)
        with self.assertRaises(RuntimeError):
            runner.save_results('windows-mapping-policy-own-timestamp', {'run': 1})
        self.assertEqual(sentinel.read_bytes(), b'preserve unrelated result')
        self.assertFalse((latest.parent / 'windows-mapping-policy-own-timestamp-results.json').exists())


class MappingPolicyMetadataTests(unittest.TestCase):
    def test_exact_eight_case_contract_and_expected_negative_control(self):
        self.assertEqual(len(set(runner.CASES)), 8)
        for location, mode in runner.CASES:
            with self.subTest(location=location, mode=mode):
                self.assertTrue(runner.check_metadata([metadata(location, mode)], location, mode, 0))
        self.assertTrue(runner.check_metadata(
            [metadata('canonical', '--mapped-import', callbacks=4, hits=2)], 'canonical', '--mapped-import', 0))

    def test_rejects_duplicate_partial_contradictory_or_preloaded_metadata(self):
        valid = metadata('canonical', '--mapped-import')
        invalid = [[], [valid, valid], [valid + ' extra=1'], [valid.replace('location=canonical', 'location=foreign')],
                   [valid.replace('preloaded_before=0', 'preloaded_before=1')],
                   [valid.replace('preloaded_after=0', 'preloaded_after=1')],
                   [valid.replace('load_error=0', 'load_error=2')],
                   [valid.replace('callback_count=1', 'callback_count=0')],
                   [valid.replace('fixed_path_hits=1', 'fixed_path_hits=0')],
                   [valid.replace('mapped=1', 'mapped=0')],
                   [valid.replace('route=import', 'route=explicit')],
                   [valid.replace('marker=0x46585232', 'marker=0x46585231')]]
        for number, lines in enumerate(invalid):
            with self.subTest(number=number):
                self.assertFalse(runner.check_metadata(lines, 'canonical', '--mapped-import', 0))
        self.assertFalse(runner.check_metadata([valid], 'canonical', '--mapped-import', 10))
        self.assertFalse(runner.check_metadata([valid], 'canonical', '--unknown', 0))


class MappingPolicyEnvironmentTests(unittest.TestCase):
    def runtime(self, environment):
        return SimpleNamespace(ENGINE=Path('/own/engine'), WINE=Path('/own/wine'), environment=lambda: environment)

    def test_original_runtime_environment_is_copied_then_rebound_and_loader_socket_removed(self):
        inherited = {'WINEPREFIX': '/productive/prefix', 'WINESERVER': '/wrong/server', 'WINELOADER': '/wrong/wine',
                     'WINELOADERNOEXEC': '1', 'WINESERVERSOCKET': '/productive/socket', 'KEEP': 'graphics'}
        runtime = self.runtime(inherited)
        fake_spec = SimpleNamespace(loader=SimpleNamespace(exec_module=lambda module: None))
        with mock.patch.object(runner.importlib.util, 'spec_from_file_location', return_value=fake_spec), \
                mock.patch.object(runner.importlib.util, 'module_from_spec', return_value=runtime):
            loaded, environment = runner.load_runtime()
        self.assertIs(loaded, runtime)
        self.assertEqual(environment['WINEPREFIX'], str(runner.PREFIX))
        self.assertEqual(environment['WINESERVER'], '/own/engine/bin/wineserver')
        self.assertEqual(environment['KEEP'], 'graphics')
        for key in ('WINESERVERSOCKET', 'WINELOADER', 'WINELOADERNOEXEC'):
            self.assertNotIn(key, environment)
            self.assertIn(key, inherited)

    def test_client_role_variables_are_refused_case_insensitively(self):
        fake_spec = SimpleNamespace(loader=SimpleNamespace(exec_module=lambda module: None))
        for key in ('CitizenFX_ToolMode', 'CITIZENFX_SOMETHING', 'citizenfx_role'):
            with self.subTest(key=key), \
                    mock.patch.object(runner.importlib.util, 'spec_from_file_location', return_value=fake_spec), \
                    mock.patch.object(runner.importlib.util, 'module_from_spec', return_value=self.runtime({key: '1'})):
                with self.assertRaisesRegex(RuntimeError, 'inherited client role'):
                    runner.load_runtime()


if __name__ == '__main__':
    unittest.main()
