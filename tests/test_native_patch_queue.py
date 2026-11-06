"""Exercise overlapping sequential patches using an own temporary local Git repository."""
import hashlib
import importlib.util
import json
from contextlib import contextmanager
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('native_patch_queue_test', PROJECT / 'scripts/native_port.py')
recipe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recipe)


@contextmanager
def own_queue():
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary).resolve()
        source = root / 'own-source'
        source.mkdir()
        subprocess.run(['git', 'init', '-q'], cwd=source, check=True)
        (source / 'own.txt').write_text('zero\n')
        subprocess.run(['git', 'add', 'own.txt'], cwd=source, check=True)
        subprocess.run(['git', '-c', 'user.name=Own Fixture', '-c', 'user.email=own-fixture@example.invalid',
                        'commit', '-qm', 'own inert baseline'], cwd=source, check=True)
        revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip()
        patches = []
        for index, before, after in ((1, 'zero', 'one'), (2, 'one', 'two'), (3, 'two', 'three')):
            data = ('diff --git a/own.txt b/own.txt\n--- a/own.txt\n+++ b/own.txt\n'
                    '@@ -1 +1 @@\n-' + before + '\n+' + after + '\n').encode()
            pins = {'own.txt': hashlib.sha256((after + '\n').encode()).hexdigest()}
            if index == 3:
                data += (b'diff --git a/new.h b/new.h\nnew file mode 100644\n'
                         b'--- /dev/null\n+++ b/new.h\n@@ -0,0 +1 @@\n+own header\n')
                pins['new.h'] = hashlib.sha256(b'own header\n').hexdigest()
            name = f'own-{index}.patch'
            (root / name).write_bytes(data)
            patches.append({'path': name, 'sha256': hashlib.sha256(data).hexdigest(), 'source_sha256': pins})
        with mock.patch.object(recipe, 'ROOT', root):
            yield root, source, {'base_revision': revision, 'patches': patches}


class NativePatchQueueTests(unittest.TestCase):
    def test_overlapping_patch_intermediate_pins_and_final_idempotence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = root / 'own-source'
            source.mkdir()
            subprocess.run(['git', 'init', '-q'], cwd=source, check=True)
            (source / 'own.txt').write_text('zero\n')
            subprocess.run(['git', 'add', 'own.txt'], cwd=source, check=True)
            subprocess.run(['git', '-c', 'user.name=Own Fixture', '-c', 'user.email=own-fixture@example.invalid',
                            'commit', '-qm', 'own inert baseline'], cwd=source, check=True)
            revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip()
            patches = []
            for index, before, after in ((1, 'zero', 'one'), (2, 'one', 'two')):
                data = ('diff --git a/own.txt b/own.txt\n--- a/own.txt\n+++ b/own.txt\n'
                        '@@ -1 +1 @@\n-' + before + '\n+' + after + '\n').encode()
                name = f'own-{index}.patch'
                (root / name).write_bytes(data)
                patches.append({'path': name, 'sha256': hashlib.sha256(data).hexdigest(),
                                'source_sha256': {'own.txt': hashlib.sha256((after+'\n').encode()).hexdigest()}})
            config = {'base_revision': revision, 'patches': patches}
            with mock.patch.object(recipe, 'ROOT', root):
                # A scratch folder inside this checkout still has its own patch root.
                with mock.patch.object(tempfile, 'tempdir', str(source)):
                    report = recipe.audit_patch_queue(config, revision, source)
                self.assertEqual(report['applied_patches'], [item['path'] for item in patches])
                self.assertEqual(report['changed_patched_outputs'], [])
                self.assertEqual((source / 'own.txt').read_text(), 'zero\n')
                recipe.apply_patches(config, source)
                self.assertEqual((source / 'own.txt').read_text(), 'two\n')
                recipe.apply_patches(config, source)
                self.assertEqual((source / 'own.txt').read_text(), 'two\n')
                (root / patches[0]['path']).write_bytes(b'changed own patch')
                with self.assertRaisesRegex(SystemExit, 'Patch digest mismatch'):
                    recipe.apply_patches(config, source)

    def test_public_queue_retains_the_verified_optional_hook_ownership_fix(self):
        config = json.loads((PROJECT / 'config/native-port.json').read_text())
        relative = 'code/client/citicore/DllGameComponent.Win32.cpp'
        spec = importlib.util.spec_from_file_location(
            'queue_ownership_reference', PROJECT / 'native/windows-core-null-target-fix/build.py')
        ownership = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ownership)
        original = subprocess.check_output([
            'git', '-C', str(PROJECT / 'upstream/fivem'),
            'show', config['base_revision'] + ':' + relative])
        patches = [item for item in config['patches'] if relative in item['source_sha256']]
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            subprocess.run(['git', 'init', '-q'], cwd=source, check=True)
            target = source / relative
            target.parent.mkdir(parents=True)
            target.write_bytes(original)
            before_ownership = None
            for item in patches:
                if item['path'] == 'patches/0009-corert-optional-hook-ownership.patch':
                    before_ownership = target.read_bytes()
                subprocess.run(['git', 'apply', '--include=' + relative, str(PROJECT / item['path'])],
                               cwd=source, check=True, capture_output=True)
            self.assertIsNotNone(before_ownership, 'The update queue omitted the measured loader correction')
            self.assertEqual(target.read_bytes(), ownership.wrap_component(before_ownership))
            self.assertEqual(target.read_bytes()[target.read_bytes().index(b'Component* DllGameComponent::CreateComponent()'):],
                             original[original.index(b'Component* DllGameComponent::CreateComponent()'):])

    def test_appended_patch_resumes_after_overlapping_prefix_and_adds_header(self):
        with own_queue() as (root, source, config):
            recipe.apply_patches({**config, 'patches': config['patches'][:2]}, source)
            self.assertEqual((source / 'own.txt').read_text(), 'two\n')
            self.assertFalse((source / 'new.h').exists())
            with mock.patch.object(recipe, 'run', wraps=recipe.run) as commands:
                recipe.apply_patches(config, source)
            self.assertEqual(commands.call_args_list, [
                mock.call(['git', 'apply', '--check', root / 'own-3.patch'], source),
                mock.call(['git', 'apply', root / 'own-3.patch'], source)])
            self.assertEqual((source / 'own.txt').read_text(), 'three\n')
            self.assertEqual((source / 'new.h').read_bytes(), b'own header\n')
            with mock.patch.object(recipe, 'run') as commands:
                recipe.apply_patches(config, source)
            commands.assert_not_called()

    def test_dirty_known_source_and_premature_header_refuse_before_any_apply(self):
        with own_queue() as (_, source, config):
            recipe.apply_patches({**config, 'patches': config['patches'][:2]}, source)
            for relative in ('own.txt', 'new.h'):
                with self.subTest(relative=relative):
                    target = source / relative
                    target.write_bytes(b'own unrecognized contents\n')
                    with mock.patch.object(recipe, 'run') as commands, \
                            self.assertRaisesRegex(SystemExit, 'refusing unrecognized source changes'):
                        recipe.apply_patches(config, source)
                    commands.assert_not_called()
                    self.assertEqual(target.read_bytes(), b'own unrecognized contents\n')
                    if relative == 'own.txt':
                        target.write_bytes(b'two\n')
                    else:
                        target.unlink()

    def test_build_refuses_incomplete_or_dirty_source_before_cmake(self):
        with own_queue() as (root, source, config):
            manifest = root / 'config.json'
            manifest.write_text(json.dumps(config))
            recipe.apply_patches({**config, 'patches': config['patches'][:2]}, source)
            with mock.patch.object(recipe, 'SOURCE', source), mock.patch.object(recipe, 'MANIFEST', manifest), \
                    mock.patch.object(recipe, 'run') as commands, mock.patch.object(recipe.shutil, 'which') as tools:
                with self.assertRaisesRegex(SystemExit, 'Patch queue incomplete'):
                    recipe.build()
                (source / 'own.txt').write_bytes(b'own dirty source\n')
                with self.assertRaisesRegex(SystemExit, 'refusing unrecognized source changes'):
                    recipe.build()
            commands.assert_not_called()
            tools.assert_not_called()

    def test_build_requires_matching_patch_bytes_even_with_complete_source(self):
        with own_queue() as (root, source, config):
            manifest = root / 'config.json'
            manifest.write_text(json.dumps(config))
            recipe.apply_patches(config, source)
            with mock.patch.object(recipe, 'SOURCE', source), mock.patch.object(recipe, 'MANIFEST', manifest), \
                    mock.patch.object(recipe, 'run') as commands, mock.patch.object(recipe.shutil, 'which', return_value='own-tool'):
                recipe.build()
                self.assertEqual(commands.call_count, 2)
                self.assertEqual(commands.call_args_list[0].args[0][:3], ['cmake', '-S', root / 'native'])
                commands.reset_mock()
                (root / 'own-3.patch').write_bytes(b'own modified patch\n')
                with self.assertRaisesRegex(SystemExit, 'Patch digest mismatch'):
                    recipe.build()
                commands.assert_not_called()


if __name__ == '__main__':
    unittest.main()
