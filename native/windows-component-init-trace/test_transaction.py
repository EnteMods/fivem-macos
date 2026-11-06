import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location('transaction', Path(__file__).with_name('transaction.py'))
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.stage = self.root / 'stage'
        self.stage.mkdir()
        (self.root / 'research').mkdir()
        (self.root / 'artifact').write_bytes(b'diagnostic')
        (self.stage / 'CitizenGame.dll').write_bytes(b'baseline')
        self.base = hashlib.sha256(b'baseline').hexdigest()
        self.diag = hashlib.sha256(b'diagnostic').hexdigest()
        self.values = {'BASE': self.base, 'DIAG': self.diag, 'ARTIFACT': 'artifact',
                       'BACKUP': 'backup/baseline', 'RECEIPT': 'research/receipt.json'}
        self.patches = patch.multiple(t, **self.values)
        self.patches.start()
        self.addCleanup(self.patches.stop)
        self.ev = patch.object(t, 'evidence')
        self.ev.start()
        self.addCleanup(self.ev.stop)
        self.checked = []

    def inventory(self, digest):
        self.checked.append(digest)
        self.assertEqual(t.checked_file(self.stage / 'CitizenGame.dll')[0], digest)

    def run_action(self, action, quiet=lambda: True):
        return t.transition(action, self.root, self.stage, self.inventory, quiet)

    def test_apply_restore(self):
        self.assertEqual(self.run_action('apply')['status'], 'verified')
        self.assertEqual(self.run_action('restore')['status'], 'restored')
        self.assertEqual(self.checked, [self.base, self.diag, self.diag, self.base])
        self.assertTrue((self.root / 'backup/baseline').exists())
        with self.assertRaises(RuntimeError):
            self.run_action('apply')

    def test_busy_does_not_write(self):
        with self.assertRaises(RuntimeError):
            self.run_action('apply', lambda: False)
        self.assertFalse((self.root / 'backup').exists())
        self.assertFalse((self.root / t.RECEIPT).exists())

    def test_unknown_target_never_overwritten(self):
        self.run_action('apply')
        target = self.stage / 'CitizenGame.dll'
        target.chmod(0o600)
        target.write_bytes(b'unknown')
        with self.assertRaises(RuntimeError):
            self.run_action('restore')
        self.assertEqual(target.read_bytes(), b'unknown')

    def test_prepared_before_swap_recovery(self):
        with patch.object(t.os, 'replace', side_effect=OSError('interruption')):
            with self.assertRaises(OSError):
                self.run_action('apply')
        self.assertEqual(json.loads((self.root / t.RECEIPT).read_text())['status'], 'prepared')
        with self.assertRaises(RuntimeError):
            t.verify_receipt(self.stage, root=self.root)
        self.assertEqual(self.run_action('restore')['status'], 'restored')

    def test_prepared_after_swap_recovery(self):
        real = t.atomic_json
        def interrupted(path, record, exclusive=False):
            if record['status'] == 'verified':
                raise OSError('interruption')
            return real(path, record, exclusive)
        with patch.object(t, 'atomic_json', side_effect=interrupted):
            with self.assertRaises(OSError):
                self.run_action('apply')
        self.assertEqual((self.stage / 'CitizenGame.dll').read_bytes(), b'diagnostic')
        self.assertEqual(self.run_action('restore')['status'], 'restored')

    def test_bad_backup_refused(self):
        self.run_action('apply')
        (self.root / t.BACKUP).chmod(0o600)
        (self.root / t.BACKUP).write_bytes(b'tampered')
        with self.assertRaises(RuntimeError):
            self.run_action('restore')
        self.assertEqual((self.stage / 'CitizenGame.dll').read_bytes(), b'diagnostic')

    def test_target_symlink_and_hardlink_rejected(self):
        target = self.stage / 'CitizenGame.dll'
        target.unlink()
        target.symlink_to(self.root / 'artifact')
        with self.assertRaises(OSError):
            self.run_action('apply')
        target.unlink()
        target.write_bytes(b'baseline')
        import os
        os.link(target, self.root / 'second-link')
        with self.assertRaises(RuntimeError):
            self.run_action('apply')

    def test_artifact_hash_mismatch_refused(self):
        (self.root / 'artifact').write_bytes(b'changed')
        with self.assertRaises(RuntimeError):
            self.run_action('apply')
        self.assertEqual((self.stage / 'CitizenGame.dll').read_bytes(), b'baseline')

    def test_evidence_checks_all_build_inputs(self):
        self.ev.stop()
        payload = self.root / 'input'
        payload.write_bytes(b'input')
        identity = {'path': 'input', 'bytes': 5, 'sha256': hashlib.sha256(b'input').hexdigest()}
        artifact = {'path': t.ARTIFACT, 'bytes': 10, 'sha256': self.diag}
        baseline = {'path': 'input', 'bytes': 5, 'sha256': self.base}
        source = dict(identity)
        proof = {'artifact': artifact, 'baseline': baseline, 'source': source,
                 'trace_core': identity, 'trace_platform': identity, 'abi_review': identity,
                 'runtime_started': False, 'runtime_staged': False, 'prefix_accessed': False}
        build = {'source_revision': t.REVISION, 'build_passed': True, 'fixture_passed': True,
                 'compiled_all_four_units_fresh': True, 'header_inputs': [identity] * 506,
                 'reused_link_inputs': [identity] * 15, 'tools': [identity] * 6,
                 'compile_commands': [{'source': identity, 'object': identity}] * 4,
                 'recipe_inputs': [identity], 'original_source': identity, 'toolchain': identity,
                 'artifact': artifact, 'baseline': baseline}
        # Point the baseline proof to its own matching baseline bytes.
        (self.root / 'base').write_bytes(b'baseline')
        baseline.update(path='base', bytes=8)
        record = json.dumps(build).encode()
        (self.root / 'record').write_bytes(record)
        proof['build_record'] = {'path': 'record', 'bytes': len(record), 'sha256': hashlib.sha256(record).hexdigest()}
        raw = json.dumps(proof).encode()
        (self.root / 'proof').write_bytes(raw)
        with patch.multiple(t, PROOF='proof', PROOF_SHA=hashlib.sha256(raw).hexdigest(), SOURCE=identity['sha256']):
            t.evidence(self.root)
            payload.write_bytes(b'wrong')
            with self.assertRaises(RuntimeError):
                t.evidence(self.root)

    def test_existing_receipt_never_replaced(self):
        receipt = self.root / t.RECEIPT
        receipt.write_text('{"unexpected":true}')
        with self.assertRaises(RuntimeError):
            self.run_action('apply')
        self.assertEqual(receipt.read_text(), '{"unexpected":true}')


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name).resolve()
        stage = root / 'stage'
        stage.mkdir()
        game_dir = root / 'game'
        game_dir.mkdir()
        link = root / 'g'
        link.symlink_to(game_dir, target_is_directory=True)
        (stage / 'CitizenFX.ini').write_text('[Game]\nIVPath=G:\\\n')
        status = root / 'status.json'
        status.write_text('{"game_executables": {}}')
        digest = hashlib.sha256(b'original').hexdigest()
        expected = {f'other-{n}.dll': digest for n in range(420)}
        expected.update({'CitizenGame.dll': digest, 'net.dll': digest})
        for name in expected:
            (stage / name).write_bytes(b'original')
        first = SimpleNamespace(expected_files=lambda marker: dict(expected),
                                digest=lambda p: hashlib.sha256(p.read_bytes()).hexdigest())
        self.game = SimpleNamespace(ROOT=root, STAGE=stage, GAME_LINK=link, GAME=game_dir,
                                    STATUS=status, first=first, verify_game=lambda path, items: None)
        self.identity = SimpleNamespace(
            TRANSACTION='core.json', NUI_TRANSACTION='nui.json', NET_HISTORY=[('net.json', 'diagnostic')],
            ORIGINAL_CORE='core', FIXED_CORE='fixed', ORIGINAL_NUI='nui', SOFTWARE_NUI='software',
            ORIGINAL_NET=digest)
        self.digest = digest

    def verify(self):
        return t.verify_inventory(self.game, self.identity, self.digest)

    def test_all_422_and_unrelated_tamper(self):
        self.assertEqual(self.verify(), 422)
        (self.game.STAGE / 'other-123.dll').write_bytes(b'changed')
        with self.assertRaises(RuntimeError):
            self.verify()

    def test_mapping_changed(self):
        self.game.GAME_LINK.unlink()
        other = self.game.ROOT / 'wrong-game'
        other.mkdir()
        self.game.GAME_LINK.symlink_to(other, target_is_directory=True)
        with self.assertRaises(RuntimeError):
            self.verify()

    def test_active_network_diagnostic_rejected(self):
        receipt = {'target': 'stage/net.dll', 'previous_sha256': self.digest,
                   'new_sha256': 'diagnostic', 'status': 'verified'}
        (self.game.ROOT / 'net.json').write_text(json.dumps(receipt))
        with self.assertRaises(RuntimeError):
            self.verify()

    def test_altered_network_receipt_rejected(self):
        receipt = {'target': 'stage/net.dll', 'previous_sha256': 'wrong',
                   'new_sha256': 'diagnostic', 'status': 'restored'}
        (self.game.ROOT / 'net.json').write_text(json.dumps(receipt))
        with self.assertRaises(RuntimeError):
            self.verify()


if __name__ == '__main__':
    unittest.main()
