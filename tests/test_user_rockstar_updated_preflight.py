import copy
from contextlib import ExitStack
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'own_updated_rockstar_preflight',
    ROOT / 'native/windows-client/run_user_rockstar_session.py')
session = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(session)


class UpdatedRockstarPreflightTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve() / 'project'
        self.prefix = self.root / 'prefixes/fivem-source-main'
        self.prefix.mkdir(parents=True)
        self.user = 'own-fixture-user'

    def installation(self, count, *, updated=False):
        roots = session.UPDATED_CODE_ROOTS if updated else session.CODE_ROOTS
        paths = [session.CODE_ROOTS[0] + '/Launcher.exe',
                 session.CODE_ROOTS[1] + '/socialclub.dll']
        if updated:
            paths.extend(roots[2] + '/' + name for name in (
                'overlay.pak', 'scui.pak', 'socialclub.dll', 'socialclub.pak',
                'uninstallRGSCRedistributable.exe'))
        paths.extend(session.CODE_ROOTS[0] + '/own-%03d.dll' % index
                     for index in range(count - len(paths)))
        files = []
        for relative in paths:
            path = self.prefix / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            raw = b'own inert fixture code'
            path.write_bytes(raw)
            files.append({'path': relative, 'bytes': len(raw),
                          'sha256': hashlib.sha256(raw).hexdigest()})
        evidence = self.root / 'research/own-code-evidence.json'
        evidence.parent.mkdir()
        evidence.write_bytes(b'{"own_fixture":true}\n')
        info = self.prefix.stat()
        manifest = {
            'schema': 1, 'kind': 'rockstar-code-only', 'roots': list(roots),
            'files': files, 'excluded_account_profiles_registry_sessions': True,
            'source_evidence': {
                'path': evidence.relative_to(self.root).as_posix(),
                'sha256': hashlib.sha256(evidence.read_bytes()).hexdigest()},
            'prefix_binding': {'project_root': str(self.root),
                               'prefix_device': info.st_dev,
                               'prefix_inode': info.st_ino, 'user': self.user}}
        self.manifest_path = self.prefix / session.MANIFEST_NAME
        self.manifest_path.write_text(json.dumps(manifest, sort_keys=True))
        self.identity = {'rockstar_code_manifest': {
            'path': session.MANIFEST_NAME,
            'sha256': hashlib.sha256(self.manifest_path.read_bytes()).hexdigest()}}
        self.identity_path = self.prefix / '.source-main-probe'
        self.identity_path.write_text(json.dumps(self.identity, sort_keys=True))
        return manifest

    def controls(self, origin, *, manual_login=True):
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.object(session, 'ROOT', self.root))
        stack.enter_context(patch.object(session, 'PREFIX', self.prefix))
        stack.enter_context(patch.object(session, '_location',
                                        return_value=(self.prefix, self.root)))
        stack.enter_context(patch.object(session.getpass, 'getuser', return_value=self.user))
        stack.enter_context(patch.object(session, '_read_identity', return_value=self.identity))
        stack.enter_context(patch.object(session, '_manual_login_authorized',
                                        return_value=manual_login))
        stack.enter_context(patch.object(session, '_check_c_drive'))
        stack.enter_context(patch.object(session, '_check_shell_folders'))
        validator = stack.enter_context(patch.object(session, 'validated_update_origin',
                                                     return_value=origin))
        verifier = stack.enter_context(patch.object(session, '_verify_code',
                                                    wraps=session._verify_code))
        return validator, verifier

    def snapshot(self):
        return (self.manifest_path.read_bytes(), self.identity_path.read_bytes(),
                copy.deepcopy(self.identity))

    def test_original_142_file_installation_keeps_two_root_policy_and_metadata(self):
        manifest = self.installation(142)
        before = self.snapshot()
        validator, verifier = self.controls(None)
        result = session.preflight()
        self.assertEqual(result['rockstar_code_manifest_sha256'],
                         self.identity['rockstar_code_manifest']['sha256'])
        validator.assert_called_once_with(self.prefix, self.root, self.identity,
                                          self.user, manifest)
        self.assertEqual(verifier.call_args.kwargs['expected_roots'], session.CODE_ROOTS)
        self.assertEqual(self.snapshot(), before)

    def test_reviewed_update_145_files_uses_three_roots_only_after_origin_validation(self):
        manifest = self.installation(145, updated=True)
        before = self.snapshot()
        validator, verifier = self.controls({'own_validated_update': True})
        result = session.preflight()
        validator.assert_called_once_with(self.prefix, self.root, self.identity,
                                          self.user, manifest)
        self.assertEqual(verifier.call_args.kwargs['expected_roots'], session.UPDATED_CODE_ROOTS)
        self.assertEqual(result['authorized_game_folder_names'], list(session.GAME_FOLDERS))
        self.assertEqual(self.snapshot(), before)

    def test_unproved_update_or_rejected_origin_never_admits_third_root(self):
        self.installation(145, updated=True)
        before = self.snapshot()
        validator, verifier = self.controls(None)
        with self.assertRaises(session.ProbePrefixError):
            session.preflight()
        self.assertEqual(verifier.call_args.kwargs['expected_roots'], session.CODE_ROOTS)
        verifier.reset_mock()
        validator.side_effect = session.ProbePrefixError('Own invalid update proof')
        with self.assertRaises(session.ProbePrefixError):
            session.preflight()
        verifier.assert_not_called()
        self.assertEqual(self.snapshot(), before)

    def test_exact_counts_remain_required_after_code_and_origin_checks(self):
        for count, updated in ((141, False), (145, False), (144, True), (146, True)):
            with self.subTest(count=count, updated=updated):
                with tempfile.TemporaryDirectory() as temporary:
                    self.root = Path(temporary).resolve() / 'project'
                    self.prefix = self.root / 'prefixes/fivem-source-main'
                    self.prefix.mkdir(parents=True)
                    self.installation(count, updated=updated)
                    before = self.snapshot()
                    _, verifier = self.controls({'own_validated_update': True} if updated else None)
                    with self.assertRaisesRegex(session.ProbePrefixError, 'exact reviewed'):
                        session.preflight()
                    self.assertEqual(verifier.call_count, 1)
                    self.assertEqual(self.snapshot(), before)


if __name__ == '__main__':
    unittest.main()
