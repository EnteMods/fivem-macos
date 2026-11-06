"""Health adapter source/input checks and mocked delegation; never start Wine."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('own_parity_health_under_test', PROJECT/'native/wine-parity-probes/health.py')
health = importlib.util.module_from_spec(spec)
spec.loader.exec_module(health)


class ParityHealthTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()/'project'
        names = {'native/wine-parity-probes/'+name for name in ('health.py', 'run.py', 'environment.py')}
        self.reports = {}
        for family, profile in health.PROFILES.items():
            raw = (PROJECT/profile['report']).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), profile['report_sha256'])
            report = json.loads(raw)
            self.reports[family] = report
            names |= {profile['report'], report['artifact']['path'], report['toolchain']['path'],
                      report['object']['path'], report['pe_inspection']['path'], report['build']['log']['path'],
                      report['build']['compile_commands']['path'], report['no_wine_contract_tests']['log']['path']}
            names |= {item['path'] for item in report['source_evidence']}
            if family == 'winhttp':
                names |= {report['generated_target_header']['path'], report['target']['cef_config']['path'],
                          report['target']['existing_main_https_build']['path']}
                names |= {item['path'] for item in report['target']['original_url_sources']}
        for name in names:
            destination = self.root/name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(PROJECT/name, destination)
        self.private = self.root/'prefixes/private/user.reg'
        self.private.parent.mkdir(parents=True)
        self.private.write_bytes(b'OWN PRIVATE SENTINEL')
        patch = mock.patch.object(health, 'ROOT', self.root)
        patch.start()
        self.addCleanup(patch.stop)

    def test_both_modes_admit_only_exact_own_pe_and_source_parser_bindings(self):
        for family, verify in (('health', health.verify_health), ('winhttp', health.verify_winhttp)):
            with self.subTest(family=family):
                result = verify()
                self.assertEqual(result['runtime_inputs'], [self.reports[family]['artifact']])
                self.assertEqual(result['parser_source']['sha256'], health.PROFILES[family]['parser_sha256'])
                self.assertEqual(len(result['runner_sources']), 3)
        self.assertEqual(health.verify_winhttp()['fixed_target']['url'], health.TARGET_URL)

    def test_cli_delegates_separate_modes_to_same_lifecycle_with_exact_arguments(self):
        for mode, arguments in (('font', ('--font',)), ('winhttp', ())):
            with self.subTest(mode=mode), mock.patch.object(health.base, 'run_cases', return_value=17) as run:
                self.assertEqual(health.main([mode]), 17)
                cases = run.call_args.args[0]
                self.assertEqual(len(cases), 1)
                self.assertEqual(cases[0]['arguments'], arguments)
                self.assertEqual(cases[0]['cwd'], cases[0]['binary'].parent)
                self.assertEqual(run.call_args.kwargs['role'], mode)
                self.assertEqual(run.call_args.kwargs['verify_inputs']()['runtime_inputs'][0]['path'],
                                 str(cases[0]['binary'].relative_to(self.root)))

    def test_original_parsers_preserve_failure_for_font_ink_and_non200_https(self):
        font = [f'RUNTIME_HEALTH_FONT_API stage_code={stage} succeeded=1' for stage in range(1, 15)]
        font += ['RUNTIME_HEALTH_RESULT mode=font stage_code=9 passed=1 before_ink=0 after_ink=100 cleanup=1']
        http = [f'RUNTIME_WINHTTP_API stage_code={stage} succeeded=1 error=0' for stage in range(1, 12)]
        http += ['RUNTIME_WINHTTP_RESULT stage_code=8 passed=1 http_status=200 status_bytes=4 cleanup=1']
        for mode, lines, replacement in (('font', font, ('after_ink=100', 'after_ink=0')),
                                          ('winhttp', http, ('http_status=200', 'http_status=302'))):
            with self.subTest(mode=mode), mock.patch.object(health.base, 'run_cases', return_value=0) as run:
                health.main([mode])
                parse = run.call_args.args[0][0]['parse_output']
                self.assertTrue(parse(lines, 0)['passed'])
                bad = [line.replace(*replacement) for line in lines]
                self.assertFalse(parse(bad, 0)['passed'])
                self.assertFalse(parse(lines, 1)['passed'])

    def test_changed_parser_is_refused_before_it_can_execute(self):
        path = self.root/'native/windows-runtime-health/contract.py'
        path.write_bytes(path.read_bytes()+b'\nraise AssertionError("UNVERIFIED CODE EXECUTED")\n')
        with self.assertRaises(RuntimeError): health.verify_health()
        with self.assertRaises(RuntimeError): health.load_health_contract()

    def test_manifest_source_scope_refuses_private_paths_before_selected_reads(self):
        family = 'health'
        invalid = copy.deepcopy(self.reports[family])
        invalid['source_evidence'][0]['path'] = 'prefixes/private/user.reg'
        path = self.root/health.PROFILES[family]['report']
        path.write_text(json.dumps(invalid))
        profiles = copy.deepcopy(health.PROFILES)
        profiles[family]['report_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        with mock.patch.object(health, 'PROFILES', profiles), \
                mock.patch.object(health.base.runtime, 'read_regular', wraps=health.base.runtime.read_regular) as read, \
                self.assertRaises(RuntimeError):
            health.verify_health()
        self.assertFalse(any(call.args[0] == self.private for call in read.call_args_list))

    def test_changed_build_report_refused_before_manifest_paths_or_runtime_delegation(self):
        report = self.root/health.PROFILES['winhttp']['report']
        report.write_text('{"path":"prefixes/private/user.reg"}')
        with mock.patch.object(health.base, 'run_cases') as run, self.assertRaises(RuntimeError):
            health.main(['winhttp'])
        run.assert_not_called()

    def test_symlink_or_hardlink_probe_is_refused_and_never_launched(self):
        path = self.root/self.reports['health']['artifact']['path']
        path.unlink()
        for kind in ('symlink', 'hardlink'):
            if kind == 'symlink': path.symlink_to(self.private)
            else: os.link(self.private, path)
            with self.subTest(kind=kind), mock.patch.object(health.base, 'run_cases') as run, \
                    self.assertRaises((SystemExit, RuntimeError)):
                health.main(['font'])
            run.assert_not_called()
            path.unlink()


if __name__ == '__main__':
    unittest.main()
