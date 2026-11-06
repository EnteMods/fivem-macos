"""Temporary files and mocked subprocesses only; no Wine or real prefix access."""
from contextlib import contextmanager, redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

PROJECT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('own_graphics_under_test', PROJECT/'native/wine-parity-probes/graphics.py')
graphics = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(graphics)
runner, runtime = graphics.runner, graphics.runtime


class GraphicsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.parent = Path(temporary.name).resolve()
        self.root = self.parent/'FiveM-macOS'
        self.root.mkdir()
        self.prefix = self.root/'prefixes/wine-parity-regression'
        self.engine = self.root/'runtime/wine-job-query-parity/engine'
        self.build = self.root/'build/windows-job-tests'
        self.build.mkdir(parents=True)
        for module, values in ((graphics, {'ROOT': self.root}),
                               (runner, {'ROOT': self.root, 'PREFIX': self.prefix, 'BUILD': self.build}),
                               (runtime, {'ROOT': self.root, 'PREFIX': self.prefix, 'ENGINE': self.engine})):
            for name, value in values.items():
                patch = mock.patch.object(module, name, value)
                patch.start()
                self.addCleanup(patch.stop)
        self.verified = {'manifest_sha256': runtime.MANIFEST_SHA, 'protocol_version': runtime.PROTOCOL}

    def patch(self, obj, name, value):
        patch = mock.patch.object(obj, name, value)
        patch.start()
        self.addCleanup(patch.stop)

    def renderer(self):
        directory = graphics.provider()
        rows, payloads = [], {}
        for name in sorted(graphics.FILES):
            machine = 0x14c if name.startswith('i386-') else 0x8664
            if name.endswith('.dll'):
                data = bytearray(256)
                data[:2] = b'MZ'
                struct.pack_into('<I', data, 60, 128)
                data[64:81] = b'Wine builtin DLL\0'
                data[128:132] = b'PE\0\0'
                struct.pack_into('<H', data, 132, machine)
                data = bytes(data)+name.encode()
            else:
                machine = 0x1000007
                data = struct.pack('<II', 0xfeedfacf, machine)+name.encode()
            path = directory/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            payloads[name] = data
            rows.append({'relative_path': name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                         'architecture': 'i386' if machine==0x14c else 'x86_64', 'machine': machine,
                         'wine_builtin_marker': True if name.endswith('.dll') else None,
                         'wine_placeholder_marker': False if name.endswith('.dll') else None,
                         'matches_verified_original_archive': True})
        archive = self.parent/'GTA-V-macOS/downloads/matched-dxmt-a444716.tar.gz'
        archive.parent.mkdir(parents=True)
        with tarfile.open(archive, 'w:gz') as output:
            for name, data in payloads.items():
                member = tarfile.TarInfo('highball/'+name)
                member.size = len(data)
                output.addfile(member, io.BytesIO(data))
        archive_data = archive.read_bytes()
        archive_hash = hashlib.sha256(archive_data).hexdigest()
        report = {'schema_version': 1, 'pin_id': 'dxmt-highball-20260930T161516Z-a444716',
                  'provider_role': graphics.ROLE, 'fixed_project_sibling': 'GTA-V-macOS',
                  'provider_relative_root': graphics.PROVIDER_RELATIVE, 'files': rows,
                  'source_archive': {'fixed_project_sibling': 'GTA-V-macOS',
                                     'relative_path': 'downloads/matched-dxmt-a444716.tar.gz',
                                     'bytes': len(archive_data), 'sha256': archive_hash}}
        self.patch(graphics, 'ARCHIVE_BYTES', len(archive_data))
        self.patch(graphics, 'ARCHIVE_SHA', archive_hash)
        self.publish_review(report)
        return report, payloads, archive

    def publish_review(self, report):
        raw = json.dumps(report).encode()
        self.assertLessEqual(len(raw), 7463)
        raw = raw.ljust(7463, b' ')
        path = self.root/graphics.REVIEW_PATH
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(raw)
        self.patch(graphics, 'REVIEW_SHA', hashlib.sha256(raw).hexdigest())

    def prefix_fixture(self):
        self.prefix.mkdir(parents=True)
        (self.prefix/'.account-free-probe').write_text('own test')
        (self.prefix/'system.reg').write_text('own boot')
        for name in ('system32', 'syswow64'):
            (self.prefix/'drive_c/windows'/name).mkdir(parents=True)
        devices = self.prefix/'dosdevices'
        devices.mkdir()
        (devices/'c:').symlink_to('../drive_c', target_is_directory=True)
        runner.bind_prefix(False)

    def test_fixed_renderer_archive_all_architectures_and_markers_verified(self):
        self.renderer()
        result = graphics.verify_renderer()
        self.assertEqual({row['relative_path'] for row in result['code_inputs']}, graphics.FILES)
        self.assertEqual(result['source_archive']['path_from_project_parent'],
                         'GTA-V-macOS/downloads/matched-dxmt-a444716.tar.gz')
        self.assertEqual(len(result['code_inputs']), 11)

    def test_report_selected_foreign_role_refused_before_any_code_or_archive_read(self):
        report, _, _ = self.renderer()
        report['files'][-1]['relative_path'] = '../../other/unknown.dll'
        self.publish_review(report)
        original = runtime.read_regular
        reads = []
        def read(path, boundary=None):
            reads.append(path)
            return original(path, boundary)
        with mock.patch.object(runtime, 'read_regular', side_effect=read):
            with self.assertRaises(RuntimeError):
                graphics.verify_renderer()
        self.assertEqual(reads, [self.root/graphics.REVIEW_PATH])

    def test_missing_last_provider_is_preflighted_before_archive_or_provider_reads(self):
        self.renderer()
        (graphics.provider()/'x86_64-windows/winemetal.dll').unlink()
        original = runtime.read_regular
        reads = []
        def read(path, boundary=None):
            reads.append(path)
            return original(path, boundary)
        with mock.patch.object(runtime, 'read_regular', side_effect=read):
            with self.assertRaises(FileNotFoundError):
                graphics.verify_renderer()
        self.assertEqual(reads, [self.root/graphics.REVIEW_PATH])

    def test_extra_file_and_hardlink_provider_are_not_adopted(self):
        self.renderer()
        extra = graphics.provider()/'unknown.dll'
        extra.write_bytes(b'other')
        with self.assertRaisesRegex(RuntimeError, 'Unbound'):
            graphics.verify_renderer()
        extra.unlink()
        path = graphics.provider()/'i386-windows/winemetal.dll'
        alias = self.parent/'alias'
        os.link(path, alias)
        with self.assertRaisesRegex(RuntimeError, 'single-link'):
            graphics.verify_renderer()

    def test_original_archive_and_provider_hash_are_independently_bound(self):
        self.renderer()
        path = graphics.provider()/'x86_64-windows/d3d11.dll'
        path.write_bytes(b'changed')
        with self.assertRaisesRegex(RuntimeError, 'code changed'):
            graphics.verify_renderer()

    def test_graphics_environment_keeps_bound_runtime_and_isolates_inherited_roles(self):
        with mock.patch.object(graphics, 'verify_renderer', return_value={}):
            with mock.patch.dict(os.environ, {'WINEPREFIX':'/private', 'WineServerSocket':'private',
                                             'CitizenFX_ToolMode':'1', 'DYLD_INSERT_LIBRARIES':'/private'}, clear=False):
                env = graphics.graphics_environment(self.verified)
        runner.validate_environment(env)
        self.assertEqual(env['WINEDLLPATH_PREPEND'], str(graphics.provider()))
        self.assertEqual(env['WINEDLLOVERRIDES'], 'winemenubuilder.exe,mscoree,mshtml=d;'+graphics.OVERRIDES)
        self.assertEqual(env['DXMT_ALLOW_CROSS_PROCESS_SWAPCHAIN'], '1')
        self.assertEqual(env['DYLD_PRINT_LIBRARIES'], '1')
        for name in ('WineServerSocket', 'CitizenFX_ToolMode', 'DYLD_INSERT_LIBRARIES'):
            self.assertNotIn(name, env)
        self.assertIn(str(self.engine/'lib/wine/x86_64-unix'), env['DYLD_LIBRARY_PATH'].split(os.pathsep))

    def test_bridge_staging_is_missing_only_repeatable_and_bound_to_both_architectures(self):
        self.renderer()
        self.prefix_fixture()
        env = runtime.environment(self.verified, {})
        first = graphics.prepare_prefix(self.verified, env)
        second = graphics.prepare_prefix(self.verified, env)
        self.assertEqual(len(first['created_relative_paths']), 2)
        self.assertEqual(second['created_relative_paths'], [])
        self.assertFalse(first['base_engine_modified'])
        self.assertEqual({item['machine'] for item in first['binding']['files']}, {0x14c,0x8664})
        for item in first['binding']['files']:
            self.assertEqual((self.prefix/item['relative_prefix_path']).stat().st_nlink, 1)
        self.assertFalse(list(self.prefix.rglob('.graphics-code-*')))

    def test_unknown_second_bridge_prevents_first_bridge_and_marker_publication(self):
        self.renderer()
        self.prefix_fixture()
        unknown = self.prefix/'drive_c/windows/syswow64/winemetal.dll'
        unknown.write_bytes(b'unknown')
        with self.assertRaisesRegex(RuntimeError, 'unknown existing'):
            graphics.prepare_prefix(self.verified, runtime.environment(self.verified, {}))
        self.assertFalse((self.prefix/'drive_c/windows/system32/winemetal.dll').exists())
        self.assertFalse(graphics._bridge_marker().exists())
        self.assertEqual(unknown.read_bytes(), b'unknown')

    def test_special_second_destination_refused_before_bridge_source_read_or_publication(self):
        self.renderer()
        self.prefix_fixture()
        os.mkfifo(self.prefix/'drive_c/windows/syswow64/winemetal.dll')
        renderer = graphics.verify_renderer()
        with mock.patch.object(graphics, 'verify_renderer', return_value=renderer):
            with mock.patch.object(runtime, 'read_regular', wraps=runtime.read_regular) as reads:
                with self.assertRaisesRegex(RuntimeError, 'single-link'):
                    graphics.prepare_prefix(self.verified, runtime.environment(self.verified, {}))
        self.assertFalse(any(str(call.args[0]).startswith(str(graphics.provider())) for call in reads.call_args_list))
        self.assertFalse((self.prefix/'drive_c/windows/system32/winemetal.dll').exists())

    def test_bad_marker_and_changed_inode_are_refused_without_publication(self):
        self.renderer()
        self.prefix_fixture()
        graphics._bridge_marker().write_text('{}')
        with self.assertRaisesRegex(RuntimeError, 'different existing'):
            graphics.prepare_prefix(self.verified, runtime.environment(self.verified, {}))
        graphics._bridge_marker().unlink()
        binding = json.loads(runner.binding_path().read_text())
        binding['inode'] += 1
        runner.binding_path().write_text(json.dumps(binding))
        with self.assertRaisesRegex(RuntimeError, 'inode binding'):
            graphics.prepare_prefix(self.verified, runtime.environment(self.verified, {}))
        self.assertFalse((self.prefix/'drive_c/windows/system32/winemetal.dll').exists())

    def test_atomic_publication_does_not_replace_an_intervening_file(self):
        self.prefix_fixture()
        destination = self.prefix/'drive_c/windows/system32/winemetal.dll'
        link = os.link
        def intervening(source, target, **kwargs):
            target.write_bytes(b'intervening')
            return link(source, target, **kwargs)
        with mock.patch.object(graphics.os, 'link', side_effect=intervening):
            with self.assertRaises(FileExistsError):
                graphics._publish_new(destination, b'own')
        self.assertEqual(destination.read_bytes(), b'intervening')
        self.assertFalse(list(destination.parent.glob('.graphics-code-*')))

    def provider_lines(self):
        paths = [graphics.provider()/'x86_64-unix/winemetal.so']+[
            self.engine/'lib/wine/x86_64-unix'/name for name in ('ntdll.so','winemac.so','win32u.so')]
        lines = ['dyld[123]: <12345678-1234-1234-1234-123456789abc> '+str(path) for path in paths]
        lines += ['0024:trace:loaddll:build_module Loaded L"C:\\\\windows\\\\system32\\\\'+name+
                  '.dll" at 0000000180000000: builtin' for name in ('d3d11','dxgi','winemetal')]
        return lines

    def test_provider_diagnostics_keep_only_fixed_code_roles_from_same_native_process(self):
        lines = self.provider_lines()+['private account text', 'dyld[999]: /private/account/library.dylib']
        result = graphics.parse_provider_diagnostics(lines, 0)
        self.assertTrue(result['passed'])
        self.assertEqual(result['provider_chain']['complete_native_process_ids'], [123])
        self.assertNotIn('private', json.dumps(result))
        self.assertEqual(result['provider_chain']['windows_builtin_modules'], ['d3d11','dxgi','winemetal'])

    def test_incomplete_cross_pid_old_provider_or_native_pe_evidence_fails(self):
        lines = self.provider_lines()
        for changed in (lines[1:], [line.replace('dyld[123]', 'dyld[124]') if i==0 else line for i,line in enumerate(lines)],
                        [line.replace(str(graphics.provider()), '/old/provider') for line in lines],
                        [line.replace(': builtin', ': native') if 'd3d11.dll' in line else line for line in lines]):
            self.assertFalse(graphics.parse_provider_diagnostics(changed, 0)['passed'])
        self.assertFalse(graphics.parse_provider_diagnostics(lines, 1)['passed'])

    def graphics_output(self, level):
        return [*(f'RUNTIME_HEALTH_GRAPHICS_API stage_code={stage} hresult=0x00000000 succeeded=1' for stage in (1,2,3)),
                'RUNTIME_HEALTH_GRAPHICS_ISSUED stage_code=4 issued=1',
                'RUNTIME_HEALTH_GRAPHICS_API stage_code=5 hresult=0x00000000 succeeded=1',
                'RUNTIME_HEALTH_GRAPHICS_ISSUED stage_code=6 issued=1',
                'RUNTIME_HEALTH_GRAPHICS_API stage_code=7 hresult=0x00000000 succeeded=1',
                f'RUNTIME_HEALTH_RESULT mode=graphics stage_code=8 passed=1 device=1 context=1 feature_level={level} '
                'mapped=1 pixel_r=64 pixel_g=128 pixel_b=191 pixel_a=255']

    def original_contract(self):
        spec = importlib.util.spec_from_file_location('unaltered_health_contract_for_test',
                                                      PROJECT/'native/windows-runtime-health/contract.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.parse_output

    def test_bogus_feature_level_fails_adapter_even_when_raw_contract_passes(self):
        contract = self.original_contract()
        lines = self.graphics_output(0xffffffff)
        self.assertTrue(contract('\n'.join(lines), 'graphics', 0)['passed'])
        parsed = graphics.parse_graphics_output(lines, 0, contract)
        self.assertTrue(parsed['raw_contract_passed'])
        self.assertFalse(parsed['feature_level_is_known_sdk_value'])
        self.assertFalse(parsed['passed'])
        for level in graphics.FEATURE_LEVELS:
            self.assertTrue(graphics.parse_graphics_output(self.graphics_output(level), 0, contract)['passed'])

    def test_graphics_case_uses_original_mode_and_adds_post_run_bridge_verification(self):
        contract = self.original_contract()
        with mock.patch.object(graphics.health, 'load_health_contract', return_value=contract):
            case, = graphics.graphics_cases()
        self.assertEqual(case['arguments'], ['--graphics'])
        self.assertTrue(case['parse_output'](self.graphics_output(0xb000),0)['passed'])
        with mock.patch.object(graphics, 'verify_bridge_binding', return_value={'own':'binding'}) as binding:
            parsed = case['parse_diagnostics'](self.provider_lines(),0)
        binding.assert_called_once_with()
        self.assertTrue(parsed['passed'])
        self.assertEqual(parsed['prefix_bridge_binding'], {'own':'binding'})

    def mocked_lifecycle(self, *, factory_change=None, prepare_error=False, mutate_env=False,
                         diagnostic_pass=True, cleanup_error=False, parser_error=False):
        binary = self.build/'own.exe'
        binary.write_bytes(b'own fixture')
        fixture = {'runtime_inputs':[{'path':str(binary.relative_to(self.root)), 'bytes':11,
                                     'sha256':hashlib.sha256(binary.read_bytes()).hexdigest()}]}
        calls, prepared = [], []
        def factory(verified):
            env = runtime.environment(verified,{})
            if factory_change:
                env.update(factory_change)
            return env
        def prepare(verified, env):
            with self.assertRaises(SystemExit):
                with runner.probe_prefix(self.prefix, root=self.root):
                    self.fail('Preparation must hold the prefix lock')
            self.assertTrue((self.prefix/'system.reg').is_file())
            prepared.append(True)
            if mutate_env:
                env['WINEPREFIX'] = '/unknown'
            if prepare_error:
                raise RuntimeError('own preparation failure')
            return {'own':True}
        def process(command, **kwargs):
            calls.append((command, dict(kwargs['env'])))
            with self.assertRaises(SystemExit):
                with runner.probe_prefix(self.prefix, root=self.root):
                    self.fail('Owned subprocess must retain prefix lock')
            if command[-1]=='-i':
                (self.prefix/'system.reg').write_text('own boot')
                (self.prefix/'dosdevices').mkdir()
                (self.prefix/'dosdevices/c:').symlink_to('../drive_c',target_is_directory=True)
            elif command[-1]=='-k' and cleanup_error:
                raise subprocess.TimeoutExpired(command, 15)
            elif command[-1].endswith('.exe'):
                kwargs['stdout'].write('own fixed metadata\n')
                kwargs['stderr'].write('own provider metadata\n')
            return SimpleNamespace(returncode=0)
        def diagnostics(lines, code):
            self.assertEqual(lines, ['own provider metadata'])
            if parser_error:
                raise RuntimeError('own diagnostics failure')
            return {'passed':diagnostic_pass}
        case = {'name':'own_graphics','binary':binary,'cwd':binary.parent,
                'parse_output':lambda lines,code:{'passed':True},'parse_diagnostics':diagnostics}
        with mock.patch.object(runtime,'verify_runtime',return_value=self.verified):
            with mock.patch.object(runner.subprocess,'run',side_effect=process) as subprocess_mock:
                with redirect_stdout(io.StringIO()):
                    status = runner.run_cases([case],verify_inputs=lambda:fixture,role='graphics-test',
                                              environment_factory=factory,prepare_prefix=prepare)
        result = json.loads(next((self.root/'research').glob('*-results.json')).read_text())
        return status,result,calls,prepared,subprocess_mock

    def test_shared_runner_holds_lock_and_requires_output_and_diagnostic_contracts(self):
        status,result,calls,prepared,_ = self.mocked_lifecycle()
        self.assertEqual(status,0)
        self.assertEqual(prepared,[True])
        self.assertTrue(result['runs'][0]['diagnostics']['passed'])
        self.assertTrue(result['quarantine_cleared_after_confirmed_cleanup'])
        self.assertEqual(len(calls),4)

    def test_shared_runner_diagnostic_failure_cannot_be_overridden_by_stdout_pass(self):
        status,result,_,_,_ = self.mocked_lifecycle(diagnostic_pass=False)
        self.assertEqual(status,1)
        self.assertFalse(result['runs'][0]['passed'])
        self.assertEqual(result['cleanup'],[{'flag':'-k','exit':0},{'flag':'-w','exit':0}])

    def test_factory_cannot_replace_prefix_server_loader_socket_or_client_roles(self):
        for changed in ({'WINEPREFIX':'/private'},{'WINESERVER':'/private/server'},{'WINELOADER':'/private/wine'},
                        {'WineServerSocket':'/private/socket'},{'CitizenFX_ToolMode':'1'},
                        {'DYLD_INSERT_LIBRARIES':'/private.dylib'}):
            env = runtime.environment(self.verified,{})
            env.update(changed)
            with self.assertRaises(RuntimeError):
                runner.validate_environment(env)
        status,result,calls,prepared,process = self.mocked_lifecycle(factory_change={'WINEPREFIX':'/private'})
        self.assertEqual(status,1)
        self.assertFalse(result['runtime_started'])
        self.assertFalse(self.prefix.exists())
        self.assertEqual(prepared,[])
        process.assert_not_called()

    def test_preparation_failure_still_cleans_initialized_runtime(self):
        status,result,_,prepared,_ = self.mocked_lifecycle(prepare_error=True)
        self.assertEqual(status,1)
        self.assertEqual(prepared,[True])
        self.assertEqual(result['runs'],[])
        self.assertEqual(result['cleanup'],[{'flag':'-k','exit':0},{'flag':'-w','exit':0}])
        self.assertTrue(result['quarantine_cleared_after_confirmed_cleanup'])

    def test_mutated_hook_environment_cannot_redirect_cleanup(self):
        status,result,calls,_,_ = self.mocked_lifecycle(mutate_env=True)
        self.assertEqual(status,1)
        self.assertEqual(result['runs'],[])
        self.assertEqual(result['cleanup'],[{'flag':'-k','exit':0},{'flag':'-w','exit':0}])
        for command,env in calls:
            self.assertEqual(env['WINEPREFIX'],str(self.prefix))
            self.assertEqual(env['WINESERVER'],str(self.engine/'bin/wineserver'))

    def test_diagnostics_exception_and_cleanup_failure_keep_failure_and_quarantine(self):
        status,result,_,_,_ = self.mocked_lifecycle(parser_error=True,cleanup_error=True)
        self.assertEqual(status,1)
        self.assertEqual(result['failure']['message'],'own diagnostics failure')
        self.assertEqual(result['cleanup'][1],{'flag':'-w','exit':0})
        self.assertTrue(result['prefix_terminal_state_uncertain'])
        self.assertTrue(runner.quarantine_path().exists())


if __name__=='__main__':
    unittest.main()
