"""Inert control-path admission and parser delegation checks; never Wine."""
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
path = ROOT / 'native/windows-hook-state-observer/run_control.py'
spec = importlib.util.spec_from_file_location('test_hook_state_own_control', path)
control = importlib.util.module_from_spec(spec)
spec.loader.exec_module(control)


def item(path, sha='a' * 64):
    return {'path': path, 'bytes': 1, 'sha256': sha}


def report():
    b = control.BUILD
    r = {'schema_version': 1, 'compiled': True, 'architecture': 'AMD64', 'runtime': '/MT',
         'runtime_inputs': [item(p) for p in (control.MARKER, control.FIXTURE, control.OBSERVER)],
         'source_evidence': [item(p) for p in sorted(control.SOURCES)],
         'vendor_sources': [item(p) for p in sorted(control.VENDOR)],
         'objects': [item(b + 'CMakeFiles/' + t + '.dir/' + s + '.obj')
                     for t, s in zip(control.TARGETS, ('marker.cpp', 'fixture.cpp', 'observer.cpp'))],
         'pe_inspections': [item(b + t + '-inspection.txt') for t in control.TARGETS],
         'maps': [item(b + t + '.map') for t in control.TARGETS],
         'generated_role_header': item(b + 'role_config.h'),
         'toolchain': item('native/windows-core/toolchain.cmake'),
         'reused_build_helper': item('native/windows-named-pipe-probe/build.py'),
         'minhook_library': item(b + 'own_minhook.lib'), 'ntdll_inspection': item(b + 'ntdll-reference.txt'),
         'build': {'exit': 0, 'log': item(b + 'build.log'), 'compile_commands': item(b + 'compile_commands.json')},
         'no_wine_tests': {'exit': 0, 'passed': 8, 'log': item(b + 'contract-tests.log')},
         'ntdll_reference': {'manifest': item('build/wine-job-query-parity/full-x86_64/engine-manifest.json', control.BASELINE_SHA),
            'artifact': item('runtime/wine-job-query-parity/engine/lib/wine/x86_64-windows/ntdll.dll', control.NTDLL_SHA),
            'exports': {'LdrLoadDll': 0x15b50, 'NtCreateFile': 0xf420, 'NtOpenFile': 0xefe0},
            'size_of_image': 4349952},
         'bounds': {'process_identities': 64, 'state_records_per_process': 64, 'read_width': 21,
            'poll_ms': 25, 'duration_ms': 300000, 'source_apis': ['LdrLoadDll', 'NtCreateFile', 'NtOpenFile'],
            'private_relay_reads': False},
         'source_or_wine_or_prefix_started': False, 'old_observers_engines_or_client_modified': False}
    return r


class OwnControlTests(unittest.TestCase):
    def test_missing_build_freeze_stops_before_any_input_read(self):
        selected_read = Mock(side_effect=AssertionError('No input read before freeze'))
        with patch.object(control, 'REPORT_BYTES', None), patch.object(control, 'REPORT_SHA', None), patch.object(control, 'read', selected_read):
            with self.assertRaises(RuntimeError):
                control.verify_inputs()
        selected_read.assert_not_called()

    def test_foreign_report_path_stops_before_selected_hash_read(self):
        record = report()
        self.assertEqual(len(control.admit_report(record)), 46)
        record['runtime_inputs'][0]['path'] = 'prefixes/fivem-source-main/user.reg'
        raw = json.dumps(record).encode()
        selected = Mock(side_effect=AssertionError('No selected read before complete role admission'))
        reader = Mock(return_value=raw)
        with patch.object(control, 'REPORT_BYTES', len(raw)), patch.object(control, 'REPORT_SHA', hashlib.sha256(raw).hexdigest()), patch.object(control, 'read', reader), patch.object(control, 'identity', selected):
            with self.assertRaises(RuntimeError):
                control.verify_inputs()
        reader.assert_called_once_with(control.REPORT)
        selected.assert_not_called()

    def test_changed_lifecycle_code_never_executes(self):
        with patch.object(control, 'read', return_value=b'raise AssertionError("must not execute")'):
            with self.assertRaisesRegex(RuntimeError, 'before execution'):
                control.load_runner()

    def test_three_fixed_cases_and_strict_empty_source_result(self):
        cases = control.make_cases({'parser_source': control.identity(control.PARSER)})
        self.assertEqual([x['name'] for x in cases], ['gated_hook_state_fixture', 'outside_root_rejection', 'empty_source_binding'])
        self.assertEqual(cases[0]['arguments'], ())
        self.assertEqual(cases[2]['arguments'], ('--source-root', control.SOURCE_ROOT, '--duration-ms', '100'))
        self.assertTrue(cases[1]['parse_output'](['{"event":"rejected","reason":1,"process_reads":0}'], 2)['passed'])
        rows = [{'event': 'ready', 'mode': 'source', 'pid': 100, 'poll_ms': 25, 'read_width': 21,
                 'duration_ms': 100, 'api_count': 3},
                {'event': 'completed', 'processes': 0, 'read_calls': 0, 'state_records': 0,
                 'stopped_processes': 0, 'failures': 0, 'close_failures': 0, 'duration_completed': True, 'exit': 0}]
        lines = lambda: [json.dumps(row) for row in rows]
        self.assertTrue(cases[2]['parse_output'](lines(), 0)['passed'])
        rows[-1]['processes'] = 1
        self.assertFalse(cases[2]['parse_output'](lines(), 0)['passed'])


if __name__ == '__main__':
    unittest.main()
