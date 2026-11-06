import csv
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location('reducer', Path(__file__).with_name('reduce_procmon.py'))
reducer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reducer)


def capture(rows, header=None):
    stream = io.StringIO(newline='')
    writer = csv.writer(stream)
    writer.writerow(reducer.HEADER if header is None else header)
    writer.writerows(rows)
    return stream.getvalue()


def event(operation='TCP Connect', path='private-host:61000 -> 192.0.2.10:443',
          detail='PRIVATE_TOKEN=do-not-export', process='FiveM_b3889_GTAProcess.exe',
          result='SUCCESS', timestamp='14:29:30.1234567', pid='2008'):
    return [timestamp, process, pid, operation, path, result, detail]


class ReductionTests(unittest.TestCase):
    def test_streamed_counts_and_private_fields(self):
        text = capture([
            event(), event(),
            event('Load Image', r'C:\Users\SECRET_USERNAME\net.dll'),
            event('RegSetValue', r'HKCU\PRIVATE_ACCOUNT', 'SECRET_PASSWORD'),
            event('ReadFile', r'C:\FiveM Application Data\data\game-storage\PRIVATE_FILE'),
        ])
        report = reducer.reduce_rows(io.StringIO(text))
        self.assertEqual(report['coverage']['total_rows'], 5)
        self.assertEqual(report['network'][0]['count'], 2)
        self.assertEqual(report['network'][0]['endpoint_b_port'], 443)
        self.assertEqual(report['selected_modules'][0]['module'], 'net.dll')
        rendered = json.dumps(report)
        for secret in ('PRIVATE_TOKEN', 'PRIVATE_ACCOUNT', 'SECRET_PASSWORD', 'SECRET_USERNAME',
                       'PRIVATE_FILE', 'private-host', '192.0.2.10'):
            self.assertNotIn(secret, rendered)
        self.assertNotIn('remote_port', rendered)

    def test_quoted_multiline_and_comma_are_one_row(self):
        report = reducer.reduce_rows(io.StringIO(capture([
            event(detail='private, value\nsecond line'), event('TCP Send'),
        ])))
        self.assertEqual(report['coverage']['total_rows'], 2)
        self.assertEqual(report['coverage']['selected_process_rows'], 2)

    def test_exact_header_and_duplicates(self):
        for header in (reducer.HEADER[:-1], reducer.HEADER + ['Detail'], ['SECRET_HEADER']):
            with self.assertRaises(reducer.InvalidCapture):
                reducer.reduce_rows(io.StringIO(capture([], header)))

    def test_bom_and_single_pass_hash_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.csv'
            raw = b'\xef\xbb\xbf' + capture([event()]).encode()
            path.write_bytes(raw)
            report = reducer.reduce_file(path)
            self.assertEqual(report['input_identity'], {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})

    def test_oversize_field_and_broken_quoted_row(self):
        with self.assertRaises(csv.Error):
            reducer.reduce_rows(io.StringIO(capture([event(detail='x' * (reducer.MAX_FIELD + 1))])))
        with self.assertRaises(csv.Error):
            reducer.reduce_rows(io.StringIO(capture([]) + '"unterminated'))

    def test_schema_row_and_group_limits(self):
        with self.assertRaises(reducer.InvalidCapture):
            reducer.reduce_rows(io.StringIO(capture([event() + ['extra']])))
        with patch.object(reducer, 'MAX_ROWS', 1):
            with self.assertRaises(reducer.InvalidCapture):
                reducer.reduce_rows(io.StringIO(capture([event(), event()])))
        with patch.object(reducer, 'MAX_GROUPS', 1):
            with self.assertRaises(reducer.InvalidCapture):
                reducer.reduce_rows(io.StringIO(capture([event(), event(pid='2009')])))

    def test_unselected_or_empty_input_cannot_look_successful(self):
        for rows in ([], [event(process='SECRET_ACCOUNT.exe')]):
            with self.assertRaises(reducer.InvalidCapture):
                reducer.reduce_rows(io.StringIO(capture(rows)))

    def test_unknown_metadata_is_counted_without_echo(self):
        report = reducer.reduce_rows(io.StringIO(capture([
            event(), event(operation='SECRET_OPERATION'), event(result='SECRET_RESULT'),
        ])))
        self.assertEqual(report['coverage']['unknown_operation_rows'], 1)
        self.assertEqual(report['coverage']['unknown_result_rows'], 1)
        self.assertNotIn('SECRET_', json.dumps(report))

    def test_port_and_domain_classification_are_not_issuer_claims(self):
        self.assertEqual(reducer.endpoint('[2001:4860:4860::8888]:443'), (443, 'IPV6_PUBLIC'))
        self.assertEqual(reducer.endpoint('runtime.fivem.net:https'), (443, 'CFX_DOMAIN'))
        self.assertEqual(reducer.endpoint('fivem.net.attacker.invalid:443'), (443, 'UNCLASSIFIED'))
        self.assertEqual(reducer.endpoint('private-host:99999'), (None, 'UNCLASSIFIED'))
        report = reducer.reduce_rows(io.StringIO(capture([event('TCP Receive')])))
        self.assertTrue(any('neither' in value for value in report['limits']))

    def test_midnight_and_twelve_hour_clocks_keep_file_order(self):
        report = reducer.reduce_rows(io.StringIO(capture([
            event(timestamp='11:59:59.9 PM'), event(timestamp='12:00:00 AM'),
        ])))
        self.assertEqual(report['capture_first_time'], '23:59:59.900000000')
        self.assertEqual(report['capture_last_time'], '00:00:00.000000000')
        self.assertIsNone(reducer.checked_time('25:00:00'))

    def test_lifecycle_retains_only_numeric_parent_and_child(self):
        report = reducer.reduce_rows(io.StringIO(capture([
            event('Process Start', detail='Parent PID: 5720, Command line: SECRET'),
            event('Process Create', detail='PID: 3000, Command line: SECRET'),
        ])))
        self.assertEqual(report['process_lifecycle'][0]['parent_pid'], 5720)
        self.assertEqual(report['process_lifecycle'][1]['child_pid'], 3000)
        self.assertNotIn('SECRET', json.dumps(report))

    def test_input_symlink_and_output_clobber_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'source.csv'
            source.write_text(capture([event()]))
            link = Path(directory) / 'link.csv'
            link.symlink_to(source)
            with self.assertRaises(OSError):
                reducer.reduce_file(link)
            output = Path(directory) / 'report.json'
            output.write_text('sentinel')
            result = subprocess.run([sys.executable, '-B', str(Path(reducer.__file__)),
                                     '--input', str(source), '--output', str(output)], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(output.read_text(), 'sentinel')

    def test_cli_never_prints_rejected_input_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'source.csv'
            source.write_text(capture([event()], ['PRIVATE_HEADER']))
            result = subprocess.run([sys.executable, '-B', str(Path(reducer.__file__)),
                                     '--input', str(source), '--output', str(Path(directory) / 'report.json')],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn('PRIVATE_HEADER', result.stdout + result.stderr)
            self.assertEqual(json.loads(result.stdout)['status'], 'FAILED')


if __name__ == '__main__':
    unittest.main()
