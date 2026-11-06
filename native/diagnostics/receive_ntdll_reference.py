"""Receive one explicit public Windows-export packet on the Mac loopback interface."""
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import io
import json
from pathlib import Path
import re
import secrets
import tempfile
import time
from urllib.parse import parse_qs
import zipfile

ROOT = Path(__file__).resolve().parents[2]
EXPECTED_NTDLL = 'a74f7482085eab125ccc09152ab7e0b5994bcb13e1a7b29880bdbb24179ecb8b'
KEYS = {'schema', 'sha256', 'fileVersion', 'machine', 'imageBase', 'sizeOfImage',
        'exportRva', 'exportSize', 'functionCount', 'nameCount', 'ordinalBase',
        'nameArrayRva', 'ordinalArrayRva', 'exports'}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key')
        result[key] = value
    return result


def validate_packet(packet):
    match = re.fullmatch(r'CFXNTDLL1:([0-9a-f]{64}):([A-Za-z0-9+/=]{1,700000})', packet.strip())
    if not match:
        raise ValueError('Unexpected packet format')
    zipped = base64.b64decode(match[2], validate=True)
    if not 64 <= len(zipped) <= 524288 or hashlib.sha256(zipped).hexdigest() != match[1]:
        raise ValueError('Packet checksum or size mismatch')
    with zipfile.ZipFile(io.BytesIO(zipped)) as archive:
        members = archive.infolist()
        if (len(members) != 1 or members[0].filename != 'ntdll-exports.json'
                or members[0].flag_bits & 1 or members[0].file_size > 4194304):
            raise ValueError('Unexpected archive content')
        raw_json = archive.read(members[0])
    data = json.loads(raw_json, object_pairs_hook=unique_object)
    if (not isinstance(data, dict) or set(data) != KEYS
            or data['schema'] != 'windows-ntdll-export-reference-v1'
            or data['machine'] != 'AMD64' or data['sha256'] != EXPECTED_NTDLL):
        raise ValueError('Unexpected metadata identity')
    for key in ('sizeOfImage', 'exportSize', 'functionCount', 'nameCount', 'ordinalBase'):
        if type(data[key]) is not int or not 0 <= data[key] <= 0xffffffff:
            raise ValueError('Invalid numeric metadata')
    if not 1 <= data['nameCount'] <= 8192 or not 1 <= data['functionCount'] <= 65536:
        raise ValueError('Invalid export count')
    for key in ('imageBase', 'exportRva', 'nameArrayRva', 'ordinalArrayRva'):
        limit = 16 if key == 'imageBase' else 8
        if not isinstance(data[key], str) or not re.fullmatch(r'0x[0-9a-f]{1,' + str(limit) + '}', data[key]):
            raise ValueError('Invalid PE address metadata')
    if (not data['sizeOfImage']
            or int(data['exportRva'], 16) + data['exportSize'] > data['sizeOfImage']
            or int(data['nameArrayRva'], 16) + 4 * data['nameCount'] > data['sizeOfImage']
            or int(data['ordinalArrayRva'], 16) + 2 * data['nameCount'] > data['sizeOfImage']):
        raise ValueError('PE table outside image')
    version = data['fileVersion']
    if not isinstance(version, str) or not re.fullmatch(r'[ -~]{1,128}', version):
        raise ValueError('Invalid file version')
    rows = data['exports']
    if not isinstance(rows, list) or len(rows) != data['nameCount']:
        raise ValueError('Invalid export rows')
    names = []
    for row in rows:
        if (not isinstance(row, dict) or set(row) != {'name', 'ordinal', 'rva'}
                or not isinstance(row['name'], str)
                or not re.fullmatch(r'[A-Za-z0-9_?@$]{1,255}', row['name'])
                or type(row['ordinal']) is not int
                or not data['ordinalBase'] <= row['ordinal'] < data['ordinalBase'] + data['functionCount']
                or not isinstance(row['rva'], str) or not re.fullmatch(r'0x[0-9a-f]{1,8}', row['rva'])):
            raise ValueError('Invalid export record')
        if int(row['rva'], 16) >= data['sizeOfImage']:
            raise ValueError('Export outside image')
        names.append(row['name'])
    if len(set(names)) != len(names) or names != sorted(names):
        raise ValueError('Unexpected export name order')
    canonical_json = json.dumps(data, ensure_ascii=True, separators=(',', ':')).encode('ascii')
    canonical_archive = io.BytesIO()
    with zipfile.ZipFile(canonical_archive, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('ntdll-exports.json', canonical_json)
    return match[1], canonical_archive.getvalue(), canonical_json, data


def main():
    token = secrets.token_hex(16)
    output = Path(tempfile.mkdtemp(prefix='windows-ntdll-reference-', dir=ROOT / 'build'))
    route = '/' + token
    accepted = False

    class Receiver(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def response(self, code, text):
            body = text.encode('utf-8')
            self.send_response(code)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Security-Policy', "default-src 'none'; form-action 'self'; base-uri 'none'")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path != route:
                self.response(404, 'Nicht gefunden')
                return
            self.response(200, '<!doctype html><meta charset="utf-8"><title>Lokale Diagnoseübernahme</title>'
                          '<h1>Windows-Exportmetadaten auf diesen Mac übernehmen</h1>'
                          '<form method="post"><label for="packet">Diagnosepaket</label>'
                          '<textarea id="packet" name="packet"></textarea><button>Übernehmen</button></form>')

        def do_POST(self):
            nonlocal accepted
            self.connection.settimeout(10)
            expected_origin = 'http://127.0.0.1:' + str(self.server.server_port)
            if self.path != route or self.headers.get('Origin') != expected_origin:
                self.response(403, 'Nicht freigegeben')
                return
            try:
                length = int(self.headers.get('Content-Length', '-1'))
                if not 1 <= length <= 800000:
                    raise ValueError('Invalid form size')
                fields = parse_qs(self.rfile.read(length).decode('utf-8'), strict_parsing=True)
                if set(fields) != {'packet'} or len(fields['packet']) != 1:
                    raise ValueError('Invalid form')
                received_hash, zipped, raw_json, data = validate_packet(fields['packet'][0])
                for name, content in [('reference.zip', zipped), ('ntdll-exports.json', raw_json)]:
                    with (output / name).open('xb') as stream:
                        stream.write(content)
                receipt = {'source': 'user-executed Windows System32 collector; clipboard to owned Mac loopback',
                           'received_zip_sha256': received_hash,
                           'canonical_zip_sha256': hashlib.sha256(zipped).hexdigest(),
                           'json_sha256': hashlib.sha256(raw_json).hexdigest(),
                           'ntdll_sha256': data['sha256'], 'name_count': data['nameCount'],
                           'binary_dll_received': False,
                           'metadata_provenance': 'user-collected; declared DLL hash matched visible Windows output, not independent binary attestation',
                           'raw_packet_or_unvalidated_archive_saved': False}
                (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
                accepted = True
                print(json.dumps({'received': str(output.relative_to(ROOT)), **receipt}), flush=True)
                self.response(200, '<!doctype html><title>Übernommen</title><h1>Übernommen und geprüft</h1>')
            except (ValueError, KeyError, UnicodeError, zipfile.BadZipFile):
                self.response(400, 'Paketprüfung fehlgeschlagen; nichts übernommen.')

    server = HTTPServer(('127.0.0.1', 0), Receiver)
    server.timeout = 1
    print(json.dumps({'local_url': 'http://127.0.0.1:' + str(server.server_port) + route,
                      'output': str(output.relative_to(ROOT))}), flush=True)
    expires = time.monotonic() + 900
    try:
        while not accepted and time.monotonic() < expires:
            server.handle_request()
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
