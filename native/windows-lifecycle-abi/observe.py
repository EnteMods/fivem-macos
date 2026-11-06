"""Add a bounded stderr observer to the unchanged, pinned diagnostic launcher."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / 'build/source-update-candidate-nqwlz36g/resume-candidate.py'
HELPER_SHA = '7ebcacf4029947eff1868c8f6485c9975bbe434d12be4880f850b271be89efe0'
IDENTITY = HELPER.with_name('candidate_identity.py')
IDENTITY_SHA = '8999d7526233b6f3698baa100935cf8eb82067c9b8a460675f9eae0480bfa0ac'
READER = ROOT / 'native/diagnostics/read_lifecycle_trace.py'
READER_SHA = 'd6ff87120b7656cf25ec183a39d96fa980dc7e21384191236bba5b802879e1be'
LIMIT = 512
VENDOR_MANIFEST = ROOT / 'build/rockstar-vendor-admission-0bogf2cm/vendor-code-manifest.json'
VENDOR_MANIFEST_SHA = '6cf2e59f34b427e72f144d1a9db2026a1f2863440d56c211175684e4713b03e1'
VENDOR_REVIEW = ROOT / 'research/rockstar-vendor-generation-review-20261105.json'
VENDOR_REVIEW_SHA = '9ae2b10eab694ef8391be76d07a8c2223d837f84dfc75bf4d2da0d9eae7648dc'


def checked_json(path, expected):
    if path.resolve(strict=True) != path or not path.is_file() or path.stat().st_nlink != 1:
        raise RuntimeError('Vendor generation input is redirected')
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise RuntimeError('Vendor generation input changed')
    return json.loads(data)


def configure_vendor_generation(helper):
    manifest = checked_json(VENDOR_MANIFEST, VENDOR_MANIFEST_SHA)
    review = checked_json(VENDOR_REVIEW, VENDOR_REVIEW_SHA)
    previous = checked_json(helper.reuse.MANIFEST, helper.reuse.MANIFEST_SHA)
    prefix = helper.game.PREFIX
    relative = str(prefix.relative_to(ROOT))
    binding = manifest.get('prefix_binding')
    if (binding != dict(prefix=relative, device=prefix.stat().st_dev, inode=prefix.stat().st_ino)
            or review.get('prefix') != relative
            or manifest.get('source_evidence') != dict(path=str(VENDOR_REVIEW.relative_to(ROOT)), sha256=VENDOR_REVIEW_SHA)
            or manifest.get('roots') != previous.get('roots')
            or manifest.get('excluded_account_profiles_registry_sessions') is not True
            or manifest.get('previous_manifest', {}).get('sha256') != helper.reuse.MANIFEST_SHA
            or len(manifest.get('files', [])) != 145
            or {x['path'] for x in manifest['files']} != {x['path'] for x in previous['files']}):
        raise RuntimeError('Vendor generation scope differs')
    helper.reuse.MANIFEST = VENDOR_MANIFEST
    helper.reuse.MANIFEST_SHA = VENDOR_MANIFEST_SHA
    helper.reuse.verify(prefix, helper.reuse.inventory())
    return dict(manifest=str(VENDOR_MANIFEST.relative_to(ROOT)), manifest_sha256=VENDOR_MANIFEST_SHA,
                review=str(VENDOR_REVIEW.relative_to(ROOT)), review_sha256=VENDOR_REVIEW_SHA,
                verified_program_files=145)


def load_pinned(path, expected, name):
    if path.resolve(strict=True) != path or not path.is_file() or path.stat().st_nlink != 1:
        raise RuntimeError('Observer input is redirected')
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise RuntimeError('Observer input changed')
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(data, str(path), 'exec'), module.__dict__)
    return module


class LifecycleStream:
    def __init__(self, stream, directory, reader):
        self.stream, self.directory, self.reader = stream, directory, reader
        descriptor = os.open(directory / 'lifecycle-callbacks.ndjson',
                             os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        self.output = os.fdopen(descriptor, 'w', encoding='ascii')
        self.eof = False
        self.status = dict(accepted_rows=0, unselected_or_invalid_marker_rows=0,
                           dropped_rows=0, collector_failed=False, collection_complete=False)

    def __enter__(self):
        return self

    def __iter__(self):
        return self

    def __next__(self):
        try:
            line = next(self.stream)
        except StopIteration:
            self.eof = True
            raise
        encoded = line.encode('utf-8', errors='replace')
        if self.reader.MARKER in encoded and not self.status['collector_failed']:
            record = self.reader.parse_debug_line(encoded)
            if record is None:
                self.status['unselected_or_invalid_marker_rows'] += 1
            elif self.status['accepted_rows'] >= LIMIT:
                self.status['dropped_rows'] += 1
            else:
                try:
                    self.output.write(json.dumps(record) + '\n')
                    self.output.flush()
                    self.status['accepted_rows'] += 1
                except Exception:
                    self.status['collector_failed'] = True
        return line

    def __exit__(self, error_type, error, traceback):
        try:
            self.stream.close()
        finally:
            try:
                self.output.close()
            except Exception:
                self.status['collector_failed'] = True
        self.status['collection_complete'] = (self.eof and error_type is None
            and not self.status['collector_failed'] and not self.status['dropped_rows'])
        with (self.directory / 'lifecycle-collector.json').open('x') as output:
            json.dump(self.status, output, indent=2)
            output.write('\n')
        return False


def interpose(original, reader, vendor_binding=None):
    def collect(stream, output, component_target=None, component_reader=None, counters=None):
        try:
            if vendor_binding is not None:
                with (output.parent / 'vendor-generation.json').open('x') as target:
                    json.dump(vendor_binding, target, indent=2)
                    target.write('\n')
            wrapped = LifecycleStream(stream, output.parent, reader)
        except OSError:
            if counters is not None:
                counters['collector_failed'] = True
            return original(stream, output, component_target, component_reader, counters)
        return original(wrapped, output, component_target, component_reader, counters)
    return collect


def main():
    if len(sys.argv) != 1:
        raise RuntimeError('This observer uses only the fixed diagnostic configuration')
    load_pinned(IDENTITY, IDENTITY_SHA, 'lifecycle_checked_identity')
    reader = load_pinned(READER, READER_SHA, 'lifecycle_fixed_reader')
    helper = load_pinned(HELPER, HELPER_SHA, 'lifecycle_checked_launcher')
    binding = configure_vendor_generation(helper)
    helper.phase_log = interpose(helper.phase_log, reader, binding)
    sys.argv = [str(HELPER), '--dxmt-resource-usage', '--trace-component-init']
    return helper.main()


if __name__ == '__main__':
    raise SystemExit(main())
