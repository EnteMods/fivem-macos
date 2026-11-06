"""Pin the original MAIN/TLS/update checks around exact compiler adaptations."""
import hashlib
import json
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'port/fivem'
CONFIG = json.loads((ROOT / 'config/native-port.json').read_text())
BASE = CONFIG['base_revision']


class MainVendorScopeTests(unittest.TestCase):
    def assert_reviewed_file(self, relative, replacements=()):
        before = subprocess.check_output(['git', 'show', BASE + ':' + relative], cwd=SOURCE)
        for old, new in replacements:
            self.assertEqual(before.count(old), 1, 'Reviewed compiler change no longer matches the pinned source')
            before = before.replace(old, new, 1)
        after = (SOURCE / relative).read_bytes()
        self.assertEqual(hashlib.sha256(before).hexdigest(), hashlib.sha256(after).hexdigest(), relative)

    def test_main_download_tls_source_stays_original(self):
        self.assert_reviewed_file('code/client/launcher/Download.cpp')

    def test_game_hashes_and_updater_checks_only_allow_reviewed_type_fixes(self):
        self.assert_reviewed_file('code/client/launcher/GameCache.cpp', ((
            b'template<int Size>\r\nstatic std::string FormatHexString(',
            b'template<size_t Size>\r\nstatic std::string FormatHexString('),))
        self.assert_reviewed_file('code/client/launcher/Updater.cpp', ((
            b'cache_ptr& localCache = localCacheFile.GetCache(cache->name);',
            b'cache_ptr localCache = localCacheFile.GetCache(cache->name);'),))

    def test_curl_preserves_pinned_tls_source_and_only_reserved_root_store_argument(self):
        revision = CONFIG['submodule_pins']['vendor/curl']
        original = subprocess.check_output(['git', 'show', revision + ':lib/vtls/openssl.c'],
                                           cwd=SOURCE / 'vendor/curl')
        self.assertEqual(original, (SOURCE / 'vendor/curl/lib/vtls/openssl.c').read_bytes())
        old = b'void* hStore = CertOpenSystemStoreA(NULL, "ROOT");'
        new = b'void* hStore = CertOpenSystemStoreA(0, "ROOT");'
        self.assertEqual(original.count(old), 1)
        overlay = ROOT / 'build/windows-client-vendor/main-vendor-generated/curl/openssl.c'
        if not overlay.exists():
            self.skipTest('Build-only curl overlay is generated locally and excluded from Git.')
        self.assertEqual(original.replace(old, new, 1), overlay.read_bytes())


if __name__ == '__main__':
    unittest.main()
