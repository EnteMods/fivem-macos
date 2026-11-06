from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'native/windows-client'))
import check_steam_oauth_abi as abi


DLL_HEADER = 'Machine: IMAGE_FILE_MACHINE_AMD64 (0x8664)\n  IMAGE_FILE_DLL (0x2000)\n'


def inspection(symbols):
    return DLL_HEADER + ''.join(f'Export {{\n  Ordinal: {n}\n  Name: {symbol}\n  RVA: 0x10\n}}\n'
                                for n, symbol in enumerate(symbols, 1))


class SteamOauthAbiTests(unittest.TestCase):
    def test_requires_every_exact_msvc_symbol(self):
        for library, exports in abi.REQUIRED.items():
            with self.subTest(library=library):
                self.assertEqual(abi.missing_exports(library, inspection(exports.values())), [])
                names = list(exports)
                symbols = list(exports.values())
                self.assertEqual(abi.missing_exports(library, inspection([*symbols[:-1], symbols[-1] + 'X'])),
                                 [names[-1]])

    def test_rejects_wrong_machine_and_non_dll(self):
        for wrong in (DLL_HEADER.replace('AMD64', 'I386'), DLL_HEADER.replace('IMAGE_FILE_DLL', 'EXE')):
            with self.assertRaisesRegex(ValueError, 'Windows x64 DLL'):
                abi.missing_exports('legitimacy.dll', wrong)

    def test_import_must_name_the_expected_provider(self):
        symbol = abi.REQUIRED['legitimacy.dll']['RefreshIdentities']
        raw = DLL_HEADER + f'Import {{\n  Name: LEGITIMACY.DLL\n  Symbol: {symbol} (0)\n}}\n'
        self.assertEqual(abi.missing_imports('glue.dll', raw), {'legitimacy.dll': []})
        self.assertEqual(abi.missing_imports('glue.dll', raw.replace('LEGITIMACY.DLL', 'other.dll')),
                         {'legitimacy.dll': ['RefreshIdentities']})
