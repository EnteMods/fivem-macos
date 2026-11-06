"""Pure source transforms only; no compiler, Wine, client, prefix or network action."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('own_numeric_wininet_overlay',
                                              ROOT/'native/wine-numeric-diagnostics/wininet_overlay.py')
overlay = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(overlay)


class WininetOverlayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.originals = {name:(ROOT/'build/wine-job-query/source'/name).read_bytes() for name in overlay.PINS}

    def test_exact_five_functions_ten_typed_returns_and_two_includes(self):
        patched, proof = overlay.apply_all(self.originals)
        self.assertEqual(set(patched),set(self.originals))
        self.assertEqual(proof['entry_count'],5)
        self.assertEqual(proof['original_return_count'],10)
        self.assertFalse(proof['header_implemented_or_validated_here'])
        functions = [item for record in proof['files'] for item in record['functions']]
        self.assertEqual({item['api_base'] for item in functions},{20,21,22,23,24})
        self.assertEqual({item['function'] for item in functions},
                         {'InternetOpenW','InternetGetConnectedState','InternetGetConnectedStateExW',
                          'HttpSendRequestW','HttpQueryInfoW'})
        combined = b''.join(patched.values())
        self.assertEqual(combined.count(overlay.HEADER),2)
        self.assertEqual(combined.count(b'CFX_NUMERIC_ENTER('),5)
        self.assertEqual(combined.count(b'CFX_NUMERIC_HANDLE_NULL_RETURN('),3)
        self.assertEqual(combined.count(b'CFX_NUMERIC_BOOL_RETURN('),7)

    def test_roundtrip_and_proof_are_deterministic_without_input_mutation(self):
        before = dict(self.originals)
        first = overlay.apply_all(self.originals)
        second = overlay.apply_all(dict(reversed(list(self.originals.items()))))
        self.assertEqual(first,second)
        self.assertEqual(self.originals,before)
        json.dumps(first[1])
        for name,data in first[0].items():
            self.assertEqual(overlay.strip(name,data),before[name])

    def test_scope_proof_replays_and_reverses_every_edit_without_unknown_changes(self):
        patched, proof = overlay.apply_all(self.originals)
        for record in proof['files']:
            name = record['relative_source_path']
            original = self.originals[name]
            current = patched[name]
            self.assertEqual(record['original'],{'bytes':len(original),'sha256':hashlib.sha256(original).hexdigest()})
            self.assertEqual(record['patched'],{'bytes':len(current),'sha256':hashlib.sha256(current).hexdigest()})
            for edit in reversed(record['edits']):
                offset = edit['patched_offset']
                replacement = edit['replacement'].encode('ascii')
                self.assertEqual(current[offset:offset+len(replacement)],replacement)
                current=current[:offset]+edit['original'].encode('ascii')+current[offset+len(replacement):]
            self.assertEqual(current,original)

    def test_entries_follow_exact_declarations_and_returns_keep_original_expression_once(self):
        _, proof = overlay.apply_all(self.originals)
        for record in proof['files']:
            source = self.originals[record['relative_source_path']]
            scopes = {item['function']:item for item in record['functions']}
            for edit in record['edits']:
                if edit['kind']=='include':
                    self.assertIsNone(edit['function'])
                    self.assertEqual(edit['replacement'].encode(),overlay.HEADER)
                    continue
                scope = scopes[edit['function']]
                self.assertGreater(edit['offset'],scope['original_begin_offset'])
                self.assertLess(edit['offset'],scope['original_end_offset'])
                if edit['kind']=='entry':
                    self.assertEqual(edit['offset'],scope['entry_offset_after_declarations'])
                    self.assertEqual(edit['original'],'')
                else:
                    self.assertEqual(edit['kind'],'return')
                    expression = edit['original'].removeprefix('return ').removesuffix(';')
                    macro = 'CFX_NUMERIC_'+scope['return_class']+'_RETURN'
                    self.assertEqual(edit['replacement'],
                                     'return '+macro+'('+scope['api_base_symbol']+', 0, '+expression+');')
                    self.assertEqual(source[edit['offset']:edit['offset']+len(edit['original'])].decode(),
                                     edit['original'])

    def test_foreign_missing_nonbytes_and_changed_source_inputs_are_refused(self):
        cases = [None,{},dict(self.originals,**{'../private':b'not read'})]
        missing = dict(self.originals)
        missing.pop(next(iter(missing)))
        cases.append(missing)
        changed = dict(self.originals)
        name = next(iter(changed))
        changed[name] = b'changed'
        cases.append(changed)
        not_bytes = dict(self.originals)
        not_bytes[name] = bytearray(not_bytes[name])
        cases.append(not_bytes)
        for case in cases:
            with self.assertRaises(ValueError): overlay.apply_all(case)

    def test_already_instrumented_input_and_wrong_strip_scope_are_refused(self):
        patched,_ = overlay.apply_all(self.originals)
        with self.assertRaises(ValueError): overlay.apply_all(patched)
        with self.assertRaises(ValueError): overlay.strip('../unknown',next(iter(patched.values())))
        for name,original in self.originals.items():
            with self.assertRaises(ValueError): overlay.strip(name,original)

    def test_unrelated_body_changes_wrong_macro_and_wrong_expression_fail_strip(self):
        patched,_ = overlay.apply_all(self.originals)
        name='dlls/wininet/internet.c'
        data=patched[name]
        for modified in (data.replace(b'INTERNET_SetLastError(0);',b'INTERNET_SetLastError(1);',1),
                         data.replace(b'CFX_NUM_INTERNET_OPEN_W, 0, NULL',b'CFX_NUM_INTERNET_OPEN_W, 1, NULL',1),
                         data.replace(b'CFX_NUMERIC_HANDLE_NULL_RETURN',b'CFX_NUMERIC_BOOL_RETURN',1),
                         data.replace(b'0, lpwai->hdr.hInternet',b'0, NULL',1)):
            with self.assertRaises(ValueError): overlay.strip(name,modified)

    def test_relocated_entry_that_strips_to_original_is_still_noncanonical(self):
        patched,_ = overlay.apply_all(self.originals)
        name='dlls/wininet/internet.c'
        entry=overlay._entry('CFX_NUM_INTERNET_OPEN_W')
        moved=patched[name].replace(entry,b'',1)+entry
        with self.assertRaisesRegex(ValueError,'Noncanonical'):
            overlay.strip(name,moved)

    def test_false_error_zero_and_existing_cleanup_statements_remain_byte_identical_after_strip(self):
        patched,_ = overlay.apply_all(self.originals)
        for name,data in patched.items():
            restored=overlay.strip(name,data)
            self.assertEqual(restored,self.originals[name])
        internet=patched['dlls/wininet/internet.c']
        self.assertIn(b'SetLastError(ERROR_SUCCESS);\n        return CFX_NUMERIC_BOOL_RETURN('
                      b'CFX_NUM_INTERNET_GET_CONNECTED_STATE_EX_W, 0, FALSE);',internet)
        http=patched['dlls/wininet/http.c']
        self.assertIn(b'SetLastError(res);\n    return CFX_NUMERIC_BOOL_RETURN('
                      b'CFX_NUM_HTTP_SEND_REQUEST_W, 0, res == ERROR_SUCCESS);',http)
        self.assertIn(b'SetLastError(res);\n    return CFX_NUMERIC_BOOL_RETURN('
                      b'CFX_NUM_HTTP_QUERY_INFO_W, 0, res == ERROR_SUCCESS);',http)

    def test_new_edits_contain_only_agreed_header_entry_and_return_macros(self):
        _,proof=overlay.apply_all(self.originals)
        edits=[edit for record in proof['files'] for edit in record['edits']]
        self.assertEqual(len(edits),17)
        self.assertEqual({edit['kind'] for edit in edits},{'include','entry','return'})
        for edit in edits:
            self.assertNotIn('GetLastError(',edit['replacement'])
            self.assertNotIn('InternetGetLastResponseInfo',edit['replacement'])
            self.assertNotIn('printf',edit['replacement'])
            self.assertNotIn('TRACE(',edit['replacement'])
            self.assertNotIn('HttpOpenRequestW',edit['replacement'])
        self.assertEqual(sum(edit['kind']=='entry' for edit in edits),5)
        self.assertEqual(sum(edit['kind']=='return' for edit in edits),10)


if __name__=='__main__':
    unittest.main()
