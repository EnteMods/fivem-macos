"""Offline helper/identity tests; no client, prefix or real stage is executed."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT/'build/source-update-candidate-nqwlz36g/resume-candidate.py'
spec = importlib.util.spec_from_file_location('component_integration_resume', HELPER)
resume = importlib.util.module_from_spec(spec)
spec.loader.exec_module(resume)
identity = resume.identity


def marker(seq=1, event=1, component=1, ordinal=0, call=0, value=1):
    return (f'[CFX_COMPONENT_INIT] seq={seq} event={event} pid=12 tid=16 '
            f'component={component} ordinal={ordinal} call={call} value={value}\n')


class StreamTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.reader = resume.component_reader()

    def tearDown(self):
        self.temp.cleanup()

    def collect(self, text):
        phase = self.root/'phase'
        output = self.root/'component'
        counters = resume.component_counters()
        resume.phase_log(io.StringIO(text), phase, resume.exclusive_component_output(output), self.reader, counters)
        return phase.read_text(), output.read_text(), counters

    def test_existing_phase_and_numeric_component(self):
        phase, output, counters = self.collect(
            '[CFX_SOURCE_PHASE] pid=12 tid=16 phase=citigame.pre-load.enter value=1\n'
            + marker() + 'arbitrary external text\n')
        self.assertEqual(json.loads(phase), {'pid':12,'tid':16,'phase':'citigame.pre-load.enter','value':1})
        self.assertEqual(set(json.loads(output)), set(self.reader.KEYS))
        self.assertEqual(counters['accepted_rows'], 1)
        self.assertTrue(counters['collection_complete'])

    def test_false_return_remains_numeric_false(self):
        _, output, _ = self.collect(marker(2,2,1,1,2,1)+marker(3,3,1,1,2,0))
        rows = [json.loads(x) for x in output.splitlines()]
        self.assertEqual(rows[-1]['value'],0)
        self.assertEqual(self.reader.summarize(rows)['processes'][0]['calls'][0]['return_value'],False)

    def test_malformed_secret_is_counted_without_raw_output(self):
        phase, output, counters = self.collect(marker().rstrip()+' RAW_SECRET\n'+
            '[CFX_COMPONENT_INIT] seq=RAW_SECRET\n')
        self.assertEqual((phase,output),('',''))
        self.assertEqual(counters['malformed_marker_rows'],2)
        self.assertNotIn('RAW_SECRET',json.dumps(counters))

    def test_oversized_and_duplicate_markers_rejected(self):
        _, output, counters = self.collect(marker().rstrip()+'x'*5000+'\n'+marker().rstrip()+marker())
        self.assertEqual(output,'')
        self.assertEqual(counters['malformed_marker_rows'],2)

    def test_opt_out_does_not_create_component_log(self):
        phase = self.root/'phase'
        resume.phase_log(io.StringIO(marker()+'[CFX_SOURCE_PHASE] pid=1 tid=2 phase=ready value=1\n'),phase)
        self.assertEqual(json.loads(phase.read_text())['phase'],'ready')
        self.assertFalse((self.root/'component').exists())

    def test_no_clobber_existing_or_symlink(self):
        output = self.root/'component';output.write_text('keep')
        with self.assertRaises(FileExistsError):resume.exclusive_component_output(output)
        self.assertEqual(output.read_text(),'keep')
        output.unlink();output.symlink_to(self.root/'missing')
        with self.assertRaises(FileExistsError):resume.exclusive_component_output(output)
        self.assertFalse((self.root/'missing').exists())

    def test_row_budget_counts_drops(self):
        with patch.object(resume,'COMPONENT_ROW_LIMIT',2):
            _, output, counters = self.collect(marker()+marker(2,2,1,1,2,1)+marker(3,3,1,1,2,1))
        self.assertEqual(len(output.splitlines()),2)
        self.assertEqual(counters['dropped_marker_rows'],1)

    def test_stream_error_is_incomplete_without_raw_error(self):
        class Broken(io.StringIO):
            def __next__(self):raise OSError('RAW_SECRET')
        output = self.root/'component';counters = resume.component_counters()
        resume.phase_log(Broken(),self.root/'phase',resume.exclusive_component_output(output),self.reader,counters)
        self.assertTrue(counters['collector_failed'])
        self.assertFalse(counters['collection_complete'])
        self.assertNotIn('RAW_SECRET',output.read_text()+json.dumps(counters))

    def test_write_error_is_incomplete_and_phase_still_drains(self):
        class Broken(io.StringIO):
            def write(self, value):raise OSError('RAW_SECRET')
        counters = resume.component_counters()
        resume.phase_log(io.StringIO(marker()+'[CFX_SOURCE_PHASE] pid=1 tid=2 phase=after value=1\n'),
                         self.root/'phase',Broken(),self.reader,counters)
        self.assertTrue(counters['collector_failed'])
        self.assertFalse(counters['collection_complete'])
        self.assertEqual(json.loads((self.root/'phase').read_text())['phase'],'after')

    def test_worker_alive_cannot_be_complete(self):
        counters = resume.component_counters();counters['collection_complete']=True
        record = {'component_init_trace':{}}
        resume.finish_component_collection(record,counters,types.SimpleNamespace(is_alive=lambda:True))
        self.assertFalse(record['component_init_trace']['counters']['collection_complete'])
        self.assertFalse(record['component_init_trace']['worker_stopped'])
        counters['accepted_rows']=12
        self.assertEqual(record['component_init_trace']['counters']['accepted_rows'],0)


class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory();self.root=Path(self.temp.name).resolve()
        self.stage=self.root/'stage';self.stage.mkdir()
        self.expected={'CitizenGame.dll':identity.BASE_CITIZEN_GAME,'CoreRT.dll':identity.ORIGINAL_CORE,
                       'nui-core.dll':identity.ORIGINAL_NUI,'net.dll':identity.ORIGINAL_NET}
        self.expected.update({f'own-{i}.dll':f'hash-{i}' for i in range(418)})
        self.actual=dict(self.expected)
        self.game=types.SimpleNamespace(ROOT=self.root,STAGE=self.stage,first=types.SimpleNamespace(
            expected_files=lambda marker:dict(self.expected),digest=lambda path:self.actual[path.name]))

    def tearDown(self):self.temp.cleanup()

    def verified(self):
        return {'status':'verified','selection':'diagnostic'}

    def test_default_baseline_all_422_checked(self):
        self.assertEqual(identity.verify_stage(self.game),422)
        self.actual['own-417.dll']='changed'
        with self.assertRaises(RuntimeError):identity.verify_stage(self.game)

    def test_diagnostic_requires_receipt_and_flag(self):
        self.actual['CitizenGame.dll']=identity.TRACE_CITIZEN_GAME
        with self.assertRaises(RuntimeError):identity.verify_stage(self.game,component_init_trace=True)
        with patch.object(identity,'component_init_state',return_value=self.verified()):
            with self.assertRaises(RuntimeError):identity.verify_stage(self.game)
            self.assertEqual(identity.verify_stage(self.game,component_init_trace=True),422)
            self.actual['own-417.dll']='changed'
            with self.assertRaises(RuntimeError):identity.verify_stage(self.game,component_init_trace=True)

    def test_prepared_refuses_both_modes(self):
        with patch.object(identity,'component_init_state',side_effect=RuntimeError('prepared')):
            for flag in (False,True):
                with self.assertRaises(RuntimeError):identity.verify_stage(self.game,component_init_trace=flag)

    def test_restored_baseline_and_no_optin(self):
        with patch.object(identity,'component_init_state',return_value={'status':'restored','selection':'baseline'}):
            self.assertEqual(identity.verify_stage(self.game),422)
            with self.assertRaises(RuntimeError):identity.verify_stage(self.game,component_init_trace=True)

    def test_count_and_pinned_baseline_not_loosened(self):
        self.expected.pop('own-417.dll')
        with self.assertRaises(RuntimeError):identity.verify_stage(self.game)
        self.expected['own-417.dll']='hash-417';self.expected['CitizenGame.dll']='unapproved'
        with self.assertRaises(RuntimeError):identity.verify_stage(self.game)

    def test_only_bool_optin(self):
        for flag in (1,'1',None):
            with self.assertRaises(RuntimeError):identity.verify_stage(self.game,component_init_trace=flag)

    def test_real_verifier_pin_cannot_be_substituted(self):
        receipt=self.root/identity.COMPONENT_TRANSACTION;receipt.parent.mkdir();receipt.write_text('{}')
        verifier=self.root/identity.COMPONENT_VERIFIER;verifier.parent.mkdir(parents=True);verifier.write_text('raise AssertionError("must not execute")')
        with self.assertRaises(RuntimeError):identity.component_init_state(self.game)

    def test_real_verified_receipt_without_artifact_proof_refuses(self):
        receipt=self.root/identity.COMPONENT_TRANSACTION;receipt.parent.mkdir();receipt.write_text('{}')
        verifier=self.root/identity.COMPONENT_VERIFIER;verifier.parent.mkdir(parents=True)
        verifier.write_bytes((ROOT/identity.COMPONENT_VERIFIER).read_bytes())
        with self.assertRaises((RuntimeError,FileNotFoundError)):identity.component_init_state(self.game)


class OptionTests(unittest.TestCase):
    def test_flags_mutually_exclusive_and_default_off(self):
        args=resume.parse_args([])
        self.assertFalse(args.trace_component_init)
        with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):
            resume.parse_args(['--trace-auth-event','--trace-component-init'])
        args=resume.parse_args(['--dxmt-resource-usage','--trace-component-init'])
        self.assertTrue(args.dxmt_resource_usage and args.trace_component_init)

    def test_env_removed_off_exact_one_on(self):
        env={'CFX_COMPONENT_INIT_TRACE':'inherited','other':'same'}
        resume.configure_component_environment(env,False);self.assertEqual(env,{'other':'same'})
        resume.configure_component_environment(env,True);self.assertEqual(env,{'other':'same','CFX_COMPONENT_INIT_TRACE':'1'})

    def test_optin_checks_p9_nui_original_net_and_3889(self):
        args=resume.parse_args(['--trace-component-init']);state={'status':'verified','selection':'diagnostic'}
        actual={'CoreRT.dll':identity.FIXED_CORE,'nui-core.dll':identity.SOFTWARE_NUI,
                'net.dll':identity.ORIGINAL_NET,'CitizenGame.dll':identity.TRACE_CITIZEN_GAME}
        game=types.SimpleNamespace(STAGE=Path('/own-fixture'),first=types.SimpleNamespace(digest=lambda path:actual[path.name]))
        with patch.object(resume,'game',game):
            resume.check_component_launch(args,422,state)
            for name in tuple(actual):
                old=actual[name];actual[name]='wrong'
                with self.assertRaises(RuntimeError):resume.check_component_launch(args,422,state)
                actual[name]=old
            args.game_build=3258
            with self.assertRaises(RuntimeError):resume.check_component_launch(args,422,state)
            args.game_build=3889
            with self.assertRaises(RuntimeError):resume.check_component_launch(args,421,state)


if __name__=='__main__':unittest.main()
