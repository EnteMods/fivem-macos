"""Temporary owned inventories and mocks only; never run Wine or access a real prefix."""
from contextlib import ExitStack
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import tempfile
import unittest
from unittest import mock

PROJECT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location('own_numeric_environment_test',
                                          PROJECT/'native/wine-numeric-diagnostics/environment.py')
runtime=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)


class NumericEnvironmentTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve()/'project'
        self.root.mkdir()
        self.work=self.root/'build/wine-numeric-diagnostics'
        self.build=self.work/'full-x86_64'
        self.source=self.work/'source'
        self.engine=self.root/'runtime/wine-numeric-diagnostics/engine'
        self.prefix=self.root/'prefixes/wine-numeric-regression'
        self.here=self.root/'native/wine-numeric-diagnostics'
        self.pin_path=self.root/'research/wine-numeric-engine-code-inputs.json'
        self.manifest=self.build/'engine-manifest.json'
        self.stack=ExitStack()
        self.addCleanup(self.stack.close)
        for name,value in {'ROOT':self.root,'HERE':self.here,'WORK':self.work,'BUILD':self.build,'SOURCE':self.source,
                           'ENGINE':self.engine,'PREFIX':self.prefix,'ROOT_PIN':self.pin_path,'MANIFEST':self.manifest,
                           'MOLTENVK':self.build/'dependencies/moltenvk/libMoltenVK.dylib'}.items():
            self.stack.enter_context(mock.patch.object(runtime,name,value))
        for name,value in {'ROOT':self.root,'WORK':self.root/'build/wine-job-query-parity',
                           'BUILD':self.root/'build/wine-job-query-parity/full-x86_64',
                           'SOURCE':self.root/'build/wine-job-query/source',
                           'ENGINE':self.root/'runtime/wine-job-query-parity/engine',
                           'MANIFEST':self.root/'build/wine-job-query-parity/full-x86_64/engine-manifest.json'}.items():
            self.stack.enter_context(mock.patch.object(runtime.baseline,name,value))

    def write(self,path,data):
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(data)
        return {'path':str(path.relative_to(self.root)),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}

    def admitted_inventory(self):
        entries=[]
        for name in ('bin/wine','bin/wineserver','lib/wine/x86_64-unix/ntdll.so'):
            item=self.write(self.engine/name,('own '+name).encode())
            item['path']=name
            item.update(kind='data',executable=False)
            entries.append(item)
        self.write(self.here/'environment.py',b'own verifier fixture')
        self.write(runtime.baseline.MANIFEST,b'{}')
        self.write(self.build/'Makefile',b'CPPFLAGS = -DCFX_NUMERIC_DIAGNOSTICS=1\n')
        value={'entries':entries,'successful_phases':[]}
        manifest=self.write(self.manifest,json.dumps(value).encode())
        pin={'schema_version':1,'profile':runtime.ROLE,'protocol_version':1810,
             'baseline_manifest_sha256':runtime.BASELINE_MANIFEST_SHA,'engine_manifest':manifest,
             'entry_count':3}
        for field,name in (('loader','bin/wine'),('server','bin/wineserver')):
            row=next(item for item in entries if item['path']==name)
            pin[field]={'path':str((self.engine/name).relative_to(self.root)),
                        'bytes':row['bytes'],'sha256':row['sha256']}
        self.write(self.pin_path,json.dumps(pin).encode())
        return value,pin

    def minimal_verification(self):
        value,pin=self.admitted_inventory()
        old={'manifest_sha256':runtime.BASELINE_MANIFEST_SHA,'protocol_version':1810,'entries':1761}
        def validate(value,pin,base):
            runtime._inventory_paths(self.engine,value['entries'])
            return value['entries'],[]
        self.stack.enter_context(mock.patch.object(runtime.baseline,'verify_runtime',return_value=old))
        self.stack.enter_context(mock.patch.object(runtime,'_validate_manifest',side_effect=validate))
        self.stack.enter_context(mock.patch.object(runtime,'_provenance_guard',return_value=lambda direct:[]))
        self.stack.enter_context(mock.patch.object(runtime,'_verify_sources',return_value={'only_mock_sources':True}))
        self.stack.enter_context(mock.patch.object(runtime,'_verify_pe_commands',return_value={'only_mock_commands':True}))
        return value,pin

    def test_missing_root_pin_blocks_before_baseline_candidate_or_environment(self):
        with mock.patch.object(runtime.baseline,'verify_runtime') as baseline:
            with self.assertRaises(FileNotFoundError): runtime.verify_runtime()
            with self.assertRaises(FileNotFoundError): runtime.environment({'arbitrary':'unverified'})
        baseline.assert_not_called()
        self.assertFalse(self.prefix.exists())

    def test_root_pin_requires_fixed_manifest_loader_server_baseline_and_protocol(self):
        _,pin=self.admitted_inventory()
        changes=({'profile':'source-client'},{'protocol_version':1809},{'baseline_manifest_sha256':'0'*64},
                 {'entry_count':True},{'entry_count':0},
                 {'engine_manifest':dict(pin['engine_manifest'],path='prefixes/fivem-source-main/private.json')},
                 {'loader':dict(pin['loader'],path='runtime/other/bin/wine')})
        for change in changes:
            self.pin_path.write_text(json.dumps({**pin,**change}))
            with self.assertRaises(RuntimeError): runtime.read_root_pin()

    def test_source_gta_and_old_api_prefix_can_never_replace_own_numeric_role(self):
        for name in ('fivem-source-main','rockstar-legacy','wine-parity-regression'):
            with mock.patch.object(runtime,'PREFIX',self.root/'prefixes'/name):
                with mock.patch.object(runtime,'read_regular') as read:
                    with self.assertRaisesRegex(RuntimeError,'Source, GTA'): runtime.read_root_pin()
            read.assert_not_called()

    def test_minimal_mock_runtime_checks_full_baseline_then_exact_own_bytes_without_prefix_creation(self):
        self.minimal_verification()
        verified=runtime.verify_runtime()
        runtime.baseline.verify_runtime.assert_called_once_with()
        self.assertEqual(verified['profile'],runtime.ROLE)
        self.assertEqual(verified['baseline_entries'],1761)
        self.assertEqual(verified['entries'],3)
        self.assertFalse(verified['runtime_or_prefix_started'])
        self.assertFalse(self.prefix.exists())

    def test_unconfirmed_baseline_is_rejected_even_when_numeric_pin_and_files_match(self):
        self.minimal_verification()
        runtime.baseline.verify_runtime.return_value={'manifest_sha256':'0'*64,'protocol_version':1810}
        with self.assertRaisesRegex(RuntimeError,'baseline verification'): runtime.verify_runtime()
        runtime._validate_manifest.assert_not_called()

    def test_changed_manifest_rejected_before_selected_candidate_paths(self):
        self.minimal_verification()
        self.manifest.write_bytes(b'changed')
        with self.assertRaisesRegex(RuntimeError,'Root-issued pin'): runtime.verify_runtime()
        runtime._validate_manifest.assert_not_called()

    def test_extra_missing_hardlinked_or_symlinked_runtime_members_fail_closed(self):
        value,pin=self.minimal_verification()
        path=self.engine/'bin/wine'
        payload=path.read_bytes()
        extra=self.engine/'extra.dll'
        extra.write_bytes(b'extra')
        with self.assertRaisesRegex(RuntimeError,'extra'): runtime.verify_runtime()
        extra.unlink()
        path.unlink()
        with self.assertRaisesRegex(RuntimeError,'missing'): runtime.verify_runtime()
        path.write_bytes(payload)
        alias=self.root/'alias'
        os.link(path,alias)
        with self.assertRaisesRegex(RuntimeError,'alias'): runtime.verify_runtime()
        alias.unlink()
        path.unlink()
        target=self.root/'other'
        target.write_bytes(payload)
        path.symlink_to(target)
        with self.assertRaises(SystemExit): runtime.verify_runtime()

    def test_changed_loader_or_server_pin_is_not_hidden_by_manifest_inventory(self):
        self.minimal_verification()
        self.engine.joinpath('bin/wine').write_bytes(b'changed')
        with self.assertRaisesRegex(RuntimeError,'artifact changed'): runtime.verify_runtime()
        runtime._verify_sources.assert_not_called()

    def test_clean_environment_uses_new_loader_server_prefix_and_only_numeric_channel(self):
        self.minimal_verification()
        verified=runtime.verify_runtime()
        inherited={'WINEPREFIX':'/source','WineServerSocket':'private','_WINE_PRIVATE':'x','__WINE_PRIVATE':'x',
                   'CitizenFX_ToolMode':'1','DYLD_INSERT_LIBRARIES':'/injection','LD_PRELOAD':'/other',
                   'DXMT_CONFIG':'old','GST_PLUGIN_PATH':'private','MVK_CONFIG':'old','LANG':'de_DE.UTF-8'}
        env=runtime.environment(verified,inherited)
        self.assertEqual(env['WINEDEBUG'],'-all,+cfxnum')
        self.assertEqual(runtime.environment(verified,inherited,diagnostics=False)['WINEDEBUG'],'-all')
        self.assertEqual(env['WINEPREFIX'],str(self.prefix))
        self.assertEqual(env['WINELOADER'],str(self.engine/'bin/wine'))
        self.assertEqual(env['WINESERVER'],str(self.engine/'bin/wineserver'))
        self.assertEqual(env['WINEDLLOVERRIDES'],'winemenubuilder.exe,mscoree,mshtml=d')
        self.assertEqual(env['DYLD_LIBRARY_PATH'].split(os.pathsep),
                         [str(self.engine/'lib/wine/x86_64-unix'),str(runtime.MOLTENVK.parent),
                          str(runtime.FRAMEWORKS),str(runtime.GST_LIB)])
        self.assertEqual(env['LANG'],'de_DE.UTF-8')
        self.assertEqual(env['GST_REGISTRY_UPDATE'],'no')
        self.assertEqual(env['GST_PLUGIN_PATH'],'')
        for name in inherited:
            if name not in ('LANG','WINEPREFIX','GST_PLUGIN_PATH'): self.assertNotIn(name,env)
        self.assertFalse(self.prefix.exists())

    def test_environment_rejects_wrong_verification_and_later_changed_root_pin(self):
        self.minimal_verification()
        verified=runtime.verify_runtime()
        with self.assertRaises(RuntimeError): runtime.environment({**verified,'profile':'source'})
        with self.assertRaises(RuntimeError): runtime.environment(verified,diagnostics='off')
        self.pin_path.write_bytes(self.pin_path.read_bytes()+b'\n')
        with self.assertRaisesRegex(RuntimeError,'current numeric'): runtime.environment(verified)

    def test_inventory_scope_is_admitted_before_any_candidate_file_reads(self):
        with mock.patch.object(runtime,'read_regular') as read:
            with self.assertRaises(RuntimeError):
                runtime._inventory_paths(self.engine,[{'path':'../../private','bytes':1,'sha256':'0'*64}])
        read.assert_not_called()

    def test_transitive_provenance_refuses_account_prefix_and_foreign_source_roots(self):
        for value in ({'path':str(self.root/'prefixes/fivem-source-main/private.json'),'bytes':1,'sha256':'0'*64},
                      {'source_root':'/private','files':[]}):
            with mock.patch.object(runtime,'read_regular') as read:
                with self.assertRaises(RuntimeError): runtime._collect_provenance(value)
            read.assert_not_called()

    def baseline_container(self):
        value={'schema_version':1,'engine_root':str(runtime.baseline.ENGINE),
               'build_root':str(runtime.baseline.BUILD),'entries':[{'path':'bin/wine','bytes':8,'sha256':'0'*64}],
               'other_evidence':{'path':str(runtime.baseline.BUILD/'own.json'),'bytes':2,'sha256':'1'*64}}
        raw=json.dumps(value).encode()
        self.write(runtime.baseline.MANIFEST,raw)
        self.stack.enter_context(mock.patch.object(runtime,'BASELINE_MANIFEST_SHA',hashlib.sha256(raw).hexdigest()))
        return value

    def test_only_the_complete_exact_pinned_baseline_manifest_is_a_document_container(self):
        value=self.baseline_container()
        self.assertEqual(runtime._collect_provenance(value),[])
        changed={**value,'entries':[{'path':'../../private','bytes':8,'sha256':'0'*64}]}
        with self.assertRaisesRegex(RuntimeError,'complete pinned baseline'): runtime._collect_provenance(changed)
        changed={**value,'schema_version':True}
        with self.assertRaisesRegex(RuntimeError,'complete pinned baseline'): runtime._collect_provenance(changed)
        runtime.baseline.MANIFEST.write_bytes(runtime.baseline.MANIFEST.read_bytes()+b'\n')
        with self.assertRaisesRegex(RuntimeError,'complete pinned baseline'): runtime._collect_provenance(value)

    def test_manifest_lookalikes_do_not_admit_relative_paths_or_read_their_selected_files(self):
        value=self.baseline_container()
        selected=self.root/'prefixes/fivem-source-main/private.json'
        for changed in ({**value,'engine_root':str(self.engine)},
                        {'engine_root':str(runtime.baseline.ENGINE),'entries':value['entries']},
                        {**value,'other_evidence':{'path':str(selected),'bytes':2,'sha256':'1'*64}}):
            read=runtime.read_regular
            reads=[]
            def recorded(path,boundary=None):
                reads.append(path)
                return read(path,boundary)
            with mock.patch.object(runtime,'read_regular',side_effect=recorded):
                with self.assertRaises(RuntimeError): runtime._collect_provenance(changed)
            self.assertNotIn(selected,reads)
            self.assertTrue(all(path==runtime.baseline.MANIFEST for path in reads))

    def test_provenance_guard_keeps_original_baseline_globals_unchanged(self):
        previous={name:getattr(runtime.baseline,name) for name in ('ROOT','WORK','BUILD','SOURCE','ENGINE')}
        guard=runtime._provenance_guard()
        self.assertEqual(guard([]),[])
        self.assertEqual(previous,{name:getattr(runtime.baseline,name) for name in previous})
        self.assertEqual(guard.__globals__['BUILD'],self.build)

    def test_registry_scope_has_ten_recipes_four_external_tests_and_eight_changes(self):
        self.assertEqual(len(runtime.RECIPE_NAMES),10)
        self.assertIn('registry_overlay.py',runtime.RECIPE_NAMES)
        self.assertEqual(len(runtime.EXTERNAL_TESTS),4)
        self.assertIn('tests/test_wine_numeric_registry_overlay.py',runtime.EXTERNAL_TESTS)
        self.assertEqual(sum(len(paths) for paths in runtime.OVERLAYS.values()),7)
        self.assertEqual(runtime.OVERLAYS['registry_overlay.py'],('include/Makefile.in',))
        self.assertEqual(len(runtime.PREFLIGHT),6)
        self.assertEqual(runtime.PREFLIGHT['test_wine_numeric_registry_overlay.py'],5)

    def test_overlay_relative_claims_are_not_reinterpreted_as_live_files(self):
        module={'path':str(self.here/'registry_overlay.py'),'bytes':1,'sha256':'0'*64}
        value={'numeric_source_has_deliberate_eight_file_overlay':True,'overlay_scopes':[
            {'module':module,'scope':{'original':{'path':'include/Makefile.in','bytes':1,'sha256':'1'*64}}}]}
        selected=runtime._collect_provenance(value)
        self.assertEqual(len(selected),1)
        self.assertEqual(selected[0][0],module)
        self.assertEqual(selected[0][1],self.here/'registry_overlay.py')
        with mock.patch.object(runtime,'read_regular') as read:
            old={**value,'numeric_source_has_deliberate_eight_file_overlay':False}
            with self.assertRaises(RuntimeError): runtime._collect_provenance(old)
        read.assert_not_called()

    def test_environment_rejects_nonstring_inherited_values(self):
        self.minimal_verification()
        verified=runtime.verify_runtime()
        with self.assertRaisesRegex(RuntimeError,'string keys and values'):
            runtime.environment(verified,{'LANG':object()})

    def test_manifest_format_counts_must_describe_all_real_inventory_entries(self):
        value,pin=self.admitted_inventory()
        formats={'mach_o_x86_64':0,'pe_amd64':0,'pe_i386':0,'data':2,'symlinks':0}
        value.update(schema_version=1,engine_root=str(self.engine),build_root=str(self.build),job_protocol_version=1810,
                     unix_architecture='x86_64',pe_architectures=['i386','AMD64'],format_counts=formats,
                     diagnostic_compile_macro=runtime.COMPILE_MACRO,diagnostic_build_flags=runtime.DIAGNOSTIC_FLAGS)
        for key in ('sources_unchanged_since_numeric_preparation','numeric_overlay_applied',
                    'original_baseline_source_unchanged','macdrv_functions_export_present','passed_static_artifact_review'):
            value[key]=True
        for key in ('external_libraries_copied_into_engine','dxmt_overlay_applied','mono_or_gecko_addons_copied',
                    'installed_engine_self_contained','wine_or_prefix_started','graphics_job_or_client_runtime_tests_performed',
                    'active_runtime_or_old_candidate_changed'):
            value[key]=False
        with self.assertRaisesRegex(RuntimeError,'format counts'):
            runtime._validate_manifest(value,pin,{'format_counts':{**formats,'data':3}})

    def makefile(self):
        return (''.join(key+' = '+value+'\n' for key,value in runtime.DIAGNOSTIC_FLAGS.items())
                +'prefix = '+str(self.engine)+'\nsrcdir = '+str(self.source)+'\n'
                +'exec_prefix = ${prefix}\nbindir = ${exec_prefix}/bin\nlibdir = ${exec_prefix}/lib\n')

    def pe_lines(self):
        return [shlex.join([item['compiler'],'-c','-o',item['target'],item['source'],
                           '-D__WINE_PE_BUILD','-g','-O2','-DCFX_NUMERIC_DIAGNOSTICS=1'])
                for item in runtime._pe_targets()]

    def command_records(self):
        self.write(self.build/'Makefile',self.makefile().encode())
        provenance=self.build/'logs'/('provenance-'+'a'*64+'.json')
        self.write(provenance,json.dumps({'build_environment':dict(runtime.DIAGNOSTIC_FLAGS)}).encode())
        def phase(name,text):
            log=self.build/'logs'/(name+'-20261102T120000000000Z.log')
            self.write(log,text.encode())
            record={'phase':name,'passed':True,'exit':0,'interrupted_or_timeout':False,'wine_or_prefix_started':False,
                    'command':['/usr/bin/make','-j4'] if name=='all' else ['own-configure'],
                    'log':runtime._identity(log),'build_provenance':runtime._identity(provenance)}
            path=self.build/(name+'-results.json')
            self.write(path,json.dumps(record).encode())
            return path,log
        config,_=phase('configure','own configuration')
        actual,actual_log=phase('all','\n'.join(self.pe_lines()))
        planned_log=self.build/'logs/pe-command-plan-20261102T120000000000Z.log'
        self.write(planned_log,'\n'.join(self.pe_lines()).encode())
        documents={}
        for key,planned,phase_path,log in (('pe_command_plan',True,config,planned_log),
                                           ('pe_command_proof',False,actual,actual_log)):
            value={'schema_version':1,'profile':'numeric-pe-command-plan' if planned else 'numeric-pe-command-proof',
                   'planned_only':planned,'actual_pe_compilation_claimed':not planned,
                   'phase':'configure' if planned else 'all','phase_result':runtime._identity(phase_path),
                   'makefile':runtime._identity(self.build/'Makefile'),'expected_flags':dict(runtime.DIAGNOSTIC_FLAGS),
                   'log':runtime._identity(log),'commands':runtime._parse_pe_commands(log.read_text()),
                   'command_target_count':10,'wine_or_prefix_started':False}
            if planned:
                value.update(command=['/usr/bin/make','-n','-o','Makefile',
                                      *[item['target'] for item in runtime._pe_targets()]],exit=0)
            else: value['plan']=runtime._identity(self.build/'pe-command-plan.json')
            path=self.build/('pe-command-plan.json' if planned else 'pe-command-proof.json')
            self.write(path,json.dumps(value).encode())
            documents[key]=runtime._identity(path)
        return documents

    def test_exact_three_flags_and_build_boundaries_refuse_substrings_comments_or_overrides(self):
        text=self.makefile()
        runtime._configuration_boundaries(text)
        for changed in (text.replace('CPPFLAGS = -D','CPPFLAGS = \n# -D',1),
                        text.replace(runtime.DIAGNOSTIC_FLAGS['i386_CFLAGS'],'-g -O2',1),
                        text.replace('x86_64_CFLAGS = -g -O2 -DCFX_NUMERIC_DIAGNOSTICS=1',
                                     'x86_64_CFLAGS = -g -O2 -DCFX_NUMERIC_DIAGNOSTICS=0'),
                        text+'CPPFLAGS = -DCFX_NUMERIC_DIAGNOSTICS=1\n',
                        text.replace(str(self.engine),'/private/other')):
            with self.assertRaises(RuntimeError): runtime._configuration_boundaries(changed)

    def test_alternate_make_operators_or_modifiers_cannot_override_any_numeric_flag(self):
        text=self.makefile()
        for name in runtime.DIAGNOSTIC_FLAGS:
            for operator in (':=','::=',':::=','+=','?=','!='):
                with self.subTest(name=name,operator=operator),self.assertRaises(RuntimeError):
                    runtime._configuration_boundaries(text+name+' '+operator+' -g -O2\n')
            for modifier in ('override','export','override export','private'):
                with self.subTest(name=name,modifier=modifier),self.assertRaises(RuntimeError):
                    runtime._configuration_boundaries(text+modifier+' '+name+' = -g -O2\n')

    def test_ten_pe_command_parser_refuses_missing_arch_wrong_source_compiler_or_macro(self):
        text='\n'.join(self.pe_lines())
        commands=runtime._parse_pe_commands(text)
        self.assertEqual(len(commands),10)
        self.assertEqual({item['architecture'] for item in commands},{'i386','x86_64'})
        for changed in ('\n'.join(self.pe_lines()[:-1]),
                        text.replace('-DCFX_NUMERIC_DIAGNOSTICS=1','',1),
                        text.replace('-DCFX_NUMERIC_DIAGNOSTICS=1','-DCFX_NUMERIC_DIAGNOSTICS=0',1),
                        text.replace('-DCFX_NUMERIC_DIAGNOSTICS=1','-DCFX_NUMERIC_DIAGNOSTICS=1 -UCFX_NUMERIC_DIAGNOSTICS',1),
                        text.replace(str(self.source),str(runtime.baseline.SOURCE),1),
                        text.replace(runtime.PE_COMPILERS['i386'],'/other/compiler',1)):
            with self.assertRaises(RuntimeError): runtime._parse_pe_commands(changed)

    def test_both_scoped_command_records_reparse_the_planned_and_real_all_logs(self):
        value=self.command_records()
        verified=runtime._verify_pe_commands(value)
        self.assertEqual(verified['target_count'],10)
        self.assertTrue(verified['both_logs_reparsed'])
        self.assertFalse(self.prefix.exists())

    def test_command_proof_selected_paths_are_all_admitted_before_phase_or_log_reads(self):
        value=self.command_records()
        proof_path=self.build/'pe-command-proof.json'
        proof=json.loads(proof_path.read_text())
        proof['log']['path']=str(self.root/'prefixes/fivem-source-main/private.log')
        proof_path.write_text(json.dumps(proof))
        value['pe_command_proof']=runtime._identity(proof_path)
        read=runtime.read_regular
        reads=[]
        def recorded(path,boundary=None):
            reads.append(path)
            return read(path,boundary)
        with mock.patch.object(runtime,'read_regular',side_effect=recorded):
            with self.assertRaisesRegex(RuntimeError,'log role'): runtime._verify_pe_commands(value)
        self.assertEqual(reads,[self.build/'pe-command-plan.json',proof_path])

    def test_dryrun_log_or_stale_command_hashes_cannot_replace_actual_compilation(self):
        value=self.command_records()
        proof_path=self.build/'pe-command-proof.json'
        proof=json.loads(proof_path.read_text())
        plan=json.loads((self.build/'pe-command-plan.json').read_text())
        proof['log']=plan['log']
        proof_path.write_text(json.dumps(proof))
        value['pe_command_proof']=runtime._identity(proof_path)
        with self.assertRaises(RuntimeError): runtime._verify_pe_commands(value)
        value=self.command_records()
        proof=json.loads(proof_path.read_text())
        proof['commands'][0]['command_sha256'][0]='0'*64
        proof_path.write_text(json.dumps(proof))
        value['pe_command_proof']=runtime._identity(proof_path)
        with self.assertRaisesRegex(RuntimeError,'re-parsed command hashes'): runtime._verify_pe_commands(value)

    def test_archived_phase_environment_must_have_both_pe_flags_as_well_as_host_cppflags(self):
        value=self.command_records()
        all_path=self.build/'all-results.json'
        phase=json.loads(all_path.read_text())
        provenance_path=Path(phase['build_provenance']['path'])
        provenance=json.loads(provenance_path.read_text())
        provenance['build_environment'].pop('x86_64_CFLAGS')
        provenance_path.write_text(json.dumps(provenance))
        for phase_name in ('configure','all'):
            path=self.build/(phase_name+'-results.json')
            changed=json.loads(path.read_text())
            changed['build_provenance']=runtime._identity(provenance_path)
            path.write_text(json.dumps(changed))
        for key,filename,phase_name in (('pe_command_plan','pe-command-plan.json','configure'),
                                       ('pe_command_proof','pe-command-proof.json','all')):
            path=self.build/filename
            record=json.loads(path.read_text())
            record['phase_result']=runtime._identity(self.build/(phase_name+'-results.json'))
            if key=='pe_command_proof': record['plan']=value['pe_command_plan']
            path.write_text(json.dumps(record))
            value[key]=runtime._identity(path)
        with self.assertRaisesRegex(RuntimeError,'three exact numeric flags'): runtime._verify_pe_commands(value)


if __name__=='__main__':
    unittest.main()
