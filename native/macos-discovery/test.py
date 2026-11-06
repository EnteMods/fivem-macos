#!/usr/bin/env python3
"""Exercise only the own native finder against inert fixtures and an explicitly named legal prefix."""
import argparse,datetime,hashlib,json,os,struct,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
BINARY=ROOT/'build/macos-discovery/gta-discovery'
ASSETS=['x64a.rpf','x64b.rpf','x64g.rpf','common.rpf','bink2w64.dll','x64/audio/audio_rel.rpf',
        'update/x64/dlcpacks/mpheist3/dlc.rpf','update/x64/dlcpacks/mptuner/dlc.rpf','update/x64/dlcpacks/mpsum2/dlc.rpf']
RESULTS=[]


def own_pe(machine=0x8664,with_version=True):
    data=bytearray(0x600 if with_version else 0x400)
    data[:2]=b'MZ';struct.pack_into('<I',data,60,0x80);data[0x80:0x84]=b'PE\0\0'
    struct.pack_into('<HHIIIHH',data,0x84,machine,2 if with_version else 1,0,0,0,0xf0,0x22)
    optional=0x98;struct.pack_into('<H',data,optional,0x20b);struct.pack_into('<I',data,optional+16,0x1000)
    struct.pack_into('<Q',data,optional+24,0x140000000);struct.pack_into('<II',data,optional+32,0x1000,0x200)
    struct.pack_into('<II',data,optional+56,0x3000 if with_version else 0x2000,0x200)
    struct.pack_into('<I',data,optional+108,16)
    sections=optional+0xf0
    struct.pack_into('<8sIIIIIIHHI',data,sections,b'.text\0\0\0',0x100,0x1000,0x200,0x200,0,0,0,0,0x60000020)
    data[0x200]=0xc3
    if with_version:
        struct.pack_into('<II',data,optional+128,0x2000,0x200)
        struct.pack_into('<8sIIIIIIHHI',data,sections+40,b'.rsrc\0\0\0',0x200,0x2000,0x200,0x400,0,0,0,0,0x40000040)
        for offset,identifier,target in [(0,16,0x80000018),(0x18,1,0x80000030),(0x30,0x409,0x48)]:
            struct.pack_into('<IIHHHH',data,0x400+offset,0,0,0,0,0,1)
            struct.pack_into('<II',data,0x410+offset,identifier,target)
        key='VS_VERSION_INFO\0'.encode('utf-16le');header=bytearray(struct.pack('<HHH',0,52,0)+key)
        header.extend(b'\0'*((-len(header))%4))
        fixed=struct.pack('<13I',0xfeef04bd,0x10000,0x10000,3889<<16,0x10000,3889<<16,0x3f,0,0x40004,1,0,0,0)
        blob=header+fixed;struct.pack_into('<H',blob,0,len(blob))
        struct.pack_into('<IIII',data,0x448,0x2060,len(blob),0,0)
        data[0x460:0x460+len(blob)]=blob
    return bytes(data)


def fixture_game(path,executable='GTA5.exe',machine=0x8664):
    path.mkdir(parents=True)
    (path/executable).write_bytes(own_pe(machine))
    for name in ASSETS:
        target=path/name;target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(b'7FPRown inert archive fixture' if name.endswith('.rpf') else b'MZown inert binary fixture')


def call(name,args,exit_code,check):
    completed=subprocess.run([str(BINARY),*map(str,args)],capture_output=True,text=True,timeout=10)
    value=json.loads(completed.stdout)
    if completed.returncode!=exit_code:raise AssertionError((name,completed.returncode,completed.stderr,value))
    check(value)
    RESULTS.append({'case':name,'exit':completed.returncode,'passed':True,'status':value['status']})
    return value


def equal(actual,expected):
    if actual!=expected:raise AssertionError((actual,expected))


def fixtures():
    with tempfile.TemporaryDirectory(prefix='cfx-native-discovery-') as temporary:
        base=Path(temporary).resolve();valid=base/'own legacy fixture';fixture_game(valid)
        call('own_structural_amd64_legacy', ['--game-dir',valid],0,
             lambda r:(equal(r['status'],'legacy_detected'),equal(r['candidates'][0]['pe']['file_version'],'1.0.3889.0'),equal(r['host_architecture'],'arm64')))
        call('explicit_input_required',[],64,lambda r:equal(r['status'],'input_error'))
        call('mutually_exclusive_options',['--prefix',base,'--game-dir',valid],64,lambda r:equal(r['status'],'input_error'))
        call('missing_directory',['--game-dir',base/'missing'],2,lambda r:equal(r['found_legacy'],False))
        invalid=base/'invalid';fixture_game(invalid);(invalid/'GTA5.exe').write_bytes(b'MZ\0')
        call('truncated_pe',['--game-dir',invalid],2,lambda r:equal(r['candidates'][0]['diagnostics'][0]['code'],'truncated_pe'))
        bad=base/'wrong architecture';fixture_game(bad,machine=0xaa64)
        call('arm64_pe_is_not_amd64_game',['--game-dir',bad],2,lambda r:equal(r['candidates'][0]['diagnostics'][0]['code'],'not_amd64'))
        huge=base/'invalid offset';fixture_game(huge);data=bytearray(own_pe());struct.pack_into('<I',data,60,0xffffffff);(huge/'GTA5.exe').write_bytes(data)
        call('malformed_pe_offset',['--game-dir',huge],2,lambda r:equal(r['candidates'][0]['diagnostics'][0]['code'],'invalid_pe_offset'))
        dll=base/'dll is not a game executable';fixture_game(dll);data=bytearray(own_pe());struct.pack_into('<H',data,0x96,0x2022);(dll/'GTA5.exe').write_bytes(data)
        call('dll_cannot_pose_as_game_executable',['--game-dir',dll],2,lambda r:equal(r['candidates'][0]['diagnostics'][0]['code'],'not_executable_image'))
        headers=base/'invalid header extent';fixture_game(headers);data=bytearray(own_pe());struct.pack_into('<I',data,0x98+60,0x100);(headers/'GTA5.exe').write_bytes(data)
        call('section_headers_outside_declared_headers',['--game-dir',headers],2,lambda r:equal(r['candidates'][0]['diagnostics'][0]['code'],'invalid_pe_headers'))
        emptycode=base/'unbacked entry';fixture_game(emptycode);data=bytearray(own_pe());struct.pack_into('<I',data,0x98+0xf0+16,0);(emptycode/'GTA5.exe').write_bytes(data)
        call('executable_virtual_zero_fill_is_not_entry_code',['--game-dir',emptycode],2,lambda r:equal(r['candidates'][0]['diagnostics'][0]['code'],'entry_not_file_backed'))
        beyond=base/'entry beyond raw';fixture_game(beyond);data=bytearray(own_pe());struct.pack_into('<I',data,0x98+16,0x1250);struct.pack_into('<I',data,0x98+0xf0+8,0x300);(beyond/'GTA5.exe').write_bytes(data)
        call('entry_beyond_raw_section_bytes',['--game-dir',beyond],2,lambda r:equal(r['candidates'][0]['diagnostics'][0]['code'],'entry_not_file_backed'))
        version=base/'truncated version value';fixture_game(version);data=bytearray(own_pe());struct.pack_into('<H',data,0x460+2,0xffff);(version/'GTA5.exe').write_bytes(data)
        call('version_metadata_truncation_is_diagnosed_not_invented',['--game-dir',version],0,lambda r:equal(r['candidates'][0]['pe']['version_diagnostic'],'invalid_version_resource'))
        value_type=base/'invalid version value type';fixture_game(value_type);data=bytearray(own_pe());struct.pack_into('<H',data,0x460+4,1);(value_type/'GTA5.exe').write_bytes(data)
        call('version_metadata_requires_binary_value',['--game-dir',value_type],0,lambda r:equal(r['candidates'][0]['pe']['version_diagnostic'],'invalid_version_resource'))
        absent=base/'missing asset';fixture_game(absent);(absent/'x64g.rpf').unlink()
        call('missing_characteristic_asset',['--game-dir',absent],2,lambda r:equal(r['candidates'][0]['valid_installation'],False))
        corrupt=base/'invalid archive';fixture_game(corrupt);(corrupt/'common.rpf').write_bytes(b'NOPEfixture')
        call('invalid_rpf_header',['--game-dir',corrupt],2,lambda r:equal(next(a for a in r['candidates'][0]['assets'] if a['path']=='common.rpf')['diagnostic'],'invalid_rpf7_header'))
        enhanced=base/'enhanced';fixture_game(enhanced,executable='GTA5_Enhanced.exe')
        call('enhanced_detected_but_unsupported',['--game-dir',enhanced],2,lambda r:(equal(r['status'],'enhanced_detected_unsupported'),equal(r['candidates'][0]['supported_by_this_component'],False)))
        mixed=base/'mixed';fixture_game(mixed);(mixed/'GTA5_Enhanced.exe').write_bytes(own_pe())
        call('mixed_editions_ambiguous',['--game-dir',mixed],2,lambda r:equal(r['candidates'][0]['edition'],'ambiguous'))
        link=base/'symlink directory';link.symlink_to(valid,target_is_directory=True)
        call('symlink_directory_not_followed',['--game-dir',link],2,lambda r:equal(r['candidates'][0]['diagnostics'][0]['code'],'symlink_not_followed'))
        outside=base/'do not read';outside.write_text('inert external fixture sentinel\n')
        (valid/'common.rpf').unlink();(valid/'common.rpf').symlink_to(outside)
        call('symlink_asset_not_followed',['--game-dir',valid],2,lambda r:equal(next(a for a in r['candidates'][0]['assets'] if a['path']=='common.rpf')['diagnostic'],'symlink_not_followed'))
        equal(outside.read_text(),'inert external fixture sentinel\n')
        prefix=base/'own wine prefix';known=prefix/'drive_c/Program Files/Rockstar Games/Grand Theft Auto V Legacy';fixture_game(known)
        profile=prefix/'drive_c/users/ignored-profile';profile.mkdir(parents=True)
        (profile/'Cookies').write_text('inert privacy sentinel\n')
        call('prefix_known_game_without_profile_search',['--prefix',prefix],0,lambda r:(equal(r['found_legacy'],True),equal(len(r['candidates']),8)))
        equal((profile/'Cookies').read_text(),'inert privacy sentinel\n')
        custom=base/'custom prefix';fixture_game(custom/'drive_c/users/ignored-profile/Grand Theft Auto V Legacy')
        call('prefix_never_searches_profiles',['--prefix',custom],2,lambda r:equal(r['found_legacy'],False))
        parent=base/'not recursive';fixture_game(parent/'nested game')
        call('game_dir_not_recursive',['--game-dir',parent],2,lambda r:equal(r['found_legacy'],False))


def legal(prefix):
    root=prefix.resolve();game=root/'drive_c/Program Files/Rockstar Games/Grand Theft Auto V Legacy'
    names=['GTA5.exe',*ASSETS]
    before={n:(game/n).stat() for n in names}
    report=call('explicit_legal_original_prefix',['--prefix',root],0,
        lambda r:(equal(r['status'],'legacy_detected'),equal(r['host_architecture'],'arm64'),equal(r['prefix_path'],str(root))))
    actual=next(x for x in report['candidates'] if x['valid_installation'] and x['edition']=='legacy')
    for n in names:
        old,new=before[n],(game/n).stat()
        equal((old.st_ino,old.st_size,old.st_mtime_ns),(new.st_ino,new.st_size,new.st_mtime_ns))
    return {'input_prefix':str(root),'game_path':actual['game_path'],'architecture':actual['architecture'],
            'edition':actual['edition'],'file_version':actual['pe'].get('file_version'),
            'asset_checks':len(actual['assets']),'source_file_inode_size_mtime_unchanged':True,
            'profile_or_registry_inventory_performed':False,'game_or_launcher_started':False}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--legal-prefix',type=Path)
    args=parser.parse_args();fixtures();actual=legal(args.legal_prefix) if args.legal_prefix else None
    r={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'binary_sha256':hashlib.sha256(BINARY.read_bytes()).hexdigest(),
       'fixture_cases':RESULTS,'passed':all(x['passed'] for x in RESULTS),'case_count':len(RESULTS),'legal_original_check':actual,
       'fixture_scope':'Own inert PE/archive headers only; structural tests never imply a genuine or runnable game',
       'only_own_native_cli_executed':True,'game_launcher_wine_or_account_process_started':False,'packaged_dmg':False}
    (ROOT/'research/macos-discovery-results.json').write_text(json.dumps(r,indent=2)+'\n')
    print(json.dumps(r,indent=2))
