"""Strict numeric-only parser for the own ANGLE fixture; no captured text is returned."""
import json

FIELDS={'mode','pid','stage','kind','code','ok','value'}
class Bad(Exception): pass

def no_duplicates(pairs):
    out={}
    for key,value in pairs:
        if key in out:raise Bad()
        out[key]=value
    return out

def parse_rows(lines,expected_mode):
    if type(expected_mode) is not int or expected_mode not in (0,1) or not isinstance(lines,(tuple,list)) or not 1<=len(lines)<=128:raise Bad()
    rows=[]
    for line in lines:
        if not isinstance(line,str) or len(line)>384 or not line:raise Bad()
        try: row=json.loads(line,object_pairs_hook=no_duplicates,parse_constant=lambda _: (_ for _ in ()).throw(Bad()))
        except (ValueError,TypeError):raise Bad()
        if type(row) is not dict or set(row)!=FIELDS:raise Bad()
        if any(type(row[k]) is not int or not 0<=row[k]<=0xffffffff for k in FIELDS-{'ok'}) or type(row['ok']) is not bool or row['mode']!=expected_mode or row['pid']==0 or row['kind'] not in (0,1,2,3):raise Bad()
        rows.append(row)
    if len({r['pid'] for r in rows})!=1 or len({r['stage'] for r in rows})!=len(rows):raise Bad()
    return rows

KINDS={**{x:0 for x in (1,4,6,7,8,17,18,19,20,40,42,89,100)},
       **{x:1 for x in (2,3,5,21,22,23,25,26,27,28,29,38,39,41,90,91)},
       **{x:2 for x in (*range(9,17),24,*range(82,89))},
       **{x:3 for x in (*range(30,38),80,81)}}
SUCCESS_CODES={0:0,1:0,2:0x3000,3:0}

def evaluate(lines,exitcode,mode):
    try:
        rows=parse_rows(lines,mode)
        if type(exitcode) is not int or exitcode not in (0,1):raise Bad()
        stages=[r['stage'] for r in rows]
        if len(stages)<14 or stages[-13:]!=list(range(80,92))+[100]:raise Bad()
        exercise=rows[:-13];cleanup=rows[-13:-1];final=rows[-1]
        if not exercise or [r['stage'] for r in exercise]!=list(range(1,len(exercise)+1)) or len(exercise)>42:raise Bad()
        if any(r['kind']!=KINDS.get(r['stage']) for r in rows):raise Bad()
        if any(r['ok'] and ((r['kind']==1 and r['code']>=0x80000000) or (r['kind']!=1 and r['code']!=SUCCESS_CODES[r['kind']])) for r in rows):raise Bad()
        if any(r['value'] not in (0,1) for r in cleanup):raise Bad()
        failures=[r for r in exercise if not r['ok']]
        cleanup_failures=[r for r in cleanup if not r['ok']]
        if len(failures)>1 or (failures and failures[0]!=exercise[-1]):raise Bad()
        complete=len(exercise)==42 and not failures and all(r['ok'] for r in cleanup)
        if final['ok']!=complete or final['value']!=int(complete) or final['code']!=0 or exitcode!=(0 if complete else 1):raise Bad()
        values={r['stage']:r['value'] for r in exercise}
        if values.get(1)!=8:raise Bad()
        if any(values[k] not in (0,1) for k in (6,7,8,17,18,20) if k in values):raise Bad()
        if 19 in values and (values[19]>7 or bool(values[19]&1)!=bool(values[17]) or bool(values[19]&4)!=bool(values[18]) or exercise[18]['ok']!=(mode==0 or values[19]==7)):raise Bad()
        if 20 in values and values[20]!=mode:raise Bad()
        if complete:
            fixed={2:1,3:1,4:35,5:0xb000,6:1,7:1,8:1,**{k:1 for k in range(9,17)},20:mode,30:1,31:1,32:1,33:36053,34:64,35:1,36:1,37:64,42:1}
            if mode==0:fixed.update({21:0,22:0,23:0,24:0,25:0,26:0,29:0,38:0,39:0,40:0,41:0})
            else:fixed.update({19:7,21:87,22:1,23:1,24:1,25:1,29:1,38:1,39:1,40:64,41:1})
            expected_cleanup={**{k:1 for k in range(80,92)},82:mode}
            if any(r['value']!=expected_cleanup[r['stage']] for r in cleanup):raise Bad()
            if any(values.get(k)!=v for k,v in fixed.items()) or any(values[k] not in (0,1) for k in (17,18)):raise Bad()
            if mode==1 and (values[17]!=1 or values[18]!=1):raise Bad()
        if 26 in values and values[26] & ~0x130:raise Bad()
        if any(values[k]>7 for k in (27,28) if k in values):raise Bad()
        return {'passed':complete,'status':'COMPLETE' if complete else 'OBSERVED_FAILURE','numeric_contract_observed':True,'mode':mode,
                'failure_stage':failures[0]['stage'] if failures else None,
                'failure_kind':failures[0]['kind'] if failures else None,
                'failure_code':failures[0]['code'] if failures else None,
                'failure_value':failures[0]['value'] if failures else None,
                'dxgi_usage_flags':values.get(26) if mode==1 else None,
                'bgra_format_caps':values.get(27), 'rgba_format_caps':values.get(28),
                'direct_srv_attempted':29 in values and mode==1,
                'direct_srv_success':next((r['ok'] for r in exercise if r['stage']==29),None) if mode==1 else None,
                'cleanup_failure_stage':cleanup_failures[0]['stage'] if cleanup_failures else None,
                'cleanup_failure_kind':cleanup_failures[0]['kind'] if cleanup_failures else None,
                'cleanup_failure_code':cleanup_failures[0]['code'] if cleanup_failures else None,
                'own_pixel_comparison':complete,'client_or_skia_verified':False}
    except (Bad,ValueError,TypeError,KeyError):
        return {'passed':False,'status':'INCOMPLETE','code':'INVALID_NUMERIC_CONTRACT','numeric_contract_observed':False,'client_or_skia_verified':False}

def angle_provider_lines(lines,expected_folder):
    # Accept only Wine module-load records matching both exact own DLL paths and native type.
    import re
    if not isinstance(lines,(list,tuple)):return False
    expected={expected_folder.casefold()+'\\libegl.dll',expected_folder.casefold()+'\\libglesv2.dll'}
    observed=set()
    for line in lines:
        if not isinstance(line,str):return False
        match=re.search(r'\bLoaded L"([^"]+)" at (?:0x)?[0-9a-fA-F]+: (builtin|native)$',line)
        if match:
            path=match[1].replace('\\\\','\\').casefold()
            if path in expected and match[2]=='native':observed.add(path)
    return observed==expected
