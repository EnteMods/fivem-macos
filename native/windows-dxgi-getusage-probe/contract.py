"""Numeric output contract for own GetUsage fixture; no raw output echoed."""
import json
FIELDS={'scenario','stage','hr','value','ok'}
class Bad(Exception):pass

def pairs(entries):
 out={}
 for k,v in entries:
  if k in out:raise Bad()
  out[k]=v
 return out

def parse(lines,code):
 try:
  if type(code) is not int or code not in (0,1) or not isinstance(lines,(list,tuple)) or not 2<=len(lines)<=34:raise Bad()
  rows=[]
  for line in lines:
   if not isinstance(line,str) or len(line)>256:raise Bad()
   obj=json.loads(line,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(Bad()))
   if type(obj) is not dict or set(obj)!=FIELDS or type(obj['ok']) is not bool or any(type(obj[k]) is not int or not 0<=obj[k]<=0xffffffff for k in FIELDS-{'ok'}):raise Bad()
   if obj['scenario']>3 or obj['stage'] not in (*range(9),99):raise Bad()
   rows.append(obj)
  start=rows[0];end=rows[-1]
  if (start['scenario'],start['stage'])!=(0,0) or (end['scenario'],end['stage'],end['hr'])!=(0,99,0) or end['value'] not in (0,1) or end['ok']!=(end['value']==1) or code!=(0 if end['ok'] else 1):raise Bad()
  if start['ok'] and (start['hr']>=0x80000000 or start['value']!=0xb000):raise Bad()
  middle=rows[1:-1]
  if len({(r['scenario'],r['stage']) for r in middle})!=len(middle):raise Bad()
  allowed={0:[1,2,3,4],1:[1,2,3,4,5],2:[1,2,3,4,6,7],3:[1,2,3,4,5,6,7,8]}
  for r in middle:
   if r['stage'] not in allowed[r['scenario']]:raise Bad()
  complete=(start['ok'] and all(r['ok'] for r in middle) and len(middle)==sum(len(x) for x in allowed.values()) and all([r['stage'] for r in middle if r['scenario']==i]==allowed[i] for i in range(4)))
  if end['ok']!=complete or (not end['ok'] and not any(not r['ok'] for r in rows[:-1])):raise Bad()
  for r in middle:
   if r['ok'] and r['stage']!=8 and r['hr']>=0x80000000:raise Bad()
   if r['stage']==2 and r['ok'] and r['value'] != ((8 if r['scenario']&1 else 0)|(32 if r['scenario']&2 else 0)):raise Bad()
   if r['stage']==4 and r['ok']:
    expected=(16 if r['scenario']&1 else 0)|(32 if r['scenario']&2 else 0)
    if (r['value']&0x30)!=expected:raise Bad()
   if r['stage']==7 and r['ok'] and r['value']!=64:raise Bad()
   if r['stage']==8 and r['ok'] and (r['value']!=0 or r['hr']<0x80000000):raise Bad()
  return {'passed':complete,'status':'COMPLETE' if complete else 'OBSERVED_FAILURE','first_failure':next(({k:r[k] for k in ('scenario','stage','hr','value')} for r in rows[:-1] if not r['ok']),None),'client_or_skia_verified':False}
 except (Bad,ValueError,TypeError,KeyError):return {'passed':False,'status':'INCOMPLETE','code':'INVALID_NUMERIC_CONTRACT','client_or_skia_verified':False}
