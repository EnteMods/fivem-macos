import json
import unittest
import parse_v1 as parse

def row(**changes):
 x={'mode':1,'pid':42,'stage':1,'kind':0,'code':0,'ok':True,'value':0};x.update(changes);return json.dumps(x)
class Tests(unittest.TestCase):
 def test_numeric(self):self.assertEqual(parse.parse_rows([row()],1)[0]['pid'],42)
 def test_sensitive(self):
  with self.assertRaises(parse.Bad):parse.parse_rows([row()[:-1]+',"path":"SECRET"}'],1)
 def test_duplicate_json_key(self):
  with self.assertRaises(parse.Bad):parse.parse_rows([row()[:-1]+',"pid":42}'],1)
 def test_pid_mismatch(self):
  with self.assertRaises(parse.Bad):parse.parse_rows([row(),row(stage=2,pid=43)],1)
 def test_mode_mismatch(self):
  with self.assertRaises(parse.Bad):parse.parse_rows([row(mode=0)],1)
 def test_duplicate_stage(self):
  with self.assertRaises(parse.Bad):parse.parse_rows([row(),row()],1)
 def test_integer_boolean(self):
  with self.assertRaises(parse.Bad):parse.parse_rows([row(pid=True)],1)
if __name__=='__main__':unittest.main()

def success(mode):
 values={1:8,2:1,3:1,4:35,5:0xb000,6:1,7:1,8:1,**{k:1 for k in range(9,17)},17:1,18:1,19:7,20:mode,25:1,26:1,27:36053,28:64,29:1,30:1,31:64,36:1,**{k:1 for k in range(80,92)},82:mode}
 if mode:values.update({21:87,22:1,23:1,24:1,32:1,33:1,34:64,35:1})
 rows=[]
 for stage in list(range(1,37))+list(range(80,92))+[100]:
  kind=parse.KINDS[stage]; value=values.get(stage,1 if stage==100 else 0)
  rows.append(json.dumps({'mode':mode,'pid':42,'stage':stage,'kind':kind,'code':parse.SUCCESS_CODES[kind],'ok':True,'value':value}))
 return rows

class OutcomeTests(unittest.TestCase):
 def test_both_modes(self):
  for m in (0,1):self.assertTrue(parse.evaluate(success(m),0,m)['passed'])
 def test_fail_record(self):
  rows=success(1);bad=json.loads(rows[9]);bad.update(ok=False,code=0x3003);rows[9]=json.dumps(bad);rows=rows[:10]+rows[36:];last=json.loads(rows[-1]);last.update(ok=False,value=0);rows[-1]=json.dumps(last)
  got=parse.evaluate(rows,1,1);self.assertEqual(got['status'],'OBSERVED_FAILURE');self.assertEqual(got['failure_stage'],10)
 def test_cleanup_failure_identified(self):
  rows=success(0);bad=json.loads(rows[36]);bad.update(ok=False,code=1282);rows[36]=json.dumps(bad);last=json.loads(rows[-1]);last.update(ok=False,value=0);rows[-1]=json.dumps(last)
  out=parse.evaluate(rows,1,0);self.assertEqual(out['status'],'OBSERVED_FAILURE');self.assertEqual((out['cleanup_failure_stage'],out['cleanup_failure_kind'],out['cleanup_failure_code']),(80,3,1282))
 def test_wrong_pixels(self):
  rows=success(1);bad=json.loads(rows[33]);bad['value']=63;rows[33]=json.dumps(bad);self.assertFalse(parse.evaluate(rows,0,1)['passed'])
 def test_no_extension_on_interop(self):
  rows=success(1);bad=json.loads(rows[16]);bad['value']=0;rows[16]=json.dumps(bad);self.assertFalse(parse.evaluate(rows,0,1)['passed'])
 def test_contradictory_status(self):
  rows=success(0);bad=json.loads(rows[9]);bad['code']=0x3003;rows[9]=json.dumps(bad);self.assertFalse(parse.evaluate(rows,0,0)['passed'])
 def test_wrong_cleanup_final(self):
  rows=success(1);bad=json.loads(rows[-1]);bad['value']=0;rows[-1]=json.dumps(bad);self.assertFalse(parse.evaluate(rows,0,1)['passed'])
 def test_cleanup_missing(self):
  rows=success(0);del rows[-2];self.assertEqual(parse.evaluate(rows,0,0)['status'],'INCOMPLETE')
 def test_raw_privacy(self):
  rows=success(0)+['PRIVATE-TOKEN'];out=parse.evaluate(rows,0,0);self.assertNotIn('PRIVATE',str(out))

class ProviderTests(unittest.TestCase):
 def test_exact_and_private(self):
  base=r'Z:\fixture'
  lines=[r'Loaded L"Z:\\fixture\\libEGL.dll" at 0x1234: native',r'Loaded L"Z:\\fixture\\libGLESv2.dll" at 0x1234: native']
  self.assertTrue(parse.angle_provider_lines(lines,base))
  self.assertFalse(parse.angle_provider_lines(lines,r'Z:\other'))
  self.assertFalse(parse.angle_provider_lines([x.replace('native','builtin') for x in lines],base))
