import json
import unittest
import parse
import parse_v1

def rows(mode):
 values={1:8,2:1,3:1,4:35,5:0xb000,6:1,7:1,8:1,**{k:1 for k in range(9,17)},17:1,18:1,19:7,20:mode,27:7,28:7,30:1,31:1,32:1,33:36053,34:64,35:1,36:1,37:64,42:1,**{k:1 for k in range(80,92)},82:mode}
 if mode:values.update({21:87,22:1,23:1,24:1,25:1,26:0,29:1,38:1,39:1,40:64,41:1})
 return [json.dumps({'mode':mode,'pid':44,'stage':k,'kind':parse.KINDS[k],'code':parse.SUCCESS_CODES[parse.KINDS[k]],'ok':True,'value':values.get(k,1 if k==100 else 0)}) for k in [*range(1,43),*range(80,92),100]]
class Tests(unittest.TestCase):
 def test_modes_v2(self):
  for mode in (0,1):self.assertTrue(parse.evaluate(rows(mode),0,mode)['passed'])
 def test_v1_rejects_v2(self):self.assertEqual(parse_v1.evaluate(rows(0),0,0)['status'],'INCOMPLETE')
 def test_v2_rejects_v1(self):
  from test_parse import success
  self.assertEqual(parse.evaluate(success(0),0,0)['status'],'INCOMPLETE')
 def test_target_failure_with_diagnostics(self):
  sample=rows(1);x=json.loads(sample[30]);x.update(ok=False,code=1282);sample[30]=json.dumps(x);sample=sample[:31]+sample[42:];final=json.loads(sample[-1]);final.update(ok=False,value=0);sample[-1]=json.dumps(final)
  out=parse.evaluate(sample,1,1);self.assertEqual(out['status'],'OBSERVED_FAILURE');self.assertEqual(out['failure_stage'],31);self.assertEqual(out['failure_code'],1282);self.assertEqual(out['dxgi_usage_flags'],0);self.assertIs(out['direct_srv_success'],True)
 def test_invalid_usage_mask(self):
  sample=rows(1);x=json.loads(sample[25]);x['value']=8;sample[25]=json.dumps(x);self.assertEqual(parse.evaluate(sample,0,1)['status'],'INCOMPLETE')
 def test_cross_mode(self):self.assertEqual(parse.evaluate(rows(1),0,0)['status'],'INCOMPLETE')
if __name__=='__main__':unittest.main()
