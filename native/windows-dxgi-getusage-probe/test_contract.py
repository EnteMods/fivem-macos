import json
import unittest
import contract

def fixture():
 rows=[{'scenario':0,'stage':0,'hr':0,'value':0xb000,'ok':True}]
 for i,stages in {0:[1,2,3,4],1:[1,2,3,4,5],2:[1,2,3,4,6,7],3:[1,2,3,4,5,6,7,8]}.items():
  for stage in stages:
   value=((8 if i&1 else 0)|(32 if i&2 else 0)) if stage==2 else ((16 if i&1 else 0)|(32 if i&2 else 0)) if stage==4 else 64 if stage==7 else 0
   rows.append({'scenario':i,'stage':stage,'hr':0x80070057 if stage==8 else 0,'value':value,'ok':True})
 rows.append({'scenario':0,'stage':99,'hr':0,'value':1,'ok':True})
 return [json.dumps(x) for x in rows]
class Tests(unittest.TestCase):
 def test_pass(self):self.assertTrue(contract.parse(fixture(),0)['passed'])
 def test_mask_disagreement(self):
  rows=fixture();row=json.loads(rows[4]);row['value']=16;rows[4]=json.dumps(row);self.assertFalse(contract.parse(rows,0)['passed'])
 def test_observed_usage_failure(self):
  rows=fixture();row=json.loads(rows[4]);row.update(value=16,ok=False);rows[4]=json.dumps(row);final=json.loads(rows[-1]);final.update(value=0,ok=False);rows[-1]=json.dumps(final)
  result=contract.parse(rows,1);self.assertEqual(result['status'],'OBSERVED_FAILURE');self.assertEqual(result['first_failure']['stage'],4)
 def test_null_failure(self):
  rows=fixture();row=json.loads(rows[-2]);row['hr']=0;rows[-2]=json.dumps(row);self.assertFalse(contract.parse(rows,0)['passed'])
 def test_missing_or_sensitive(self):
  rows=fixture();self.assertFalse(contract.parse(rows[:-1],0)['passed']);result=contract.parse(rows+['PRIVATE'],0);self.assertNotIn('PRIVATE',str(result))
if __name__=='__main__':unittest.main()
