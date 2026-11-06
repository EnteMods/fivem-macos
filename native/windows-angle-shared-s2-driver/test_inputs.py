import hashlib
import tempfile
from pathlib import Path
import unittest
import inputs

class Tests(unittest.TestCase):
 def test_exact_tree(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d).resolve();(p/'a').write_bytes(b'a');inputs.verify_runtime_tree(p,{'a':hashlib.sha256(b'a').hexdigest()})
   (p/'unexpected').write_bytes(b'x')
   with self.assertRaises(inputs.Invalid):inputs.verify_runtime_tree(p,{'a':hashlib.sha256(b'a').hexdigest()})
 def test_symlink(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d).resolve();(p/'x').write_bytes(b'x');(p/'a').symlink_to(p/'x')
   with self.assertRaises(inputs.Invalid):inputs.digest(p/'a')
 def test_parent_escape(self):
  with self.assertRaises((inputs.Invalid,FileNotFoundError)):inputs.build_path('../unsafe')
if __name__=='__main__':unittest.main()
