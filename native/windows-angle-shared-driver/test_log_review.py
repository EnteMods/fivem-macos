import unittest
import log_review as x
class Tests(unittest.TestCase):
 def test_safe_categories(self):
  out=x.extract(b'ERROR ANGLE D3D SECRET https://example.invalid\nERROR EGLImage 0x80004005\n')
  self.assertEqual(out['categories']['angle_d3d_error'],1);self.assertEqual(out['categories']['egl_image_error'],1);self.assertEqual(out['allowlisted_status_codes']['0x80004005'],1)
  self.assertNotIn('SECRET',str(out));self.assertNotIn('https',str(out))
 def test_limit(self):
  with self.assertRaises(ValueError):x.extract(b'x'*(x.LIMIT+1))
if __name__=='__main__':unittest.main()
