import importlib.util
from pathlib import Path
import tempfile
import unittest

PATH = Path(__file__).resolve().parents[1] / "scripts/verify_environment.py"
SPEC = importlib.util.spec_from_file_location("verify_environment", PATH)
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


class PrefixIsolationTests(unittest.TestCase):
    def test_original_prefix_is_rejected(self):
        self.assertFalse(VERIFY.isolated_prefix(VERIFY.BASE / "prefixes/rockstar-legacy"))

    def test_parent_escape_is_rejected(self):
        self.assertFalse(VERIFY.isolated_prefix(VERIFY.ROOT / "prefixes/../../GTA-V-macOS/prefixes/rockstar-legacy"))

    def test_symlink_to_original_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "prefixes").mkdir()
            alias = root / "prefixes/test"
            alias.symlink_to(VERIFY.BASE / "prefixes/rockstar-legacy", target_is_directory=True)
            self.assertFalse(VERIFY.isolated_prefix(alias, root=root))

    def test_ordinary_isolated_directory_is_accepted(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            prefix = root / "prefixes/test"
            prefix.mkdir(parents=True)
            self.assertTrue(VERIFY.isolated_prefix(prefix, root=root))


if __name__ == "__main__":
    unittest.main()
