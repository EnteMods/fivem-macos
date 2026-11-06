"""Check that compatibility patches retain the original platform/auth decisions."""
import json
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "port/fivem"
BASE = json.loads((ROOT / "config/native-port.json").read_text())["base_revision"]


def original(relative):
    return subprocess.check_output(["git", "show", BASE + ":" + relative], cwd=SOURCE)


class CompatibilityScopeTests(unittest.TestCase):
    def assert_original_region(self, relative, start, end, reviewed_replacements=()):
        before = original(relative).decode().replace("\r\n", "\n")
        after = (SOURCE / relative).read_text().replace("\r\n", "\n")
        for old, new in reviewed_replacements:
            self.assertEqual(before.count(old), 1, "Reviewed compiler adaptation no longer matches upstream")
            before = before.replace(old, new, 1)
        self.assertEqual(before.count(start), 1, "Pinned upstream region is ambiguous")
        self.assertEqual(after.count(start), 1, "Patched region is missing or duplicated")
        self.assertEqual(before[before.index(start):before.index(end, before.index(start))],
                         after[after.index(start):after.index(end, after.index(start))])

    def test_wine_detection_remains_original(self):
        relative = "code/client/citicore/LaunchMode.h"
        self.assertEqual((SOURCE / relative).read_bytes(), original(relative))

    def test_wine_security_selection_remains_original(self):
        relative = "code/client/citicore/ComponentLoader.cpp"
        before = original(relative).decode().replace("\r\n", "\n")
        after = (SOURCE / relative).read_text().replace("\r\n", "\n")
        start = 'if (nameWide == L"adhesive")'
        end = '\n\t\tAddComponent(new DllGameComponent(va(PLATFORM_LIBRARY_STRING, nameWide.c_str())))'
        self.assertEqual(before[before.index(start):before.index(end)],
                         after[after.index(start):after.index(end)])

    def test_component_auth_and_integrity_error_handling_unchanged(self):
        relative = "code/client/citicore/DllGameComponent.Win32.cpp"
        before = original(relative).decode().replace("\r\n", "\n")
        after = (SOURCE / relative).read_text().replace("\r\n", "\n")
        start = "Component* DllGameComponent::CreateComponent()"
        self.assertEqual(before[before.index(start):], after[after.index(start):])

    def test_no_security_module_source_changes(self):
        names = subprocess.check_output(["git", "diff", "--name-only", BASE], cwd=SOURCE, text=True).splitlines()
        forbidden = ("code/components/adhesive/", "code/components/legitimacy/",
                     "code/components/sticky/", "code/components/svadhesive/")
        self.assertFalse([name for name in names if name.startswith(forbidden)])

    def test_nui_cef_api_hash_check_and_preinit_control_flow_remain_original(self):
        # Include the enclosing entry point so an unchanged check cannot sit behind
        # a new early return or a preprocessor condition that skips validation.
        self.assert_original_region(
            "code/components/nui-core/src/NUIInitialize.cpp",
            "void Component_RunPreInit()", "\nnamespace nui\n{")

    def test_nui_legitimacy_headers_and_trusted_frame_gate_remain_original(self):
        relative = "code/components/nui-core/src/NUIClient.cpp"
        self.assert_original_region(relative, "static bool IsTrustedEntitlementFrame(",
                                    "static bool IsSupportedScheme(")
        # The conditional creates a temporary string. Const-reference binding is
        # the reviewed clang-cl fix; header selection and processing stay exact.
        original_binding = '\t\tauto& frameUrl = (frame) ? frame->GetURL().ToString() : std::string{};'
        compatible_binding = '\t\tconst auto& frameUrl = (frame) ? frame->GetURL().ToString() : std::string{};'
        self.assert_original_region(relative, "auto NUIClient::OnBeforeResourceLoad(",
                                    "CefRefPtr<CefResourceHandler> NUIClient::GetResourceHandler(",
                                    ((original_binding, compatible_binding),))


if __name__ == "__main__":
    unittest.main()
