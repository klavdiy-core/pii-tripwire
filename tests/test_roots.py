"""scan --roots FILE: internal path roots that must not appear in a public repo. The roots here are fictional.

The case behind it: a test docstring in a public repo carried the path of a private file
(written in source as an escaped Windows path), and a name-based search missed it.
"""
import io
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pii_tripwire as pt  # noqa: E402

ROOTS = "# fictional internal roots\nC:\\Secret Notes\ninbox-private.jsonl\n\n"


class Roots(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name
        self.roots = self.put("roots.txt", ROOTS)
        self.nolist = os.path.join(self.d, "no-list.json")              # no identifier list needed for --roots

    def tearDown(self):
        self.tmp.cleanup()

    def put(self, name, text):
        p = os.path.join(self.d, name)
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)
        return p

    def scan(self, *files):
        out, err = io.StringIO(), io.StringIO()
        old = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = out, err
        try:
            code = pt.scan(["--roots", self.roots, *files], self.nolist)
        finally:
            sys.stdout, sys.stderr = old
        return code, out.getvalue(), err.getvalue()

    def test_an_escaped_windows_path_in_a_docstring_is_found(self):
        f = self.put("test_x.py", '"""The audit of 25.10 (C:\\\\Secret Notes\\\\00_box\\\\audit.json)."""\nimport os\n')
        code, out, _ = self.scan(f)
        self.assertEqual(code, 1)
        self.assertIn(f"{f}:1: an internal path from your roots list", out)

    def test_forward_slashes_and_any_case(self):
        f = self.put("notes.md", "see c:/SECRET NOTES/plan.md\nand logs/inbox-private.jsonl\n")
        code, out, _ = self.scan(f)
        self.assertEqual(code, 1)
        self.assertEqual(out.count("an internal path"), 2)

    def test_the_root_itself_is_never_printed(self):
        f = self.put("a.txt", "C:\\Secret Notes\\x\n")
        _, out, err = self.scan(f)
        self.assertNotIn("secret notes", (out + err).lower())

    def test_a_longer_name_that_starts_the_same_is_not_a_hit(self):
        f = self.put("b.txt", "C:\\Secret Notesbook\\x and inbox-private.jsonlx\n")
        code, out, _ = self.scan(f)
        self.assertEqual((code, out), (0, ""))

    def test_clean_file_passes(self):
        f = self.put("c.txt", "nothing internal here, C:\\Users\\me is not on the list\n")
        self.assertEqual(self.scan(f)[0], 0)

    def test_an_unreadable_roots_file_is_not_a_pass(self):
        self.roots = os.path.join(self.d, "missing-roots.txt")
        f = self.put("d.txt", "anything\n")
        code, _, err = self.scan(f)
        self.assertEqual(code, 2)
        self.assertIn("roots", err)

    # a second review ran it on files Windows tools write: three ways it looked checked and was not
    def test_a_roots_file_with_a_bom_still_matches(self):
        with open(self.roots, "w", encoding="utf-8-sig") as f:          # Notepad / Windows PowerShell write a BOM
            f.write("C:\\Secret Notes\n")
        f2 = self.put("bom.txt", "C:\\Secret Notes\\x\n")
        self.assertEqual(self.scan(f2)[0], 1)

    def test_a_utf16_roots_file_is_not_checked_not_a_crash(self):
        with open(self.roots, "w", encoding="utf-16") as f:             # PowerShell 5 `>` and Out-File
            f.write("C:\\Secret Notes\n")
        f2 = self.put("u16.txt", "anything\n")
        code, _, err = self.scan(f2)
        self.assertEqual(code, 2)
        self.assertNotIn("Traceback", err)

    def test_a_roots_file_with_no_roots_is_not_a_pass(self):
        self.roots = self.put("only-comments.txt", "# nothing yet\n\n   \n# still nothing\n")
        f2 = self.put("e2.txt", "C:\\Secret Notes\\x\n")
        code, _, err = self.scan(f2)
        self.assertEqual(code, 2)
        self.assertIn("no roots", err)

    def test_cli(self):
        f = self.put("e.py", 'P = "C:\\\\Secret Notes\\\\q"\n')
        env = dict(os.environ, PII_TRIPWIRE_LIST=self.nolist)
        r = subprocess.run([sys.executable, pt.__file__, "scan", "--roots", self.roots, f],
                           capture_output=True, text=True, env=env, timeout=30)
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("an internal path", r.stdout)


if __name__ == "__main__":
    unittest.main()
