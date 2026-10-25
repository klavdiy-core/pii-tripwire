"""pii_tripwire.py scan: the same matches as the hook, over files before a commit (Sokol's task, 25.10)."""
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pii_tripwire as pt  # noqa: E402

SCRIPT = os.path.join(os.path.dirname(__file__), "..", "pii_tripwire.py")
PHONE = "+380501234567"          # fictional


class Scan(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.list = os.path.join(self.tmp.name, "list.json")
        pt.add(self.list, "phone", PHONE)
        pt.add(self.list, "id", "AB 123456")
        self.f = os.path.join(self.tmp.name, "notes.md")
        with open(self.f, "w", encoding="utf-8") as fh:
            fh.write("# notes\n"
                     "call +38 050 123 45 67 tomorrow\n"            # line 2
                     "commit 9fab123456c0de fixed it\n"              # a hash: no
                     "order 9990501234567000 shipped\n"             # an order number: no
                     "or (050) 123-45-67\n"                          # line 5
                     "nothing here\n"
                     "short form 0501234567.\n")                     # line 7

    def tearDown(self):
        self.tmp.cleanup()

    def cli(self, *args, cwd=None):
        env = dict(os.environ, PII_TRIPWIRE_LIST=self.list)
        return subprocess.run([sys.executable, os.path.abspath(SCRIPT), "scan", *args], capture_output=True,
                              text=True, encoding="utf-8", env=env, cwd=cwd)

    def test_three_spellings_are_caught_and_a_hash_and_an_order_number_are_not(self):
        hits = pt.scan_text(pt.load(self.list), open(self.f, encoding="utf-8").read())
        self.assertEqual([(line, cat) for line, cat in hits], [(2, "phone"), (5, "phone"), (7, "phone")])

    def test_cli_prints_path_line_category_never_the_value_and_exits_1(self):
        r = self.cli(self.f)
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("notes.md:2: a phone number", r.stdout)
        self.assertNotIn("050", r.stdout + r.stderr)
        self.assertNotIn("1234567", r.stdout + r.stderr)

    def test_a_clean_file_exits_0(self):
        clean = os.path.join(self.tmp.name, "clean.md")
        with open(clean, "w", encoding="utf-8") as fh:
            fh.write("all good\n")
        r = self.cli(clean)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_no_list_cannot_check_and_says_so(self):
        env = dict(os.environ, PII_TRIPWIRE_LIST=os.path.join(self.tmp.name, "nope.json"))
        r = subprocess.run([sys.executable, os.path.abspath(SCRIPT), "scan", self.f], capture_output=True, text=True,
                           encoding="utf-8", env=env)
        self.assertEqual(r.returncode, 2)
        self.assertIn("no list", r.stderr.lower())

    def test_binary_and_missing_files_are_reported_not_crashed_on(self):
        b = os.path.join(self.tmp.name, "img.png")
        with open(b, "wb") as fh:
            fh.write(b"\x89PNG\x00\xff\xfe" * 10)
        r = self.cli(b, os.path.join(self.tmp.name, "gone.md"))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("img.png: skipped (binary)", r.stderr)
        self.assertIn("gone.md: skipped (cannot read it)", r.stderr)

    def test_a_deleted_file_in_the_commit_is_not_reported(self):
        repo = os.path.join(self.tmp.name, "repo2")
        os.makedirs(repo)
        git = lambda *a: subprocess.run(["git", "-C", repo, *a], capture_output=True, text=True, check=True)
        git("init", "-q")
        git("config", "user.email", "t@example.test")
        git("config", "user.name", "t")
        with open(os.path.join(repo, "old.md"), "w", encoding="utf-8") as fh:
            fh.write("bye\n")
        git("add", "old.md")
        git("commit", "-q", "-m", "x")
        git("rm", "-q", "old.md")
        r = self.cli("--staged", cwd=repo)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn("old.md", r.stdout + r.stderr)

    def test_staged_checks_what_will_be_committed(self):
        repo = os.path.join(self.tmp.name, "repo")
        os.makedirs(repo)
        git = lambda *a: subprocess.run(["git", "-C", repo, *a], capture_output=True, text=True, check=True)
        git("init", "-q")
        git("config", "user.email", "t@example.test")
        git("config", "user.name", "t")
        with open(os.path.join(repo, "a.md"), "w", encoding="utf-8") as fh:
            fh.write("hello\nphone 0501234567\n")
        with open(os.path.join(repo, "b.md"), "w", encoding="utf-8") as fh:
            fh.write("clean\n")
        git("add", "a.md", "b.md")
        with open(os.path.join(repo, "a.md"), "w", encoding="utf-8") as fh:
            fh.write("hello\n")                       # the working copy is clean; the staged one is not
        r = self.cli("--staged", cwd=repo)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("a.md:2: a phone number", r.stdout)
        self.assertNotIn("b.md", r.stdout)


if __name__ == "__main__":
    unittest.main()
