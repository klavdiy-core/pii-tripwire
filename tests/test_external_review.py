"""An external review (25.10): data past 2 MB was never looked at, and the result said clean. Red on 0.3.1."""
import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pii_tripwire as pt  # noqa: E402

SCRIPT = os.path.join(os.path.dirname(__file__), "..", "pii_tripwire.py")
PHONE = "+380501234567"          # fictional


class PastTwoMegabytes(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.list = os.path.join(self.tmp.name, "list.json")
        pt.add(self.list, "phone", PHONE)

    def tearDown(self):
        self.tmp.cleanup()

    def test_a_number_after_two_megabytes_of_text_is_found(self):
        # the reviewer's repro: 2 000 100 letters x, a newline, the number (2 000 122 bytes) -> scan said 0, silent
        f = os.path.join(self.tmp.name, "big.txt")
        with open(f, "w", encoding="utf-8") as fh:
            fh.write("x" * 2_000_100 + "\n" + PHONE + "\n")
        r = subprocess.run([sys.executable, os.path.abspath(SCRIPT), "scan", f], capture_output=True, text=True,
                           encoding="utf-8", env=dict(os.environ, PII_TRIPWIRE_LIST=self.list))
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("big.txt:2:", r.stdout)                                   # the right line number

    def test_a_number_split_across_reading_blocks_is_found(self):
        f = os.path.join(self.tmp.name, "edge.txt")
        with open(f, "w", encoding="utf-8") as fh:
            fh.write("y\n" * 999_998 + "call " + PHONE + " now\n" + "z\n" * 10)
        r = subprocess.run([sys.executable, os.path.abspath(SCRIPT), "scan", f], capture_output=True, text=True,
                           encoding="utf-8", env=dict(os.environ, PII_TRIPWIRE_LIST=self.list))
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("edge.txt:999999:", r.stdout)

    def test_line_numbers_count_newlines_only_across_blocks(self):
        # a second review: «p\x0cq» lines (a form feed inside each) put the number at :900001, not :700001
        f = os.path.join(self.tmp.name, "ff.txt")
        with open(f, "w", encoding="utf-8", newline="") as fh:
            fh.write("p\x0cq\n" * 700_000 + PHONE + "\n")
        r = subprocess.run([sys.executable, os.path.abspath(SCRIPT), "scan", f], capture_output=True, text=True,
                           encoding="utf-8", env=dict(os.environ, PII_TRIPWIRE_LIST=self.list))
        self.assertIn("ff.txt:700001:", r.stdout)

    def test_one_endless_line_is_said_incomplete_not_clean(self):
        f = os.path.join(self.tmp.name, "oneline.txt")
        with open(f, "w", encoding="utf-8") as fh:
            fh.write("x" * (pt.MAX_LINE + 10))
        r = subprocess.run([sys.executable, os.path.abspath(SCRIPT), "scan", f], capture_output=True, text=True,
                           encoding="utf-8", env=dict(os.environ, PII_TRIPWIRE_LIST=self.list))
        self.assertEqual(r.returncode, 2)
        self.assertIn("INCOMPLETE", r.stderr)

    def test_the_hook_sees_a_number_past_two_megabytes(self):
        event = {"tool_name": "WebFetch", "tool_input": {"url": "https://example.org", "prompt": "x" * 2_100_000 +
                                                                 " " + PHONE}}
        import io
        from contextlib import redirect_stdout
        out = io.StringIO()
        with redirect_stdout(out):
            pt.run_hook(json.dumps(event), list_path=self.list)
        self.assertIn('"deny"', out.getvalue())


if __name__ == "__main__":
    unittest.main()
