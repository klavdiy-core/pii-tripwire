"""scan --patterns: common shapes, no private list needed (Sokol's task, 25.10). All values are fictional or the
standard test values (the Visa test card, the IBAN from the IBAN documentation)."""
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pii_tripwire as pt  # noqa: E402

SCRIPT = os.path.join(os.path.dirname(__file__), "..", "pii_tripwire.py")
GHP = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"            # 36 chars after the prefix, fictional
BOT = "123456789:" + "AAH" + "x" * 32                              # the shape of a Telegram bot token, fictional


class Patterns(unittest.TestCase):
    def hits(self, line):
        return [c for _, c in pt.scan_patterns(line)]

    def test_planted_values_are_caught(self):
        self.assertEqual(self.hits("call +1 415 555 0123 today"), ["phone"])
        self.assertEqual(self.hits("card 4111 1111 1111 1111 exp 12/29"), ["card"])
        self.assertEqual(self.hits(f"token = '{GHP}'"), ["secret"])
        self.assertEqual(self.hits("write to ann.lee@mailbox.org"), ["email"])
        self.assertEqual(self.hits("IBAN DE89 3704 0044 0532 0130 00"), ["iban"])
        self.assertEqual(self.hits("-----BEGIN OPENSSH PRIVATE KEY-----"), ["secret"])
        self.assertEqual(self.hits(f"HERALD_TELEGRAM_TOKEN={BOT}"), ["secret"])
        self.assertEqual(self.hits("key sk-" + "Z" * 40), ["secret"])
        self.assertEqual(self.hits("xoxb-" + "1" * 12 + "-" + "a" * 24), ["secret"])

    def test_look_alikes_pass(self):
        for line in ("released 2026-10-25 at 04:18", "commit d571667 and 8e30b46c0ffee1234567", "msg 106, msg 44869",
                     "version 2.1.310", "4111 1111 1111 1112 fails Luhn", "price +15%", "id 1234567890123456",
                     "see docs@example.com", "noreply@anthropic.com", "Co-Authored-By: x <a@users.noreply.github.com>",
                     "DE89 3704 0044 0532 0130 01 (bad check digits)", "-----BEGIN PUBLIC KEY-----",
                     "score +7 (12) 34", "ref +1234567890123456789"):          # too few / too many digits
            with self.subTest(line=line):
                self.assertEqual(self.hits(line), [])

    def test_cli_prints_category_not_value_and_needs_no_list(self):
        with tempfile.TemporaryDirectory() as d:
            f = os.path.join(d, "notes.md")
            with open(f, "w", encoding="utf-8") as fh:
                fh.write(f"ok\ncard 4111 1111 1111 1111\nt {GHP}\n2026-10-25 d571667 msg 106\n")
            env = dict(os.environ, PII_TRIPWIRE_LIST=os.path.join(d, "no-list.json"))
            r = subprocess.run([sys.executable, os.path.abspath(SCRIPT), "scan", "--patterns", f], capture_output=True,
                               text=True, encoding="utf-8", env=env)
            self.assertEqual(r.returncode, 1, r.stderr)
            self.assertIn("notes.md:2: a payment card number", r.stdout)
            self.assertIn("notes.md:3: a secret (token or key)", r.stdout)
            self.assertNotIn("notes.md:4", r.stdout)
            self.assertNotIn("4111", r.stdout + r.stderr)
            self.assertNotIn("a1B2c3", r.stdout + r.stderr)
            clean = os.path.join(d, "clean.md")
            with open(clean, "w", encoding="utf-8") as fh:
                fh.write("released 2026-10-25, commit d571667, msg 106\n")
            r = subprocess.run([sys.executable, os.path.abspath(SCRIPT), "scan", "--patterns", clean],
                               capture_output=True, text=True, encoding="utf-8", env=env)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_patterns_and_the_list_together(self):
        with tempfile.TemporaryDirectory() as d:
            lst = os.path.join(d, "list.json")
            pt.add(lst, "id", "AB 123456")
            f = os.path.join(d, "x.md")
            with open(f, "w", encoding="utf-8") as fh:
                fh.write("passport AB 123456\ncard 4111111111111111\n")
            env = dict(os.environ, PII_TRIPWIRE_LIST=lst)
            r = subprocess.run([sys.executable, os.path.abspath(SCRIPT), "scan", "--patterns", f], capture_output=True,
                               text=True, encoding="utf-8", env=env)
            self.assertEqual(r.returncode, 1)
            self.assertIn("x.md:1: a document or ID number from your private list", r.stdout)
            self.assertIn("x.md:2: a payment card number", r.stdout)


if __name__ == "__main__":
    unittest.main()
