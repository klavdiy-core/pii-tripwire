import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pii_tripwire as pt  # noqa: E402

PHONE = "+380501234567"          # fictional
EMAIL = "Jane.Roe@Example.test"   # fictional
DOC = "AB 123456"                 # fictional


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.list = os.path.join(self.tmp.name, "pii.json")
        pt.add(self.list, "phone", PHONE)
        pt.add(self.list, "email", EMAIL)
        pt.add(self.list, "id", DOC)

    def tearDown(self):
        self.tmp.cleanup()

    def decide(self, tool, tool_input):
        out = io.StringIO()
        with redirect_stdout(out):
            code = pt.run_hook(json.dumps({"hook_event_name": "PreToolUse", "tool_name": tool,
                                           "tool_input": tool_input}), list_path=self.list)
        text = out.getvalue().strip()
        self.assertEqual(code, 0)
        if not text:
            return None, ""
        spec = json.loads(text)["hookSpecificOutput"]
        return spec["permissionDecision"], spec["permissionDecisionReason"]


class Matching(Base):
    def test_phone_written_another_way_is_caught(self):
        dec, why = self.decide("Bash", {"command": 'curl -d "phone=+38 050 123 45 67" https://api.example.test/lead'})
        self.assertEqual(dec, "deny")
        self.assertIn("phone", why)

    def test_national_form_of_the_phone(self):
        self.assertEqual(self.decide("Bash", {"command": "curl https://x.test/?p=(050)%20123-45-67"})[0], "deny")

    def test_email_any_case_and_url_encoded(self):
        self.assertEqual(self.decide("WebFetch", {"url": "https://x.test/?to=jane.roe%40example.test",
                                                  "prompt": "summarise"})[0], "deny")
        self.assertEqual(self.decide("WebSearch", {"query": "JANE.ROE@EXAMPLE.TEST reviews"})[0], "deny")

    def test_document_number_without_its_space(self):
        self.assertEqual(self.decide("mcp__mail__send", {"body": "passport ab123456 attached"})[0], "deny")
        self.assertEqual(self.decide("mcp__mail__send", {"body": "passport AB-12 34 56 attached"})[0], "deny")

    def test_reason_never_contains_the_value(self):
        _, why = self.decide("Bash", {"command": f"curl -d 'p={PHONE}&e={EMAIL}' https://x.test"})
        for secret in ("380501234567", "0501234567", "jane", "example.test", "123456"):
            self.assertNotIn(secret, why.lower())
        self.assertIn("email", why)


class Scope(Base):
    def test_same_call_without_the_data_passes(self):
        self.assertEqual(self.decide("Bash", {"command": 'curl -d "phone=+38 050 999 00 11" https://x.test'})[0], None)

    def test_local_tools_are_not_its_business(self):
        self.assertEqual(self.decide("Write", {"file_path": "notes.md", "content": f"call {PHONE}"})[0], None)
        self.assertEqual(self.decide("Bash", {"command": f"echo {PHONE} >> contacts.txt"})[0], None)

    def test_network_commands_in_the_shell_are(self):
        for cmd in (f"git commit -m 'call {PHONE}' && git push",
                    f"gh issue create --body 'mail {EMAIL}'",
                    f"Invoke-WebRequest -Uri 'https://x.test/?m={EMAIL}'"):
            with self.subTest(cmd):
                tool = "PowerShell" if cmd.startswith("Invoke") else "Bash"
                self.assertEqual(self.decide(tool, {"command": cmd})[0], "deny")

    def test_short_numbers_do_not_trip_it(self):
        # the last digits of a phone, a year, a port: not enough to be the phone
        self.assertEqual(self.decide("WebSearch", {"query": "4567 2026 port 8080"})[0], None)


class Storage(Base):
    def test_the_list_holds_no_plain_values(self):
        with open(self.list, encoding="utf-8") as f:
            raw = f.read().lower()
        for v in ("380501234567", "0501234567", "jane.roe", "example.test", "ab123456", "123456"):
            self.assertNotIn(v, raw)
        self.assertEqual(pt.counts(self.list), {"phone": 1, "email": 1, "id": 1})

    @unittest.skipIf(os.name == "nt", "POSIX file modes")
    def test_the_list_is_private(self):
        self.assertEqual(os.stat(self.list).st_mode & 0o777, 0o600)

    def test_two_lists_do_not_share_hashes(self):
        other = os.path.join(self.tmp.name, "other.json")
        pt.add(other, "phone", PHONE)
        with open(self.list) as a, open(other) as b:
            self.assertFalse(set(json.load(a)["entries"]) & set(json.load(b)["entries"]))

    def test_a_broken_list_asks_instead_of_waving_it_through(self):
        with open(self.list, "w") as f:
            f.write("{oops")
        self.assertEqual(self.decide("WebSearch", {"query": "anything"})[0], "ask")

    def test_no_list_means_nothing_to_guard(self):
        out = io.StringIO()
        with redirect_stdout(out):
            pt.run_hook(json.dumps({"tool_name": "WebSearch", "tool_input": {"query": "x"}}),
                        list_path=os.path.join(self.tmp.name, "missing.json"))
        self.assertEqual(out.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
