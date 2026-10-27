"""install: the hook it writes must run with an interpreter that exists, really deny, and keep the user's settings.

A bare `python` in the hook command is not on PATH on many Windows machines (only the `py` launcher is), and a hook
that fails to start is a non-blocking error - the outbound call goes through and the tripwire is silently off.
"""
import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pii_tripwire as pt  # noqa: E402

PHONE = "+380501234567"          # fictional


class Install(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.settings = os.path.join(self.tmp.name, ".claude", "settings.json")

    def tearDown(self):
        self.tmp.cleanup()

    def command(self):
        with open(self.settings, encoding="utf-8") as f:
            data = json.load(f)
        cmds = [c["command"] for h in data["hooks"]["PreToolUse"] for c in h["hooks"]]
        self.assertEqual(len(cmds), 1)
        return cmds[0]

    def test_hook_runs_with_the_interpreter_that_installed_it(self):
        pt.install(self.settings)
        exe = shlex.split(self.command(), posix=True)[0]
        self.assertEqual(os.path.normcase(os.path.abspath(exe)), os.path.normcase(os.path.abspath(sys.executable)))

    def test_the_written_command_really_denies(self):
        lst = os.path.join(self.tmp.name, "list.json")
        pt.add(lst, "phone", PHONE)
        pt.install(self.settings)
        call = {"tool_name": "WebFetch", "tool_input": {"url": "https://example.test/?q=+38 050 123 45 67"}}
        env = dict(os.environ, PII_TRIPWIRE_LIST=lst)
        r = subprocess.run(self.command(), input=json.dumps(call), capture_output=True, text=True, shell=True, env=env,
                           timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout)
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_an_old_bare_python_hook_is_rewritten_on_reinstall(self):
        os.makedirs(os.path.dirname(self.settings))
        old = {"hooks": {"PreToolUse": [{"matcher": "^(WebFetch|WebSearch|Bash|PowerShell)$|^mcp__", "hooks": [
            {"type": "command", "command": 'python "C:/old/place/pii_tripwire.py" hook'}]}]}}
        with open(self.settings, "w", encoding="utf-8") as f:
            json.dump(old, f)
        pt.install(self.settings)
        cmd = self.command()
        self.assertNotIn("C:/old/place", cmd)
        exe = shlex.split(cmd, posix=True)[0]
        self.assertEqual(os.path.normcase(os.path.abspath(exe)), os.path.normcase(os.path.abspath(sys.executable)))

    # a second review of 1cbb895: two defects in the reinstall path
    def test_a_foreign_hook_that_mentions_the_file_is_not_rewritten(self):
        os.makedirs(os.path.dirname(self.settings))
        foreign = "bash my_audit.sh --watch pii_tripwire.py"
        with open(self.settings, "w", encoding="utf-8") as f:
            json.dump({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
                {"type": "command", "command": foreign}]}]}}, f)
        pt.install(self.settings)
        with open(self.settings, encoding="utf-8") as f:
            cmds = [c["command"] for h in json.load(f)["hooks"]["PreToolUse"] for c in h["hooks"]]
        self.assertIn(foreign, cmds)
        self.assertTrue(any(c.rstrip().endswith("hook") and "pii_tripwire.py" in c and c != foreign for c in cmds))

    def _cmds_after_install(self, command):
        with open(self.settings, "w", encoding="utf-8") as f:
            json.dump({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
                {"type": "command", "command": command}]}]}}, f)
        pt.install(self.settings)
        with open(self.settings, encoding="utf-8") as f:
            return [c["command"] for h in json.load(f)["hooks"]["PreToolUse"] for c in h["hooks"]]

    # second review note (26.10): a foreign program whose command merely ENDS with "pii_tripwire.py hook"
    def test_a_foreign_program_ending_with_our_words_is_not_rewritten(self):
        os.makedirs(os.path.dirname(self.settings))
        for foreign in ("/usr/local/bin/other pii_tripwire.py hook",
                        "bash wrap.sh pii_tripwire.py hook",
                        'node "C:/x/pii_tripwire.py" hook'):
            cmds = self._cmds_after_install(foreign)
            self.assertIn(foreign, cmds, foreign)
            self.assertEqual(len(cmds), 2, foreign)

    def test_every_shape_we_ever_wrote_is_still_repaired(self):
        os.makedirs(os.path.dirname(self.settings))
        for old in ('python "C:/old/place/pii_tripwire.py" hook',
                    "python3 /home/u/pii_tripwire.py hook",
                    '"C:/Python311/python.exe" "C:/a b/pii_tripwire.py" hook',
                    'py "C:\\old\\pii_tripwire.py" hook',
                    '"/usr/bin/python3.11" "/opt/pii_tripwire.py" hook'):
            cmds = self._cmds_after_install(old)
            self.assertEqual(len(cmds), 1, old)
            self.assertNotEqual(cmds[0], old, old)

    def test_the_backup_keeps_the_original_across_reinstalls(self):
        os.makedirs(os.path.dirname(self.settings))
        original = json.dumps({"model": "keep-me", "hooks": {"PreToolUse": [{"matcher": "Edit", "hooks": [
            {"type": "command", "command": "other-hook"}]}]}})
        with open(self.settings, "w", encoding="utf-8") as f:
            f.write(original)
        for _ in range(3):
            pt.install(self.settings)
        with open(self.settings + ".bak", encoding="utf-8") as f:
            self.assertEqual(f.read(), original)

    def test_an_unexpected_shape_is_refused_and_not_touched(self):
        os.makedirs(os.path.dirname(self.settings))
        for bad in ({"hooks": []}, {"hooks": {"PreToolUse": None}}, []):
            text = json.dumps(bad)
            with open(self.settings, "w", encoding="utf-8") as f:
                f.write(text)
            with self.assertRaises(ValueError):
                pt.install(self.settings)
            with open(self.settings, encoding="utf-8") as f:
                self.assertEqual(f.read(), text)

    def test_keeps_settings_leaves_a_backup_and_does_not_duplicate(self):
        os.makedirs(os.path.dirname(self.settings))
        with open(self.settings, "w", encoding="utf-8") as f:
            json.dump({"model": "keep-me", "hooks": {"PreToolUse": [{"matcher": "Edit", "hooks": [
                {"type": "command", "command": "other-hook"}]}]}}, f)
        pt.install(self.settings)
        pt.install(self.settings)
        with open(self.settings, encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["model"], "keep-me")
        cmds = [c["command"] for h in data["hooks"]["PreToolUse"] for c in h["hooks"]]
        self.assertIn("other-hook", cmds)
        self.assertEqual(sum("pii_tripwire.py" in c for c in cmds), 1)
        self.assertTrue(os.path.exists(self.settings + ".bak"))


if __name__ == "__main__":
    unittest.main()
