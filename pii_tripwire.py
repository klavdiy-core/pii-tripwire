#!/usr/bin/env python3
"""pii-tripwire: stop Claude Code from sending your phone numbers, emails and document numbers out.

You keep a private list (salted hashes only, never the values). Before every outbound tool call (WebFetch,
WebSearch, any MCP tool, and shell commands that talk to the network: curl, wget, git push, gh, ssh,
Invoke-WebRequest ...) the hook looks for those values in the call, written any usual way (+38 050 123 45 67 /
(050) 123-45-67 / 0501234567, any-case or URL-encoded emails, AB 123456 / ab123456), and denies the call.
The reason names the category, never the value. Nothing is logged. Standard library only.
"""
import getpass
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from urllib.parse import unquote_plus

__version__ = "0.3.3"
CATEGORIES = ("phone", "email", "id")
NAMES = {"phone": "a phone number", "email": "an email address", "id": "a document or ID number"}
DEFAULT_LIST = os.path.join(os.path.expanduser("~"), ".claude", "pii-tripwire", "list.json")
MAX_TEXT = 2_000_000          # one block or window; the WHOLE text is still checked, block by block
WINDOW_OVERLAP = 512          # longer than any value (an e-mail is at most 254 characters)
MAX_LINE = 8_000_000          # a single line longer than this is not checked: said, exit 2
PHONE_TAIL = 9                       # national and international forms share their last 9 digits
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
PHONE_RUN = re.compile(r"\+?\d[\d \t().\-/]{6,}\d")
MAX_PHONE_DIGITS = 15
ID_RUN = re.compile(r"[A-Za-z0-9]+(?:[ \-./][A-Za-z0-9]+)*")
NETWORK = re.compile(
    r"\b(curl|wget|httpie|https?|nc|ncat|netcat|ssh|scp|sftp|ftp|telnet|rsync|gh|hub|aws|gcloud|az|kubectl|"
    r"twine|mail|sendmail|mutt)\b|\bgit\s+(push|send-email)\b|\bdocker\s+push\b|\bnpm\s+publish\b|"
    r"Invoke-WebRequest|Invoke-RestMethod|\biwr\b|\birm\b|Send-MailMessage|Net\.WebClient|HttpClient|"
    r"\brequests\.(get|post|put)\b|\burllib\.request\b|\bfetch\(", re.I)
OUTBOUND_TOOLS = {"WebFetch", "WebSearch"}
SHELL_TOOLS = {"Bash", "PowerShell"}


# ---------- normalising ----------

def _digits(s):
    return re.sub(r"\D", "", s)


def _compact(s):
    return re.sub(r"[^A-Za-z0-9]", "", s).upper()


def _h(salt, kind, value):
    return hashlib.sha256(f"{salt}|{kind}|{value}".encode("utf-8")).hexdigest()


# ---------- the list ----------

def load(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict) or "salt" not in data or "entries" not in data:
        raise ValueError("not a pii-tripwire list")
    return data


def add(path, category, value):
    if category not in CATEGORIES:
        raise ValueError(f"category must be one of {', '.join(CATEGORIES)}")
    data = load(path) if os.path.exists(path) else {"version": 1, "salt": os.urandom(16).hex(), "entries": {},
                                                    "aux": {}, "id_lengths": []}
    salt = data["salt"]
    if category == "email":
        norm = value.strip().lower()
        if not EMAIL_RE.fullmatch(norm):
            raise ValueError("that does not look like an email address")
        data["entries"][_h(salt, "email", norm)] = "email"
    elif category == "phone":
        d = _digits(value)
        if len(d) < PHONE_TAIL:
            raise ValueError(f"a phone number needs at least {PHONE_TAIL} digits")
        data["entries"][_h(salt, "phone", d)] = "phone"
        data["aux"][_h(salt, "phone-tail", d[-PHONE_TAIL:])] = "phone"
    else:
        c = _compact(value)
        if len(c) < 6:
            raise ValueError("an ID needs at least 6 letters or digits")
        data["entries"][_h(salt, "id", c)] = "id"
        data["id_lengths"] = sorted(set(data.get("id_lengths", [])) | {len(c)})
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f)
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return category


def counts(path):
    out = {}
    for cat in load(path)["entries"].values():
        out[cat] = out.get(cat, 0) + 1
    return out


# ---------- finding ----------

def _strings(x):
    if isinstance(x, str):
        yield x
    elif isinstance(x, dict):
        for v in x.values():
            yield from _strings(v)
    elif isinstance(x, (list, tuple)):
        for v in x:
            yield from _strings(v)


def find(data, text):
    """Categories from the list that occur in text. Values are compared as salted hashes only."""
    if len(text) > MAX_TEXT:
        # windows over the whole text, overlapping by more than any value can be long: text[:MAX_TEXT] waved through a
        # number placed after 2 MB as if it had been checked (external review, 25.10)
        hit = set()
        for s in range(0, len(text), MAX_TEXT):
            hit |= find(data, text[max(0, s - WINDOW_OVERLAP):s + MAX_TEXT])
        return hit
    salt, entries, aux = data["salt"], data["entries"], data.get("aux", {})
    texts = [text, unquote_plus(text)]
    hit = set()
    for t in texts:
        for m in EMAIL_RE.finditer(t):
            cat = entries.get(_h(salt, "email", m.group(0).lower()))
            if cat:
                hit.add(cat)
        for m in PHONE_RUN.finditer(t):
            d = _digits(m.group(0))
            if entries.get(_h(salt, "phone", d)):
                hit.add("phone")
            # the tail only where a number ends, and only in a run no longer than a phone can be (E.164: 15)
            if len(d) <= MAX_PHONE_DIGITS and aux.get(_h(salt, "phone-tail", d[-PHONE_TAIL:])):
                hit.add("phone")
        lengths = data.get("id_lengths", [])
        for m in ID_RUN.finditer(t):
            # whole tokens only: an ID written "AB-12 34 56" is caught, one inside a hash or glued across a comma is not
            toks = re.split(r"[ \-./]", m.group(0).upper())
            for i in range(len(toks)):
                acc = ""
                for tok in toks[i:]:
                    acc += tok
                    if len(acc) in lengths and entries.get(_h(salt, "id", acc)) == "id":
                        hit.add("id")
                    if len(acc) >= max(lengths, default=0):
                        break
    return hit


def _lines(text):
    """Lines as an editor numbers them: split at \\n only, a trailing \\r dropped. splitlines() also splits at form
    feeds, \\x85 and friends, so a number after 2 MB of «p\\fq» lines was reported at :900001, not :700001 (Tsaplya)."""
    return [x[:-1] if x.endswith("\r") else x for x in text.split("\n")]


def scan_text(data, text):
    """[(line number, category)] for every line holding a value from the list (same matching as the hook)."""
    hits = []
    for n, line in enumerate(_lines(text), 1):
        for cat in CATEGORIES:
            if cat in find(data, line):
                hits.append((n, cat))
    return hits


# ---------- common shapes, no list needed (scan --patterns) ----------
PATTERN_NAMES = {"phone": "a phone number (international form)", "email": "an email address",
                 "card": "a payment card number", "iban": "an IBAN", "secret": "a secret (token or key)"}
PHONE_RE = re.compile(r"(?<![\w+])\+\d[\d ().-]{6,20}\d(?![\d])")
EMAIL_RE = re.compile(r"(?<![\w.+-])([A-Za-z0-9._%+-]{1,64})@([A-Za-z0-9.-]+\.[A-Za-z]{2,24})(?![\w-])")
# placeholder domains (RFC 2606/6761 and their everyday variants): any "example" label, .test, .invalid, localhost
PLACEHOLDER_DOMAIN = re.compile(r"(^|\.)(example(\.[a-z]{2,})*|test|invalid|localhost|users\.noreply\.github\.com)$",
                                re.I)
# a card stands alone: not inside a longer letters-and-digits token (hex hashes in lockfile URLs used to match)
CARD_RE = re.compile(r"(?<![\w-])[2-6]\d{3}(?:[ -]?\d{2,4}){2,4}(?![\w-])")
IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b")
SECRET_RES = [re.compile(p) for p in (
    r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", r"\bgithub_pat_[A-Za-z0-9_]{60,}", r"\bsk-[A-Za-z0-9_-]{20,}",
    r"\bxox[abprs]-[A-Za-z0-9-]{10,}", r"-----BEGIN [A-Z ]*PRIVATE KEY-----", r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b",
    r"\bAKIA[0-9A-Z]{16}\b")]


def _luhn(digits):
    total, odd = 0, True
    for ch in reversed(digits):
        d = int(ch)
        if not odd:
            d = d * 2 - 9 if d * 2 > 9 else d * 2
        total, odd = total + d, not odd
    return total % 10 == 0


def _iban_ok(s):
    s = s.replace(" ", "")
    if not 15 <= len(s) <= 34:
        return False
    moved = s[4:] + s[:4]
    return int("".join(str(int(c, 36)) for c in moved)) % 97 == 1


def scan_patterns(text):
    """[(line number, category)] for common shapes of personal data and secrets, no list needed. Strict on purpose:
    a phone only in international form (+ and 8-15 digits), a card only with a network's first digit and a valid
    Luhn sum, an IBAN only with valid check digits, an email not at a placeholder domain or a noreply address. Dates,
    commit hashes, versions and message numbers do not match any of them."""
    hits = []
    for n, line in enumerate(_lines(text), 1):
        cats = []
        if any(r.search(line) for r in SECRET_RES):
            cats.append("secret")
        ibanish = [(m.start(), m.end()) for m in IBAN_RE.finditer(line)]       # digits inside an IBAN are not a card
        for m in CARD_RE.finditer(line):
            if any(s <= m.start() < e for s, e in ibanish):
                continue
            digits = re.sub(r"\D", "", m.group(0))
            if len(set(re.findall(r"[ -]", m.group(0)))) > 1:
                continue                       # one kind of separator in a card number ("20261025 2026-10-25" is two)
            if 13 <= len(digits) <= 19 and _luhn(digits):
                cats.append("card")
                break
        if any(_iban_ok(m.group(0)) for m in IBAN_RE.finditer(line)):
            cats.append("iban")
        for m in PHONE_RE.finditer(line):
            if 8 <= len(re.sub(r"\D", "", m.group(0))) <= 15 and "card" not in cats:
                cats.append("phone")
                break
        for m in EMAIL_RE.finditer(line):
            local, domain = m.group(1).lower(), m.group(2).lower()
            if not PLACEHOLDER_DOMAIN.search(domain) and not local.startswith(("noreply", "no-reply")):
                cats.append("email")
                break
        hits += [(n, c) for c in cats]
    return hits


def _staged():
    """{path: staged content} for files added, copied or modified in the index: what the commit will hold."""
    names = subprocess.run(["git", "diff", "--cached", "--name-only", "--diff-filter=ACM", "-z"], capture_output=True,
                           check=True).stdout.decode("utf-8", "replace").split("\0")
    out = {}
    for name in filter(None, names):
        blob = subprocess.run(["git", "show", f":{name}"], capture_output=True)
        out[name] = blob.stdout if blob.returncode == 0 else None
    return out


def scan(argv, list_path):
    """scan [--patterns] <files...> | scan [--patterns] --staged. Prints path:line: category (never the value).
    Exit 1 on a find, 2 if there is nothing to check against (no list and no --patterns) or a path was not checked."""
    patterns = "--patterns" in argv
    argv = [a for a in argv if a != "--patterns"]
    has_list = os.path.exists(list_path)
    if not has_list and not patterns:
        print("pii-tripwire: no list yet, nothing to check against (pii_tripwire.py add ..., or scan --patterns)",
              file=sys.stderr)
        return 2
    data = load(list_path) if has_list else None
    if argv[:1] == ["--staged"]:
        try:
            sources = _staged()
        except (OSError, subprocess.CalledProcessError):
            print("pii-tripwire: not inside a git repository", file=sys.stderr)
            return 2
    else:
        if not argv:
            print("pii-tripwire: scan what? give files or folders, or --staged", file=sys.stderr)
            return 2
        sources = {p: _FROM_DISK for a in argv for p in _walk(a)}      # read block by block below
    found = unchecked = 0
    for path, staged in sources.items():
        try:
            if staged is None:                                          # a staged blob git could not show
                raise OSError(path)
            blocks = _blocks(path) if staged is _FROM_DISK else iter([(0, staged, True)])
            for first_line, raw, first in blocks:
                if first and b"\0" in raw[:8000]:
                    print(f"pii-tripwire: {path}: skipped (binary)", file=sys.stderr)
                    break
                text = raw.decode("utf-8", "replace")
                for n, cat in (scan_text(data, text) if data is not None else []):
                    print(f"{path}:{first_line + n}: {NAMES[cat]} from your private list")
                    found += 1
                for n, cat in (scan_patterns(text) if patterns else []):
                    print(f"{path}:{first_line + n}: {PATTERN_NAMES[cat]}")
                    found += 1
        except OSError:
            # a path that was not checked is never a pass: a typo or an unexpanded glob must not read as "clean"
            print(f"pii-tripwire: {path}: NOT CHECKED (cannot read it)", file=sys.stderr)
            unchecked += 1
        except _LineTooLong as e:
            print(f"pii-tripwire: {path}: INCOMPLETE (line {e.args[0]} is over {MAX_LINE:,} bytes; checked up to it)",
                  file=sys.stderr)
            unchecked += 1
    if found:
        return 1
    return 2 if unchecked else 0


class _LineTooLong(Exception):
    pass


_FROM_DISK = object()          # a scan source read from the file itself (staged sources carry their bytes)


def _blocks(path):
    """(lines before this block, bytes, first?) over the WHOLE file, about MAX_TEXT at a time, cut only at line ends so
    no value is split and the line numbers stay true. f.read(MAX_TEXT) used to stop at 2 MB and the rest was reported
    clean (external review, 25.10)."""
    with open(path, "rb") as f:
        carry, before, first = b"", 0, True
        while True:
            chunk = f.read(MAX_TEXT)
            buf = carry + chunk
            if not chunk:
                if buf:
                    yield before, buf, first
                return
            cut = buf.rfind(b"\n") + 1
            if cut == 0:
                if len(buf) > MAX_LINE:
                    raise _LineTooLong(before + 1)
                carry = buf
                continue
            yield before, buf[:cut], first
            first = False
            before += buf[:cut].count(b"\n")
            carry = buf[cut:]


SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv"}


def _walk(p):
    """A file is itself; a folder is every file under it (version-control and dependency folders left out)."""
    if not os.path.isdir(p):
        yield p
        return
    for root, dirs, files in os.walk(p):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            yield os.path.join(root, name)


def is_outbound(tool, tool_input):
    if tool in OUTBOUND_TOOLS or tool.startswith("mcp__"):
        return True
    if tool in SHELL_TOOLS:
        return bool(NETWORK.search(str((tool_input or {}).get("command", ""))))
    return False


# ---------- the hook ----------

def _decide(decision, reason):
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision,
                                             "permissionDecisionReason": "pii-tripwire: " + reason}}))
    return 0


def run_hook(stdin_text, list_path=None):
    path = list_path or os.environ.get("PII_TRIPWIRE_LIST") or DEFAULT_LIST
    try:
        event = json.loads(stdin_text or "{}")
        tool, tool_input = event.get("tool_name", ""), event.get("tool_input") or {}
    except (ValueError, AttributeError):
        # an input it cannot read is not a pass: with a list to guard, the call is asked about (it used to be allowed)
        if os.path.exists(path):
            return _decide("ask", "the hook input could not be read, so this call was not checked. "
                                  "Look at it yourself before allowing it.")
        return 0
    if not is_outbound(tool, tool_input):
        return 0
    if not os.path.exists(path):
        return 0
    try:
        data = load(path)
        hits = find(data, "\n".join(_strings(tool_input)))
    except Exception:  # noqa: BLE001 — a broken list must not wave an outbound call through
        return _decide("ask", "the private list could not be read, so this outbound call was not checked. "
                              "Look at it yourself before allowing it.")
    if not hits:
        return 0
    what = " and ".join(NAMES[c] for c in CATEGORIES if c in hits)
    return _decide("deny", f"this call would send {what} from your private list outside this machine. "
                           "Remove it from the call. If sending it is really intended, ask the user to do it "
                           "themselves.")


# ---------- install ----------

def install(settings_path, script=None):
    script = (script or os.path.abspath(__file__)).replace("\\", "/")
    # the interpreter that runs install, by full path: a bare `python` is often not on PATH on Windows (only `py`),
    # and a hook that cannot start does not block - the tripwire would be silently off
    py = '"' + os.path.abspath(sys.executable).replace("\\", "/") + '"'
    data = {}
    if os.path.exists(settings_path):
        with open(settings_path, encoding="utf-8") as f:
            data = json.load(f)
        shutil.copy2(settings_path, settings_path + ".bak")
    entries = data.setdefault("hooks", {}).setdefault("PreToolUse", [])
    command = f'{py} "{script}" hook'
    ours = [c for h in entries for c in h.get("hooks", []) if "pii_tripwire.py" in c.get("command", "")]
    if ours:
        for c in ours:                       # a reinstall repairs an old entry (bare `python`, a moved script)
            c["command"] = command
    else:
        entries.append({"matcher": "^(WebFetch|WebSearch|Bash|PowerShell)$|^mcp__",
                        "hooks": [{"type": "command", "command": command}]})
    os.makedirs(os.path.dirname(os.path.abspath(settings_path)), exist_ok=True)
    with open(settings_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return settings_path


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    cmd = argv[0] if argv else "--help"
    path = os.environ.get("PII_TRIPWIRE_LIST") or DEFAULT_LIST
    if cmd in ("-h", "--help"):
        print(__doc__ + "\nusage: pii_tripwire.py add phone|email|id   (asks for the value, so it stays out of your "
              "shell history)\n       pii_tripwire.py list | install [SETTINGS] | hook"
              "\n       pii_tripwire.py scan <files...> | scan --staged   (before a commit; exit 1 on a find)")
        return 0
    if cmd == "scan":
        return scan(argv[1:], path)
    if cmd == "add":
        if len(argv) < 2 or argv[1] not in CATEGORIES:
            print("usage: pii_tripwire.py add phone|email|id", file=sys.stderr)
            return 2
        if len(argv) > 2:
            value = argv[2]                  # works, but the value stays in shell history
        elif not sys.stdin.isatty():
            value = sys.stdin.readline().strip()   # piped: echo ... | add phone (getpass would wait for a console)
        else:
            value = getpass.getpass(f"{argv[1]} (not shown): ")
        try:
            add(path, argv[1], value)
        except ValueError as e:
            print(f"pii-tripwire: {e}", file=sys.stderr)
            return 2
        print(f"added one {argv[1]} to {path} (stored as a salted hash)")
        return 0
    if cmd == "list":
        if not os.path.exists(path):
            print("no list yet: pii_tripwire.py add phone|email|id")
            return 0
        print(", ".join(f"{n} {c}" for c, n in sorted(counts(path).items())) + f"  ({path})")
        return 0
    if cmd == "hook":
        return run_hook(sys.stdin.buffer.read().decode("utf-8", "replace"))
    if cmd == "install":
        target = argv[1] if len(argv) > 1 else os.path.join(os.path.expanduser("~"), ".claude", "settings.json")
        print(f"installed into {install(target)} (a .bak was left next to it)")
        return 0
    print(f"unknown command {cmd!r}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
