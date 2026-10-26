# pii-tripwire

Stop Claude Code from sending your phone numbers, emails and document numbers out.

```text
$ echo '{"tool_name":"WebFetch","tool_input":{"url":"https://example.test/?q=+38 050 123 45 67"}}' | python pii_tripwire.py hook
… "permissionDecision": "deny", "permissionDecisionReason": "pii-tripwire: this call would send a phone number from your private list outside this machine. …"

$ python pii_tripwire.py scan notes.md
notes.md:1: a phone number from your private list
```
That is the whole idea: the number was on your list as `+380501234567`, it was written differently, and it still did not get out. The value itself is never printed.

> RU: ты сказал агенту «не трогай мои личные данные», а он всё равно вставил телефон в запрос. pii-tripwire держит твой личный список (только солёные хэши) и не пускает наружу вызов, в котором есть что-то из него.

## What hurts

An agent was told not to use someone's personal data, and leaked it anyway. A rule in the prompt is a wish. A check at the moment a tool call leaves the machine is a wall.

## What it does

You keep a private list of your own identifiers. A `PreToolUse` hook — a small program Claude Code runs before every tool call, which can allow or deny it ([Claude Code hooks](https://docs.anthropic.com/en/docs/claude-code/hooks)) — checks every **outbound** call against it:

- `WebFetch`, `WebSearch`, any MCP tool (`mcp__…`);
- shell commands that talk to the network: `curl`, `wget`, `git push`, `gh`, `ssh`, `scp`, `rsync`, `Invoke-WebRequest`, `Send-MailMessage`…

If the call holds a value from your list, written any usual way, it is **denied**:

| on the list | also caught as |
|---|---|
| `+380501234567` | `+38 050 123 45 67`, `(050) 123-45-67`, `0501234567`, `%2B380501234567` |
| `Jane.Roe@Example.test` | `jane.roe@example.test`, `JANE.ROE@EXAMPLE.TEST`, `jane.roe%40example.test` |
| `AB 123456` | `ab123456`, `AB-12 34 56` |

Only whole values count, so it does not cry wolf on git work: an ID inside a commit hash (`9fab123456c0de`), two words that happen to glue into it (`grade AB, 123456 views`), or a long order number that ends with your phone's digits all pass.

The deny names the **category** ("a phone number from your private list"), never the value, so Claude can remove it without the value turning up in another message. Local tools (`Write`, `Edit`, `echo … >> file`) are not its business. Calls are not logged.

The list stores **salted SHA-256 hashes**, not the values: a random salt per list, file mode 600 on macOS and Linux. If the list cannot be read, an outbound call is not waved through: the hook asks you.

Standard library only, Python 3.8+.

## Install

```sh
curl -O https://raw.githubusercontent.com/klavdiy-core/pii-tripwire/main/pii_tripwire.py
python pii_tripwire.py add phone        # asks for the value, so it stays out of your shell history
echo "+380501234567" | python pii_tripwire.py add phone   # or piped, for scripts
python pii_tripwire.py add email
python pii_tripwire.py add id           # passport, tax number, IBAN...
python pii_tripwire.py list             # counts only: "1 email, 1 id, 1 phone"
python pii_tripwire.py install          # adds the hook to ~/.claude/settings.json (a .bak is left)
```

The list lives in `~/.claude/pii-tripwire/list.json` (or `PII_TRIPWIRE_LIST`).

`install` writes the full path of the Python that ran it into the hook, so the hook starts even where a bare `python`
is not on PATH. Moved the file or changed Python? Run `install` again — it repairs its own entry instead of adding a
second one; your other hooks, even one that names `pii_tripwire.py`, are left as they are. `settings.json.bak` is made
once, before the first install, and kept: a reinstall does not replace your original with a copy that already holds
the hook. If `settings.json` is broken or shaped unexpectedly, install says so and writes nothing. (Before 0.3.3 the
hook said just `python`: on a Windows machine with only the `py` launcher it could not start, and a hook that cannot
start does not block anything.)

On Windows: use `py` if `python` is not on your PATH; `~` is your user folder, so the settings file is
`C:\Users\<you>\.claude\settings.json`. In PowerShell `curl` may be an alias — `curl.exe -O …` or download the file.

**Check that it works** — feed the hook a fake call with a number from your list, written another way:

```sh
echo '{"tool_name":"WebFetch","tool_input":{"url":"https://example.test/?q=<your number, spaced differently>"}}' | python pii_tripwire.py hook
```
You should see `"permissionDecision": "deny"`. The same call without the number prints nothing and exits 0 — the call is let through.

## Before a commit: scan the files

The hook sees commands, not files. To check the files themselves, against the same list and with the same matching:

```sh
python pii_tripwire.py scan notes.md docs/*.md   # given files
python pii_tripwire.py scan --staged             # exactly what the next commit will hold (the index, not the working copy)
```

Each find is printed as `path:line: a phone number from your private list` — the category, never the value. A folder is scanned file by file (`.git`, `node_modules` and virtualenvs left out). Exit 1 on a find, 0 when clean, 2 when there is no list yet, no paths were given, or any path could not be read (a typo, an unexpanded glob): a path that was not checked is never a pass. Binary and unreadable files are named as skipped. As a git hook: `python /path/to/pii_tripwire.py scan --staged` in `.git/hooks/pre-commit`.

**No list needed: `--patterns`.** `scan --patterns --staged` (or with files) also looks for common shapes, with or
without your list: a phone in international form (`+` and 8–15 digits), an email address, a payment card number (a
network's first digit and a valid Luhn sum), an IBAN (valid check digits), and the shapes of secrets: GitHub tokens
(`ghp_…`, `github_pat_…`), `sk-…` API keys, Slack `xox…-` tokens, Telegram bot tokens, AWS access key ids and
`-----BEGIN … PRIVATE KEY-----`. Each find says what it is, never the value. Dates, commit hashes, versions, message
numbers, a public key, digits inside a longer token (a hex hash in a lockfile URL), digit groups with mixed
separators (`20261025 2026-10-25`), `noreply@…` addresses and placeholder domains (any `example` domain such as
`example.com` or `example.co.uk`, and `.test`, `.invalid`, `localhost`) do not match. A national phone number without `+`
is not caught by the patterns; put your own in the list for that.

## Internal paths in a public repo: `--roots`

Your own folder names leak too: a test written in a private setup carries `C:\\Work Notes\\audit.json` into a public
repo. List the roots that must never appear, one per line (`#` for comments), and scan with them:

```sh
python pii_tripwire.py scan --roots ~/.config/my-roots.txt --staged      # e.g. in .git/hooks/pre-commit
```

A root matches inside any path, in any case and with either slash, including the doubled backslashes of a path
written in source code; `C:\Notes` does not match `C:\Notesbook`. A find is printed as
`file:line: an internal path from your roots list` - never the root itself. A roots file that cannot be read as UTF-8
(UTF-16 from PowerShell 5, for one) or holds no roots is exit 2, not a pass; a UTF-8 BOM is fine.
Keep the roots file **outside** the repo you scan: unlike the identifier list it is plain text (a root has to match
inside longer paths, so it cannot be hashed), so it stays private by where it lives.

## Next to the secret scanners

For secrets in your code, use a real secret scanner — they are far more thorough than this. pii-tripwire is for a
narrower thing. Cells are from each project's own README (26.10.2026).

| | pii-tripwire | [gitleaks](https://github.com/gitleaks/gitleaks) | [trufflehog](https://github.com/trufflesecurity/trufflehog) |
|---|---|---|---|
| looks for | **your own list**: your phone, email, document numbers, in any usual spelling | secrets, by regex rules | leaked credentials, by many detectors, and it **verifies** them |
| when | **the moment a Claude Code tool call would send it out** (a hook that denies the call), plus `scan` of files | pre-commit hook, CI action, scans of git repos, directories, stdin | pre-commit hook, GitHub Action, scans of git repos, filesystems, object stores, wikis, chats, logs and more |
| licence | MIT | MIT | AGPL-3.0 |

If your worry is an API key in a commit: gitleaks or trufflehog. If it is an AI agent pasting your own phone number
into a web request — written as `(050) 123-45-67` while your list says `+380501234567` — that is what this was built for.

## What it does not catch (said plainly)

- **Names and street addresses.** Declension, transliteration and spelling make them unmatchable without many false alarms. v1 does structured identifiers only.
- **Data that leaves inside a file.** `curl -F @contacts.csv`, or `git push` of a commit whose *files* contain the number: the hook sees the command, not the file. For commits, run `scan --staged` before committing (above).
- **Encoded data.** Base64, hex, or any other re-encoding of the value.
- **The chat itself.** It guards tool calls. It cannot stop the model from writing the value in its answer to you.
- **Network tools it doesn't know by name.** A custom script that uploads things looks like a local command.
- **A hand-off to a sub-agent** (`Task`) is not checked itself; the sub-agent's own outbound calls go through the same hook.
- **On Windows** file mode 600 does nothing; the list is still hashes only.
- **One very long line** (8 MB or more with no line end; the exact point is 8-10 MB, by how reads fall) is not checked: the file is reported `INCOMPLETE` and the scan exits 2,
  never "clean". Files of any size are otherwise read whole, 2 MB at a time, and a hook call of any size is checked
  in overlapping windows. Before 0.3.2 everything past the first 2 MB was skipped and the result still said clean —
  found by an external review, fixed in 790264d.

It is a tripwire for the common accident, not a data-loss-prevention system.

## Test

```sh
python -m unittest discover -s tests
```

A phone in another notation, in national form, URL-encoded; emails in any case and percent-encoded; document numbers with and without separators; the same call without the data passing; local tools and local shell commands passing; `git push`, `gh` and `Invoke-WebRequest` checked; short numbers not tripping it; no plain values in the list; separate salts per list; a broken list asking; no list doing nothing; the deny reason never holding the value; no false alarm inside hashes, glued words or numbers longer than a phone can be (over 15 digits; a shorter run that ends in your digits is flagged, since it may be your number with another prefix); a piped `add`; `scan` catching three spellings of a phone in a file but not a commit hash or an order number, never printing the value, checking the staged copy rather than the working one, skipping binary, missing and deleted files. Every check here was broken on purpose to see a test go red. All values in the tests are fictional.

## License

MIT
