# pii-tripwire

Stop Claude Code from sending your phone numbers, emails and document numbers out.

> RU: ты сказал агенту «не трогай мои личные данные», а он всё равно вставил телефон в запрос. pii-tripwire держит твой личный список (только солёные хэши) и не пускает наружу вызов, в котором есть что-то из него.

## What hurts

An agent was told not to use someone's personal data, and leaked it anyway. A rule in the prompt is a wish. A check at the moment a tool call leaves the machine is a wall.

## What it does

You keep a private list of your own identifiers. A `PreToolUse` hook checks every **outbound** call against it:

- `WebFetch`, `WebSearch`, any MCP tool (`mcp__…`);
- shell commands that talk to the network: `curl`, `wget`, `git push`, `gh`, `ssh`, `scp`, `rsync`, `Invoke-WebRequest`, `Send-MailMessage`…

If the call holds a value from your list, written any usual way, it is **denied**:

| on the list | also caught as |
|---|---|
| `+380501234567` | `+38 050 123 45 67`, `(050) 123-45-67`, `0501234567`, `%2B380501234567` |
| `Jane.Roe@Example.test` | `jane.roe@example.test`, `JANE.ROE@EXAMPLE.TEST`, `jane.roe%40example.test` |
| `AB 123456` | `ab123456`, `AB-12 34 56` |

The deny names the **category** ("a phone number from your private list"), never the value, so Claude can remove it without the value turning up in another message. Local tools (`Write`, `Edit`, `echo … >> file`) are not its business. Calls are not logged.

The list stores **salted SHA-256 hashes**, not the values: a random salt per list, file mode 600 on macOS and Linux. If the list cannot be read, an outbound call is not waved through: the hook asks you.

Standard library only, Python 3.8+.

## Install

```sh
curl -O https://raw.githubusercontent.com/klavdiy-core/pii-tripwire/main/pii_tripwire.py
python pii_tripwire.py add phone        # asks for the value, so it stays out of your shell history
python pii_tripwire.py add email
python pii_tripwire.py add id           # passport, tax number, IBAN...
python pii_tripwire.py list             # counts only: "1 email, 1 id, 1 phone"
python pii_tripwire.py install          # adds the hook to ~/.claude/settings.json (a .bak is left)
```

The list lives in `~/.claude/pii-tripwire/list.json` (or `PII_TRIPWIRE_LIST`).

## What it does not catch (said plainly)

- **Names and street addresses.** Declension, transliteration and spelling make them unmatchable without many false alarms. v1 does structured identifiers only.
- **Data that leaves inside a file.** `curl -F @contacts.csv`, or `git push` of a commit whose *files* contain the number: the hook sees the command, not the file.
- **Encoded data.** Base64, hex, or any other re-encoding of the value.
- **The chat itself.** It guards tool calls. It cannot stop the model from writing the value in its answer to you.
- **Network tools it doesn't know by name.** A custom script that uploads things looks like a local command.
- **On Windows** file mode 600 does nothing; the list is still hashes only.

It is a tripwire for the common accident, not a data-loss-prevention system.

## Test

```sh
python -m unittest discover -s tests
```

A phone in another notation, in national form, URL-encoded; emails in any case and percent-encoded; document numbers with and without separators; the same call without the data passing; local tools and local shell commands passing; `git push`, `gh` and `Invoke-WebRequest` checked; short numbers not tripping it; no plain values in the list; separate salts per list; a broken list asking; no list doing nothing; the deny reason never holding the value. Every check here was broken on purpose to see a test go red. All values in the tests are fictional.

## License

MIT
