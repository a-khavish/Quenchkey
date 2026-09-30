# Contributing

Bug reports, fixes and honest criticism are all welcome. Please read the short
section on honesty below before opening a pull request that adds a feature —
it is the one thing here that is not negotiable, and knowing it in advance
saves everybody's time.

## Getting set up

```bash
git clone https://github.com/a-khavish/Quenchkey
cd quenchkey
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pip install ruff
```

Then:

```bash
python -m pytest                                   # 602 tests, about three minutes
python -m ruff check --select F,E --line-length 100 .
xvfb-run -a python tools/dialog_parade.py          # every dialog, on a small screen
```

The interface tests need a display. `xvfb-run` is enough; a real desktop is
better, because a window manager behaves differently from none and several
bugs in this project were only visible under one.

## The honesty rule

This tool exists because most "self-destructing file" software claims things
it cannot do. So:

- **Do not add a feature that cannot do what its name says.** No screenshot
  blocking. No "only our app can open these files". No folders made
  inaccessible by permissions or hiding, presented as protection.
- **Do not describe local state as tamper-proof.** Expiry on a machine
  somebody else controls is tamper-*evident*. The event log and the anchor are
  how that is detected, and detection is what gets claimed.
- **Do not imply an opened file can be recalled.** It cannot. Anything already
  extracted, printed or forwarded is gone from this tool's reach, and every
  dialog that writes a file says so.
- **Say the limitation where the person is**, not in a footnote. If a feature
  has a caveat, the caveat belongs in the dialog that offers the feature.
- **No "military-grade encryption"** or any other phrase that sounds like a
  claim and is not one. Name the primitive and the parameters instead.

A patch that makes the tool sound better than it is will be declined however
well it is written. A patch that makes an existing claim weaker but truer is
the most welcome kind there is.

## Tests

Every change needs a test, and the test should fail for the right reason
before the change. Two habits worth copying from the existing suite:

- **Test the negative claims.** `test_no_file_key_is_anywhere_in_the_record`
  looks for a live entry's key in the audit record's plaintext. `test_a_copy_
  made_by_hand_survives_a_loan` asserts a limitation rather than a capability.
  These are the tests that stop a claim rotting.
- **Prefer the real thing to a mock.** The timestamp tests stand up an actual
  RFC 3161 authority with openssl. The interface tests drive real X input
  events. A mocked timestamp proves the mock was called.

Name tests as sentences: `test_a_moved_file_is_found_by_digest_and_relinked`,
not `test_search_2`.

## Style

- Four spaces, 100 columns, no trailing whitespace.
- Comments explain *why*, not *what*. A comment that restates the code is
  worse than none.
- Docstrings on anything a reader would otherwise have to reverse-engineer,
  especially where the design is a trade-off rather than an obvious choice.
- British spelling in prose, because the rest of it is.
- No emoji in code, comments, commit messages or interface text.

## Cryptography

Changes to the vault format, the blob format, the KDF parameters, or anything
in `crypto.py` need:

- a reason in the commit message that a reviewer can check;
- a test that the old format still reads, if the change is to a format;
- a note in `SECURITY.md` if it changes what an attacker has to do.

Do not roll a primitive. Everything here is from `cryptography` and
`argon2-cffi`, and the one place that builds a structure by hand — the RFC
3161 request — does so because it is small enough to read, and hands
verification straight back to openssl.

## Commits

One change per commit, with a message that says what and why:

```
Lock edits back in when a loan is brought back

A checkout that shredded the working copies discarded any work done in
them, and the overdue sweep did it without being asked. Fingerprint each
file on the way out so check-in can tell an edit from an untouched copy,
and write an edited one back into the same entry under the same key.
```

