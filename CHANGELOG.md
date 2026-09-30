# Changelog

Versions follow [semantic versioning](https://semver.org).

## 1.0.0 — 2026-09-30

First release. Nothing was published before it, so there is nothing here to
migrate from and no deprecations to read: what follows is what the release
contains, arranged by what it is for.

### The idea

The encrypted file and its key live in different places. When a file expires
it is the **key** that is destroyed, not the file — so every scattered copy
becomes permanently unreadable at the same instant, including the ones on a USB
stick, in an email attachment and in a backup you had forgotten about. This is
cryptographic erase, the mechanism NIST SP 800-88 Rev. 1 recommends for media
you cannot physically reach.

- Argon2id, calibrated on the machine it runs on to about a second per guess
  (measured here at 256 MiB, one pass, parallelism 4).
- ChaCha20-Poly1305 or AES-256-GCM, with headers authenticated as associated
  data.
- Chunked streaming AEAD for payloads — 1 MiB chunks, nonce of a random
  4-byte prefix and an 8-byte counter — so memory stays flat for any file size
  and a truncated file is refused rather than partly decrypted.

### Deadlines

Four ways for a key to die, combinable per entry, whichever comes first:

- a wall-clock deadline;
- an opening allowance (three opens, then the key goes);
- a check-in interval — a dead man's switch, destroyed if the vault is not
  opened in time;
- on demand, immediately.

Enforced by a systemd user timer as well as by the running application, so a
deadline passes whether or not anything is open. A clock set backwards is
caught by a watermark the vault never lets go backwards, and reported.

**Warnings before it happens.** A week out, a day out, and within the hour,
each said once. Moving a deadline arms its warnings again, because a different
moment is a different thing to be told about. The background task, which has
no passphrase, says how many and how soon but never which file — the names
are inside the vault and stay there.

### Evidence

- A hash-chained event log, with a short anchor fingerprint to publish
  somewhere you do not control.
- **Timestamps from an authority** (RFC 3161), so the anchor is signed by a
  party neither you nor an auditor controls, and so the vault can take
  somebody else's reading of the time and move its watermark forward on it.
  Off unless you ask for it; only a hash leaves the machine; verified against
  a certificate you supply, and honestly reported as unverified without one.
- Ed25519-signed certificates of destruction that verify with **no passphrase
  and no vault**.
- The custodian's name and role on every certificate.
- **A record for an auditor**: a separate file beside the vault, under a
  passphrase of its own, holding every entry's rules, each destruction and its
  reason, the whole event chain and the certificates — and no file key in any
  form, because the record is built from the vault rather than carved out of
  it. Signed with the same key that signs certificates, so an auditor holding
  one of those can confirm where the record came from.
- `quenchkey-recover`, a standalone tool that imports nothing from this
  project and reads the vault, the chain, the certificates, shared files and
  audit records.

### Getting in

- A passphrase strength estimator that reports a genuine upper bound rather
  than a flattering one, using shortest-path segmentation over a dictionary,
  keyboard walks, dates and repeats.
- Generated passphrases: 24 random characters across all four classes, priced
  at exactly 157.2 bits by inclusion–exclusion rather than estimated, and
  copied into the confirmation field so nobody retypes them.
- A keyfile or a FIDO2 security key as a second factor.
- SLIP-39 recovery shares, any *k* of *n*, as word lists you can write on
  paper.
- Auto-lock on idle, with keys wiped from memory on lock.

### Working with files

- Lock files or folders into the vault; shred the originals if you want.
- **Loans.** Open on loan instead of for good: the paths are recorded, and
  when the loan ends the working copies are cleared away. Edits made while it
  was out are **locked back into the vault**, not shredded — each file is
  fingerprinted on the way out, an untouched copy leaves the vault
  byte-for-byte as it was, and an edited one is written back under the same
  key with its deadline and opening count intact. If the edits cannot go back,
  nothing is shredded and the app says why.
- **Watched folders.** Drop a file in and it is locked a few seconds later on
  a preset rule, original shredded. Only while the vault is unlocked, and only
  once the file has stopped changing — both said on screen, because both are
  structural.
- **Shared files** that carry their own key and open anywhere with no vault,
  and which declare in their header that they have no deadline and cannot be
  given one. Batch-unlock several at once, extracted in place or repacked
  without a password.
- **Handing files over to another vault**, which is the way round that
  limitation. The key is wrapped to the recipient's vault instead of to a
  passphrase, so when they accept it the deadline lands in their vault and
  their own sweep enforces it. Each vault derives an X25519 identity from the
  signing seed it already has; the identity card carries that public key and a
  signature over it, which anybody can check with no passphrase. The terms
  travel inside the file, authenticated, so the recipient reads them before
  deciding and neither side can change them afterwards.
- **Checking the locked files.** Every entry records its file's SHA-256 at
  lock time; this reads them all back and reports intact, altered or missing.
  For a missing one, searching a folder matches candidates by digest rather
  than by name, and pointing an entry at where its file actually is changes
  the path and nothing else.

### Safety net

- **Vault backups**, with the price of restoring one stated first: how many
  events would be undone and how many destroyed keys would come back. Needs
  `ROLL BACK` typed, keeps the vault it replaced, and writes the rollback
  permanently into the restored chain.
- **A duress passphrase** that destroys the vault instead of opening it. It
  cannot do anything subtler, and the reason is in the design: it does not
  derive the master key, so nothing derived from it can decrypt anything.
  What it can do is overwrite the file, which needs no key.

### From a terminal

`quenchkey lock report.pdf --expires 90d` and seventeen more commands — `ls`,
`status`, `open`, `check-in`, `sweep`, `expire`, `check`, `warn`, `audit`,
`stamp`, `share`, `deposit`, `hand-over`, `accept`, `card`, `backup`, `help`.
One binary: `quenchkey` on its own opens the window, and Qt is never imported
on the terminal path, so the command line works over SSH and in a container.

`quenchkey help` is one page grouped by what you are trying to do rather than
alphabetically, coloured where colour distinguishes something: red for a thing
that has just become unreadable or is about to, amber for a thing that wants a
decision, green for a thing that went as asked, nothing else coloured at all.
Colour switches itself off when output is not a terminal, when `NO_COLOR` is
set, when `TERM` is `dumb`, and whenever `--json` is asked for.

**The vault's passphrase comes from a prompt and from nowhere else.** Not an
argument, because arguments are visible to every process and land in shell
history. Not an environment variable, because it is inherited by every child
process and ends up in systemd units and CI logs. Not a file, because a file
holding a vault's passphrase is the one thing this tool tells you not to make.

So the commands that need the vault open cannot run unattended, which is the
design rather than an oversight — a tool that says never to write your
passphrase down, and then ships an option for doing exactly that, is not
saying it very hard.

**A cron job does not need them.** `quenchkey deposit` locks files into your
own vault using nothing but your identity card, which holds no secret: the file
key is wrapped to the vault's public identity, so the file is unreadable the
moment it is written, by anybody, including the script that wrote it. You
accept them next time you open the vault, on the terms the job proposed.

Two secrets that are not the vault's may still come from the environment,
because leaking either costs something bounded rather than everything: an
audit record's passphrase, which opens metadata and no documents, and a shared
file's own passphrase, which opens one file.

`status`, `check` and `warn` exit 4 rather than 0 when they find something, so
a monitoring job can watch a vault without parsing prose.

### On the desktop

- Your own file manager's chooser, through the XDG desktop portal, rather than
  a home-made one.
- An applications-menu entry, hicolor icons, and a registered `.qkey` type.
- Minimise to tray, quit, or ask — and autostart on login.
- Per-kind output destinations: always this folder, or ask every time.
- A seventeen-page manual inside the application, searchable.
- In-app uninstall that leaves the vault alone. It requires an unlocked vault,
  and the dialog says plainly that this is friction rather than security:
  removing the application has never given anybody access to anything, and
  deleting the vault does the opposite of unlocking it.
- Opens filling the screen and stays resizable. The action row folds onto a
  second line and the page scrolls, so the window works at any size with
  nothing hidden — including a 1366×768 display at 200% text.

### What it does not do, said in the application as well as here

There is a menu item called *What this does not protect against*. It says that
local expiry is tamper-evident and not rollback-proof; that a file already
opened cannot be recalled; that a shared file can never expire; that failed-
attempt lockout is a convenience and not a security boundary; and that the
passphrase is the actual security. There is no screenshot blocking, no claim
that only this application can open these files, no "military-grade
encryption", and no pretence that local state is tamper-proof.

### Verification that ships with it

- 617 tests covering the round trip, wrong passphrases, tamper detection on
  every field, the clock ratchet, the strength estimator's upper-bound
  contract, and the negative claims — that no file key is in an audit record,
  that a handover cannot be opened by its sender, that a copy made by hand
  survives a loan.
- A dialog parade that opens all 26 dialogs at four text scales and fails if a
  button lands off-screen or a label is clipped.
- A recorded walkthrough that is itself a test: it drives the real application
  under a real window manager with real X input events, finds each control by
  the label a person would read, and fails if one is missing or does not do
  what it says. The standalone tool then re-reads what the interface built.
- The timestamp tests stand up an actual RFC 3161 authority with openssl and
  talk to it over HTTP, rather than mocking the protocol.
