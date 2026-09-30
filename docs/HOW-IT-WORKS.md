# How Quenchkey works, in detail

This is the technical companion to the [README](../README.md). The README
explains what the program does and how to use it. This file explains how it is
built, what it is made of, and exactly what it can and cannot promise.

If you are deciding whether to trust this with something that matters, this is
the file to read. Everything in it is checkable against the source.

---

## Contents

- [One passphrase, and keys you never see](#one-passphrase-and-keys-you-never-see)
- [What it actually does, step by step](#what-it-actually-does)
- [Why this and not VeraCrypt, 7-Zip, age or Cryptomator](#why-this-and-not-veracrypt-7-zip-age-or-cryptomator)
- [The event log is a hash chain, and you can anchor it](#the-event-log-is-a-hash-chain-and-you-can-anchor-it)
- [Certificates of destruction](#certificates-of-destruction)
- [Recovery shares](#recovery-shares)
- [Openings, deadlines and the dead man's switch](#openings-can-be-counted)
- [A security key as a second factor](#a-security-key-as-a-second-factor)
- [Carrying the vault, and life without this tool](#carrying-the-vault-and-life-without-this-tool)
- [What this does not protect against](#what-this-does-not-protect-against)
- [Prior art, and a cautionary tale](#prior-art-and-a-cautionary-tale)
- [Project layout](#project-layout)

---

## One passphrase, and keys you never see

You memorise **one** passphrase. That is the only secret you ever type, and the
only one you can lose.

Every item you lock gets its **own** 256-bit key, generated fresh from
`os.urandom`. You never see those keys, never type them, never store them
anywhere. They live in the vault, and the passphrase is what unwraps the vault.

```
        your passphrase
              │
              ▼
        Argon2id  ──►  master key ──► unwraps the vault
                                          │
                                          ├── key for holiday-photos.qkey
                                          ├── key for term-sheet.qkey
                                          └── key for board-pack.qkey
                                                  (256 random bits each,
                                                   generated, never typed)
```

**The two-layer design is what makes expiry possible at all.** A key derived
from your passphrase could always be derived again by typing the passphrase
again — nothing could ever truly expire, because the ingredients to rebuild it
would still be in your head. A random key that exists in exactly one place can
be destroyed, and once it is, there is nothing left to rebuild it from.

It also means changing your passphrase is cheap: a new master key is derived
and the vault re-encrypted under it, while the per-file keys are untouched, so
everything you locked previously still opens. (Recovery shares reconstruct the
*master* key, so a passphrase change does invalidate them — see below.)

---

---

## What it actually does

### Cryptography

No primitive is implemented in this project.

| | |
|---|---|
| Key derivation | **Argon2id**, from `argon2-cffi`. Calibrated at vault creation to about one second on your machine — 256 MiB and four passes on typical hardware. Salt and cost parameters are stored in the vault header. |
| Cipher | **ChaCha20-Poly1305** by default, **AES-256-GCM** available. Both from `cryptography`, which wraps OpenSSL. |
| Per-file keys | A fresh 256-bit key from `os.urandom` for every locked item. File keys are never derived from the passphrase. |
| Large files | Encrypted in 1 MiB chunks, each authenticating its own index and whether it is the last. Chunks cannot be reordered, duplicated, dropped or spliced in from another file, and the stream cannot be truncated unnoticed. |

Authentication is not optional anywhere. Every piece of metadata — expiry
dates, timestamps, the clock watermark, the KDF parameters themselves — sits
inside an authenticated region, so editing any of it breaks the tag and the
file refuses to open rather than opening with altered terms.

### The vault

One file. A small cleartext header, then a single authenticated-encrypted
region holding everything else.

```
offset  size  field
0       8     magic  b"QKEYVALT"
8       1     format version
9       1     KDF id           (1 = Argon2id)
10      1     cipher id        (1 = ChaCha20-Poly1305, 2 = AES-256-GCM)
11      1     flags            bit 0 = a keyfile is required
12      16    Argon2 salt                 }
28      4     Argon2 time cost            } passed to the cipher as
32      4     Argon2 memory cost (KiB)    } associated data, so it is
36      4     Argon2 parallelism          } covered by the auth tag
40      12    nonce
52      ...   ciphertext || 16-byte tag
```

Inside: the clock watermark, one entry per locked item (path, key, dates,
original filenames), and an event log. The payload is a length-prefixed binary
structure rather than JSON, so raw key bytes are read into a `bytearray` that
can be wiped afterwards instead of passing through immutable `str` objects.

Saving is atomic: write a temporary file, `fsync`, overwrite the old file's
bytes with random data, then `os.replace`.

### The locked file

```
offset  size  field
0       8     magic  b"QKEYLOCK"
8       1     format version
9       1     cipher id
10      2     reserved
12      16    entry id (links the blob to its vault entry)
28      4     nonce prefix
32      4     chunk size
36      8     plaintext length
44      ...   chunk 0 || chunk 1 || ...
```

The 44-byte header is the associated data for every chunk. **There is no key in
this file**, and nothing in it that can be used to derive one.

The selection is packed into a 7z archive first — store-only, since ciphertext
does not compress and compressing before encrypting leaks information about the
plaintext through the output length. The archive is encrypted with encrypted
headers (`-mhe=on`), using a password derived from the per-file key via HKDF.
**That inner layer adds nothing to the security of the finished `.qkey` file**
— the whole archive is already inside Quenchkey's own authenticated
ciphertext. It is there because packing has to produce a seekable file before
it can be encrypted, and this way that temporary file is never plaintext on
disk. Because the password comes from the file key, it dies with it.

### Expiry

Checked in two places, because neither alone is enough: on a timer while the
app is open, and lazily on every unlock, in case the app has not run for a
month.

The clock used is never earlier than the highest value the vault has ever
recorded. Winding the system clock backwards does not extend a deadline, and a
backwards step is refused outright at unlock with an explanation — you can
override it, and the override is written to the event log.

When a deadline passes, the key is overwritten with zeros in the vault and the
vault is rewritten. Deleting the `.qkey` file as well is optional and off by
default, because the point is that deleting it was never necessary.

### Passphrases

The Generate button produces seven words drawn with `secrets.randbelow` from a
built-in 2048-word list: **77 bits, exactly**, not an estimate. Every word is
4–7 lowercase letters with a unique three-letter prefix.

For a passphrase you type yourself, the meter prices the string the way a
cracker would — finding the cheapest way to describe it as dictionary words,
known bad passwords, digit runs, repeats, keyboard walks, dates and
substitutions, solved as a shortest-path problem over the string. That number
is a **heuristic upper bound on strength, not a measurement**. Real crackers
use frequency-ranked corpora of breached passwords and information about you
that this app does not have. Read it as "no better than this".

`Password123!` scores 14 bits here. It should.

Below 60 bits the app will still let you through, after an override that spells
out the cost and requires typing a confirmation phrase in full. The decision is
recorded in the vault so it can be seen later.

### Keyfiles (optional second factor)

Quenchkey generates the keyfile itself and will not let you nominate an
arbitrary photo or mp3. That is not purity — it is that cloud clients re-encode
images, photo apps strip EXIF, music players rewrite tags, and the moment those
bytes change the keyfile stops opening the vault. The failure appears long
afterwards, looks exactly like a wrong passphrase, and the data is
unrecoverable.

A generated keyfile is 4 KiB with a recognisable banner and a checksum, so
corruption can be *reported* rather than discovered too late. Only the first
1 MiB of any keyfile is read — the same bound VeraCrypt uses.

---

---

## Why this and not VeraCrypt, 7-Zip, age or Cryptomator

Those are good tools. For most jobs one of them is the better answer, and this
section says so.

|  | Encrypts files well | Memory-hard KDF | Destroys keys on a schedule | Proof of destruction |
|---|---|---|---|---|
| **7-Zip (AES-256)** | yes | **no** — 2^19 SHA-256 iterations, not memory-hard | no | no |
| **age** | yes | scrypt (passphrase mode) | no | no |
| **Cryptomator** | yes | scrypt | no | no |
| **VeraCrypt** | yes | yes — Argon2id, or PBKDF2 at 500k iterations | no | no |
| **Quenchkey** | yes | yes — Argon2id, calibrated to ~1s | **yes** | **signed certificate** |

Encryption is not the differentiator. VeraCrypt in particular is more mature
than this project, has had far more scrutiny, and does things Quenchkey does
not: full-disk encryption, hidden volumes, plausible deniability under coercion.
If what you need is "nobody can read this", use VeraCrypt.

Two gaps every one of them shares. The first is **key lifecycle**. They all assume the key
lives as long as you want the data to. None of them has a concept of a key that
stops existing on a schedule, so with all of them "expiring" a file means finding
and deleting every copy — which is impossible the moment a copy is somewhere you
cannot reach.

The second is **evidence**. NIST SP 800-88 recognises destroying the key as a
Purge-level sanitisation method and asks for a record of it, while noting that
the method is hard to verify. None of these tools produces one. Cloud key
management services do this for infrastructure data; nothing did it for a
person's own files.

That is the gap Quenchkey fills, and it is a narrow one:

> **It revokes copies you no longer control — including your own.**

The backup from three months ago, the copy on the laptop you sold, the folder
that synced to a cloud account before you thought about it, the archive on a
machine you no longer have access to. You cannot delete any of those. You can
destroy the one key that opens all of them, and Quenchkey is a tool for doing
that deliberately and on a schedule rather than hoping it never matters.

### When *not* to use it

Being clear about this is more useful than a feature list:

- **You just want files encrypted and never expired.** Use age or VeraCrypt.
  Quenchkey adds a vault you can lose for no benefit you are using.
- **You need plausible deniability under coercion.** VeraCrypt's hidden volumes
  do this; Quenchkey has no equivalent and will not pretend otherwise.
- **You need transparent encryption of a folder you work in daily.** Cryptomator
  is built for that. Quenchkey is lock-and-forget, not a working directory.
- **You need to revoke access from someone who already has the key, or stop
  someone opening a file you sent them.** That requires a server mediating every
  open — Digify, Vera, Microsoft Purview and similar. They can genuinely do it,
  and the price is a permanent dependency on that vendor being online, in
  business, uncompromised, and not compelled. Quenchkey cannot do this. It
  cannot recall a file someone has already opened, and it says so in the app.
- **You want a cross-platform GUI today.** This is a Linux/PyQt5 application.
  The formats and the recovery script are portable; the interface is not yet.

### What you get in exchange

One passphrase, keys you never handle, a deadline that survives a clock being
wound back, a format documented well enough to decrypt without this software,
and a tool that states its limitations in its own interface rather than in the
fine print.

---

---

## The event log is a hash chain, and you can anchor it

Every vault keeps an event log — created, locked, unlocked, expiry changed,
clock rollback accepted, key destroyed. Each event now carries the SHA-256 hash
of the event before it, computed over a canonical serialisation with a domain
separator, and covering the event's sequence number and its `prev` link as well
as its contents. Editing an old event changes its hash, which breaks the link in
the event after it, and every link from there to the end. The **head** — the
hash of the most recent event — is therefore a fingerprint of the vault's entire
history.

The log already lived inside the vault's authenticated encrypted region, so
somebody *without* the passphrase could never touch it. Chaining is aimed at a
different problem: the person who has the passphrase, or who simply restores a
copy of the vault taken before a deadline. **Against that, the chain on its own
proves nothing.** Someone holding the passphrase can rewrite the whole log and
recompute every hash, and a restored older vault verifies perfectly because it
*was* consistent at the moment it was taken.

What makes the chain worth having is an **anchor**: the head, written down
somewhere the vault is not. The main window shows a short form of it in the
header, beside the lock button — sixteen hex characters, grouped, 64 bits — and
**Vault ▸ Anchor this vault's history…** offers both that and the full
64-character head to copy. Put it in a
password manager, a notebook, a commit message, a message to a colleague. A
rewritten or restored vault cannot reproduce a head that was recorded *after* the
events it is missing, so a later comparison either matches or does not.

Checking it needs neither the application nor trust in it:

```bash
./tools/quenchkey-recover.py audit vault.qkv --expect A1B2-C3D4-E5F6-0789
```

`audit` recomputes the chain from the genesis value, checks it against the head
stored alongside the events — which catches a log that verifies internally but
has had its tail removed — prints the anchor, and, given `--expect`, says
`MATCHES` or `DOES NOT MATCH` and exits non-zero on a mismatch. It accepts either
the short anchor or the full head.

Two honest qualifications. **This is detection, not prevention**, and nothing
that runs only on your own computer can offer prevention; a mismatch tells you
the history in front of you is not the one you recorded, and it cannot stop that
happening or tell you which events were lost. And the chain is bounded: the log
keeps the most recent 2000 events and drops the oldest beyond that, which
necessarily breaks verification from the genesis event, so the vault records that
it has been truncated and both the app and `audit` say that verification starts
mid-chain rather than passing it off as an intact chain. A vault written before
chaining existed is linked retroactively on upgrade, which proves nothing about
those older events — whoever ran the upgrade could have edited them first — so
the vault records when live chaining began and says as much.

---

## Certificates of destruction

NIST SP 800-88 Rev. 1 classifies **Cryptographic Erase** — sanitising data by
destroying its key rather than overwriting the bytes — as a *Purge*-level
technique, one that renders recovery of the target data infeasible using
state-of-the-art laboratory techniques. That is exactly what happens when a
Quenchkey deadline passes. The same document names the method's weakness: it is
hard to *verify*, it asks for a record of sanitisation carrying the method, the
tool, the date, the verification approach and the person answerable, and it warns
that anyone unable to verify a cryptographic erase should use a method they can
verify instead.

Quenchkey produces that record. Each vault holds its own Ed25519 signing key,
inside the encrypted payload, and whenever a key is destroyed — by a deadline, by
a used-up open allowance, by a dead man's switch, or manually — the vault signs a
statement and keeps it. The certificate names the vault by a short id derived
from its public key, identifies the item by entry id, filenames and the SHA-256
of the encrypted `.qkey` file, records the sizes, when it was locked, when it
was scheduled to die, when it actually died and why, the cipher and the Argon2id
parameters in use, and where the destruction sits in the event chain (sequence
number, head and anchor). An optional custodian block carries a name, title,
contact and organisation for vaults inside an organisation that already has
auditors expecting those fields; it is empty by default, because a personal vault
has no use for it.

Anyone can check one, without the passphrase, without the vault and without this
application:

```bash
./tools/quenchkey-recover.py verify cert.json --vault vault.qkv --file secret.qkey
```

`--vault` is what turns "this document is internally consistent" into "this came
from the vault I already know about" — without it, a valid signature only shows
that whoever holds the embedded public key signed the document, which anybody can
arrange for a vault of their own, and both the app and the tool say so in those
terms. `--file` compares a `.qkey` on disk against the hash the certificate
records, so a recipient can confirm that the file they are holding is the one
whose key is gone. The limitations paragraph is printed at the end because it is
part of the document.

**A certificate is evidence the vault produces about itself.** It proves that
this vault, and not another, issued the statement, that not a byte of it has
changed since, and which file it refers to. It cannot prove that no copy of the
key was taken before the destruction, that no copy of the unencrypted content
exists anywhere else, or that the clock of the machine involved was honest — and
since the signing key lives inside the vault, anyone with the passphrase can sign
whatever they like. That caveat is written on every certificate, in its own text,
so it travels with the document instead of living in a manual. It is worth
considerably more than an assertion in an email and considerably less than an
independent audit. Note also that the certificate records the destruction of the
key, not the sanitisation of the encrypted file: deleting the `.qkey` is
optional and off by default, and the certificate states whether it happened.

---

## Recovery shares

The README documents an uncomfortable tension: backing up the vault protects you
against forgetting the passphrase, and is also the one thing that undoes expiry,
because a copy taken before a deadline can be restored after it. A single backup
file cannot give you both.

Recovery shares are the honest way to split the difference. The master key is
divided into *n* shares of which any *k* reconstruct it, using SLIP-39 — the
scheme Trezor publishes and ships — through their own `shamir-mnemonic` library
rather than a hand-rolled implementation. Each share is 33 ordinary English words
with its own checksum, so a mistyped share is rejected and can be pinned to the
share it is in and corrected without re-entering the others; the first two words
identify the set, so a share from a different vault is obvious before anything is
decoded. Fewer than *k* shares reveal nothing at all. **Recovery shares…**
generates a set — the interface offers up to eight shares — displays them once
without keeping a copy, and will write them out one file per share at mode 0600.
A quorum reopens the vault from the unlock screen, or from the standalone tool
with `--shares`, which needs `pip install shamir-mnemonic` on top of its usual two
dependencies.

The point of shares is that no single artefact restores access on its own: there
is nothing to steal, subpoena or leave behind on a backup drive, and control can
be made collective — "two of these three directors, together".

**A quorum of shares is exactly as powerful as the passphrase.** It bypasses the
passphrase and the second factor entirely, because that is what it is for, so a
share is as sensitive as the passphrase itself and should be stored apart from
the other shares and apart from the vault. A threshold of one is not a split at
all; it is a spare passphrase in an unusual format, and it multiplies the number
of things that can be stolen without adding any protection, so the app asks you
to confirm that in writing before it will generate one.

Two further limits. **Shares do not survive a passphrase change**: they
reconstruct the master key, and changing the passphrase or the second factor
derives a new one, so shares made beforehand stop working. Generate a fresh set
afterwards and destroy the old ones; the app logs the change with that note
attached. And shares **do not resurrect destroyed keys**. They rebuild the key
that opens the vault as it stands now, and a per-file key that has already been
destroyed is zeros inside that vault. What shares can do, exactly like a vault
backup, is open an *older* copy of the vault — so they carry the same rollback
caveat as everything else stored locally.

---

## Openings can be counted

An entry can be given an allowance of openings — once, twice, three, five, ten,
or unlimited — and when the allowance runs out the key is destroyed, a
certificate is issued for it, and the event log records why. The table shows the
count as it stands, and an entry with an allowance but no time-based deadline
counts down as "until opens run out" rather than pretending to have a clock.

An opening is counted only once the files are actually out of the archive, so a
failed or cancelled extraction does not spend one. The check happens in two
places: the vault refuses to hand over a key whose allowance is already used up,
and the periodic sweep treats a used-up allowance as due in the same way it
treats a passed deadline, so an entry that reached its limit is cleaned up even
if nothing tried to open it again.

**This is bookkeeping inside the vault, not a property of the cryptography.** The
count lives in the vault file and is enforced by whatever reads it, so the same
rollback caveat applies as everywhere else: restoring a vault from before the
openings were spent restores the allowance along with the key. More directly, the
standalone recovery tool deliberately never writes to the vault, so extracting
with it does not consume an opening — it prints a note saying exactly that when
the entry has a limit. Anyone with the passphrase can therefore read a
"three openings" entry as often as they like.

And the obvious one: a limit on openings is not a limit on copies. Once an
opening has produced plaintext on somebody's disk, that plaintext is an ordinary
file and none of it passes through Quenchkey again.

---

## A dead man's switch

An entry can be told to destroy its key if the vault is not opened within a set
interval — seven days, thirty, ninety, a year, or off. **Opening the vault is the
check-in.** There is nothing else to do, no separate button, no service to ping.
The switch's deadline is folded together with any fixed expiry date into a single
moment, so the interface only ever shows one countdown; the "expires" column
marks it as `(no check-in)` when it is the switch that bites first.

The order of operations is load-bearing. When the vault opens, the sweep runs
**first** and destroys anything already overdue; only the survivors then have
their switches reset. Checking in first would mean a dead man's switch could
never fire at all, because the act of opening the vault to look would itself
postpone it.

Be clear about what a switch is for. It fires whether you were busy, ill, or
simply away for a month — that is the entire point of it, and it makes no
distinction between those cases and the one you had in mind when you set it. If
it matters, a switch measured in days deserves more thought than one measured in
a year.

There are three limits worth stating. A switch is enforced by the vault, from the
vault's own record of when it was last opened, so **restoring an older copy of
the vault resets the clock** along with everything else — the same caveat as every
other rule here. The clock watermark stops a deadline being *extended* by winding
the system clock backwards, and it has nothing to say about a clock wound
*forwards*, which brings a switch forward with it. And destruction happens when
something actually runs the sweep: on a timer while the app is open, and at the
next unlock. A vault that is never opened again has not had its keys destroyed —
it has a switch that is overdue, and the key dies the moment anybody opens it.

---

---

## You are warned before a key dies

A deadline that arrives unannounced is the one way this tool can lose your work
without being asked to, and a dead man's switch is the sharpest case — it is
armed precisely for when nobody is looking.

So both the application and the background timer look a little way ahead and
say what is coming: **a week out, a day out, and within the hour.**

Each is said **once**. A notification that repeated every fifteen minutes is one
people turn off, and a warning nobody reads is no warning. Moving a deadline
arms its warnings again, because a different moment is a different thing to be
told about.

The background timer has no passphrase, so it can only say *how many* and *how
soon* — never which file. The names are inside the vault and stay there; putting
them in a plain file beside it so a notification could be chattier would be a
poor trade, and this is the kind of trade that gets made quietly in software
that does not say what it is doing.

From a script, `quenchkey warn` lists what is coming and exits 4 if there is
anything, and `quenchkey warn --send` marks them as said. Looking is free:
reading the list does not silence tomorrow's warning to somebody who was not
watching standard output.

---

---

## A security key as a second factor

Alongside "passphrase only" and a generated keyfile, a vault can require a FIDO2
hardware security key, using the CTAP2 `hmac-secret` extension. The authenticator
holds a secret that never leaves the device and returns a 32-byte value derived
from that secret and a salt stored in the vault; touching the key is required,
and the secret cannot be copied off it. That makes it the only second factor here
that resists an attacker who has read every file on your machine — a keyfile, by
contrast, is a file, and can be copied like one.

The parameters a security key needs — the credential id and the salt — are **not
secret**, and they have to be readable before the vault can be opened at all, so
they live in the vault's cleartext header. The whole header is passed to the
cipher as associated data, so they are covered by the authentication tag: swapping
in another key's credential does not produce a vault that opens with degraded
security, it produces a vault that refuses to open. The factor's contribution is
hashed with its own domain separator and appended to the passphrase after a
separator byte, so a keyfile digest and an authenticator's output can never be
confused with one another, and neither can be mistaken for a passphrase on its
own.

It needs the `fido2` package (`pip install fido2`) and a key that actually
implements `hmac-secret` — most YubiKey 5 and later models do, older and simpler
U2F-only keys do not, and a key that cannot is rejected at registration with an
explanation rather than silently falling back to something weaker. Registration
asks for presence rather than a PIN, so this is something-you-have and not a
second thing you know.

**This path has never been run against real hardware.** It was written against
the CTAP2 specification, and the only thing it has ever been driven against is a
simulated authenticator in this codebase — a deterministic stand-in that
reproduces the contract (a per-device secret, an HMAC over the salt) with no
hardware at all. That stand-in is emphatically not a security device: its "device
secret" is an ordinary value in memory, and it is not reachable from the
application. It can show that the vault-side logic holds together; it cannot show
that this code drives a physical key correctly, and nothing in an automated test
suite can. Treat FIDO2 support as needing a hardware check before you rely on it.
The interface says the same thing at the point where you would choose it.

Finally, the consequence that catches people out with any hardware factor: **lose
the key and the vault is unopenable**, exactly as if you had forgotten the
passphrase. There is no reset here either. Register a second key, or generate
recovery shares, before you put anything you care about behind one.

---

---

## Expiry while Quenchkey is closed

Deadlines are enforced whenever the application is open. A systemd **user**
timer can also clean up while it is not — with one honest limitation, which
comes straight out of the design.

The vault is a single encrypted blob. Entries, deadlines, paths and keys are
all inside it, under a key derived from your passphrase. A background task that
does not know the passphrase therefore cannot open it, cannot read a deadline
from it, and cannot write to it. You can have any two of these three:

1. the vault is protected by the passphrase alone,
2. keys are destroyed on time with nothing unlocked,
3. nothing about your vault is written outside it.

Quenchkey keeps (1) always, and lets you trade a defined piece of (3) for (2):

```
Vault ▸ Expiry while Quenchkey is closed…
```

Switching it on writes `vault.qkv.schedule` beside the vault, mode 0600, **not
encrypted** — encrypting it under a key kept next to it would protect nothing,
so it is written in the clear and documented instead. It holds, for each item
with a deadline, when that deadline falls, where the locked file is, and
whether it asked to be deleted. No keys, no contents, no filenames from inside
the archive.

The timer then deletes expired files on time. It **cannot** destroy the key —
that happens at the next unlock, which is the first moment the vault can be
written at all. That matters less than it sounds: deleting the file was never
the protection, and an entry past its deadline is refused by every read path
whether or not its key bytes have been overwritten yet. The window it leaves is
narrow and specific, and stated in `quenchkey/schedule.py`.

It is off by default, and none of it reaches another machine.

```bash
systemctl --user status quenchkey-sweep.timer   # is it running?
quenchkey --sweep                               # run it now, by hand
```

---

---

## Carrying the vault, and life without this tool

**The tool is a convenience, not a dependency.**

A vault is a single file. Copy `~/.quenchkey/vault.qkv` and your `.qkey` files
to a USB stick, another machine, any operating system — nothing is tied to the
computer that made them. No registry entries, no per-machine keys, no
activation, no account. Point the app at it with `--vault /path/to/vault.qkv`
and carry on.

And if the app is not there at all — or this project is abandoned, or you simply
do not trust a GUI with your data — `tools/quenchkey-recover.py` opens a vault
without it:

```bash
pip install cryptography argon2-cffi        # nothing else, no Qt

./tools/quenchkey-recover.py list    vault.qkv
./tools/quenchkey-recover.py extract vault.qkv <entry-id> -o recovered/
./tools/quenchkey-recover.py decrypt vault.qkv file.qkey -o file.7z
```

That script is standalone on purpose. It imports **nothing** from the
`quenchkey` package — it re-implements both formats from the layouts documented
above, in about two hundred lines, because a recovery tool that shared code with
the application would only prove the application agrees with itself. The test
suite runs it as a subprocess with the project stripped from the import path and
checks that it returns the original bytes, and a test asserts it contains no
project imports so that guarantee cannot regress by accident.

It also refuses expired entries with the same finality the app does, for the
same reason: the key is not there to be found.

If both were somehow lost, the formats are documented above completely enough to
write a decryptor from scratch in an afternoon. The security rests on Argon2id
and an authenticated cipher, not on anyone having this software.

---

---

## If you forget the passphrase

The files are gone. Permanently.

There is no reset, no recovery code, no support address and no back door. The
master key is derived from your passphrase with Argon2id and a random 16-byte
salt; there is nothing stored anywhere that shortcuts that derivation. Guessing
is the only route in, and a decent passphrase makes guessing hopeless.

This is not an oversight to be fixed later. Any mechanism that could let *you*
back in without the passphrase — an escrow key, a recovery file, a vendor
service — is by definition a mechanism someone else can use, compel or steal.
Quenchkey does not have one, which is precisely why a destroyed key is really
destroyed.

Practical consequences, stated plainly:

- **Write the passphrase down and store it somewhere physical.** A generated
  seven-word phrase on paper in a drawer is a far better trade than a weak
  phrase you are confident you will remember.
- **If you use a keyfile, back it up**, on separate media from the vault. Losing
  it is exactly as fatal as forgetting the passphrase.
- **Back up the vault file itself.** The `.qkey` files are useless without it.
  Note that a backup of the vault is also the one thing that undoes expiry — see
  the limitations below. That tension is real and there is no way to have both.

### You can choose a weak passphrase anyway

The 60-bit floor is enforced, but it is your vault. Below the floor, an override
appears that tells you what the passphrase is actually worth and what that means
for someone holding a copy of your vault file. Accepting it requires ticking an
acknowledgement *and* typing `I ACCEPT THE RISK` in full — enough friction that
nobody arrives there by clicking through.

The choice is recorded in the vault's event log and shown afterwards in
**Security details**, so a vault protected by a weak passphrase says so rather
than looking identical to a strong one.

---

---

## What this does not protect against

This is the section that matters. It is also in the app, from the footer of the
main window.

### Rolling back local state

Expiry is enforced by your machine, using your machine's clock and your
machine's vault file. Someone who copies `~/.quenchkey` before a deadline and
restores it afterwards gets the key back.

Clock rollback is handled — deadlines are judged against the latest time the
vault has ever seen, and a backwards step is refused and logged. A filesystem
snapshot or a copied folder is not, and cannot be. **This is unavoidable for any
tool that runs entirely on your own computer.** Local state is tamper-*evident*
at best; it is never tamper-proof. Anything stronger needs a key server that
refuses to hand the key back, which is a different product with different
trade-offs, and Quenchkey does not pretend to be it.

### Files that have already been opened

Once a recipient decrypts and extracts a file, it is an ordinary file on their
disk. It can be copied, printed, photographed or forwarded, and none of that
passes through Quenchkey. **Once someone has opened a file, it cannot be
recalled.** Expiry destroys the key to the locked copy; it has no reach over
anything that has already come out of one.

### Screenshots and screen capture

Quenchkey does not block screenshots and will not pretend to. Intercepting the
Print Screen key stops nothing — a phone camera defeats it in a second, as does
a virtual machine, a capture card or a screen reader. Tools that advertise this
are selling theatre.

### "Only our app can open these files"

Not a claim made here. This app can decrypt, so shipping this app ships that
ability, and the format is documented above precisely so that it does not
depend on secrecy. A custom extension changes the filename and nothing else.
What protects the contents is 256 bits of randomness in an encrypted vault.

### Hidden or permission-protected folders

Nothing is hidden and no file permissions are relied on to keep anyone out.
Root defeats permissions and a live USB defeats both. The only honest version of
"inaccessible" is that the plaintext genuinely does not exist while the file is
locked — which is what locking does.

### The failed-attempt delay

The pause after repeated wrong passphrases is a convenience feature. It slows
down someone sitting at your keyboard. An attacker who copies the vault file
attacks it offline, at whatever rate their hardware allows, where this app never
runs and no counter exists. The Argon2id parameters are the real defence, and
they are why unlocking takes about a second.

### Data left behind on disk

Deletion overwrites the bytes first, but on a copy-on-write filesystem (Btrfs,
ZFS), a log-structured one, or an SSD doing wear levelling, the original blocks
can survive untouched. Snapshots, backups and your editor's temporary files are
all outside its reach. Treat "shredded" as "removed with reasonable care", not
"provably gone".

The same applies to the vault itself. Each save overwrites the previous file's
bytes before replacing it, which helps on a plain overwrite-in-place filesystem
and not at all on the others. A forensic recovery of an older vault file, by
someone who also has your passphrase, could recover a key that has since been
destroyed.

### Memory

The master key is held in a `bytearray` and overwritten on lock, and keys are
kept out of logs and tracebacks. This is best effort: Python copies objects
freely, garbage collection is not prompt, and nothing here prevents the key
being written to swap or captured in a core dump. It shortens the window; it
does not close it.

### A compromised machine

If something is already running as you — a keylogger, a memory scraper, a
malicious browser extension — it can take the passphrase as you type it or the
keys out of memory while the vault is open. No file encryption tool solves this.

### Coercion

There is no duress passphrase and no hidden volume. If someone can compel you to
unlock the vault, it unlocks.

### Metadata

A `.qkey` file does not reveal filenames, but it does reveal roughly how much
data is inside it, to the megabyte. The vault reveals its own existence, its
size, and when it was last written.

---

---

## What is left, then?

The passphrase, Argon2id, an authenticated cipher, and the fact that a key which
no longer exists cannot be recovered by anyone — including whoever holds the
encrypted file, and including you.

That part is real, and it is the whole product.

---

---

## Prior art, and a cautionary tale

This is not a new idea, and the most famous attempt at it failed badly. Anyone
evaluating Quenchkey should know that history, because it is the reason this
tool is deliberately less ambitious than it could be.

In 2009 Roxana Geambasu, Tadayoshi Kohno, Amit Levy and Henry Levy at the
University of Washington published **Vanish**. It encrypted data locally with a
random key, split that key with Shamir secret sharing, and scattered the shares
across the Vuze BitTorrent DHT. Nobody had to remember to delete anything: the
normal churn of nodes leaving the network would erase the shares on its own,
and after roughly eight hours the data became unreadable to everyone, including
its author. It was an elegant answer to the problem, and it had a property
Quenchkey does not: expiry that did not depend on the holder's cooperation,
their machine, or their honesty.

Within a year it was broken. At NDSS 2010, Scott Wolchok and colleagues showed
that a Sybil attack on the DHT — many cheap fake nodes, continuously hopping
around the identifier space and harvesting values as they were replicated —
could collect the shares before they expired. They recovered about **99% of
supposedly destroyed objects for roughly $5,900 a year**, against the Vanish
authors' own estimate that such an attack would cost $860,000. Their conclusion
was general and worth repeating: do not rely on a distributed system for a
security property it was never designed to provide.

Quenchkey sits at a deliberately more modest point in the same design space.
It never publishes key shares anywhere, so the attack that defeated Vanish does
not apply to it — there is no DHT to crawl, and the key exists in exactly one
place under your control. The price is precisely the limitation documented at
length above: because expiry is enforced by your own machine and your own vault
file, a copy of that vault taken before a deadline and restored afterwards
defeats it.

That trade is the central design decision in this project. Vanish chose
automatic, uncooperative expiry and paid for it with a trust assumption about a
public network that did not hold. Quenchkey chooses an expiry you can
personally undo, and spends its effort instead on making the undoing
*detectable* — the hash chain and its anchor — and on making the destruction
*provable* to someone else when it does happen — the signed certificates.

Neither choice is obviously right. But a tool in this space that does not tell
you Vanish existed, and what happened to it, is not being straight with you.

**References**

- Geambasu, Kohno, Levy and Levy, *Vanish: Increasing Data Privacy with
  Self-Destructing Data*, USENIX Security 2009.
  <https://css.csail.mit.edu/6.858/2010/readings/vanish.pdf>
- Wolchok, Hofmann, Heninger, Felten, Halderman, Rossbach, Waters and Witchel,
  *Defeating Vanish with Low-Cost Sybil Attacks Against Large DHTs*, NDSS 2010.
  <https://jhalderm.com/pub/papers/unvanish-ndss10-web.pdf>
- NIST SP 800-88 Rev. 1, *Guidelines for Media Sanitization*, on Cryptographic
  Erase. <https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-88r1.pdf>

---

---

## Project layout

```
quenchkey/
├── install.sh                 one-command install and uninstall
├── quenchkey.py                  launcher
├── LICENSE                    Apache 2.0
├── NOTICE                     dependency licences, and the PyQt5 caveat
├── CHANGELOG.md
├── pyproject.toml
├── requirements.txt
├── CONTRIBUTING.md            including the honesty rule
├── SECURITY.md                what it protects against, and what it does not
├── .github/                   CI: the suite, the parade, a clean install
├── quenchkey/
│   ├── crypto.py              Argon2id, AEAD wrappers, wipeable secrets
│   ├── vault.py               vault format, entries, clock ratchet
│   ├── chain.py               hash-chained event log and anchors
│   ├── certificate.py         signed certificates of destruction
│   ├── recovery.py            SLIP-39 k-of-n recovery shares
│   ├── factors.py             keyfile and FIDO2 second factors
│   ├── archive.py             7z packing, selection order, manifest
│   ├── locker.py              .qkey format, chunked streaming AEAD
│   ├── expiry.py              deadlines, sweeps, key destruction
│   ├── schedule.py            the index a keyless background sweep can read
│   ├── backup.py              vault copies, and the price of restoring one
│   ├── watch.py               folders that lock what lands in them
│   ├── warnings.py            saying a key is about to die, once
│   ├── integrity.py           checking the locked files, and finding them
│   ├── handover.py            sending a file to another vault, deadline and all
│   ├── audit.py               the auditor's record, with no keys in it
│   ├── timestamping.py        RFC 3161, for the anchor and the clock
│   ├── cli.py                 the terminal, with lock at its centre
│   ├── terminal.py            colour, and the four ways it switches off
│   ├── settings.py            preferences, kept outside the vault
│   ├── autostart.py           one .desktop file in ~/.config/autostart
│   ├── uninstall.py           removing the application, not the vault
│   ├── help_text.py           the manual, as data
│   ├── passphrase.py          generation and strength estimation
│   ├── keyfile.py             second factor
│   ├── session.py             the open vault, auto-lock, timers
│   ├── wordlist.py            2048 words, 11 bits each
│   ├── data/                  dictionary for the strength estimator
│   └── ui/
│       ├── theme.py           palette and stylesheet
│       ├── widgets.py         strength meter, banners, confirmations
│       ├── workers.py         background threads
│       ├── dialogs.py         anchor, certificates, shares, custodian
│       ├── filechooser.py     picks the desktop's chooser over Qt's
│       ├── gate.py            create / unlock
│       ├── main_window.py     the table, timers, limitations text
│       ├── lock_dialog.py     lock flow
│       ├── unlock_dialog.py   unlock flow
│       ├── share_dialog.py    files that carry their own key, and unlocking them
│       ├── settings_dialog.py where things are saved, and closing behaviour
│       ├── feature_dialogs.py backups, folders, duress, integrity, audit, handover
│       ├── help_dialog.py     the manual, with search
│       ├── destinations.py    one place that decides where a file goes
│       ├── tray.py            the tray icon, and whether there is a tray
│       └── app.py             bootstrap
├── tests/                     617 tests
├── packaging/
│   ├── quenchkey.desktop         applications-menu entry
│   ├── quenchkey.svg             icon
│   └── quenchkey-mime.xml        the .qkey file type
├── tools/
│   ├── quenchkey-recover.py      standalone decryptor, no project imports
│   ├── record_demo.py         records the walkthrough, and tests it
│   ├── uidriver.py            real X input events, for the above
│   ├── dialog_parade.py       opens every dialog and checks it fits the screen
│   ├── screenshots.py         regenerates docs/screenshots from live widgets
│   ├── render_logo.py         re-exports the PNG icons from the SVG
│   ├── finish-release.sh      the GitHub steps that need credentials
│   └── setup-signing.sh       GPG signing, so commits show as Verified
└── assets/                    logo, SVG + PNG at 16/32/64/256
```

---

## Not in this version

No tunnels, no web serving, no sync, no server of any kind. Deliberately: the
local tool is the part that has to be right first.

There is also no remote deletion, and there will not be. Once a file is on a
machine you do not control, nothing you run can reach in and delete it — the
recipient owns that machine, and can copy the disk, cut the network, freeze
the clock or patch out whatever agent you asked them to install. Every product
that claims otherwise is either shipping DRM that a determined recipient
defeats in an afternoon, or lying. What works instead is the mechanism this
whole application is built on: never hand over a permanent key, and destroy
your copy. See [Prior art, and a cautionary tale](#prior-art-and-a-cautionary-tale)
for what happened to the last system that promised it.

---
