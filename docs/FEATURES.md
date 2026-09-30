# Every feature, explained

The [README](../README.md) covers the things most people use. This file covers
all of it, one feature at a time, including the ones you may never need.

Each section says what the feature does and, where it matters, what it cannot
do. The second part is the one worth reading.

---

## Contents

- [Help, settings, and how the window behaves](#help-settings-and-how-the-window-behaves)
- [Sharing a file: the one that has no lifespan](#sharing-a-file-the-one-that-has-no-lifespan)
- [Backups, and the one honest cost of having them](#backups-and-the-one-honest-cost-of-having-them)
- [Watched folders](#watched-folders)
- [Checking a file out](#checking-a-file-out)
- [Handing a file over to another vault](#handing-a-file-over-to-another-vault)
- [Checking the locked files](#checking-the-locked-files)
- [A record for an auditor](#a-record-for-an-auditor)
- [Trusted time](#trusted-time)
- [A duress passphrase](#a-duress-passphrase)
- [From a terminal](#from-a-terminal)

---

## Help, settings, and how the window behaves

### The manual is in the application

```
Help ▸ How to use Quenchkey…
```

Nine pages covering every feature, searchable, including the two questions
people ask first — *how do I open a .qkey file* and *can another application
open one*. The short answers: from Quenchkey, by double-clicking it, or with the
standalone `quenchkey-recover` script; and no other program knows the container
format, but that is a fact about the format and not a protection. What stops
someone reading your files is the encryption, not the obscurity of the
wrapper, and Quenchkey does not claim otherwise.

The same text is available without a display:

```python
python3 -c "from quenchkey import help_text; print(help_text.as_plain_text())"
```

### Where files are saved

```
Vault ▸ Settings…
```

Each kind of output — files opened from the vault, files opened from a shared
`.qkey`, new locked files, new shared files, certificates, recovery shares,
generated keyfiles — can go to a fixed folder or ask every time.

Asking always means **your desktop's own file chooser**, which is also where
you rename a file on the way out. Quenchkey draws no file browser of its own
anywhere, and there is a test that fails if `QFileDialog` so much as appears
in those modules. A fixed folder skips the question; nothing is overwritten
either way, since a name already in use gets `(2)` appended.

Settings live in `~/.config/quenchkey/settings.json`, outside the vault and
unencrypted, because most of them have to be read before anything is
unlocked. Nothing secret is stored there — there is a test that checks the
file's structure rather than trusting that.

### The window, the tray, and starting on login

The window opens filling the screen, and stays resizable and movable.

Closing it can quit, keep Quenchkey in the tray, or ask — and the answer can be
remembered. Quitting locks the vault and wipes every key from memory; the tray
keeps deadlines being checked and the vault still auto-locks on idle.

GNOME has no system tray of its own; what looks like one is an extension such
as AppIndicator. Where there is none, **closing quits whatever the setting
says**, because a window that disappeared while claiming to still be running
would be worse than either outcome. The settings screen says so rather than
letting you find out.

Starting on login writes one ordinary `.desktop` file to
`~/.config/autostart`, which you can delete by hand. It does not unlock
anything: Quenchkey opens at the passphrase screen exactly as it would otherwise,
and there is no stored passphrase that could skip it.

### Uninstalling from inside

```
Help ▸ Uninstall Quenchkey…
```

Removes the application, its menu entry, icons, file-type registration,
background timer and autostart entry. Your vault and your locked files are
left alone — removing the application destroys no keys.

**This is a convenience, not a security control.** There is no lock in the
application for anyone to bypass by deleting it: what protects a locked file
is that it is encrypted and its key is elsewhere or gone. Delete Quenchkey and
you are left with unreadable files and a recovery script that still asks for
the passphrase. A system-wide installation needs root, and a graphical
application quietly acquiring root to delete files is not something this will
do — it says so and gives you the command.

---

---

## Sharing a file: the one that has no lifespan

Everything above works by keeping the key somewhere the holder of the locked
file does not control. Destroy that one key and every copy dies at once.

**Lock files to share** does the opposite, on purpose. The file gets a fresh
256-bit key as usual, but that key is wrapped by a passphrase of its own and
written *into the file*. Send someone the file and the passphrase and they can
open it on any machine, with no vault, no account, no network and nothing
installed — `tools/quenchkey-recover.py share` reads it on its own.

**Which means it can never expire.** Not "expiry is not implemented for shared
files" — there is nowhere to enforce it from. The key is inside every copy, so
there is nothing left anywhere that could be taken away. A deadline on such a
file would be a countdown with nothing behind it.

So Quenchkey keeps the two apart rather than blurring them:

- A flag in the file header says which kind it is, in the clear and
  authenticated, so every tool can report it without a passphrase.
  `quenchkey-recover share --describe file.qkey` prints it and derives nothing.
- Shared files never appear in the list of vault entries. They have their own
  section, their own marker and their own heading: *no deadline, not
  recallable*.
- Creating one needs the words `NO DEADLINE` typed out.

```bash
./tools/quenchkey-recover.py share --describe handover.qkey
./tools/quenchkey-recover.py share handover.qkey -o ./opened
```

Send the passphrase by a different route from the file. Neither can be changed
afterwards, and neither can be revoked.

### Opening them again

```
Vault ▸ Unlock shared files…
```

Shared files arrive in batches and usually share a passphrase, so this is a
list with tick boxes rather than a file chooser opened once per file. It shows
every shared file this vault wrote; **Add files…** opens your desktop's own
chooser for anything it did not — one somebody sent you, for instance.

Give the passphrase once and tick whatever it opens. Files with a different
passphrase are reported on their own line and everything else still opens.

**Everything lands beside the locked file it came from.** Opening somebody's
documents is not a reason to move them somewhere else, so there is no
"extract to…" and nothing to choose. What comes out depends on what went in:

| Went in | Comes out |
|---|---|
| one document | `figures_quenchkeyunlocked.bin`, next to `single.qkey` |
| several | a folder `bundle_quenchkeyunlocked/`, next to `bundle.qkey` |
| either, as an archive | `bundle_quenchkeyunlocked.7z`, **with no password at all** |

The `_quenchkeyunlocked` suffix is so a folder holding both versions reads at a
glance. Nothing existing is ever overwritten — unlock the same file twice and
you get `… (2)`, not a replaced first copy.

The archive option is for passing something on to somebody who should not need
a passphrase. Any archive manager opens it, which is the point and the risk:
nothing protects it any more.

**Keep the locked .qkey file as well** is ticked by default. Clearing it
shreds and deletes the locked copy once the contents are safely out — and only
then, so a wrong passphrase never costs you the file. It reaches that one copy
and no other: every copy elsewhere still opens with the same passphrase.

---

---

## Backups, and the one honest cost of having them

```
Vault ▸ Vault backups…
```

Losing the vault file loses everything in it — every locked file at once, as
though every deadline had fired together. **Recovery shares do not cover
this:** they rebuild the master key, but the per-file keys live *inside* the
vault, so with the file gone there is nothing for that key to open.

A backup is a byte-for-byte copy. It is already encrypted under your
passphrase, so it needs no second one, and keeping it beside the vault
protects against nothing.

The cost is real and stated rather than hidden: **a backup is a copy of a past
state, and expiry only runs forwards.** Restore one and the keys it held come
back, including keys destroyed on purpose. That cannot be engineered away
while also having backups, so restoring is made loud instead:

- before it happens, you are told exactly how many events would be undone and
  how many destroyed keys would return;
- rolling one back needs `ROLL BACK` typed out;
- the vault you replace is moved aside, not deleted;
- the restored vault carries a permanent, chained record that it was rolled
  back and by how much, so an audit shows the gap.

Each backup has a small manifest beside it, readable with no passphrase, so
you can see what a backup holds before deciding to use it.

---

---

## Watched folders

```
Vault ▸ Watched folders…
```

A folder where anything that appears is packed, encrypted under a fresh key
and the original shredded — with whatever rule the folder was given. No dialog
at the moment of dropping. Useful for a scanner's output folder, or downloads.

Two limits, both structural:

**It only runs while the vault is unlocked.** Locking needs the vault, so a
file dropped in while Quenchkey is closed sits there in the clear until you
next open it. A watched folder is a convenience, not a guard on the folder.

**A file is locked once it has stopped changing** — about six seconds at the
same size and timestamp — or a download in progress would be encrypted
half-written. `.part`, `.crdownload`, `.tmp`, editor backups and hidden files
are never picked up at all.

---

---

## Checking a file out

Opening a locked file normally is a one-way door: the copies are ordinary
files with no deadline, and nothing here can reach them afterwards.

A **loan** is the other option, and it is the second choice in the Open
dialog. The files come out the same way, but their paths are recorded. When the
loan runs out — or when you press **Bring it back** — the working copies are
shredded and the entry goes back to being merely locked. The key is not
destroyed; the file returns.

**Edits made while it is out are locked back in, not shredded.** Each file is
fingerprinted as it goes out, so bringing it back can tell an edited file from
an untouched one. An untouched copy is simply removed and the vault is left
byte-for-byte as it was. An edited one is written back into the same entry
first, under the same key, keeping its deadline, its opening count and its
place in the event log — and the chain records that it happened.

If the edits *cannot* go back — the key was destroyed while the file was out,
or half of what went out has gone missing — then nothing is shredded. The
copies are left where they are and the app says why. A feature that quietly
destroyed an afternoon's work when a timer fired would be a trap rather than a
convenience, so the timer takes the same care a person pressing the button
would.

What a loan reaches is exactly what that extraction wrote, at the paths it
wrote them to. Not a copy you made afterwards, not a file your editor saved
elsewhere, not a backup that ran in the meantime. **A loan is tidying up after
yourself, not control over where your file went** — and there is a test that
asserts a copy made by hand survives it.

---

---

## Handing a file over to another vault

```
Vault ▸ Hand over to another vault…
```

A shared file cannot expire, and the section above says why. This is the way
round it, and it needs the other person to be running Quenchkey too.

Instead of wrapping the file key to a passphrase, it is wrapped to the
**recipient's vault**. When they accept it, the key lands inside their vault as
an ordinary entry, with the deadline you proposed, and **their** background
sweep destroys it on time. Nothing has to reach across a network on the day,
because nothing has to: the key was already in the place that expires.

**How it is addressed.** Each vault derives an X25519 key pair from the signing
seed it already keeps for certificates — a separate HKDF info string, so the
signing key and the agreement key are never the same bytes used twice. The
recipient exports an *identity card*: their vault id, their Ed25519 public key,
their X25519 public key, and a signature binding the second to the first.
Anybody can check that signature with no passphrase and no vault, which is what
stops a card being edited in transit to name somebody else's key.

The card holds no secret. Email it, paste it into a chat, publish it. The worst
anybody can do with your card is send you a file only you can open.

**The terms travel inside the file**, authenticated, so the recipient reads
them before deciding and neither of you can change them afterwards without the
file failing to open. And there is no way to read the file *without* accepting
them, which is the point: accepting is what puts the deadline in your vault.

Three things this does not buy, all of which the dialog says as plainly as
this does:

- **They can decline.** A file they never accept is a file they cannot read.
  That is the honest failure mode, and it is their choice.
- **Once they accept and open it, the copy is an ordinary file.** Expiry
  destroys their key to the locked copy and reaches nothing else.
- **It is their machine.** They can back up their vault and restore it after
  the deadline, exactly as you can with yours. Tamper-evident, not
  tamper-proof — the rollback is written into their event chain, and that is
  all anybody local can offer.

What it does buy is the ordinary case, which is most cases: a colleague who
wants the same thing you do, and a file that stops being readable on the day
you both agreed on, without either of you having to remember.

---

---

## Checking the locked files

```
Vault ▸ Check the locked files…
```

Every entry records the SHA-256 of its `.qkey` file at the moment it was
written. This reads each of those files back and compares, so a vault notices
a failing drive, a copy that never finished, or a file that has been swapped.

**It is detection, not prevention**, and the distinction matters. An altered
file was already going to be refused: the encryption authenticates what it
decrypts, so a modified file fails rather than returning wrong content. What
this buys you is finding out now instead of on the day you need the file.

A locked file that was *moved* reads as missing, because the vault stores a
path. **Look for missing ones** searches a folder you choose and matches
candidates **by digest** — not by name, which may well have been changed too.
A candidate is only accepted when its hash is the one the vault recorded.
Pointing an entry at where its file actually is changes the path and nothing
else: the key, the deadline, the opening count and its place in the event log
all stay as they are, and the move is written into the chain.

---

---

## A record for an auditor

```
Vault ▸ Record for an auditor…
```

A retention policy is often somebody else's business — a data protection
officer confirming last year's files really did expire, an auditor who wants
the event log, a client who wants evidence their documents were destroyed.
Handing any of them the vault passphrase is absurd: it opens every document in
it. Handing them nothing means they take your word.

So this writes a **separate record** beside the vault, under a passphrase of
its own, holding what they need:

- every entry's name, size, rules, opening count and deadline;
- when each key was destroyed, and why;
- the whole hash-chained event log, which they verify themselves;
- the certificates of destruction the vault has issued.

**And no file key.** Not wrapped, not derived, not in any form that could
become one. The record is *built from* the vault rather than being a slice of
it, so there is nothing in the file for a holder to attack however patient
they are. That is a stronger statement than "we did not give them the key",
and it is the reason for doing it this way. There is a test that takes a live
entry's key and looks for it in the record's plaintext.

The record is **signed** with the same key that signs certificates of
destruction, so an auditor holding any certificate from this vault already has
the public key and can confirm the record came from the vault it claims to.

They read it with the standalone tool, which imports nothing from this project:

```bash
quenchkey-recover audit-record vault.qkv.audit \
    --public-key <from any certificate this vault issued>
```

Two honest notes, both in the dialog. **Choose a passphrase that is not the
vault's** — nothing here can stop you, because the vault does not keep its own
passphrase and has nothing to compare against, and using it would hand an
auditor every document. And **it is a snapshot**, rewritten when you write it:
an auditor reading a record from a vault last opened in March is reading March.
Comparing its anchor against one you published independently is how they tell.

---

---

## Trusted time

```
Vault ▸ Anchor this vault's history… ▸ Have somebody else sign it
```

The weakest joint in local expiry is the clock. The vault keeps a watermark and
never accepts a time earlier than the latest it has seen, which makes a clock
set backwards **evident** rather than impossible — somebody with your machine
can still wind it back before the vault has noticed a deadline pass.

An [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161) timestamp authority takes
a hash and returns that hash and a time, signed. It never sees the data. The
token proves one thing and proves it forever, offline, to anybody: *this hash
existed no later than this time.*

That buys two things here:

1. **The anchor becomes third-party evidence.** Instead of writing the
   fingerprint down yourself and remembering to, a signature from a party
   neither you nor an auditor controls says that history existed at that
   moment. Somebody who later restores an old backup cannot produce a token
   for the newer chain head — they would need the authority to sign a date
   that has passed.
2. **The clock is corrected rather than trusted.** Fetching a token tells the
   vault what the time is according to somebody else, and that reading moves
   the watermark forward — so a machine whose clock was wound back is put
   right the next time it can reach an authority.

And what it does not buy:

- **It does not work offline.** A machine kept off the network keeps whatever
  protection the ratchet gives it and no more. A fetch that fails is reported
  as a fetch that failed, and the deadline is still enforced.
- **It cannot stop the clock being wound back.** Only make the winding visible
  and correct it afterwards.
- **It is only as good as the authority.** A token verifies against a
  certificate you supply; without one it is stored but not verified, and the
  dialog says so rather than showing a tick it has not earned.

Off unless you ask for it — it is the one feature here that touches the network
at all — and only ever a hash leaves the machine. The request is built in-tree,
because it is a small fixed structure and building it by hand is checkable;
verification is handed straight to `openssl ts -verify`, because verifying a
CMS signature chain is exactly the kind of thing not to write yourself.

The tests for this stand up an actual timestamp authority with openssl and talk
to it over HTTP, rather than mocking the protocol. A mocked timestamp proves
the mock was called.

---

---

## A duress passphrase

```
Vault ▸ Duress passphrase…
```

A second passphrase. Typed at the unlock screen it overwrites and deletes the
vault, and Quenchkey comes back as though no vault had ever been made — no
message, no confirmation, because anyone standing over your shoulder would
read them.

Off unless you set it, and setting it needs `DESTROY THE VAULT` typed out.

Three things it is important to be clear about:

- **It destroys your data, permanently.** It is not a decoy vault with
  different contents. Every key goes.
- **It reaches one file on one machine.** A backup, another disk, a filesystem
  snapshot — none are touched. Somebody who copied the vault before you typed
  it still has everything.
- **It must be nothing like your real passphrase.** Mistyping the real one is
  simply wrong and costs nothing; the duress one has to match exactly.
- **The unlock screen acts on it, not the vault format.** `quenchkey-recover`
  reports the duress passphrase as simply wrong and deletes nothing, by
  design — a recovery tool that destroyed vaults would be the wrong tool.
  Somebody who reaches for it instead is not stopped by this.

How it works: the duress passphrase does not derive the master key, so nothing
derived from it can decrypt anything. What is stored is a hash of the key it
derives, under the *same* salt and cost as the real one — so a single
derivation answers both questions, and an attacker guessing at the file pays
the same price either way. The digest lives in the header's authenticated
block, and the passphrase itself is never stored.

Because it cannot decrypt the vault, it cannot do anything subtler than
destroy the file: no shredding entries one at a time, no convincing empty
vault with the real one hidden underneath. Anyone who tells you their tool
does that on a local file is describing something else.

---

---

## From a terminal

The window is where this gets used. A command line adds the things a dialog
cannot reach — a nightly job that locks yesterday's exports, a monitoring check
that fails the build if a vault has not been swept — and it is deliberately
narrower than the window, for a reason worth reading before the command list.

```
quenchkey help
```

One page, grouped by what you are trying to do rather than alphabetically,
coloured where colour distinguishes something: **red** for a thing that has
just become unreadable or is about to, **amber** for a thing that wants a
decision, **green** for a thing that went as asked, and nothing else coloured
at all. It switches itself off when output is not a terminal, when `NO_COLOR`
is set, when `TERM` is `dumb`, and whenever `--json` is asked for — because a
JSON document with escape codes in it is not a JSON document. `QUENCHKEY_COLOR=always`
forces it on for piping into `less -R`.

### The passphrase comes from a prompt, and from nowhere else

Not an argument, because arguments are visible to every process on the machine
and land in shell history. **Not an environment variable**, because it is
inherited by every child process and ends up in systemd units and CI logs.
**Not a file**, because a file holding the passphrase to a vault is the one
thing this whole tool tells you not to make.

So every command that needs the vault open **cannot run unattended**, and that
is the design rather than an oversight. It is also the honest answer to the
obvious objection: a tool that says "never write your passphrase down" and then
ships `--passphrase-file` for convenience is not saying it very hard.

### Which is fine, because a cron job does not need them

```bash
# Once, from the application or the terminal:
quenchkey card --output ~/.config/quenchkey/mine.qkid

# Then nightly, with the vault shut and no secret anywhere on the machine:
quenchkey deposit /srv/exports/*.csv \
    --to ~/.config/quenchkey/mine.qkid \
    --expires 90d --shred
```

`deposit` is a handover addressed to yourself. The file key is wrapped to your
own vault's public identity, so the file is unreadable the moment it is written
— by anybody, including the script that wrote it and the person who set the
script up. You accept them next time you open the vault, on the terms the job
proposed, and from then on they are ordinary entries with ordinary deadlines.

The identity card it needs holds no secret at all. It can sit in a config
directory, in a git repository, in a Puppet manifest — losing it lets somebody
deposit files into your vault, which is not a thing worth worrying about.

### Locking, interactively

```bash
quenchkey lock report.pdf --expires 90d
quenchkey lock exports/*.csv --expires 2027-01-01 --shred
quenchkey lock notes.txt --max-opens 1 --delete-on-expiry
quenchkey lock ~/Archive --expires 1y --check-in 30d --label "last year"
```

| | |
|---|---|
| `--expires WHEN` | `90d`, `6h`, `2 weeks`, `1.5h`, `1y`, `2027-01-01`, or `never` |
| `--max-opens N` | destroy the key after N openings |
| `--check-in EVERY` | a dead man's switch: `30d`, `6 months` |
| `--shred` | shred the originals once locked. Not recoverable |
| `--delete-on-expiry` | also delete this machine's `.qkey` when the key dies |
| `--output-dir DIR` | where the `.qkey` goes (default: beside the first file) |
| `--label TEXT` | a name for the entry in the table |
| `--dry-run` | say what would happen, touch nothing |

### The rest

| | | |
|---|---|---|
| `deposit` | lock into your own vault | **no passphrase** |
| `share` | lock with a passphrase of its own, for anybody | its own |
| `card` | this vault's identity card | prompt |
| `hand-over --to CARD` | send to another vault, deadline and all | prompt, or `--anonymous` for none |
| `accept FILE --yes` | take a handover into this vault | prompt |
| `ls` | every entry, with rules and time remaining | prompt |
| `status` | one screen; exits 4 if something wants attention | prompt |
| `warn` | what is about to have its key destroyed | prompt |
| `check` | verify every locked file against its digest | prompt |
| `open ENTRY` | extract it, or `--loan 4h` to borrow it | prompt |
| `check-in [ENTRY]` | bring a loan back, keeping any edits | prompt |
| `sweep` | destroy the keys of everything past its deadline | prompt |
| `expire ENTRY --yes` | destroy a key now. Irreversible | prompt |
| `audit` | publish the auditor's record | prompt + the record's own |
| `stamp` | have an authority sign the anchor | prompt |
| `backup DEST` | copy the vault somewhere the vault is not | prompt |

Two secrets that are *not* the vault's may still come from the environment,
because leaking either costs something bounded rather than everything: the
audit record's passphrase, which opens metadata and no documents, and a shared
file's own passphrase, which opens that one file. Those are
`QUENCHKEY_RECORD_PASSPHRASE` and `--record-passphrase-file`. The standalone
recovery tool keeps its own variable as well, because recovering a vault when
this application is gone is precisely the case that cannot depend on a prompt
being there.

### Exit codes, because that is what a script reads

| | |
|---|---|
| 0 | what was asked for happened |
| 1 | it did not — the reason is on standard error |
| 2 | the command line itself was wrong |
| 3 | the vault could not be opened |
| 4 | a check failed: something expired, altered or missing |

`status`, `check` and `warn` exit 4 rather than 0 when they find something, so
a monitoring job can watch a vault without parsing prose. `warn --send` exits 0
on successful delivery instead, because then the question being asked is a
different one.

```bash
# Nightly. Needs a person, so run it from a terminal session, not cron.
quenchkey status || notify-me
```

One binary. `quenchkey` on its own opens the window; `quenchkey lock …` is the
terminal, and Qt is never imported on that path, so the command line works over
SSH and in a container.

Nothing is quieter from the terminal than from a dialog. `expire` prints in red
what it is about to make unreadable and refuses without `--yes`. `lock` says in
amber when it has set no rules at all. `share` says the file it just wrote can
never expire and points at `hand-over` instead.

---
