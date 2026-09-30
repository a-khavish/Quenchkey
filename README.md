<p align="center">
  <img src="assets/quenchkey-256.png" width="110" alt="Quenchkey">
</p>

<h1 align="center">Quenchkey</h1>

<p align="center"><em>The key goes out.</em></p>

<p align="center">
  <a href="#install-it">Install</a> ·
  <a href="#what-it-looks-like">Screenshots</a> ·
  <a href="#why-you-might-want-this">Why</a> ·
  <a href="#what-it-cannot-do">Limits</a> ·
  <a href="docs/FEATURES.md">All features</a> ·
  <a href="docs/HOW-IT-WORKS.md">How it works</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/platform-Linux-informational" alt="Linux">
  <img src="https://img.shields.io/badge/licence-Apache%202.0-blue" alt="Apache 2.0">
  <img src="https://img.shields.io/badge/tests-617%20passing-success" alt="617 tests">
  <img src="https://img.shields.io/badge/version-1.0.0-lightgrey" alt="1.0.0">
</p>

---

## The problem

You send someone a file. A contract, a scan of your passport, last year's
accounts. You meant them to see it this week, not forever.

Now think about where that file actually is. Their laptop. Their phone,
because they opened the email on it. Their backup, which runs every night.
The copy they forwarded to a colleague. The copy in their deleted items that
isn't really deleted.

You cannot delete any of those. Nobody can. Every tool that promises to is
either lying to you or quietly assuming the other person won't try.

## What Quenchkey does instead

It stops trying to delete the file, and deletes **the key** instead.

Think of it like a safe deposit box. You put the documents in the box and lock
it. The box can sit in a hundred places — their laptop, their backup, a USB
stick in a drawer. None of that matters, because the only key is in your
pocket.

When the time is up, Quenchkey destroys the key. Not a copy of it. The only
one. And in the same moment, **every box everywhere stops opening**, including
the ones you forgot about and the ones you never knew existed.

This isn't a trick or a clever licence check. There is genuinely nothing left
that can open those files. Not this program, not me, not somebody with a
supercomputer and a decade to spare.

<p align="center">
  <img src="docs/demo/quenchkey-demo.gif" width="860" alt="Quenchkey walkthrough">
</p>

<p align="center">
  <sub><a href="docs/demo/quenchkey-demo.mp4">Watch the full recording</a> ·
  the GIF is shortened</sub>
</p>

---

## Who this is for

You might find it useful if you:

- **Send sensitive documents by email** and would rather they stopped being
  readable after the deal closes.
- **Keep records you are legally required to delete** after a set period, and
  would like to prove you did.
- **Have a folder of old tax returns, medical letters or legal paperwork** you
  can't bring yourself to delete but don't want sitting around in plain view.
- **Work with a client's data** and promised to destroy it when the job ends.
- **Want a dead man's switch**: if something happens to you and nobody opens
  the program for six months, certain files quietly become unreadable.

You probably don't need it if you just want a password on a folder. A zip file
with a password does that, and it's simpler.

---

## Why you might want this

**It reaches copies you've lost track of.** This is the whole point and
nothing else does it. Every other tool deletes one file in one place. If you
have ever thought "I wish I'd never sent that," this is the only answer that
actually works.

**It tells you the truth.** Most software in this space makes promises it
cannot keep — blocking screenshots, "only our app can open this," remote
deletion from someone else's computer. None of that works, and this program
has a menu item called *What this does not protect against* that says so in
plain language. You will find the honest limits in the program itself, not
buried in a licence agreement.

**It gives you proof.** When a key is destroyed, Quenchkey writes a signed
certificate saying what was destroyed and when. Anyone can check that
certificate — your client, your auditor, a regulator — without needing your
password or even having Quenchkey installed. If you have ever had to prove you
deleted something, you know how hard that normally is.

**Your files aren't held hostage.** The file format is documented and there's
a separate little program that opens your files without needing Quenchkey at
all. If this project disappears tomorrow, your files still open. That's a
promise most encryption tools can't make.

**Nothing leaves your computer.** No account, no sign-up, no cloud, no
subscription, no telemetry. It's one program and one file on your own machine.
It's free and the source code is public.

---

## What it looks like

**The main window.** Everything you've locked, how long each one has left, and
how many times it can still be opened.

![The main window](docs/screenshots/06-main.png)

**Locking files.** Pick the files, choose when the key should die, and the
program tells you exactly what you're agreeing to before anything happens.

![Locking files](docs/screenshots/08-lock-flow.png)

**Setting a passphrase.** The strength meter doesn't flatter you. If what you
typed is weak, it says so and refuses. Press Generate and it makes you
something genuinely strong.

![Choosing a passphrase](docs/screenshots/04-create-strong.png)

**Opening a file.** You can open it for good, or borrow it — borrowing means
any edits you make get put back in the vault and the loose copies are cleaned
up afterwards.

![Opening on loan](docs/screenshots/10-loan.png)

**Proof of destruction.** A signed certificate for every key destroyed,
checkable by anyone, with no password needed.

![Certificates of destruction](docs/screenshots/12-certificates.png)

**The manual lives inside the program.** Seventeen pages, searchable, no
internet needed.

![The built-in manual](docs/screenshots/26-help.png)

**And the honest part.** This screen is in the menu, not hidden in a
footnote.

![What it does not protect against](docs/screenshots/28-limitations.png)

<details>
<summary><strong>More screenshots</strong> (click to open)</summary>

<br>

**Weak passphrases are refused outright**, with the reason given.

![A weak passphrase](docs/screenshots/01-create-weak.png)

**Backups**, with the cost of restoring one spelled out first. Restoring an
old backup brings back keys you destroyed on purpose, so the program tells you
how many before it will do it.

![Vault backups](docs/screenshots/18-backups.png)

**Watched folders.** Drop a file in and it's locked a few seconds later,
automatically.

![Watched folders](docs/screenshots/19-watched-folders.png)

**Checking your locked files** are still intact and haven't been corrupted or
swapped.

![Checking the locked files](docs/screenshots/21-integrity.png)

**Sending a file to somebody else's Quenchkey**, with the deadline travelling
along with it.

![Handing a file over](docs/screenshots/23-handover.png)

**A record for an auditor** — everything they need to verify your retention
policy, and none of your documents.

![A record for an auditor](docs/screenshots/24-auditor.png)

**Recovery shares.** Split the key to your vault into five pieces and keep
them in different places; any three put it back together.

![Recovery shares](docs/screenshots/13-recovery-shares.png)

**Settings.** Where files are saved, what closing the window does, whether it
starts when you log in.

![Settings](docs/screenshots/25-settings.png)

</details>

---

## Install it

Quenchkey runs on Linux. There's no Windows or Mac version.

### What you need first

Nothing, really. The installer checks for what's missing and offers to install
it. You'll need an internet connection the first time, and the ability to type
your password when it asks (it needs to install a few system libraries).

Supported: Ubuntu, Debian, Linux Mint, Pop!\_OS, Fedora, Arch, Manjaro,
openSUSE, Alpine, and anything close to those.

### The three commands

Open a terminal and paste these in, one at a time:

```bash
git clone https://github.com/a-khavish/Quenchkey.git
cd Quenchkey
./install.sh --user
```

That's it. It takes a few minutes the first time, mostly downloading the
graphics libraries.

> **If `git` isn't installed**, you can instead download the ZIP from the
> green **Code** button at the top of this page, unzip it, open a terminal in
> that folder, and run `./install.sh --user`.

### What the installer actually does

It tells you each step as it goes, and it doesn't do anything behind your
back:

| It does this | Where |
|---|---|
| Installs the program and its libraries | `~/.local/lib/quenchkey/` |
| Adds the `quenchkey` command | `~/.local/bin/` |
| Adds it to your applications menu | `~/.local/share/applications/` |
| Registers the `.qkey` file type, so locked files get the right icon | `~/.local/share/mime/` |
| Sets up a background check for expired files | `~/.config/systemd/user/` |

Everything goes in your own home folder. It doesn't touch system directories
and it doesn't need to be root for the program itself — only for installing
system libraries, and only if they're missing.

### Starting it

Find **Quenchkey** in your applications menu, or type `quenchkey` in a
terminal.

The first time it runs, it asks you to create a vault and choose a passphrase.
Read that screen carefully: **there is no password reset.** If you forget it,
everything you lock is gone permanently. That's not a limitation anyone can
fix; it's what makes the rest of it work.

### Removing it

```bash
cd Quenchkey
./install.sh --uninstall
```

**Your files are left alone.** Uninstalling removes the program, not your
vault or your locked files. If you want those gone too, delete `~/.quenchkey`
yourself — and understand that doing so makes every file you locked unreadable
forever.

<details>
<summary><strong>If something goes wrong</strong></summary>

<br>

**"Permission denied" when running `./install.sh`**

```bash
chmod +x install.sh
./install.sh --user
```

**`quenchkey: command not found` after installing**

The installer will have told you about this. Your shell doesn't know about
`~/.local/bin` yet. Add this line to the end of `~/.bashrc` (or `~/.zshrc` if
you use zsh), then close and reopen the terminal:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Starting it from the applications menu works either way.

**It complains about the "xcb" platform plugin**

A graphics library is missing. On Ubuntu or Debian:

```bash
sudo apt install libxcb-xinerama0 libxcb-cursor0 libxkbcommon-x11-0
```

**The background expiry check isn't running**

Run this once, after you've logged in to your desktop:

```bash
systemctl --user enable --now quenchkey-sweep.timer
```

**Text is too small or too large on a high-resolution screen**

```bash
quenchkey --font-scale 1.3
```

Any number works. If the whole interface is the wrong size rather than just
the text, try `quenchkey --scale 1.5` instead.

**Something else**

Open an [issue](https://github.com/a-khavish/Quenchkey/issues) and include
what you ran and what it said. Please don't attach your vault or your
passphrase — they're never needed to fix a bug, and an issue is public forever.

</details>

---

## How you'd actually use it

**Lock a file with a deadline.** Click *Lock files*, pick the file, choose
"90 days", confirm. You get a `.qkey` file. Email it, put it on a USB stick,
upload it anywhere you like. In 90 days the key is destroyed and every copy of
that `.qkey` stops opening — including yours.

**Shred the original as you go.** There's a checkbox for it. The locked copy
becomes the only copy.

**Let a file expire after being opened twice.** Instead of a date, set an
opening allowance. Useful when you want somebody to read something once or
twice and no more.

**Set a dead man's switch.** "Destroy the key if I don't open Quenchkey for
six months." Opening the program is the check-in; there's nothing else to do.
It warns you a week, a day and an hour before, so it never catches you out.

**Send something to somebody who doesn't have Quenchkey.** Use *Lock files to
share*. They get a file they can open with a passphrase you give them, on any
computer, with no software of yours. The honest catch, which the program tells
you plainly: a file like that can never expire, because the key travels inside
it.

**Send something to somebody who does have Quenchkey.** Use *Hand over to
another vault*. They send you their identity card (a small file with no secret
in it), you address the file to them, and when they accept it your deadline
lands inside their vault and their copy expires on schedule.

**Prove you destroyed something.** Open *Certificates of destruction*, export
one, send it. They can verify it without Quenchkey and without any password of
yours.

There's more — [every feature is written up here](docs/FEATURES.md) — but
that's the shape of it.

---

## What it cannot do

This is the part most programs bury. Read it before you rely on any of this.

**A file somebody has already opened is gone.** Once they've opened it, the
document is an ordinary file on their computer. They can save it, print it,
photograph the screen, email it on. Destroying the key reaches the locked copy
and nothing else. **There is no recall.**

**Somebody who copies your vault before the deadline can put it back
afterwards.** If a person has your computer and your passphrase, they can take
a copy of the vault today and restore it next year, and the keys come back.
Quenchkey records that this happened in a tamper-evident log, so you can tell
— but it cannot prevent it. No program running on a computer somebody else
controls can.

**Files you share with a passphrase can never expire.** The key is inside the
file, so there's nothing left anywhere to destroy. The program says this on
the screen where you make one, not in a footnote.

**Your passphrase is the whole thing.** A weak one means weak protection, no
matter what else the program does. There is no reset, no recovery code, no
support email. Set up recovery shares in advance if that worries you.

**Anything is readable while the vault is open.** Keys are in memory then. It
locks itself when you're idle, and you should lock it yourself when you walk
away.

**If your computer is already compromised, none of this helps.** Something
recording your keystrokes gets your passphrase. No program can fix that from
inside.

### Things deliberately not built

Each of these appears in competing products. None of them work:

- **Blocking screenshots.** Not possible from a normal program, and a phone
  camera beats every version of it.
- **"Only our app can open these files."** The format is documented and there
  is a separate tool that opens them. This claim is a lie wherever you see it.
- **Hidden or locked folders.** Anybody with your account undoes it in
  seconds.
- **Deleting files from someone else's computer.** There is no mechanism.
  They own the machine.

---

## Is it any good?

Fair question for a program nobody has heard of. Here's what you can check
yourself rather than take on trust:

**617 automated tests**, which run on every change. They don't only test that
features work — they test the limits. One takes a live key and searches the
auditor's record for it, to prove it isn't there. Another makes a copy of a
file by hand and proves the program doesn't touch it, because the program
claims it can't.

**Every screen is tested at four different text sizes** on a small laptop
screen, and the build fails if a button ends up off the edge.

**The walkthrough video above is itself a test.** A script drives the real
program with real mouse clicks and keystrokes, finds each button by the words
a person would read, and fails if a button is missing or doesn't do what it
says. Several steps read the warning text off the screen and fail if it has
gone, so a caveat can't quietly disappear from a dialog.

**A separate program re-reads everything afterwards.** It shares no code with
the main application, so if the program wrote something only it understands,
the test catches it.

And the thing you can't check, so I'll just say it: **I'm the only person who
has used this.** It's version 1.0.0 and it has had no real-world mileage. If
you find something broken, please
[open an issue](https://github.com/a-khavish/Quenchkey/issues) — I'd rather
hear about it than not.

---

## For the curious

| | |
|---|---|
| [Every feature, explained](docs/FEATURES.md) | All of it, one at a time |
| [How it works](docs/HOW-IT-WORKS.md) | The cryptography, the file formats, the design |
| [Security](SECURITY.md) | What it protects against, and what it doesn't |
| [Contributing](CONTRIBUTING.md) | How to help, and the one rule |
| [Changelog](CHANGELOG.md) | What's in this release |

Short version for people who want it: Argon2id tuned to about a second per
guess, ChaCha20-Poly1305 or AES-256-GCM, 1 MiB chunked streaming with
everything authenticated, Ed25519 signatures, X25519 for addressing files to
another vault, SLIP-39 for recovery shares, RFC 3161 timestamps. Nothing
home-made: it all comes from `cryptography` and `argon2-cffi`.

---

## Licence

Apache 2.0. Do what you like with it, including commercially.

One thing to know if you plan to distribute a packaged build: **PyQt5, the
graphics library, is GPL v3** unless you buy a commercial licence from
Riverbank. That affects redistributing a bundled binary, not using the
program. The interface code is kept in one folder (`quenchkey/ui/`) and
everything underneath it is independent of Qt, so replacing the interface is
possible if that matters to you.

See [`LICENSE`](LICENSE) for the terms and [`NOTICE`](NOTICE) for the
dependencies.
