# Copyright 2026 Quenchkey contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""The manual, as data, so the window and the tests read the same words.

Written as (title, paragraphs) sections under named pages. Paragraphs
beginning with "- " become bullets and "> " becomes a monospaced block; there
is no other markup, because a help page nobody can read in a terminal is a
help page that rots.
"""

from __future__ import annotations

PAGES: list = [
    ("Getting started", [
        ("What Quenchkey actually does", [
            "Quenchkey encrypts files and keeps the key somewhere separate from "
            "them. When a deadline passes it destroys the key, not the file.",
            "That is the whole idea, and it is worth a moment. Deleting a file "
            "reaches only the copy you can see. Destroying its key reaches "
            "every copy at once — the one on your disk, the one in last "
            "month's backup, the one you emailed, the one on a drive you "
            "forgot about. None of them can be read again, by this "
            "application or by anything else, because the key that could read "
            "them no longer exists anywhere.",
            "The standards bodies call this cryptographic erase. NIST "
            "SP 800-88 lists it as a way of sanitising media, and it is the "
            "only mechanism here that does any real work.",
        ]),
        ("The vault, and the one passphrase", [
            "Everything starts with a vault: one file, by default at "
            "~/.quenchkey/vault.qkv, holding the keys to everything you lock. It "
            "is protected by a single passphrase, and that passphrase is the "
            "entire security of the system.",
            "There is no reset, no recovery email and no back door. Forget it "
            "and every file you locked stays locked for good. The one safety "
            "net is recovery shares, which you have to set up in advance — "
            "see the Recovery page.",
            "Press Generate when creating the vault. It produces 24 random "
            "characters, which is about 157 bits: not guessable by anybody, "
            "ever, at any budget. It is also not memorable, so put it in a "
            "password manager before you lock anything.",
        ]),
        ("Locking your first files", [
            "- Press Lock files… , or drag files onto the window.",
            "- Choose what should end the file's life: a deadline, a number "
            "of openings, a check-in interval, or any combination. Whichever "
            "comes first destroys the key.",
            "- Quenchkey packs the selection into one .qkey file, encrypts it "
            "with a fresh 256-bit key, and puts that key in the vault.",
            "The .qkey file can go anywhere — a USB stick, a shared folder, "
            "a backup. It is unreadable without the vault, and it becomes "
            "permanently unreadable the moment the key is destroyed.",
        ]),
    ]),

    ("Opening files", [
        ("Opening something from the vault", [
            "Select it and press Open… . Quenchkey decrypts it and writes the "
            "files out as ordinary files.",
            "Two things to know. Opening spends one of the allowance if you "
            "set one. And once files are out, they are out: the copies you "
            "extracted are ordinary files with no deadline and nothing "
            "Quenchkey can do to them. Expiry reaches the locked file, never the "
            "copies you made from it.",
        ]),
        ("How do I open a .qkey file?", [
            "Three ways, and the third is the one that matters:",
            "- From Quenchkey. If it came from your vault, select it and press "
            "Open… . If it is a shared file, use Vault ▸ Unlock shared "
            "files… .",
            "- By double-clicking it. The installer registers the .qkey "
            "file type with your desktop, so a double-click opens Quenchkey.",
            "- Without Quenchkey at all, using the standalone recovery script "
            "that ships alongside it. It shares no code with this "
            "application and needs nothing from it:",
            "> quenchkey-recover list    vault.qkv",
            "> quenchkey-recover extract vault.qkv <entry-id> -o ./recovered",
            "> quenchkey-recover share   handover.qkey -o ./recovered",
        ]),
        ("Can another application open a .qkey file?", [
            "No — and that is a statement about the format, not a claim of "
            "protection.",
            "A .qkey file is a Quenchkey container: a header, then the file "
            "encrypted in chunks. No archive manager knows that layout, so "
            "7-Zip, Ark and File Roller will all decline it. Renaming it to "
            ".7z or .zip will not help.",
            "But nothing is stopping anybody from writing a program that "
            "reads it. The format is documented in the README and the "
            "recovery script is the reference implementation. What stops "
            "someone reading your files is the encryption and the passphrase, "
            "not the obscurity of the container. Quenchkey does not claim that "
            "only it can open these files, because that would not be true and "
            "would not matter if it were.",
            "The only thing that genuinely cannot be undone is a destroyed "
            "key. After that no program, including this one, can read the "
            "file.",
        ]),
    ]),

    ("Sharing", [
        ("Files you can send to someone", [
            "Vault ▸ Lock files to share… packs a selection into one .qkey "
            "file with a passphrase of its own. Send the file and the "
            "passphrase and the recipient can open it on any machine, with no "
            "vault, no account and nothing installed.",
            "Send the passphrase by a different route from the file. An email "
            "with both in it is an email with neither.",
        ]),
        ("A shared file has no deadline, and cannot be given one", [
            "This is the one trade-off worth understanding.",
            "Everything else in Quenchkey works because the key is somewhere the "
            "holder of the locked file does not control. A shared file "
            "carries its own key, wrapped by its passphrase — that is exactly "
            "what lets someone else open it — so there is nothing left "
            "anywhere that could be destroyed to take it back.",
            "It is not weaker cryptographically. It is the same cipher and "
            "the same key derivation as your vault, and guessing the "
            "passphrase is the only way in. What it cannot do is expire, and "
            "it cannot be recalled once sent.",
            "Because of that, shared files never appear in the list of vault "
            "entries. They have a section of their own, marked no deadline, "
            "not recallable, and creating one asks you to type NO DEADLINE.",
        ]),
        ("Unlocking them again", [
            "Vault ▸ Unlock shared files… lists every shared file this vault "
            "wrote, and Add files… opens any others through your own file "
            "manager. Tick what you want, give the passphrase once.",
            "Files locked with a different passphrase are reported on their "
            "own line; the rest still open.",
            "- One document comes out as one file, named "
            "something_quenchkeyunlocked.ext",
            "- Several come out in a folder named after the locked file",
            "- Or produce one 7z archive with no password at all, for passing "
            "on to somebody who should not need a passphrase",
            "Nothing existing is ever overwritten. Unlock the same file twice "
            "and you get a second copy, not a replaced first one.",
        ]),
    ]),

    ("Deadlines", [
        ("The three rules", [
            "- A deadline. A moment after which the key is destroyed.",
            "- An opening allowance. Destroy the key after it has been opened "
            "this many times.",
            "- A check-in interval. A dead man's switch: if you do not open "
            "Quenchkey within the interval, the key is destroyed.",
            "Set any combination. Whichever comes first wins.",
        ]),
        ("Expiry while Quenchkey is closed", [
            "Vault ▸ Expiry while Quenchkey is closed… turns on a background "
            "task that deletes expired files when nothing is unlocked.",
            "It deletes files. It cannot destroy keys, and the reason is "
            "structural: the vault is one encrypted blob, so a task that does "
            "not know your passphrase cannot open it, read a deadline from it "
            "or write to it. Keys are destroyed at your next unlock, which is "
            "the first moment the vault can be written at all.",
            "Switching it on writes a list of your deadlines beside the "
            "vault, readable only by you and not encrypted — encrypting it "
            "under a key kept next to it would protect nothing. It holds no "
            "keys and no file contents. It is off until you turn it on.",
        ]),
        ("Rolling back the clock", [
            "Quenchkey remembers the latest time it has ever seen and never "
            "accepts an earlier one, so setting the clock back does not "
            "extend a deadline.",
            "What it cannot stop is a copy of the whole vault folder, taken "
            "before a deadline and restored afterwards. Local expiry is "
            "tamper-evident, not tamper-proof. The event log and its anchor "
            "are how you detect that — see the Verifying page.",
            "A timestamp from an authority narrows it: the vault takes "
            "somebody else’s reading of the time and moves its watermark "
            "forward on it, so a machine whose clock was wound back is put "
            "right the next time it can reach one. See the Trusted time "
            "page — and note that it needs the network, and cannot stop "
            "the winding, only make it visible and correct it afterwards.",
        ]),
    ]),

    ("Recovery", [
        ("If you forget the passphrase", [
            "There is nothing anybody can do. No reset, no recovery, no "
            "support address that can help. The keys in the vault are "
            "encrypted with a key derived from your passphrase; without it "
            "they are random noise.",
            "The only protection is one you set up in advance.",
        ]),
        ("Recovery shares", [
            "Vault ▸ Recovery shares… splits the vault's master key into a "
            "set of shares, any threshold of which reconstructs it. Three of "
            "five, for instance — any three work, any two are useless.",
            "They use SLIP-39, the Trezor standard, so they are word lists "
            "you can write on paper. Keep them apart from each other and "
            "apart from the vault: shares kept in the same drawer as the "
            "vault are a spare key taped to the door.",
            "They are shown once, when generated. Quenchkey does not keep a copy "
            "and cannot show them again.",
        ]),
    ]),

    ("Verifying", [
        ("The event log and its anchor", [
            "Every action is recorded in a hash chain: each entry includes "
            "the hash of the one before, so altering any of them changes "
            "every hash after it.",
            "The anchor is a short fingerprint of the whole history, shown in "
            "the window header. Write it down somewhere else — a notebook, a "
            "different machine — and you can tell later whether the history "
            "you are looking at is the one you had.",
            "This detects tampering; it does not prevent it. Detection is "
            "what a local file can honestly offer.",
        ]),
        ("Certificates of destruction", [
            "Every destroyed key produces a signed certificate: what was "
            "destroyed, when, why, under which method.",
            "They are signed with an Ed25519 key belonging to the vault, and "
            "verify with no passphrase and no vault — a third party can check "
            "one holding nothing but the document:",
            "> quenchkey-recover verify certificate.json",
            "Set a custodian under Vault ▸ Custodian details… and their name "
            "and role go onto every certificate the vault issues.",
        ]),
    ]),

    ("Settings", [
        ("Where files are saved", [
            "Settings lets each kind of output go somewhere fixed or ask "
            "every time.",
            "Asking always opens your desktop's own file chooser — the same "
            "one every other application uses — which is also where you "
            "rename a file on the way out. Quenchkey does not draw its own file "
            "browser anywhere.",
            "A fixed folder skips the question. Nothing is ever overwritten "
            "either way: a name already in use gets (2) appended.",
        ]),
        ("The window and the tray", [
            "The window opens filling the screen and can still be resized and "
            "moved.",
            "Closing it can quit, keep Quenchkey in the tray, or ask. Quitting "
            "locks the vault and wipes every key from memory; the tray keeps "
            "deadlines being checked, and the vault still locks itself when "
            "idle.",
            "GNOME has no system tray of its own — what looks like one is an "
            "extension such as AppIndicator. Without it, closing the window "
            "quits whatever the setting says, because a window that vanished "
            "while claiming to still be running would be worse than either.",
        ]),
        ("Starting on login", [
            "Settings can add Quenchkey to your desktop's autostart folder. It "
            "writes one ordinary .desktop file under ~/.config/autostart, "
            "which you can delete by hand at any time.",
            "Starting on login does not unlock anything. Quenchkey opens at the "
            "passphrase screen exactly as it would otherwise. There is no "
            "stored passphrase, so there is nothing that could skip it.",
        ]),
    ]),

    ("Backups", [
        ("Why a backup matters more than you would think", [
            "Losing the vault file loses everything in it. Not "
            "\u201cinconveniently\u201d \u2014 completely: every locked file becomes "
            "unreadable at once, as though every deadline had fired together.",
            "Recovery shares do not cover this. They rebuild the master key, "
            "but the per-file keys live inside the vault, so with the file "
            "gone there is nothing for that key to open. Somebody who deletes "
            "~/.quenchkey by accident destroys the lot.",
            "Vault \u25b8 Vault backups\u2026 takes a copy. It is already "
            "encrypted under your passphrase, so it needs no second one \u2014 and "
            "keeping it beside the vault protects against nothing, so put it "
            "somewhere else.",
        ]),
        ("What restoring costs", [
            "A backup is a copy of a past state, and expiry only runs "
            "forwards. Restore one and the keys it held come back, including "
            "keys this vault destroyed on purpose.",
            "That cannot be engineered away while also having backups, so "
            "restoring is made loud instead. Before it happens you are told "
            "exactly how many events would be undone and how many destroyed "
            "keys would return, and you type ROLL BACK to go ahead. The vault "
            "you replace is moved aside rather than deleted, so restoring the "
            "wrong one is recoverable.",
            "Afterwards the restored vault carries a permanent, chained "
            "record that it was rolled back and by how much. An audit of it "
            "later shows the gap rather than hiding it.",
        ]),
    ]),

    ("Watched folders", [
        ("Drop a file in, and it locks itself", [
            "Vault \u25b8 Watched folders\u2026 sets up a folder where anything "
            "that appears is packed, encrypted under a fresh key and the "
            "original shredded \u2014 with whatever rule you gave the folder. No "
            "dialog at the moment of dropping.",
            "Useful for a scanner output folder, a downloads folder, or "
            "anywhere things arrive that should not sit around in the clear.",
        ]),
        ("The two limits", [
            "It only runs while the vault is unlocked. Locking needs the "
            "vault, so a file dropped in while Quenchkey is closed sits there "
            "in the clear until you next open it. A watched folder is a "
            "convenience, not a guard on the folder.",
            "A file is locked once it has stopped changing \u2014 about six "
            "seconds at the same size and timestamp. Otherwise a download in "
            "progress would be encrypted half-written. Partial downloads, "
            "editor scratch files and hidden files are never picked up at all.",
        ]),
    ]),

    ("Checking files out", [
        ("Opening on loan instead of for good", [
            "Opening a locked file normally is a one-way door: the copies "
            "that come out are ordinary files with no deadline, and nothing "
            "here can reach them afterwards.",
            "A loan is the other option, and it is the second choice in the "
            "Open dialog. The files come out the same way, but their paths "
            "are recorded. When the loan runs out \u2014 or when you press "
            "Bring it back \u2014 anything you edited is locked back into the "
            "vault, the working copies are shredded, and the entry goes back "
            "to being merely locked. The key is not destroyed; the file "
            "returns, that is all.",
        ]),
        ("Your edits are not thrown away", [
            "Each file is fingerprinted as it goes out, so bringing it back "
            "can tell an edited file from an untouched one. An untouched copy "
            "is simply shredded and the vault is left exactly as it was. An "
            "edited one is written back into the same entry first, under the "
            "same key, keeping its deadline, its opening count and its place "
            "in the event log.",
            "If the edits cannot be written back \u2014 the key was destroyed "
            "while the file was out, or part of what went out has gone "
            "missing \u2014 nothing is shredded. The working copies are left "
            "exactly where they are and the app says why. A feature that "
            "quietly destroyed an afternoon\u2019s work when a timer fired "
            "would be a trap, not a convenience.",
        ]),
        ("What it reaches", [
            "It reaches the copies that extraction made, at the paths it "
            "wrote them to.",
            "It does not reach a copy you made afterwards, a file your editor "
            "saved somewhere else, a backup that ran in the meantime, or "
            "anything on another machine. Those are not brought back and not "
            "shredded. A loan is tidying up after yourself, not control over "
            "where your file went.",
        ]),
    ]),

    ("Duress", [
        ("A passphrase that destroys the vault", [
            "Vault \u25b8 Duress passphrase\u2026 arms a second passphrase. Typing "
            "it at the unlock screen overwrites and deletes the vault, and "
            "Quenchkey comes back as though no vault had ever been made. "
            "There is no confirmation at that moment; that is the point.",
            "It is off unless you set it, and setting it asks you to type "
            "DESTROY THE VAULT first.",
        ]),
        ("Three things to be clear about", [
            "- It destroys your data, permanently. It is not a decoy vault "
            "with different contents. Every key goes, and every .qkey file "
            "you locked becomes unreadable \u2014 to you as much as to anyone.",
            "- It reaches one file on one machine. A backup, a copy on "
            "another disk, a filesystem snapshot: none are touched. Somebody "
            "who copied the vault before you typed it still has everything.",
            "- It is the unlock screen that acts on it, not the vault "
            "format. The standalone quenchkey-recover tool asks for a "
            "passphrase and will simply report the duress one as wrong; "
            "it never deletes anything. Somebody who reaches for that "
            "tool instead is not stopped by a duress passphrase.",
            "- It must be nothing like your real passphrase. Mistyping the "
            "real one is simply wrong and costs nothing; the duress one has "
            "to match exactly. Choosing something close to your real "
            "passphrase is how people destroy their own vault by accident.",
        ]),
        ("How it works, and what it cannot do", [
            "The duress passphrase does not derive the master key \u2014 nothing "
            "derived from it can decrypt anything. What is stored is a hash "
            "of the key it derives, under the same salt and cost as the real "
            "one, so a single derivation answers both questions and an "
            "attacker guessing at the file pays the same price either way.",
            "Because it cannot decrypt the vault, it cannot do anything "
            "subtler than destroy the file. It cannot shred entries one at a "
            "time, and it cannot hand back a convincing empty vault with the "
            "real one hidden underneath.",
        ]),
    ]),

    ("Handing files over", [
        ("A deadline that survives being sent", [
            "A shared file carries its own key, which is why it can never "
            "expire: expiry destroys a key the holder of the file does not "
            "control, and a self-contained file has nothing that can be taken "
            "away from it.",
            "A handover is the way round that, and it needs the other person "
            "to be running Quenchkey too. The key is wrapped to their vault "
            "instead of to a passphrase, so when they accept it the deadline "
            "lands inside their vault and their own background sweep destroys "
            "it on time. Nothing has to reach across a network on the day.",
        ]),
        ("How to do it", [
            "They send you their identity card \u2014 Vault \u25b8 My identity "
            "card \u25b8 Save my card. It holds no secret, so any means of "
            "sending it will do: email, chat, a USB stick, published on a web "
            "page. The worst somebody can do with your card is send you a "
            "file only you can open.",
            "You use Vault \u25b8 Hand over to another vault, open their card, "
            "choose the files and set the terms. The file that comes out opens "
            "in one vault and nowhere else, so send it however you like.",
            "They use Vault \u25b8 Accept a handover. They see the terms first "
            "and can decline.",
        ]),
        ("What the terms are, and what they are not", [
            "The deadline, the opening allowance and the check-in interval "
            "travel inside the file, authenticated. They read them before "
            "accepting, and neither of you can change them afterwards without "
            "the file failing to open.",
            "Three things this does not buy, all of which the dialog says "
            "too. They can decline, and a file they never accept is a file "
            "they cannot read. Once they accept and open it, the copy that "
            "comes out is an ordinary file and nothing here reaches it. And "
            "it is their machine \u2014 they can restore a backup of their own "
            "vault after the deadline, exactly as you can with yours, which "
            "is tamper-evident and not tamper-proof.",
        ]),
        ("Where the addressing comes from", [
            "Each vault derives a key-agreement key from the signing seed it "
            "already keeps for certificates, under its own separator so the "
            "two are never the same bytes used twice. The card carries that "
            "public key and an Ed25519 signature over it, which anybody can "
            "check with no passphrase and no vault \u2014 that is what stops a "
            "card being edited in transit to name somebody else\u2019s key.",
            "The fingerprint on the card is there so somebody can read it "
            "back to you over the telephone. The signature proves the card "
            "was not altered; only that check proves who wrote it.",
        ]),
    ]),

    ("Checking the files", [
        ("Noticing before it matters", [
            "Every entry records the SHA-256 of its locked file at the moment "
            "it was written. Vault \u25b8 Check the locked files reads each of "
            "those files back and compares, which is how a vault notices a "
            "failing drive, a copy that never finished, or a file that has "
            "been swapped.",
            "This is detection, not prevention. An altered file was already "
            "going to be refused \u2014 the encryption authenticates what it "
            "decrypts, so a modified file fails rather than returning wrong "
            "content. What the check buys you is finding out now instead of "
            "on the day you need the file.",
        ]),
        ("Finding one that moved", [
            "A locked file that was moved reads as missing, because the vault "
            "stores a path. Look for missing ones searches a folder you "
            "choose and matches candidates by digest \u2014 not by name, which "
            "may well have been changed too.",
            "A candidate is only accepted when its hash is the one the vault "
            "recorded. Pointing an entry at where its file actually is "
            "changes the path and nothing else: the key, the deadline, the "
            "opening count and its place in the event log all stay as they "
            "are, and the move is written into the chain.",
        ]),
    ]),

    ("A record for an auditor", [
        ("Showing the retention without showing the documents", [
            "A retention policy is often somebody else\u2019s business \u2014 a "
            "data protection officer confirming last year\u2019s files really "
            "did expire, or a client wanting evidence theirs were destroyed. "
            "Handing them the vault passphrase would open every document in "
            "it; handing them nothing means they take your word.",
            "Vault \u25b8 Record for an auditor writes a separate file beside "
            "the vault, under a passphrase of its own, holding every "
            "entry\u2019s name, size, rules and opening count, when and why "
            "each key was destroyed, the whole event log, and the "
            "certificates.",
        ]),
        ("There is no key in it", [
            "Not wrapped, not derived, not in any form that could become one. "
            "The record is built from the vault rather than being a slice of "
            "it, so there is nothing in the file for a holder to attack "
            "however long they keep it. That is a stronger statement than "
            "\u201cwe did not give them the key\u201d, and it is the reason for "
            "doing it this way.",
            "The record is signed with the same key that signs certificates "
            "of destruction. An auditor holding any certificate from this "
            "vault already has the public key, so they can confirm the record "
            "came from the vault it claims to.",
        ]),
        ("What to tell them", [
            "Give them the record and its passphrase, and nothing else. They "
            "read it with the standalone tool, which imports nothing from "
            "this application: quenchkey-recover audit-record vault.qkv.audit "
            "--public-key <from any certificate>.",
            "Choose a passphrase that is not the vault\u2019s. Nothing here can "
            "stop you \u2014 the vault does not keep its own passphrase, so it "
            "has nothing to compare against \u2014 and using it would hand an "
            "auditor every document.",
            "It is a snapshot, rewritten when you write it. An auditor "
            "reading a record from a vault last opened in March is reading "
            "March. Comparing its anchor against one you published "
            "independently is how they tell.",
        ]),
    ]),

    ("Trusted time", [
        ("Somebody else\u2019s opinion of what time it is", [
            "The weakest joint in local expiry is the clock. The vault keeps "
            "a watermark and never accepts a time earlier than the latest it "
            "has seen, which makes a clock set backwards evident rather than "
            "impossible \u2014 somebody with your machine can still wind it "
            "back before the vault has noticed a deadline pass.",
            "A timestamp authority takes a hash and returns that hash and a "
            "time, signed. It never sees the data. The token proves one thing "
            "and proves it forever, offline, to anybody: this hash existed no "
            "later than this time.",
        ]),
        ("What it buys, in two places", [
            "The anchor becomes third-party evidence. Instead of writing the "
            "fingerprint down yourself and remembering to, a signature from a "
            "party neither you nor an auditor controls says that history "
            "existed at that moment. Somebody who later restores an old "
            "backup cannot produce a token for the newer chain head.",
            "The clock is corrected rather than trusted. Fetching a token "
            "tells the vault what the time is according to somebody else, and "
            "that reading moves the watermark forward \u2014 so a machine whose "
            "clock was wound back is put right the next time it can reach an "
            "authority.",
        ]),
        ("What it does not buy", [
            "- It does not work offline. A machine kept off the network keeps "
            "whatever protection the ratchet gives it and no more.",
            "- It cannot stop the clock being wound back. It can only make "
            "the winding visible and correct it afterwards.",
            "- It is only as good as the authority. A token verifies against "
            "a certificate you supply; without one it is stored but not "
            "verified, and the dialog says so rather than showing a tick it "
            "has not earned.",
            "It is off unless you ask for it: it is the one feature here that "
            "talks to the network at all, and only ever a hash leaves the "
            "machine.",
        ]),
    ]),

    ("From a terminal", [
        ("The same operations, and deliberately fewer of them", [
            "The window is where this gets used. A command line adds what a "
            "dialog cannot reach \u2014 a nightly job that locks yesterday\u2019s "
            "exports, a monitoring check that fails if a vault has not been "
            "swept \u2014 and it is narrower than the window on purpose.",
            "quenchkey help prints one page grouped by what you are trying to "
            "do, coloured where colour distinguishes something: red for a "
            "thing that has just become unreadable or is about to, amber for a "
            "thing that wants a decision, green for a thing that went as "
            "asked. Nothing else is coloured, and it switches itself off when "
            "output is not a terminal, when NO_COLOR is set, or whenever "
            "--json is asked for.",
        ]),
        ("The passphrase comes from a prompt, and from nowhere else", [
            "Not an argument, because arguments are visible to every process "
            "on the machine and land in shell history. Not an environment "
            "variable, because it is inherited by every child process and ends "
            "up in systemd units and CI logs. Not a file, because a file "
            "holding the passphrase to a vault is the one thing this tool "
            "tells you not to make.",
            "So every command that needs the vault open cannot run "
            "unattended. That is the design rather than an oversight: a tool "
            "that says never to write your passphrase down, and then ships an "
            "option for doing exactly that, is not saying it very hard.",
        ]),
        ("Which is fine, because a cron job does not need them", [
            "quenchkey deposit locks files into your own vault using nothing "
            "but your identity card. The file key is wrapped to your vault\u2019s "
            "public identity, so the file is unreadable the moment it is "
            "written \u2014 by anybody, including the script that wrote it. You "
            "accept them next time you open the vault, on the terms the job "
            "proposed.",
            "The card holds no secret. It can sit in a config directory or a "
            "repository; losing it lets somebody deposit files into your "
            "vault, which is not a thing worth worrying about.",
            "Two secrets that are not the vault\u2019s may still come from the "
            "environment, because leaking either costs something bounded "
            "rather than everything: an audit record\u2019s passphrase, which "
            "opens metadata and no documents, and a shared file\u2019s own "
            "passphrase, which opens that one file.",
        ]),
        ("Exit codes, because that is what a script reads", [
            "- 0: what was asked for happened",
            "- 1: it did not, and the reason is on standard error",
            "- 2: the command line itself was wrong",
            "- 3: the vault could not be opened",
            "- 4: a check failed \u2014 something expired, altered or missing",
            "status, check and warn all exit 4 rather than 0 when they find "
            "something, so a monitoring job can watch a vault without parsing "
            "prose. Nothing is quieter from the terminal than from a dialog: "
            "expire prints in red what it is about to make unreadable and "
            "refuses without --yes, and lock says in amber when it has set no "
            "rules at all.",
        ]),
    ]),

    ("Limits", [
        ("What Quenchkey does not do", [
            "- It cannot delete anything on someone else's computer. Once a "
            "file is on a machine you do not control you have no authority "
            "there — the recipient can copy the disk, cut the network, freeze "
            "the clock, or remove whatever you asked them to install. No "
            "product can do this; the ones that claim to are shipping "
            "something a determined recipient defeats in an afternoon.",
            "- It cannot recall a file you already opened, or one you shared.",
            "- It cannot stop screenshots, photographs of the screen, or "
            "somebody reading over your shoulder.",
            "- It cannot protect you on a machine that is already "
            "compromised. Malware with your privileges sees what you see.",
            "- It cannot make a weak passphrase strong. That is the one thing "
            "everything else rests on.",
        ]),
        ("Uninstalling", [
            "Help ▸ Uninstall Quenchkey… removes the application, its menu "
            "entry, its icons and its background timer.",
            "Your vault is left alone, deliberately. Removing the application "
            "does not destroy a single key — that only ever happens on a "
            "deadline you set, or when you ask for it. To remove the vault as "
            "well, delete ~/.quenchkey yourself, and understand that doing so "
            "makes every .qkey file you locked permanently unreadable.",
            "Deleting Quenchkey is not a way around anything. There is no lock "
            "in the application to bypass: what protects your files is that "
            "they are encrypted and that the key is gone. With Quenchkey removed "
            "you are left with unreadable files and a recovery script that "
            "still asks for the passphrase.",
        ]),
    ]),
]


def page_titles() -> list:
    return [title for title, _sections in PAGES]


def as_plain_text() -> str:
    """The whole manual as text, for a terminal or a bug report."""
    lines = []
    for page, sections in PAGES:
        lines.append(page.upper())
        lines.append("=" * len(page))
        lines.append("")
        for heading, paragraphs in sections:
            lines.append(heading)
            lines.append("-" * len(heading))
            for paragraph in paragraphs:
                lines.append(paragraph)
                lines.append("")
        lines.append("")
    return "\n".join(lines)
