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

"""Checking that the locked files are still the locked files.

Every entry records the SHA-256 of its ``.qkey`` file at the moment it was
written. Until now that digest was only ever read when a certificate was
issued, which meant a vault could sit for years pointing at a file that had
been truncated by a full disk, corrupted by a failing drive, or replaced.

Two things happen here.

**Checking.** Walk every entry, hash the file it points at, and say which of
four states it is in: intact, changed, missing, or unverifiable because it
predates the digest being recorded. Changed is the interesting one, and worth
being precise about what it does and does not mean. The AEAD already refuses
to decrypt a modified file, so a changed digest is not a security hole that
was open — it is early notice of one that would otherwise surprise you on the
day you needed the file. Detection, not prevention: the same honesty that
applies to the rest of this tool.

**Finding.** A ``.qkey`` file that was moved reads "file missing" forever,
because the vault stores a path. Searching a folder the user chooses and
matching candidates *by digest* re-points the entry without trusting the
filename, which may well have been changed too. A candidate is only accepted
when its hash is the one the vault recorded — there is no fuzzy matching here,
and a file that merely has the right name is not enough.

Neither of these needs the passphrase to be *useful*, but both need the vault
open to be *trusted*: the digests live inside the authenticated payload, which
is the whole point of keeping them there.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from .certificate import file_digest
from .vault import Entry, Vault

#: The four states an entry's locked file can be in.
INTACT = "intact"
CHANGED = "changed"
MISSING = "missing"
UNKNOWN = "unverifiable"

#: Where the time of the last check is remembered, in the vault's own notes.
NOTE_KEY = "last_integrity_check"

#: Files considered when searching for something that moved.
BLOB_SUFFIX = ".qkey"

ProgressFn = Callable[[str, float], None]


@dataclass
class Finding:
    """One entry, and what was found where it points."""

    entry_id: str
    name: str
    path: str
    state: str
    recorded: str = ""
    found: str = ""
    size: int = 0

    @property
    def ok(self) -> bool:
        return self.state == INTACT

    def explain(self) -> str:
        if self.state == INTACT:
            return "matches the digest recorded when it was locked"
        if self.state == MISSING:
            return "not at the path the vault has for it"
        if self.state == UNKNOWN:
            return ("locked before digests were recorded, so there is nothing "
                    "to compare against")
        return ("does not match the digest recorded when it was locked — it "
                "has been altered, truncated or replaced")


@dataclass
class CheckReport:
    """What one pass over every entry found."""

    checked_at: float = 0.0
    findings: list = field(default_factory=list)
    #: Seconds the pass took, which is worth showing for a large vault.
    took: float = 0.0

    def _of(self, state: str) -> list:
        return [f for f in self.findings if f.state == state]

    @property
    def intact(self) -> list:
        return self._of(INTACT)

    @property
    def changed(self) -> list:
        return self._of(CHANGED)

    @property
    def missing(self) -> list:
        return self._of(MISSING)

    @property
    def unverifiable(self) -> list:
        return self._of(UNKNOWN)

    @property
    def ok(self) -> bool:
        return not self.changed and not self.missing

    def summary(self) -> str:
        if not self.findings:
            return "There is nothing in this vault to check."
        total = len(self.findings)
        if self.ok and not self.unverifiable:
            return (f"All {total} locked file{'s' if total != 1 else ''} match "
                    f"the digests recorded when they were locked.")
        parts = []
        if self.intact:
            parts.append(f"{len(self.intact)} intact")
        if self.changed:
            parts.append(f"{len(self.changed)} altered")
        if self.missing:
            parts.append(f"{len(self.missing)} missing")
        if self.unverifiable:
            parts.append(f"{len(self.unverifiable)} with no digest on record")
        return ", ".join(parts) + f", out of {total}."

    def advice(self) -> str:
        """What to do about it, when there is something to do."""
        if self.missing and self.changed:
            return ("Search for the missing ones — they may simply have been "
                    "moved. An altered file will not decrypt, so restore it "
                    "from a backup if you have one.")
        if self.missing:
            return ("They may only have been moved. Searching a folder "
                    "matches candidates by digest rather than by name.")
        if self.changed:
            return ("An altered file will not decrypt: the encryption refuses "
                    "it rather than returning wrong data. Restore it from a "
                    "backup if you have one; the key in the vault is fine.")
        return ""


def check(vault: Vault, progress: Optional[ProgressFn] = None) -> CheckReport:
    """Hash every locked file and compare it with what the vault recorded."""
    started = time.monotonic()
    report = CheckReport(checked_at=time.time())
    entries = vault.entries()

    for index, entry in enumerate(entries):
        if progress:
            progress(entry.display_name, index / max(1, len(entries)))
        report.findings.append(_check_one(entry))

    report.took = time.monotonic() - started
    vault.set_note(NOTE_KEY, {
        "at": report.checked_at,
        "checked": len(report.findings),
        "intact": len(report.intact),
        "changed": len(report.changed),
        "missing": len(report.missing),
    })
    vault.log_event("integrity_checked",
                    checked=len(report.findings),
                    intact=len(report.intact),
                    changed=len(report.changed),
                    missing=len(report.missing))
    vault.save()
    if progress:
        progress("done", 1.0)
    return report


def _check_one(entry: Entry) -> Finding:
    path = entry.blob_path
    if not os.path.exists(path):
        return Finding(entry.id, entry.display_name, path, MISSING,
                       recorded=entry.blob_sha256)
    if not entry.blob_sha256:
        return Finding(entry.id, entry.display_name, path, UNKNOWN,
                       size=_size(path))
    found = file_digest(path) or ""
    state = INTACT if found == entry.blob_sha256 else CHANGED
    return Finding(entry.id, entry.display_name, path, state,
                   recorded=entry.blob_sha256, found=found, size=_size(path))


def _size(path: str) -> int:
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def last_check(vault: Vault) -> Optional[dict]:
    """When the vault was last checked, and what was found. None if never."""
    record = vault.note(NOTE_KEY)
    return dict(record) if isinstance(record, dict) else None


# --------------------------------------------------------------------------
# finding one that moved
# --------------------------------------------------------------------------

@dataclass
class Match:
    """A file on disk whose digest is the one an entry is looking for."""

    entry_id: str
    name: str
    was: str
    now: str

    def describe(self) -> str:
        return f"{self.name}: {os.path.basename(self.now)}"


@dataclass
class SearchReport:
    """What searching a folder turned up."""

    searched: str = ""
    scanned: int = 0
    matches: list = field(default_factory=list)
    #: Entries still unaccounted for after the search.
    unfound: list = field(default_factory=list)

    def summary(self) -> str:
        if not self.matches:
            return (f"Looked at {self.scanned} file"
                    f"{'s' if self.scanned != 1 else ''} and found none of the "
                    f"missing ones. Try another folder, or a folder further up.")
        found = len(self.matches)
        left = len(self.unfound)
        tail = (f" {left} still unaccounted for." if left else "")
        return (f"Matched {found} missing file{'s' if found != 1 else ''} by "
                f"digest.{tail}")


def search(vault: Vault, directory: str, recursive: bool = True,
           progress: Optional[ProgressFn] = None) -> SearchReport:
    """Look for entries whose file has moved, matching on the digest.

    Nothing is written by this function. It reports what it found so the
    caller can show it and ask; :func:`relink` is what commits.
    """
    report = SearchReport(searched=os.path.abspath(directory))
    wanted: dict = {}
    looking_for: list = []
    for entry in vault.entries():
        if entry.blob_sha256 and not os.path.exists(entry.blob_path):
            wanted.setdefault(entry.blob_sha256, []).append(entry)
            looking_for.append(entry)
    if not wanted:
        return report
    # Sizes are only a shortcut, and only a safe one when every entry being
    # looked for has one recorded. One entry without leaves the shortcut off,
    # so nothing is skipped that might have matched.
    sizes = {e.blob_size for e in looking_for}
    check_size = all(e.blob_size for e in looking_for)

    for path in _candidates(directory, recursive):
        report.scanned += 1
        if progress:
            progress(os.path.basename(path), 0.0)
        # Size first: hashing every .qkey in a large folder is the slow part,
        # and a file of the wrong size cannot be the one being looked for.
        if check_size and _size(path) not in sizes:
            continue
        digest = file_digest(path)
        if not digest or digest not in wanted:
            continue
        for entry in wanted.pop(digest):
            report.matches.append(Match(entry.id, entry.display_name,
                                        entry.blob_path, os.path.abspath(path)))

    report.unfound = [e for group in wanted.values() for e in group]
    if progress:
        progress("done", 1.0)
    return report


def _candidates(directory: str, recursive: bool):
    root = os.path.abspath(directory)
    if not recursive:
        try:
            for name in sorted(os.listdir(root)):
                path = os.path.join(root, name)
                if name.endswith(BLOB_SUFFIX) and os.path.isfile(path):
                    yield path
        except OSError:
            return
        return
    for base, dirs, names in os.walk(root):
        dirs[:] = [d for d in sorted(dirs) if not d.startswith(".")]
        for name in sorted(names):
            if name.endswith(BLOB_SUFFIX):
                yield os.path.join(base, name)


def relink(vault: Vault, matches) -> int:
    """Point the matched entries at where their files actually are.

    Only the path changes. The key, the deadline, the opening count and the
    entry's place in the event log are all untouched, because none of them
    had anything to do with where the file happened to be sitting.
    """
    moved = 0
    for match in matches:
        entry = vault.get(match.entry_id)
        if os.path.abspath(entry.blob_path) == os.path.abspath(match.now):
            continue
        entry.blob_path = os.path.abspath(match.now)
        vault.log_event("blob_relinked", entry=entry.id,
                        was=match.was, now=entry.blob_path,
                        matched_on="sha256")
        moved += 1
    if moved:
        vault.save()
    return moved
