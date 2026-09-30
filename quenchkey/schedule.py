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

"""Letting a background process clean up on time, without giving it the keys.

The vault is one encrypted blob. Entries, deadlines, paths and keys all live
inside it, under a key derived from the passphrase. That is the right design,
and it has a consequence worth stating plainly: **a background process that
does not know the passphrase can see nothing in the vault and change nothing
in it.** It cannot read a deadline, so it cannot know when one passes, and it
cannot destroy a key, because destroying one means rewriting the encrypted
payload.

There is no clever way around that. The choice is between three things and you
may have two:

1. the vault is protected by the passphrase alone,
2. keys are destroyed on time with nobody logged in and nothing unlocked,
3. no secret and no index sits outside the vault.

Quenchkey keeps (1) always. This module implements a narrow version of (2) by
giving up a specific, stated piece of (3): an opt-in index file, next to the
vault, listing for each entry with a deadline its id, when that deadline
falls, where its locked file is, and whether it asked to be deleted.

**That index is not encrypted.** Encrypting it under a key kept beside it
would be theatre — anything that can read one can read the other — so it is
written in the clear at mode 0600 and documented here instead of being dressed
up. Anyone who can read your home directory learns how many things you have
locked and when they expire. They already learn most of that from the
``.qkey`` filenames sitting in the same folders. It is still more than
nothing, which is why this is off until you turn it on.

What the sweeper can and cannot do
----------------------------------

It **can** delete a locked file at its deadline, on your own machine, with
nothing open, and tell you it did.

It **cannot** destroy the key — that waits for the next unlock, which is when
the vault can actually be written. It records what fell due in a pending list,
and the application acts on it the moment you open the vault.

That ordering matters less than it looks. Deleting the file was never the
protection: copies elsewhere survive it. The key is the protection, and an
entry past its deadline is already refused by every read path in the
application whether or not its key bytes have been overwritten yet. The
window this leaves open is narrow and specific: someone who takes a copy of
the vault *and* obtains the passphrase between the deadline and your next
unlock can still read that entry. Prompt destruction closes it; this closes
it at next unlock instead.

And none of it reaches another machine. See the README.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Iterable, Optional

#: Appended to the vault's own path.
INDEX_SUFFIX = ".schedule"
PENDING_SUFFIX = ".pending"
#: Which look-ahead warnings this sweeper has already sent. Kept beside the
#: index rather than in the vault, because the sweeper cannot open the vault.
WARNED_SUFFIX = ".warned"

INDEX_VERSION = 1

#: Written and read by the owner only. The content is metadata in the clear,
#: so the permission bits are the only thing protecting it.
FILE_MODE = 0o600


def index_path(vault_path: str) -> str:
    return vault_path + INDEX_SUFFIX


def pending_path(vault_path: str) -> str:
    return vault_path + PENDING_SUFFIX


def warned_path(vault_path: str) -> str:
    return vault_path + WARNED_SUFFIX


@dataclass
class ScheduledEntry:
    """One entry's deadline, as much as the sweeper is allowed to know."""

    id: str
    deadline: float
    blob_path: str
    delete_blob: bool

    def to_dict(self) -> dict:
        return {"id": self.id, "deadline": self.deadline,
                "blob_path": self.blob_path, "delete_blob": self.delete_blob}

    @classmethod
    def from_dict(cls, raw: dict) -> "ScheduledEntry":
        return cls(str(raw["id"]), float(raw["deadline"]),
                   str(raw.get("blob_path", "")), bool(raw.get("delete_blob")))


@dataclass
class SweepReport:
    """What one run of the sweeper did."""

    checked: int = 0
    due: list[str] = field(default_factory=list)
    deleted: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    failed: list[tuple[str, str]] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.deleted or self.due)

    def summary(self) -> str:
        if not self.due:
            return f"Nothing due. {self.checked} deadline" \
                   f"{'s' if self.checked != 1 else ''} checked."
        parts = [f"{len(self.due)} deadline{'s' if len(self.due) != 1 else ''} passed"]
        if self.deleted:
            parts.append(f"{len(self.deleted)} locked file"
                         f"{'s' if len(self.deleted) != 1 else ''} deleted")
        if self.failed:
            parts.append(f"{len(self.failed)} could not be deleted")
        return ", ".join(parts) + ". Keys are destroyed at the next unlock."


# --------------------------------------------------------------------------
# writing, from the application
# --------------------------------------------------------------------------

def write_index(vault_path: str, entries: Iterable[ScheduledEntry]) -> str:
    """Replace the index. Called whenever the vault is saved and this is on."""
    target = index_path(vault_path)
    document = {
        "version": INDEX_VERSION,
        "vault": os.path.abspath(vault_path),
        "written": time.time(),
        "entries": [entry.to_dict() for entry in entries],
    }
    _write_private(target, json.dumps(document, indent=2))
    return target


def remove_index(vault_path: str) -> None:
    """Take the index away again when background expiry is switched off."""
    for path in (index_path(vault_path), pending_path(vault_path)):
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


def _write_private(path: str, text: str) -> None:
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    tmp = f"{path}.tmp-{os.getpid()}"
    handle = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, FILE_MODE)
    try:
        with os.fdopen(handle, "w") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        os.chmod(path, FILE_MODE)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def read_index(vault_path: str) -> Optional[list[ScheduledEntry]]:
    """The scheduled entries, or None when there is no index to read."""
    try:
        with open(index_path(vault_path)) as fh:
            document = json.load(fh)
    except (FileNotFoundError, ValueError):
        return None
    if document.get("version") != INDEX_VERSION:
        return None
    entries = []
    for raw in document.get("entries", []):
        try:
            entries.append(ScheduledEntry.from_dict(raw))
        except (KeyError, TypeError, ValueError):
            continue
    return entries


# --------------------------------------------------------------------------
# the pending list, written by the sweeper and consumed at unlock
# --------------------------------------------------------------------------

def read_pending(vault_path: str) -> dict[str, float]:
    """Entry ids the sweeper saw fall due, and when it saw them."""
    try:
        with open(pending_path(vault_path)) as fh:
            document = json.load(fh)
    except (FileNotFoundError, ValueError):
        return {}
    due = document.get("due", {})
    return {str(k): float(v) for k, v in due.items()} if isinstance(due, dict) else {}


def record_pending(vault_path: str, entry_ids: Iterable[str],
                   at: Optional[float] = None) -> None:
    """Add to the pending list without losing what is already on it."""
    moment = time.time() if at is None else at
    due = read_pending(vault_path)
    for entry_id in entry_ids:
        due.setdefault(entry_id, moment)
    if due:
        _write_private(pending_path(vault_path),
                       json.dumps({"due": due}, indent=2))


def clear_pending(vault_path: str, entry_ids: Iterable[str]) -> None:
    """Drop ids the application has now actually destroyed."""
    due = read_pending(vault_path)
    for entry_id in entry_ids:
        due.pop(entry_id, None)
    if due:
        _write_private(pending_path(vault_path), json.dumps({"due": due}, indent=2))
    else:
        try:
            os.unlink(pending_path(vault_path))
        except FileNotFoundError:
            pass


# --------------------------------------------------------------------------
# the sweep itself, with no vault open
# --------------------------------------------------------------------------

#: How far ahead the keyless sweeper looks, and what it calls each distance.
#: The same three levels the application uses, on purpose: a person who has
#: the vault open and one who does not should hear about a deadline at the
#: same moments.
LOOKAHEAD: list[tuple[str, float]] = [
    ("week", 7 * 86400.0),
    ("day", 86400.0),
    ("hour", 3600.0),
]


@dataclass
class Upcoming:
    """A deadline that is close, as much as the sweeper is allowed to know.

    Note what is *not* here: a filename. The index outside the vault holds
    ids, times and blob paths and nothing else, and adding a display name so
    that a notification could be chattier would put the names of everything
    you have locked in a plain file on disk. So the warning says how many and
    how soon, and where to look for which.
    """

    level: str
    count: int
    soonest: float

    def title(self) -> str:
        return {
            "week": "A key is destroyed in a week",
            "day": "A key is destroyed tomorrow",
            "hour": "A key is destroyed within the hour",
        }[self.level]

    def message(self, now: Optional[float] = None) -> str:
        moment = time.time() if now is None else now
        left = max(0.0, self.soonest - moment)
        hours = left / 3600
        when = (f"{round(left / 60)} minutes" if left < 5400
                else f"{round(hours)} hours" if hours < 36
                else f"{round(hours / 24)} days")
        subject = ("One locked item loses its key" if self.count == 1
                   else f"{self.count} locked items lose their keys")
        return (f"{subject} in {when}. Open Quenchkey to see which, to move "
                f"the deadline, or to check in.")


def upcoming(vault_path: str, now: Optional[float] = None) -> list:
    """Deadlines close enough to be worth mentioning, grouped by level.

    Grouped rather than one per entry: three files expiring within the hour
    is one thing to say, not three notifications.
    """
    entries = read_index(vault_path)
    if not entries:
        return []
    moment = time.time() if now is None else now

    buckets: dict = {}
    for entry in entries:
        left = entry.deadline - moment
        if left <= 0:
            continue
        level = None
        for name, window in reversed(LOOKAHEAD):     # hour, then day, then week
            if left <= window:
                level = name
                break
        if level is None:
            continue
        found = buckets.get(level)
        if found is None:
            buckets[level] = Upcoming(level, 1, entry.deadline)
        else:
            found.count += 1
            found.soonest = min(found.soonest, entry.deadline)

    order = [name for name, _window in LOOKAHEAD]
    return sorted(buckets.values(), key=lambda u: order.index(u.level))


def _warned(vault_path: str) -> dict:
    try:
        with open(warned_path(vault_path)) as fh:
            record = json.load(fh)
        return record if isinstance(record, dict) else {}
    except (OSError, ValueError):
        return {}


def _remember_warned(vault_path: str, record: dict) -> None:
    target = warned_path(vault_path)
    handle = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, FILE_MODE)
    try:
        with os.fdopen(handle, "w") as fh:
            json.dump(record, fh, separators=(",", ":"))
    except OSError:
        pass


def warn_upcoming(vault_path: str, notifier, now: Optional[float] = None) -> list:
    """Say once, per level per deadline, that something is coming.

    Keyed by the level and the deadline it refers to, so moving a deadline
    arms its warnings again and a sweeper that runs every fifteen minutes does
    not send the same thing ninety-six times a day.
    """
    due = upcoming(vault_path, now)
    if not due:
        return []

    remembered = _warned(vault_path)
    sent = []
    for item in due:
        key = f"{item.level}:{int(item.soonest)}"
        if key in remembered:
            continue
        try:
            notifier(item.title(), item.message(now))
        except Exception:  # noqa: BLE001 - a broken notifier is not fatal
            continue
        remembered[key] = round(time.time())
        sent.append(item)

    if sent:
        # Anything referring to a moment already past can go; without this the
        # file grows a line per deadline forever.
        moment = time.time() if now is None else now
        remembered = {key: when for key, when in remembered.items()
                      if _deadline_of(key) > moment - 86400}
        _remember_warned(vault_path, remembered)
    return sent


def _deadline_of(key: str) -> float:
    try:
        return float(key.rsplit(":", 1)[1])
    except (IndexError, ValueError):
        return 0.0


def sweep(vault_path: str, now: Optional[float] = None) -> SweepReport:
    """Delete what is due, record what fell due, open nothing.

    The clock is only ever read forwards here. A sweeper that trusted a
    rolled-back clock could not bring a deadline back — the vault keeps its
    own watermark and the application re-checks everything at unlock — but it
    could be talked out of deleting a file, so the deadline is treated as
    passed if either this clock or the index's own write time says so.
    """
    moment = time.time() if now is None else now
    report = SweepReport()
    entries = read_index(vault_path)
    if entries is None:
        return report

    report.checked = len(entries)
    due_ids = []
    for entry in entries:
        if entry.deadline > moment:
            continue
        due_ids.append(entry.id)
        report.due.append(entry.id)
        if not entry.delete_blob or not entry.blob_path:
            continue
        try:
            os.unlink(entry.blob_path)
            report.deleted.append(entry.blob_path)
        except FileNotFoundError:
            report.missing.append(entry.blob_path)
        except OSError as exc:
            report.failed.append((entry.blob_path, str(exc)))

    if due_ids:
        record_pending(vault_path, due_ids, moment)
    return report
