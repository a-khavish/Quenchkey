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

"""Deadlines, and the moment a key stops existing.

Expiry is checked in two places, because neither alone is enough:

* **On every unlock.** The app may not have been running when a deadline
  passed — it may not have been running for a month. The sweep at unlock time
  catches everything that fell due while nothing was watching.
* **On a timer while the app is open.** So that a file expires in front of the
  user rather than at some later start-up.

The clock used is :meth:`Vault.effective_now`, which never goes backwards: it
is the later of the system clock and the highest value the vault has ever
recorded. Winding the system clock back therefore does not extend a deadline.

What it does *not* defend against is a copy of the vault file taken before
expiry and restored afterwards. Nothing a local-only tool can do prevents
that. It is recorded in the event log, which makes it evident after the fact,
and it is stated as a limitation in the README rather than papered over.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Optional

from .locker import shred_file
from .vault import (
    REASON_DEADLINE, REASON_HEARTBEAT, REASON_MANUAL, REASON_OPENS, Entry, Vault,
)

#: Presets offered in the lock dialog, as ``(label, seconds or None)``.
EXPIRY_PRESETS: list[tuple[str, Optional[int]]] = [
    ("1 hour", 3600),
    ("24 hours", 86400),
    ("7 days", 7 * 86400),
    ("30 days", 30 * 86400),
    ("Never", None),
]

#: Dead man's switch intervals, in days.
HEARTBEAT_PRESETS: list[tuple[str, Optional[float]]] = [
    ("Off", None),
    ("7 days", 7.0),
    ("30 days", 30.0),
    ("90 days", 90.0),
    ("1 year", 365.0),
]

#: Open allowances offered in the lock dialog.
OPEN_LIMIT_PRESETS: list[tuple[str, Optional[int]]] = [
    ("Unlimited", None),
    ("Once", 1),
    ("Twice", 2),
    ("3 times", 3),
    ("5 times", 5),
    ("10 times", 10),
]

# Thresholds used to colour a countdown as its deadline approaches.
URGENCY_CRITICAL = 3600          # under an hour
URGENCY_WARNING = 24 * 3600      # under a day

URGENCY_EXPIRED = "expired"
URGENCY_CRITICAL_KEY = "critical"
URGENCY_WARNING_KEY = "warning"
URGENCY_CALM = "calm"
URGENCY_NONE = "none"


@dataclass
class SweepReport:
    """What a sweep did."""

    expired: list[Entry] = field(default_factory=list)
    blobs_deleted: list[str] = field(default_factory=list)
    blobs_missing: list[str] = field(default_factory=list)
    checked_at: float = 0.0

    #: Why each entry went, keyed by entry id.
    reasons: dict = field(default_factory=dict)

    #: Ids the background sweeper had already seen fall due while nothing was
    #: unlocked. Their keys are destroyed here, at the first opportunity the
    #: vault had to be written; the sweeper could only delete the files.
    swept_in_background: list = field(default_factory=list)

    #: Loans that ran out in this pass, one report each.
    checkins: list = field(default_factory=list)

    #: What the watched folders picked up, if any are set.
    watched: object = None

    @property
    def changed(self) -> bool:
        return bool(self.expired)

    def summary(self) -> str:
        if not self.expired:
            return "Nothing had expired."
        names = ", ".join(e.display_name for e in self.expired[:3])
        more = "" if len(self.expired) <= 3 else f" and {len(self.expired) - 3} more"
        n = len(self.expired)
        causes = {self.reasons.get(e.id, REASON_DEADLINE) for e in self.expired}
        why = _describe_causes(causes)
        return (f"{n} item{'s' if n != 1 else ''} expired ({names}{more}){why}. "
                f"Their keys have been destroyed.")


def _describe_causes(causes: set) -> str:
    if causes == {REASON_HEARTBEAT}:
        return " because the vault had not been opened in time"
    if causes == {REASON_OPENS}:
        return " having used up their permitted openings"
    if causes == {REASON_DEADLINE}:
        return ""
    return " for a mix of reasons"


def due_entries(vault: Vault, now: Optional[float] = None) -> list[Entry]:
    now = vault.effective_now() if now is None else now
    return [e for e in vault.entries() if e.is_due(now)]


def check_in(vault: Vault) -> list[Entry]:
    """Reset the dead man's switches after a sweep has had its chance.

    Order matters: the sweep runs first, so anything already overdue is
    destroyed, and only the survivors have their clocks reset. Checking in
    first would mean a dead man's switch could never fire.
    """
    return vault.check_in()


def sweep(vault: Vault, now: Optional[float] = None,
          delete_blobs: bool = True) -> SweepReport:
    """Destroy the keys of every entry whose deadline has passed.

    The vault is written once, after all keys have been shredded, so a crash
    part-way through cannot leave some keys destroyed in memory but intact on
    disk.
    """
    now = vault.effective_now() if now is None else now
    report = SweepReport(checked_at=now)

    for entry in due_entries(vault, now):
        reason = entry.due_reason(now) or REASON_DEADLINE
        vault.shred_key(entry.id, reason=reason)
        report.expired.append(entry)
        report.reasons[entry.id] = reason

    if report.expired:
        vault.save()

    if delete_blobs:
        for entry in report.expired:
            if not entry.delete_blob_on_expiry:
                continue
            if os.path.exists(entry.blob_path):
                if shred_file(entry.blob_path):
                    report.blobs_deleted.append(entry.blob_path)
            else:
                report.blobs_missing.append(entry.blob_path)

    return report


def expire_now(vault: Vault, entry_ids: list[str],
               delete_blobs: bool = False) -> SweepReport:
    """Destroy keys immediately, ahead of their deadline. Irreversible."""
    report = SweepReport(checked_at=time.time())
    for entry_id in entry_ids:
        entry = vault.get(entry_id)
        if entry.key_destroyed:
            continue
        vault.shred_key(entry.id, reason=REASON_MANUAL)
        report.expired.append(entry)
        report.reasons[entry.id] = REASON_MANUAL
    if report.expired:
        vault.save()
    if delete_blobs:
        for entry in report.expired:
            if os.path.exists(entry.blob_path):
                if shred_file(entry.blob_path):
                    report.blobs_deleted.append(entry.blob_path)
            else:
                report.blobs_missing.append(entry.blob_path)
    return report


def urgency(entry: Entry, now: float) -> str:
    """Bucket an entry for colour-coding a countdown.

    Uses the unified deadline, so a dead man's switch counts down in exactly
    the same way a fixed deadline does.
    """
    if entry.key_destroyed:
        return URGENCY_EXPIRED
    deadline = entry.deadline()
    if deadline is None:
        return URGENCY_NONE
    remaining = deadline - now
    if remaining <= 0:
        return URGENCY_EXPIRED
    if remaining <= URGENCY_CRITICAL:
        return URGENCY_CRITICAL_KEY
    if remaining <= URGENCY_WARNING:
        return URGENCY_WARNING_KEY
    return URGENCY_CALM


def format_remaining(entry: Entry, now: float) -> str:
    """Human countdown for the table's 'time remaining' column."""
    if entry.key_destroyed:
        return "key destroyed"
    deadline = entry.deadline()
    if deadline is None:
        return "no deadline" if entry.max_opens is None else "until opens run out"
    remaining = deadline - now
    if remaining <= 0:
        return "due now"
    return format_duration(remaining)


def describe_deadline(entry: Entry) -> str:
    """What the 'expires' column says, given which rule bites first."""
    if entry.expires is None and entry.heartbeat_days is None:
        return "never"
    heartbeat = entry.heartbeat_deadline()
    if heartbeat is not None and (entry.expires is None or heartbeat < entry.expires):
        return f"{format_time(heartbeat)} (no check-in)"
    return format_time(entry.expires)


def format_duration(seconds: float) -> str:
    seconds = int(max(0, seconds))
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    if days:
        return f"{days}d {hours:02d}h {minutes:02d}m"
    if hours:
        return f"{hours}h {minutes:02d}m {secs:02d}s"
    if minutes:
        return f"{minutes}m {secs:02d}s"
    return f"{secs}s"


def format_size(num_bytes: int) -> str:
    size = float(num_bytes)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or unit == "TiB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TiB"


def format_time(timestamp: Optional[float]) -> str:
    if timestamp is None:
        return "never"
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(timestamp))
