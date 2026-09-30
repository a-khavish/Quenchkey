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

"""Telling somebody a key is about to die, before it does.

A deadline that arrives unannounced is the one way this tool can lose
somebody's work without being asked to. The dead man's switch is the sharpest
case: it is armed precisely for the situation where nobody is looking, and if
the first news of it is that the key has gone then the feature has done harm.

So the background sweep, which already runs whether or not the application is
open, also looks a little way ahead and says what is coming. Three levels, each
sent once:

    a week out   ·   a day out   ·   an hour out

Sent once is the whole design. A notification that repeats every fifteen
minutes is one people turn off, and a warning nobody reads is no warning. What
has been said is recorded in the vault against the entry and the deadline it
referred to, so moving a deadline arms the warnings again while merely opening
the vault does not.

Nothing here decides *how* to tell anybody. That is the caller's business —
the tray in a running application, ``notify-send`` from the timer, standard
output from the command line — and this module only works out what is worth
saying.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

from .vault import Entry, Vault

#: How far ahead each warning goes out, longest first. The names are what a
#: person reads, not an internal code.
LEVELS: list[tuple[str, float]] = [
    ("week", 7 * 86400.0),
    ("day", 86400.0),
    ("hour", 3600.0),
]

#: Where the record of what has been said lives inside the vault extras.
EXTRA_KEY = "warnings_sent"


@dataclass
class Warning_:
    """One thing worth telling somebody, once."""

    entry_id: str
    name: str
    level: str
    seconds_left: float
    deadline: float
    reason: str

    @property
    def urgency(self) -> str:
        return {"week": "notice", "day": "warning", "hour": "critical"}[self.level]

    def title(self) -> str:
        return {
            "week": "A key is destroyed in a week",
            "day": "A key is destroyed tomorrow",
            "hour": "A key is destroyed within the hour",
        }[self.level]

    def message(self) -> str:
        when = _plainly(self.seconds_left)
        if self.reason == "heartbeat":
            return (f"{self.name} loses its key in {when} unless you open "
                    f"Quenchkey before then. Opening the vault is the "
                    f"check-in; nothing else counts.")
        return (f"{self.name} loses its key in {when}. After that the locked "
                f"file cannot be opened — by this application or any other.")


@dataclass
class WarningReport:
    """What a look-ahead pass found."""

    checked_at: float = 0.0
    due: list = field(default_factory=list)
    #: Warnings suppressed because they had already been sent.
    already_sent: int = 0

    @property
    def changed(self) -> bool:
        return bool(self.due)

    def summary(self) -> str:
        if not self.due:
            return "Nothing is close enough to a deadline to warn about."
        first = self.due[0]
        more = len(self.due) - 1
        tail = f", and {more} other{'s' if more != 1 else ''}" if more else ""
        return f"{first.name} loses its key in {_plainly(first.seconds_left)}{tail}."


def _plainly(seconds: float) -> str:
    """A duration the way somebody would say it out loud."""
    seconds = max(0.0, seconds)
    if seconds < 90:
        return "under two minutes"
    minutes = seconds / 60
    if minutes < 90:
        return f"{round(minutes)} minutes"
    hours = minutes / 60
    if hours < 36:
        return "an hour" if round(hours) == 1 else f"{round(hours)} hours"
    days = hours / 24
    return "a day" if round(days) == 1 else f"{round(days)} days"


def _sent(vault: Vault) -> dict:
    record = vault.note(EXTRA_KEY)
    return dict(record) if isinstance(record, dict) else {}


def _key(entry: Entry, level: str, deadline: float) -> str:
    """Identifies one warning, for one deadline.

    The deadline is part of the key on purpose. Push a deadline back and the
    warnings for the new one have not been sent yet, which is correct: it is a
    different moment. Rounded to the second so that a float that has been
    through JSON still matches itself.
    """
    return f"{entry.id}:{level}:{int(deadline)}"


def pending(vault: Vault, now: Optional[float] = None) -> WarningReport:
    """Everything worth saying right now, without recording that it was said.

    Separated from :func:`send` so a caller can look without committing: the
    command line lists what is coming without silencing tomorrow's warning to
    somebody who is not reading standard output.
    """
    moment = vault.effective_now() if now is None else now
    report = WarningReport(checked_at=moment)
    sent = _sent(vault)

    for entry in vault.entries():
        if entry.key_destroyed:
            continue
        deadline = entry.deadline()
        if deadline is None:
            continue
        left = deadline - moment
        if left <= 0:
            # Already due. The sweep deals with that; a warning would be a lie.
            continue

        level = _level_for(left)
        if level is None:
            continue
        if _key(entry, level, deadline) in sent:
            report.already_sent += 1
            continue

        report.due.append(Warning_(
            entry_id=entry.id,
            name=entry.display_name,
            level=level,
            seconds_left=left,
            deadline=deadline,
            reason="heartbeat" if _is_heartbeat(entry, deadline) else "deadline",
        ))

    report.due.sort(key=lambda w: w.seconds_left)
    return report


def _level_for(seconds_left: float) -> Optional[str]:
    """The most urgent level this entry has crossed into.

    Most urgent, not every level: a vault left closed for a fortnight and
    opened with an hour to go should say "within the hour" once, not deliver
    three notifications in a row about the same file.
    """
    for name, window in reversed(LEVELS):        # hour, day, week
        if seconds_left <= window:
            return name
    return None


def _is_heartbeat(entry: Entry, deadline: float) -> bool:
    heartbeat = entry.heartbeat_deadline()
    return heartbeat is not None and abs(heartbeat - deadline) < 1.0


def send(vault: Vault, notifier, now: Optional[float] = None) -> WarningReport:
    """Work out what is worth saying, say it, and record that it was said.

    ``notifier`` is called once per warning with ``(title, message, urgency)``.
    A notifier that raises is not allowed to take the sweep down with it — the
    warning simply goes unrecorded and will be offered again next time, which
    is the safe direction to fail in.
    """
    report = pending(vault, now)

    # Tidy first, and unconditionally: an entry removed from the vault leaves
    # a line behind, and if pruning only happened when something new went out
    # then a quiet vault would keep them forever.
    sent = _sent(vault)
    kept = _forget_stale(sent, vault)
    if len(kept) != len(sent):
        vault.set_note(EXTRA_KEY, kept)
        vault.save()
        sent = kept

    if not report.due:
        return report

    delivered = []
    for warning in report.due:
        try:
            notifier(warning.title(), warning.message(), warning.urgency)
        except Exception:  # noqa: BLE001 - a broken notifier is not fatal
            continue
        sent[_key_for_warning(warning)] = round(time.time())
        delivered.append(warning)

    if delivered:
        vault.set_note(EXTRA_KEY, sent)
        vault.log_event("deadline_warnings_sent",
                        count=len(delivered),
                        levels=sorted({w.level for w in delivered}))
        vault.save()

    report.due = delivered
    return report


def _key_for_warning(warning: Warning_) -> str:
    return f"{warning.entry_id}:{warning.level}:{int(warning.deadline)}"


def _forget_stale(sent: dict, vault: Vault) -> dict:
    """Drop the record for entries that no longer exist.

    Without this the vault accumulates a line per warning forever, including
    for files removed years ago.
    """
    live = {entry.id for entry in vault.entries()}
    return {key: when for key, when in sent.items()
            if key.split(":", 1)[0] in live}


def rearm(vault: Vault, entry_id: str) -> None:
    """Forget what was said about one entry, so its warnings go out again.

    Called when an entry's rules change. Strictly this is belt and braces —
    the deadline is part of the key, so a new deadline is already a new
    warning — but a rule change that leaves the deadline alone (a heartbeat
    turned off, say) is tidier handled here than reasoned about later.
    """
    sent = _sent(vault)
    remaining = {key: when for key, when in sent.items()
                 if not key.startswith(f"{entry_id}:")}
    if len(remaining) != len(sent):
        vault.set_note(EXTRA_KEY, remaining)
