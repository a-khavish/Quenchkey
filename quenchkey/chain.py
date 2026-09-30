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

"""The hash-chained event log.

Every event records the hash of the one before it, so the log is a chain: any
edit to an old entry changes its hash, which breaks every link after it. The
head — the hash of the most recent event — is therefore a fingerprint of the
vault's entire history.

What this buys, and what it does not
------------------------------------

The log already lives inside the vault's authenticated encrypted region, so
somebody *without* the passphrase cannot touch it at all. Chaining is aimed at
a different attacker: the one who has the passphrase, or who simply restores a
copy of the vault taken before a deadline.

By itself, the chain does not stop that person. Someone holding the passphrase
can rewrite the whole log and recompute every hash, and a restored older vault
is internally consistent because it *was* consistent when it was taken.

What makes the chain useful is an **anchor**: the head hash, written down
somewhere outside the vault — a password manager, a note, a commit message, a
message to a colleague. A restored or rewritten vault cannot reproduce a head
that was recorded after the events it is missing. So:

* chain alone      -> the log is self-consistent, and nothing more
* chain + anchor   -> rollback and rewriting become *detectable*

That is still detection, not prevention. Nothing local can prevent it. The
honest claim is that Quenchkey gives you a short string to write down that
turns "I have no way of knowing" into "I can check".
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Iterable, Optional

#: Domain separator, so an event hash can never collide with a hash computed
#: over some other structure that happens to serialise identically.
EVENT_DOMAIN = b"quenchkey/event/v1"

#: The ``prev`` of the very first event.
GENESIS = "0" * 64

#: Fields that are part of an event's identity. ``hash`` is derived, so it is
#: excluded when hashing; everything else, including ``prev`` and ``seq``, is
#: covered.
DERIVED_FIELDS = ("hash",)


class ChainError(Exception):
    """The event chain does not verify."""


def canonical(event: dict) -> bytes:
    """Serialise an event deterministically for hashing.

    Sorted keys and compact separators, so the same event always produces the
    same bytes regardless of how the dict was built or which Python version
    ordered it.
    """
    payload = {k: v for k, v in event.items() if k not in DERIVED_FIELDS}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def event_hash(event: dict) -> str:
    return hashlib.sha256(EVENT_DOMAIN + canonical(event)).hexdigest()


def link(event: dict, previous_hash: str, seq: int) -> dict:
    """Attach ``seq`` and ``prev`` to an event and compute its hash."""
    event = dict(event)
    event["seq"] = seq
    event["prev"] = previous_hash
    event["hash"] = event_hash(event)
    return event


def append(events: list[dict], event: dict) -> dict:
    """Link a new event onto the end of ``events`` and return it."""
    previous = events[-1]["hash"] if events else GENESIS
    linked = link(event, previous, len(events))
    events.append(linked)
    return linked


def head(events: Iterable[dict]) -> str:
    """The chain head: the hash of the last event, or the genesis value."""
    events = list(events)
    return events[-1]["hash"] if events else GENESIS


@dataclass
class ChainReport:
    """The result of verifying a chain."""

    ok: bool
    head: str
    length: int
    broken_at: Optional[int] = None
    reason: str = ""

    def summary(self) -> str:
        if self.ok:
            return (f"{self.length} event{'s' if self.length != 1 else ''}, "
                    f"chain intact.")
        return (f"Chain broken at event {self.broken_at}: {self.reason} "
                "Something has edited this vault's history, or the vault was "
                "written by a different build.")


def verify(events: Iterable[dict], expected_head: Optional[str] = None) -> ChainReport:
    """Recompute the chain and report whether it holds together.

    ``expected_head`` is the value stored alongside the events. Checking it
    catches an events list that verifies internally but has had its tail
    removed.
    """
    events = list(events)
    previous = GENESIS

    for index, event in enumerate(events):
        if event.get("seq") != index:
            return ChainReport(False, previous, len(events), index,
                               f"sequence number is {event.get('seq')!r}, expected {index}.")
        if event.get("prev") != previous:
            return ChainReport(False, previous, len(events), index,
                               "it does not follow the event before it.")
        recomputed = event_hash(event)
        if event.get("hash") != recomputed:
            return ChainReport(False, previous, len(events), index,
                               "its contents do not match its own hash.")
        previous = recomputed

    if expected_head is not None and previous != expected_head:
        return ChainReport(False, previous, len(events), len(events),
                           "the recorded chain head does not match the events; "
                           "events appear to have been removed from the end.")

    return ChainReport(True, previous, len(events))


def rechain(events: Iterable[dict]) -> list[dict]:
    """Rebuild the chain over existing events.

    Used when upgrading a vault written before chaining existed. The events
    keep their contents and gain links — but note carefully that chaining old
    events *retroactively* proves nothing about them: whoever ran the upgrade
    could have changed them first. Only events added after the upgrade carry
    tamper-evidence, which is why the vault records when live chaining began.
    """
    rebuilt: list[dict] = []
    for event in events:
        clean = {k: v for k, v in event.items() if k not in ("seq", "prev", "hash")}
        append(rebuilt, clean)
    return rebuilt


def fingerprint(chain_head: str, groups: int = 4, size: int = 4) -> str:
    """A short, readable form of the head, for writing down or reading aloud.

    The full head is 64 hex characters, which nobody transcribes correctly.
    This takes the leading bytes and groups them: 16 hex characters is 64 bits,
    far beyond what anyone could grind out a collision for in this setting,
    where the attacker must also produce a *plausible* vault history.
    """
    trimmed = chain_head[:groups * size]
    return "-".join(trimmed[i:i + size] for i in range(0, len(trimmed), size)).upper()
