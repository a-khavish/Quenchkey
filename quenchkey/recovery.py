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

"""Recovery shares: splitting the master key so no single thing can restore it.

The README documents an uncomfortable tension. Backing up the vault protects
you against forgetting the passphrase — and is also the one thing that undoes
expiry, because a copy taken before a deadline can be restored after it. You
cannot have both from a single file.

Recovery shares resolve it. The master key is split into *n* shares of which
any *k* reconstruct it, using SLIP-39 — the scheme Trezor publishes and ships,
implemented here by their own library rather than by hand. Hand off shares to
different people or different places and:

* losing the passphrase is survivable, because *k* shares rebuild the key;
* no single artefact exists that restores access on its own, so there is
  nothing to steal, subpoena, or accidentally leave on a backup drive;
* control can be made collective — "two of these three directors, together".

Each share is a list of 33 ordinary English words with its own checksum, so a
share that has been mistyped is rejected rather than silently producing the
wrong key.

The honest caveats
------------------

*k shares together are exactly as powerful as the passphrase.* They bypass it
entirely, by design. Anyone who gathers a quorum opens the vault, so shares are
secrets, and a threshold of 1 is simply a spare passphrase in a funny format.

*Shares do not survive a passphrase change.* They reconstruct the master key,
and changing the passphrase produces a new one. Issue fresh shares afterwards;
the app says so at the time.

*Shares undo expiry the same way a vault backup does.* A quorum reconstructs
the key that opens the vault — but only the vault as it exists now. They do not
resurrect a per-file key that has already been destroyed, because that key is
zeros in the current vault and the shares do not contain it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Optional

import shamir_mnemonic

from .crypto import KEY_SIZE, SecretBytes

#: SLIP-39 supports one group here: a simple "any k of n" split. Its multi-group
#: features are on purpose not exposed — the extra flexibility buys little for
#: this use and makes the instructions much harder to get right under stress.
GROUP_THRESHOLD = 1

MIN_SHARES = 2
MAX_SHARES = 16

#: SLIP-39 refuses to issue several shares at a threshold of 1, and it is right
#: to: every share would then be a complete spare passphrase, which multiplies
#: what can be stolen without splitting anything. Two is the real minimum.
MIN_THRESHOLD = 2

WORDS_PER_SHARE = 33


class RecoveryError(Exception):
    """Shares could not be generated, or a quorum could not be combined."""


@dataclass
class ShareSet:
    """A freshly generated set of shares."""

    threshold: int
    shares: list[str]

    @property
    def count(self) -> int:
        return len(self.shares)

    def describe(self) -> str:
        return (f"{self.count} shares, any {self.threshold} of which "
                f"reconstruct the key")

    def instructions(self) -> str:
        return (
            f"Any {self.threshold} of these {self.count} shares will open the "
            f"vault without its passphrase. Fewer than {self.threshold} reveal "
            "nothing at all.\n\n"
            "Store them apart from one another, and apart from the vault. A "
            "share is as sensitive as the passphrase, because a quorum of them "
            "replaces it. Write them on paper rather than leaving them in the "
            "same cloud account that holds the vault.\n\n"
            "If you change the vault's passphrase, these shares stop working. "
            "Generate a new set afterwards and destroy the old ones."
        )


def generate(master_key: SecretBytes, threshold: int, count: int) -> ShareSet:
    """Split a master key into ``count`` shares needing ``threshold`` to rebuild."""
    if len(master_key) != KEY_SIZE:
        raise RecoveryError(f"the master key must be {KEY_SIZE} bytes")
    if not (MIN_SHARES <= count <= MAX_SHARES):
        raise RecoveryError(f"choose between {MIN_SHARES} and {MAX_SHARES} shares")
    if threshold > count:
        raise RecoveryError("the threshold cannot exceed the number of shares")
    if threshold < MIN_THRESHOLD:
        raise RecoveryError(
            "a threshold of one would make every share a complete spare "
            "passphrase, which multiplies what can be stolen without splitting "
            "anything. SLIP-39 refuses it and so does this. Use two or more.")

    try:
        groups = shamir_mnemonic.generate_mnemonics(
            group_threshold=GROUP_THRESHOLD,
            groups=[(threshold, count)],
            master_secret=master_key.bytes(),
            passphrase=b"",
        )
    except Exception as exc:  # noqa: BLE001 - surfaced as one clear error
        raise RecoveryError(f"could not generate shares: {exc}") from exc
    return ShareSet(threshold, list(groups[0]))


def normalise(share: str) -> str:
    """Tidy a share the user typed or pasted: collapse whitespace, lowercase."""
    return re.sub(r"\s+", " ", share.strip().lower())


def looks_like_share(text: str) -> bool:
    words = normalise(text).split()
    return len(words) == WORDS_PER_SHARE and all(w.isalpha() for w in words)


def share_label(share: str) -> str:
    """The first two words, which SLIP-39 uses to identify a share set.

    Useful in the interface: shares belonging to the same vault share this
    prefix, so a mismatched share is obvious before anything is decoded.
    """
    words = normalise(share).split()
    return " ".join(words[:2]) if len(words) >= 2 else ""


def inspect(shares: Iterable[str]) -> tuple[list[str], list[str]]:
    """Validate shares one at a time, returning (accepted, complaints).

    SLIP-39 checks each share's own checksum, so a single mistyped word can be
    pinned to the share it is in and corrected without re-entering the rest.
    Doing this per share, before any attempt to combine, is what makes that
    possible — combining them all at once would only report that something,
    somewhere, was wrong.
    """
    accepted: list[str] = []
    complaints: list[str] = []
    seen_identifier = None

    for position, raw in enumerate(shares, start=1):
        if not raw or not raw.strip():
            continue
        cleaned = normalise(raw)
        words = cleaned.split()
        if len(words) != WORDS_PER_SHARE:
            complaints.append(
                f"Share {position} has {len(words)} words; a share is "
                f"{WORDS_PER_SHARE}.")
            continue
        try:
            parsed = shamir_mnemonic.share.Share.from_mnemonic(cleaned)
        except Exception as exc:  # noqa: BLE001
            complaints.append(
                f"Share {position} failed its checksum — a word is mistyped or "
                f"out of order ({exc}).")
            continue
        if seen_identifier is None:
            seen_identifier = parsed.identifier
        elif parsed.identifier != seen_identifier:
            complaints.append(
                f"Share {position} belongs to a different set: its first two "
                f"words are {' '.join(words[:2])!r}, which does not match the "
                "others.")
            continue
        if cleaned in accepted:
            complaints.append(f"Share {position} is a duplicate of one already given.")
            continue
        accepted.append(cleaned)

    return accepted, complaints


def combine(shares: Iterable[str]) -> SecretBytes:
    """Reconstruct the master key from a quorum of shares.

    Extra shares are welcome. SLIP-39 itself insists on being handed exactly
    the threshold and rejects a larger set, which would punish the obvious
    thing to do — paste in every share you have — so surplus shares are
    validated and then set aside.
    """
    accepted, complaints = inspect(shares)
    if not accepted:
        raise RecoveryError(
            " ".join(complaints) if complaints else "No shares were given.")

    threshold = detect_threshold(accepted[0]) or len(accepted)
    if len(accepted) < threshold:
        detail = (" " + " ".join(complaints)) if complaints else ""
        raise RecoveryError(
            f"{len(accepted)} valid share{'s' if len(accepted) != 1 else ''} "
            f"given, but {threshold} are needed. Fewer than the threshold "
            f"reveal nothing at all, by design.{detail}")

    try:
        secret = shamir_mnemonic.combine_mnemonics(accepted[:threshold],
                                                   passphrase=b"")
    except shamir_mnemonic.MnemonicError as exc:
        raise RecoveryError(_explain(str(exc), len(accepted))) from exc
    except Exception as exc:  # noqa: BLE001
        raise RecoveryError(f"the shares could not be combined: {exc}") from exc

    if len(secret) != KEY_SIZE:
        raise RecoveryError(
            f"the shares reconstructed {len(secret)} bytes, not {KEY_SIZE}: "
            "they belong to something other than a Quenchkey vault")
    return SecretBytes(secret)


def _explain(message: str, given: int) -> str:
    """Turn a library error into something a person under pressure can act on."""
    lowered = message.lower()
    if "checksum" in lowered:
        return ("One of the shares failed its checksum — a word is mistyped or "
                "out of order. Each share carries its own checksum, so the "
                "faulty one can be corrected without affecting the others. "
                f"({message})")
    if "threshold" in lowered or "insufficient" in lowered or "expecting" in lowered:
        return (f"{given} share{'s' if given != 1 else ''} "
                f"{'are' if given != 1 else 'is'} not enough to reconstruct the "
                f"key. Fewer than the threshold reveal nothing, by design. "
                f"({message})")
    if "identifier" in lowered or "different" in lowered or "group" in lowered:
        return ("These shares do not all belong to the same set. Check the "
                f"first two words — they match across shares of one vault. "
                f"({message})")
    return f"The shares could not be combined: {message}"


def detect_threshold(share: str) -> Optional[int]:
    """Read the member threshold out of a single share, without combining.

    Lets the interface say "you need three of these" while the user is still
    entering the first one.
    """
    try:
        parsed = shamir_mnemonic.share.Share.from_mnemonic(normalise(share))
        return parsed.member_threshold
    except Exception:  # noqa: BLE001 - a share we cannot parse tells us nothing
        return None
