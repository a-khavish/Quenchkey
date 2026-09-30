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

"""Passphrase generation and strength estimation.

The passphrase is the security of this application. Everything else is
plumbing around it. If the passphrase is guessable then the Argon2 cost
parameters, the cipher choice and the expiry logic are all beside the point: an
attacker with a copy of a ``.qkey`` file and a copy of the vault works
offline, at whatever speed their hardware allows, with Quenchkey nowhere in
sight. So the setup screen pushes hard toward a generated passphrase, and the
meter is deliberately pessimistic.

What the number means
---------------------

For a passphrase this app generated, the figure is **exact**: each word is
drawn with ``secrets.randbelow(2048)`` from a 2048-word list, so it contributes
exactly 11 bits, and the app knows how many words it drew.

For anything typed by hand, the figure is a **heuristic upper bound on
strength**, computed the way a cracker would price the string: find the
cheapest way to describe it — as dictionary words, as a known common password,
as digit runs, as repeats, as keyboard walks, as dates, as l33t-substituted
versions of any of those — and add up the cost of that description. The search
for the cheapest description is a shortest-path problem over the string, solved
exactly.

It is still only a model. Real crackers use frequency-ranked corpora of
breached passwords, targeted rules, and information about you that this app
does not have. Read the number as "no better than this", never "at least this".
"""

from __future__ import annotations

import gzip
import math
import os
import re
import secrets
import string
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from typing import Iterable, Optional

from .wordlist import BITS_PER_WORD, WORDLIST

_GENERATION_SET = {w: i for i, w in enumerate(WORDLIST)}
_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

DEFAULT_WORD_COUNT = 7
DEFAULT_SEPARATOR = "-"

#: Hard floor enforced at vault creation.
MIN_LENGTH = 12
MIN_BITS = 60

#: What the Generate button produces: 7 x 11 = 77 bits, in the same range as
#: a six-word Diceware phrase from the 7776-word list.
RECOMMENDED_WORDS = 7

#: Band thresholds in bits. The boundaries are judgement calls, but they are
#: judged against an offline attack on these Argon2id parameters rather than
#: against a login form with rate limiting: 40 bits falls in a day, 60 bits is
#: the floor worth accepting, and 75 bits is past any feasible brute force.
BANDS: list[tuple[int, str]] = [
    (0, "Far too weak"),
    (40, "Weak"),
    (60, "Usable"),
    (75, "Strong"),
    (100, "Very strong"),
]

#: Cost charged for one recognised dictionary word. Pessimistic on purpose:
#: it assumes the attacker works from a ~4k-word high-frequency list, which is
#: cheaper than the ~300k-word list used here for *detection*. Charging the
#: detection list's real size would flatter long-tail words like "photosphere".
DICTIONARY_BITS = 12.0

#: Extra cost for a capitalisation pattern beyond all-lower / Initial / ALL-CAPS.
CAPITALISATION_BITS = 1.0
LEET_BITS = 1.0

_KEYBOARD_ROWS = (
    "`1234567890-=",
    "qwertyuiop[]\\",
    "asdfghjkl;'",
    "zxcvbnm,./",
)

_LEET = {
    "4": "a", "@": "a", "8": "b", "(": "c", "3": "e", "6": "g", "9": "g",
    "1": "l", "!": "i", "|": "l", "0": "o", "5": "s", "$": "s", "7": "t",
    "+": "t", "2": "z", "€": "e",
}

_SEQUENCES = ("abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiop")


# --------------------------------------------------------------------------
# data loading
# --------------------------------------------------------------------------

@lru_cache(maxsize=1)
def _english() -> frozenset[str]:
    path = os.path.join(_DATA_DIR, "english.txt.gz")
    try:
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            return frozenset(line.strip() for line in fh if line.strip())
    except OSError:
        # Degrade to the generation wordlist rather than failing outright.
        return frozenset(WORDLIST)


@lru_cache(maxsize=1)
def _common_passwords() -> dict[str, int]:
    path = os.path.join(_DATA_DIR, "common-passwords.txt.gz")
    try:
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            return {line.strip(): rank
                    for rank, line in enumerate(fh, start=1) if line.strip()}
    except OSError:
        return {}


# --------------------------------------------------------------------------
# generation
# --------------------------------------------------------------------------

def generate_passphrase(word_count: int = DEFAULT_WORD_COUNT,
                        separator: str = DEFAULT_SEPARATOR) -> str:
    """Generate a passphrase with exactly ``word_count * 11`` bits of entropy.

    Uses ``secrets``, i.e. the operating system CSPRNG. The wordlist length is
    a power of two, so ``randbelow`` introduces no modulo bias.
    """
    if word_count < 1:
        raise ValueError("word_count must be at least 1")
    words = [WORDLIST[secrets.randbelow(len(WORDLIST))] for _ in range(word_count)]
    return separator.join(words)


def generated_bits(word_count: int) -> int:
    return word_count * BITS_PER_WORD


# --------------------------------------------------------------------------
# characters
# --------------------------------------------------------------------------

#: Every printable ASCII character except the space: lower case, upper case,
#: digits and the 32 punctuation marks. 94 in all, so 6.55 bits each. The
#: space is left out because too many systems in the chain between here and
#: wherever someone writes this down will strip or collapse it.
CHARACTER_ALPHABET = (string.ascii_lowercase + string.ascii_uppercase
                      + string.digits + string.punctuation)

#: The four classes a generated password is required to contain at least one
#: of. This buys nothing in entropy — it costs a little, see
#: :func:`character_bits` — but composition rules are common enough in the
#: places people store these that a password failing one is a nuisance.
CHARACTER_CLASSES: tuple[str, ...] = (
    string.ascii_lowercase, string.ascii_uppercase,
    string.digits, string.punctuation,
)

#: 24 characters, a shade over 157 bits.
DEFAULT_CHARACTER_LENGTH = 24

#: Lengths the interface offers, and nothing longer. Past roughly 128 bits the
#: passphrase has stopped being the weakest part of the system by any margin
#: worth measuring — the cipher keys are 256-bit, the derivation is the same
#: either way, and no amount of further entropy changes what an attacker can
#: do. Longer options exist here because people are asked for them, not
#: because they help.
CHARACTER_LENGTHS = (16, 20, 24, 32, 48)

#: Where more entropy stops changing anything measurable.
PRACTICAL_CEILING_BITS = 128


def generate_characters(length: int = DEFAULT_CHARACTER_LENGTH,
                        alphabet: str = CHARACTER_ALPHABET,
                        classes: Iterable[str] = CHARACTER_CLASSES) -> str:
    """A uniformly random string containing at least one of every class.

    Each character is drawn with ``secrets.choice``, i.e. the operating system
    CSPRNG, and the whole string is redrawn — never patched — if a class is
    missing. Patching one in afterwards would bias the result; redrawing
    leaves the distribution uniform over exactly the strings that qualify,
    and :func:`character_bits` prices that restriction honestly.
    """
    if length < 1:
        raise ValueError("length must be at least 1")
    wanted = [set(group) for group in classes if group]
    if len(wanted) > length:
        raise ValueError("length is too short to contain every class")
    while True:
        candidate = "".join(secrets.choice(alphabet) for _ in range(length))
        present = set(candidate)
        if all(present & group for group in wanted):
            return candidate


def _all_classes_probability(length: int, alphabet: str,
                             classes: Iterable[str]) -> float:
    """The chance a uniform draw already contains every class.

    Inclusion-exclusion over the classes. With the default alphabet at 24
    characters this is about 0.93 — dominated by the one-in-fifteen chance of
    drawing no digit at all, since digits are the smallest class.
    """
    groups = [set(group) & set(alphabet) for group in classes]
    groups = [group for group in groups if group]
    size = len(set(alphabet))
    if not groups or size == 0:
        return 1.0
    total = 0.0
    for mask in range(1 << len(groups)):
        excluded: set = set()
        bits = 0
        for index, group in enumerate(groups):
            if mask & (1 << index):
                excluded |= group
                bits += 1
        remaining = size - len(excluded)
        if remaining <= 0:
            contribution = 0.0
        else:
            contribution = (remaining / size) ** length
        total += ((-1) ** bits) * contribution
    return max(0.0, min(1.0, total))


def character_bits(length: int = DEFAULT_CHARACTER_LENGTH,
                   alphabet: str = CHARACTER_ALPHABET,
                   classes: Optional[Iterable[str]] = CHARACTER_CLASSES) -> float:
    """Exact entropy of :func:`generate_characters`, composition rule included.

    Requiring every class shrinks the set of possible outputs, so it *lowers*
    the entropy rather than raising it. The loss is small — about a tenth of a
    bit at the default length — but it is a loss, and the number this returns
    is the one the interface shows.
    """
    size = len(set(alphabet))
    if size < 2 or length < 1:
        return 0.0
    bits = length * math.log2(size)
    if classes:
        probability = _all_classes_probability(length, alphabet, classes)
        if probability <= 0.0:
            return 0.0
        bits += math.log2(probability)
    return bits


# --------------------------------------------------------------------------
# estimation
# --------------------------------------------------------------------------

@dataclass
class Match:
    """One segment of the cheapest description of a passphrase."""

    start: int
    end: int
    kind: str
    bits: float
    detail: str = ""

    @property
    def length(self) -> int:
        return self.end - self.start


@dataclass
class Strength:
    bits: float
    label: str
    fraction: float
    notes: list[str]
    is_generated_phrase: bool
    meets_minimum: bool
    matches: list[Match]

    @property
    def band(self) -> int:
        idx = 0
        for i, (threshold, _label) in enumerate(BANDS):
            if self.bits >= threshold:
                idx = i
        return idx


def _deleet(text: str) -> str:
    return "".join(_LEET.get(ch, ch) for ch in text)


def _capitalisation_bits(token: str) -> float:
    letters = [c for c in token if c.isalpha()]
    if not letters:
        return 0.0
    if all(c.islower() for c in letters):
        return 0.0
    if all(c.isupper() for c in letters):
        return 1.0
    if letters[0].isupper() and all(c.islower() for c in letters[1:]):
        return 1.0
    # Mixed case in an unusual pattern: at most one bit per letter, which is
    # what choosing a case per position costs.
    return min(len(letters), 1.0 + CAPITALISATION_BITS * 2)


def _charset_bits(text: str) -> float:
    classes = 0
    if re.search(r"[a-z]", text):
        classes += 26
    if re.search(r"[A-Z]", text):
        classes += 26
    if re.search(r"[0-9]", text):
        classes += 10
    if re.search(r"[ ]", text):
        classes += 1
    if re.search(r"[^A-Za-z0-9 ]", text):
        classes += 32
    return math.log2(classes) if classes else 1.0


def _keyboard_walk_bits(token: str) -> Optional[float]:
    lowered = token.lower()
    if len(lowered) < 4:
        return None
    for row in _KEYBOARD_ROWS:
        for seq in (row, row[::-1]):
            if lowered in seq:
                # Choosing a starting key and a direction and a length.
                return math.log2(len(seq) * 2) + math.log2(len(lowered))
    return None


def _sequence_bits(token: str) -> Optional[float]:
    lowered = token.lower()
    if len(lowered) < 3:
        return None
    for seq in _SEQUENCES:
        if lowered in seq or lowered in seq[::-1]:
            return math.log2(len(seq) * 2) + math.log2(len(lowered))
    return None


def _repeat_bits(token: str) -> Optional[float]:
    if len(token) < 3:
        return None
    for base_len in range(1, len(token) // 2 + 1):
        base = token[:base_len]
        if base * (len(token) // base_len) == token and len(token) % base_len == 0:
            reps = len(token) // base_len
            if reps < 2:
                continue
            return base_len * _charset_bits(base) + math.log2(reps) + 1.0
    return None


def _date_bits(token: str) -> Optional[float]:
    if re.fullmatch(r"(19|20)\d{2}", token):
        return math.log2(120)               # a plausible year
    if re.fullmatch(r"\d{6}|\d{8}", token):
        return math.log2(365 * 120)          # a plausible full date
    return None


def _segment_candidates(text: str, lowered: str, deleeted: str) -> list[Match]:
    """Every way a substring of ``text`` could be cheaply described."""
    english = _english()
    common = _common_passwords()
    candidates: list[Match] = []
    n = len(text)
    charset = _charset_bits(text)

    for start in range(n):
        for end in range(start + 1, min(n, start + 24) + 1):
            token = text[start:end]
            low = lowered[start:end]
            deleet = deleeted[start:end]
            length = end - start

            if low in common:
                candidates.append(Match(
                    start, end, "common-password",
                    math.log2(max(2, common[low])) + _capitalisation_bits(token),
                    f"{token!r} is a well-known password"))
            elif deleet in common:
                candidates.append(Match(start, end, "common-password",
                                        math.log2(max(2, common[deleet])) + LEET_BITS
                                        + _capitalisation_bits(token),
                                        f"{token!r} is a well-known password with substitutions"))

            if length >= 3:
                if low in english:
                    candidates.append(Match(start, end, "word",
                                            DICTIONARY_BITS + _capitalisation_bits(token),
                                            f"{token!r} is a dictionary word"))
                elif deleet in english and deleet != low:
                    candidates.append(Match(start, end, "word",
                                            DICTIONARY_BITS + LEET_BITS
                                            + _capitalisation_bits(token),
                                            f"{token!r} is a dictionary word with substitutions"))

            if length >= 3:
                bits = _sequence_bits(token)
                if bits is not None:
                    candidates.append(Match(start, end, "sequence", bits,
                                            f"{token!r} is a straight run"))
                bits = _keyboard_walk_bits(token)
                if bits is not None:
                    candidates.append(Match(start, end, "keyboard", bits,
                                            f"{token!r} is a walk along one keyboard row"))
                bits = _repeat_bits(token)
                if bits is not None:
                    candidates.append(Match(start, end, "repeat", bits,
                                            f"{token!r} is a repeated pattern"))
                bits = _date_bits(token)
                if bits is not None:
                    candidates.append(Match(start, end, "date", bits,
                                            f"{token!r} looks like a date"))

            if token.isdigit() and length >= 2:
                candidates.append(Match(start, end, "digits",
                                        length * math.log2(10), f"{token!r} is digits"))

        # Fallback: one arbitrary character.
        candidates.append(Match(start, start + 1, "char", charset, ""))

    return candidates


def _cheapest_description(text: str) -> tuple[float, list[Match]]:
    """Shortest path over the string: the cheapest total description."""
    lowered = text.lower()
    deleeted = _deleet(lowered)
    n = len(text)
    best = [math.inf] * (n + 1)
    chosen: list[Optional[Match]] = [None] * (n + 1)
    best[0] = 0.0

    by_start: dict[int, list[Match]] = {}
    for match in _segment_candidates(text, lowered, deleeted):
        by_start.setdefault(match.start, []).append(match)

    for i in range(n):
        if best[i] == math.inf:
            continue
        for match in by_start.get(i, ()):
            # Each structural segment costs a little extra: the attacker's
            # rule engine has to choose how many pieces to combine and in what
            # order. One bit per joint is a conservative charge.
            #
            # Raw characters are exempt, and that exemption is load-bearing.
            # A run of unrecognisable characters is one brute-forced region,
            # not a series of decisions to be stitched together, and charging
            # a joint between each pair would price a random 24-character
            # password *above* its true entropy — turning a number documented
            # as "no better than this" into a flattering lie in the one case
            # where the truth is already known exactly.
            joint = 0.0 if match.kind == "char" else 1.0
            total = best[i] + match.bits + joint
            if total < best[match.end]:
                best[match.end] = total
                chosen[match.end] = match

    matches: list[Match] = []
    pos = n
    while pos > 0 and chosen[pos] is not None:
        match = chosen[pos]
        matches.append(match)
        pos = match.start
    matches.reverse()
    # The first segment pays no joint; there is nothing before it to join to.
    opening = 0.0 if (matches and matches[0].kind == "char") else 1.0
    return max(0.0, best[n] - opening), matches


def _looks_generated(text: str) -> Optional[int]:
    parts = [p for p in re.split(r"[-_. ]+", text.lower()) if p]
    if len(parts) >= 2 and all(p in _GENERATION_SET for p in parts):
        return len(parts)
    return None


def estimate(passphrase: str, exact_bits: Optional[float] = None) -> Strength:
    """Estimate the strength of a passphrase. See the module docstring.

    ``exact_bits`` is for a passphrase this application generated itself and
    is still holding unchanged. A random character string cannot be
    recognised as generated by looking at it — that is the point of it — so
    the caller has to say so, and in exchange the figure stops being an upper
    bound and becomes the real number.
    """
    text = unicodedata.normalize("NFKC", passphrase)
    if not text:
        return Strength(0.0, BANDS[0][1], 0.0,
                        ["Enter a passphrase, or press Generate."], False, False, [])

    if exact_bits is not None:
        notes = [f"{len(text)} characters drawn one at a time from a "
                 f"{len(set(CHARACTER_ALPHABET))}-character alphabet — "
                 f"{exact_bits:.0f} bits exactly, not an estimate."]
        if exact_bits >= PRACTICAL_CEILING_BITS:
            notes.append(f"Past about {PRACTICAL_CEILING_BITS} bits nothing "
                         f"measurable improves; the keys themselves are "
                         f"256-bit. The reason to go longer is a rule someone "
                         f"else set, not this one.")
        # On purpose not "…or set up recovery shares": this same panel is
        # used for a drive's passphrase and for a shared file's, and neither
        # of those has recovery shares. The vault screen says that where it
        # is true.
        notes.append("There is nothing memorable about this. Put it in a "
                     "password manager before you rely on it.")
        return Strength(float(exact_bits), _label_for(exact_bits),
                        _fraction(exact_bits), notes, True,
                        exact_bits >= MIN_BITS and len(text) >= MIN_LENGTH, [])

    word_count = _looks_generated(text)
    if word_count:
        bits = float(generated_bits(word_count))
        notes = [f"{word_count} words from the built-in list — {BITS_PER_WORD} bits "
                 f"each, {bits:.0f} bits exactly, not an estimate."]
        if word_count < 6:
            notes.append(f"Six words is the sensible minimum for a vault; "
                         f"{RECOMMENDED_WORDS} is what Generate produces.")
        return Strength(bits, _label_for(bits), _fraction(bits), notes, True,
                        bits >= MIN_BITS and len(text) >= MIN_LENGTH, [])

    bits, matches = _cheapest_description(text)
    notes = _notes_for(text, bits, matches)
    meets = bits >= MIN_BITS and len(text) >= MIN_LENGTH
    return Strength(bits, _label_for(bits), _fraction(bits), notes, False, meets, matches)


#: How each kind of match is described when several of them turn up together.
_KIND_SUMMARY = {
    "word": "recognisable words",
    "common-password": "well-known passwords",
    "sequence": "straight runs like 1234 or abcd",
    "keyboard": "walks along a keyboard row",
    "repeat": "repeated patterns",
    "date": "things that look like dates",
    "digits": "runs of digits",
}


def _notes_for(text: str, bits: float, matches: Iterable[Match]) -> list[str]:
    notes: list[str] = []
    matches = list(matches)

    interesting = [m for m in matches if m.kind != "char" and m.detail]

    # Group by kind, so three dictionary words produce one note rather than
    # three near-identical ones.
    by_kind: dict[str, list[Match]] = {}
    for match in interesting:
        by_kind.setdefault(match.kind, []).append(match)

    for kind, group in sorted(by_kind.items(), key=lambda item: min(
            m.bits for m in item[1]))[:3]:
        if len(group) == 1:
            match = group[0]
            notes.append(f"{match.detail} — about {match.bits:.0f} bits, not "
                         f"{match.length} character"
                         f"{'s' if match.length != 1 else ''} worth.")
        else:
            covered = sum(m.length for m in group)
            total = sum(m.bits for m in group)
            notes.append(
                f"{len(group)} {_KIND_SUMMARY.get(kind, kind)} in there "
                f"({', '.join(repr(text[m.start:m.end]) for m in group[:4])}"
                f"{', …' if len(group) > 4 else ''}) — about {total:.0f} bits "
                f"between them, not {covered} characters worth.")

    if len(text) < MIN_LENGTH:
        notes.append(f"A new vault needs at least {MIN_LENGTH} characters; this is {len(text)}.")
    if bits < MIN_BITS:
        notes.append(f"Below the {MIN_BITS}-bit floor for a new vault. Press "
                     f"Generate: {RECOMMENDED_WORDS} random words are easier to "
                     "remember than a mangled word, and the strength figure is "
                     "then exact rather than estimated.")
    elif not interesting:
        notes.append("No dictionary words, runs or repeats found. The figure is still "
                     "a pessimistic estimate, not a measurement.")
    return notes


def _label_for(bits: float) -> str:
    label = BANDS[0][1]
    for threshold, name in BANDS:
        if bits >= threshold:
            label = name
    return label


def _fraction(bits: float) -> float:
    return max(0.0, min(1.0, bits / 120.0))


def crack_time_note(bits: float, guesses_per_second: float = 1e6) -> str:
    """A rough note on offline attack cost, with its assumption stated.

    A million Argon2id guesses per second is a generous allowance for an
    attacker with serious hardware against 256 MiB, 4-pass parameters — real
    rates are typically far lower. The figure is about orders of magnitude.
    """
    if bits <= 0:
        return "Guessed immediately."
    seconds = (2 ** (bits - 1)) / guesses_per_second
    for limit, unit, divisor in ((60, "seconds", 1), (3600, "minutes", 60),
                                 (86400, "hours", 3600), (86400 * 365, "days", 86400)):
        if seconds < limit:
            return f"roughly {seconds / divisor:,.0f} {unit} of offline guessing"
    years = seconds / (86400 * 365)
    if years < 1000:
        return f"roughly {years:,.0f} years of offline guessing"
    return f"roughly {years:.0e} years of offline guessing"
