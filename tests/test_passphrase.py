"""Passphrase generation, and whether the meter can be trusted."""

from __future__ import annotations

import collections
import math
import re

import pytest

from quenchkey import keyfile, passphrase as pp
from quenchkey.wordlist import WORDLIST


# -- the wordlist -----------------------------------------------------------

def test_wordlist_is_a_power_of_two():
    """Uniform selection with randbelow depends on this."""
    assert len(WORDLIST) == 2048
    assert math.log2(len(WORDLIST)).is_integer()


def test_wordlist_entries_are_distinct_and_typable():
    assert len(set(WORDLIST)) == len(WORDLIST)
    assert all(re.fullmatch(r"[a-z]{4,7}", word) for word in WORDLIST)


def test_wordlist_prefixes_are_unambiguous():
    """Three letters identify a word, so shorthand is never ambiguous."""
    assert len({word[:3] for word in WORDLIST}) == len(WORDLIST)


# -- generation -------------------------------------------------------------

def test_generated_passphrase_has_the_requested_shape():
    phrase = pp.generate_passphrase(7)
    assert len(phrase.split("-")) == 7
    assert all(word in WORDLIST for word in phrase.split("-"))


def test_generated_passphrases_do_not_repeat():
    phrases = {pp.generate_passphrase(7) for _ in range(300)}
    assert len(phrases) == 300


def test_generation_is_roughly_uniform():
    """A chi-square goodness-of-fit test against a flat distribution.

    Under a uniform draw, chi-square over 2047 degrees of freedom has mean
    2047 and standard deviation sqrt(2 x 2047) = 64. The bounds below are six
    standard deviations either side, which catches a biased generator without
    failing by chance. Both tails matter: a suspiciously *even* spread would
    mean the draws were not independent.
    """
    draws = 40_000
    counts = collections.Counter()
    for _ in range(draws // 8):
        counts.update(pp.generate_passphrase(8).split("-"))

    buckets = len(WORDLIST)
    expected = draws / buckets
    chi_square = sum((counts.get(word, 0) - expected) ** 2 / expected
                     for word in WORDLIST)

    degrees = buckets - 1
    spread = math.sqrt(2 * degrees)
    assert degrees - 6 * spread < chi_square < degrees + 6 * spread, (
        f"chi-square {chi_square:.0f} is outside the expected range for a "
        f"uniform draw over {buckets} words")


def test_generated_phrase_is_scored_exactly():
    strength = pp.estimate(pp.generate_passphrase(7))
    assert strength.is_generated_phrase
    assert strength.bits == 77
    assert "not an estimate" in " ".join(strength.notes)


def test_default_generated_passphrase_clears_the_minimum():
    strength = pp.estimate(pp.generate_passphrase(pp.RECOMMENDED_WORDS))
    assert strength.meets_minimum
    assert strength.label in ("Strong", "Very strong")


def test_rejects_a_zero_word_request():
    with pytest.raises(ValueError):
        pp.generate_passphrase(0)


# -- estimation -------------------------------------------------------------

@pytest.mark.parametrize("weak", [
    "password", "Password1", "P@ssw0rd", "qwerty123", "letmein",
    "iloveyou1234", "aaaaaaaaaaaaaa", "12345678", "summer2019", "hunter2",
])
def test_known_bad_passphrases_score_far_below_the_floor(weak):
    strength = pp.estimate(weak)
    assert strength.bits < pp.MIN_BITS, f"{weak!r} scored {strength.bits:.0f} bits"
    assert not strength.meets_minimum


def test_leet_substitution_does_not_buy_strength():
    plain = pp.estimate("password").bits
    leeted = pp.estimate("p4ssw0rd").bits
    assert leeted < plain + 8, "substitutions should be nearly free to an attacker"


def test_dictionary_words_are_priced_as_words_not_characters():
    """Four words must not score like sixteen random characters."""
    words = pp.estimate("correcthorsebatterystaple").bits
    assert words < 16 * 6, "a word is about 12 bits, not one class-worth per letter"


def test_a_long_random_string_scores_well():
    strength = pp.estimate("x7#Qm2vL!pZ9wR&t")
    assert strength.bits > 80
    assert strength.meets_minimum


def test_repeats_and_runs_are_recognised():
    assert pp.estimate("abcdefghijkl").bits < pp.estimate("xmqbzrtvwkdj").bits
    assert pp.estimate("aaaaaaaaaaaa").bits < 20


def test_short_passphrases_fail_the_length_floor():
    strength = pp.estimate("x7#Qm2v")
    assert not strength.meets_minimum


def test_empty_passphrase_is_handled():
    strength = pp.estimate("")
    assert strength.bits == 0
    assert not strength.meets_minimum


def test_notes_are_specific_rather_than_generic():
    notes = " ".join(pp.estimate("Manchester1878!").notes)
    assert "Manchester" in notes


def test_crack_time_note_scales_with_bits():
    assert "second" in pp.crack_time_note(20)
    assert "year" in pp.crack_time_note(90)


# -- keyfiles ---------------------------------------------------------------

def test_generated_keyfile_is_the_expected_shape(tmp_path):
    path = keyfile.generate(str(tmp_path / "k.keyfile"))
    info = keyfile.verify(path)
    assert info.intact and info.is_quenchkey_keyfile
    assert info.size == keyfile.KEYFILE_SIZE


def test_two_keyfiles_differ(tmp_path):
    first = keyfile.generate(str(tmp_path / "a.keyfile"))
    second = keyfile.generate(str(tmp_path / "b.keyfile"))
    assert open(first, "rb").read() != open(second, "rb").read()


def test_a_single_changed_byte_is_detected(tmp_path):
    """The whole point: corruption is reported before data is lost."""
    path = keyfile.generate(str(tmp_path / "k.keyfile"))
    import os
    os.chmod(path, 0o600)
    data = bytearray(open(path, "rb").read())
    data[500] ^= 0x01
    open(path, "wb").write(bytes(data))

    info = keyfile.verify(path)
    assert not info.intact
    assert "changed" in info.message
    with pytest.raises(keyfile.KeyfileError):
        keyfile.require_usable(path)


def test_a_truncated_keyfile_is_detected(tmp_path):
    import os
    path = keyfile.generate(str(tmp_path / "k.keyfile"))
    os.chmod(path, 0o600)
    data = open(path, "rb").read()
    open(path, "wb").write(data[:2000])
    assert not keyfile.verify(path).intact


def test_a_foreign_file_is_usable_but_flagged(tmp_path):
    path = tmp_path / "holiday.jpg"
    path.write_bytes(b"\xff\xd8\xff" + b"x" * 5000)
    info = keyfile.verify(str(path))
    assert not info.is_quenchkey_keyfile
    assert "cannot tell you" in info.message
    assert keyfile.require_usable(str(path)) == str(path)


def test_refuses_to_overwrite_without_being_asked(tmp_path):
    path = keyfile.generate(str(tmp_path / "k.keyfile"))
    with pytest.raises(keyfile.KeyfileError):
        keyfile.generate(path)


# --------------------------------------------------------------------------
# character passwords
# --------------------------------------------------------------------------

def test_a_generated_password_has_every_character_class():
    for _ in range(40):
        value = pp.generate_characters()
        assert len(value) == pp.DEFAULT_CHARACTER_LENGTH
        for group in pp.CHARACTER_CLASSES:
            assert set(value) & set(group), f"{value!r} has no {group[:4]}…"


def test_generated_passwords_use_the_whole_alphabet():
    """Over enough draws every character should turn up at least once."""
    seen: set = set()
    for _ in range(400):
        seen |= set(pp.generate_characters())
    assert seen == set(pp.CHARACTER_ALPHABET)


def test_generated_passwords_do_not_repeat():
    values = {pp.generate_characters() for _ in range(200)}
    assert len(values) == 200


def test_the_composition_rule_lowers_the_entropy_rather_than_raising_it():
    """Requiring every class shrinks the output set, so it costs bits.

    A rule that looks like it adds strength actually removes a little, and
    the figure the interface shows has to be the honest one.
    """
    naive = pp.DEFAULT_CHARACTER_LENGTH * math.log2(len(pp.CHARACTER_ALPHABET))
    exact = pp.character_bits(pp.DEFAULT_CHARACTER_LENGTH)
    assert exact < naive
    assert naive - exact < 0.2  # small, but real


def test_the_entropy_matches_a_direct_count_on_a_tiny_alphabet():
    """Checked against every possible string, where that is countable."""
    import itertools
    alphabet = "ab1!"
    classes = ("ab", "", "1", "!")
    length = 4
    qualifying = sum(
        1 for candidate in itertools.product(alphabet, repeat=length)
        if all(set(candidate) & set(group) for group in classes if group)
    )
    expected = math.log2(qualifying)
    assert pp.character_bits(length, alphabet, classes) == pytest.approx(expected)


def test_character_entropy_rises_with_length():
    values = [pp.character_bits(n) for n in pp.CHARACTER_LENGTHS]
    assert values == sorted(values)
    assert pp.character_bits(24) > 150


def test_a_password_too_short_for_its_classes_is_refused():
    with pytest.raises(ValueError):
        pp.generate_characters(3)


def test_a_generated_password_is_reported_as_exact():
    value = pp.generate_characters()
    bits = pp.character_bits(len(value))
    strength = pp.estimate(value, bits)
    assert strength.is_generated_phrase
    assert strength.bits == pytest.approx(bits)
    assert strength.meets_minimum
    assert any("exactly" in note for note in strength.notes)
    assert any("memorable" in note for note in strength.notes)


def test_without_being_told_the_same_password_is_only_an_upper_bound():
    """It cannot be recognised by inspection, which is the point of it."""
    value = pp.generate_characters()
    assert pp.estimate(value).is_generated_phrase is False


def test_the_blind_estimate_never_exceeds_a_random_passwords_real_entropy():
    """The number is documented as an upper bound. It has to actually be one.

    A random character password is the one case where the true figure is
    known exactly, so it is the one case that can catch the estimator
    flattering a passphrase. It used to: every segment was charged an extra
    bit for being joined to the next, and since an unrecognisable string is
    one segment per character, a 24-character password collected 23 bits it
    had never earned and was priced above its own entropy.

    The half-bit of slack is the composition rule: the blind estimate prices
    an unrestricted draw, and requiring every class makes the real thing
    fractionally cheaper than that.
    """
    for _ in range(50):
        value = pp.generate_characters()
        true_bits = pp.character_bits(len(value))
        assert pp.estimate(value).bits <= true_bits + 0.5


def test_a_long_run_of_raw_characters_is_priced_as_one_region():
    """Twice the random characters should be worth about twice the bits.

    Averaged over many draws rather than compared one to one: a random string
    occasionally contains an accidental dictionary word, which the segmenter
    correctly prices cheaply, and a single sample can be a few bits either way
    because of it.
    """
    import statistics

    short = statistics.mean(
        pp.estimate(pp.generate_characters(16)).bits for _ in range(25))
    long = statistics.mean(
        pp.estimate(pp.generate_characters(32)).bits for _ in range(25))

    assert 1.85 < long / short < 2.15


def test_joining_recognisable_pieces_still_costs_something():
    """The exemption is for raw characters only, not for structure."""
    one = pp.estimate("photosphere").bits
    three = pp.estimate("photosphere-lantern-quay").bits
    assert three > one * 2
