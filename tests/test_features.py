"""Recovery shares, open limits, the dead man's switch, and second factors."""

from __future__ import annotations

import os
import time

import pytest

from quenchkey import expiry, factors, locker, recovery
from quenchkey.crypto import AuthenticationError, SecretBytes
from quenchkey.vault import (
    REASON_HEARTBEAT, REASON_OPENS, KeyDestroyed, SecurityKeyRequired, Vault,
)

from conftest import PASSPHRASE


# ==========================================================================
# recovery shares
# ==========================================================================

def test_a_quorum_reconstructs_the_key():
    key = SecretBytes.random()
    shares = recovery.generate(key, threshold=3, count=5)
    assert recovery.combine(shares.shares[:3]) == key


def test_fewer_than_the_threshold_reveal_nothing():
    key = SecretBytes.random()
    shares = recovery.generate(key, threshold=3, count=5)
    with pytest.raises(recovery.RecoveryError) as caught:
        recovery.combine(shares.shares[:2])
    assert "3 are needed" in str(caught.value)
    assert "reveal nothing" in str(caught.value)


def test_surplus_shares_are_accepted():
    """Handing over every share you own is the obvious thing to do."""
    key = SecretBytes.random()
    shares = recovery.generate(key, threshold=2, count=5)
    assert recovery.combine(shares.shares) == key


@pytest.mark.parametrize("threshold,count", [(2, 2), (2, 3), (3, 5), (5, 8)])
def test_every_quorum_shape_round_trips(threshold, count):
    key = SecretBytes.random()
    shares = recovery.generate(key, threshold, count)
    assert recovery.combine(shares.shares[:threshold]) == key


def test_shares_have_the_documented_shape():
    shares = recovery.generate(SecretBytes.random(), 2, 3)
    for share in shares.shares:
        assert len(share.split()) == recovery.WORDS_PER_SHARE
        assert recovery.looks_like_share(share)
    assert len({recovery.share_label(s) for s in shares.shares}) == 1


def test_a_mistyped_word_is_pinned_to_its_own_share():
    key = SecretBytes.random()
    shares = recovery.generate(key, 3, 5)
    words = shares.shares[0].split()
    words[9] = "zebra"
    broken = " ".join(words)

    accepted, complaints = recovery.inspect([broken] + shares.shares[1:4])
    assert len(accepted) == 3
    assert any("Share 1" in complaint for complaint in complaints)
    # The remaining good shares still reach a quorum.
    assert recovery.combine([broken] + shares.shares[1:4]) == key


def test_shares_from_different_sets_are_rejected():
    first = recovery.generate(SecretBytes.random(), 2, 3)
    second = recovery.generate(SecretBytes.random(), 2, 3)
    _accepted, complaints = recovery.inspect([first.shares[0], second.shares[0]])
    assert any("different set" in complaint for complaint in complaints)


def test_duplicate_shares_do_not_count_towards_the_quorum():
    shares = recovery.generate(SecretBytes.random(), 3, 5)
    with pytest.raises(recovery.RecoveryError):
        recovery.combine([shares.shares[0], shares.shares[0], shares.shares[0]])


def test_the_threshold_is_readable_from_one_share():
    shares = recovery.generate(SecretBytes.random(), 4, 6)
    assert recovery.detect_threshold(shares.shares[0]) == 4


def test_shares_open_a_real_vault(vault, sample_files, workspace):
    locker.lock_files(vault, sample_files[:1], expires=None,
                      output_dir=str(workspace / "locked"))
    shares = recovery.generate(vault.master_key(), 2, 3)
    vault.save()
    vault.lock()

    rebuilt = recovery.combine(shares.shares[:2])
    reopened = Vault.unlock_with_master_key(vault.path, rebuilt)
    assert len(reopened.entries()) == 1
    assert reopened.chain_report().ok


def test_the_unlock_method_is_recorded(vault, workspace):
    shares = recovery.generate(vault.master_key(), 2, 3)
    vault.save()
    vault.lock()

    reopened = Vault.unlock_with_master_key(
        vault.path, recovery.combine(shares.shares[:2]))
    methods = [e.get("method") for e in reopened.events if e["kind"] == "unlocked"]
    assert methods[-1] == "recovery shares"


def test_shares_stop_working_after_a_passphrase_change(vault, fast_kdf):
    shares = recovery.generate(vault.master_key(), 2, 3)
    vault.reencrypt("a completely different passphrase", kdf_params=fast_kdf)
    vault.lock()

    stale = recovery.combine(shares.shares[:2])
    with pytest.raises(AuthenticationError):
        Vault.unlock_with_master_key(vault.path, stale)


def test_shares_do_not_resurrect_a_destroyed_key(vault, sample_files, workspace):
    """A quorum reopens the vault. It cannot rebuild what is no longer in it."""
    entry = locker.lock_files(vault, sample_files[:1], expires=None,
                              output_dir=str(workspace / "locked")).entry
    shares = recovery.generate(vault.master_key(), 2, 3)
    vault.shred_key(entry.id)
    vault.save()
    vault.lock()

    reopened = Vault.unlock_with_master_key(
        vault.path, recovery.combine(shares.shares[:2]))
    with pytest.raises(KeyDestroyed):
        reopened.key_for(entry.id)


def test_rejects_impossible_splits():
    key = SecretBytes.random()
    # A threshold of one is refused on principle, not just by arithmetic.
    for threshold, count in [(4, 3), (1, 3), (2, 99), (0, 3)]:
        with pytest.raises(recovery.RecoveryError):
            recovery.generate(key, threshold, count)


# ==========================================================================
# open limits
# ==========================================================================

def test_an_opening_is_counted(vault, sample_files, workspace):
    entry = locker.lock_files(vault, sample_files[:1], expires=None,
                              output_dir=str(workspace / "locked"),
                              max_opens=3).entry
    locker.unlock_entry(vault, entry.id, str(workspace / "out"))
    assert vault.get(entry.id).open_count == 1
    assert vault.get(entry.id).opens_remaining == 2


def test_the_key_dies_on_the_last_opening(vault, sample_files, workspace):
    entry = locker.lock_files(vault, sample_files[:1], expires=None,
                              output_dir=str(workspace / "locked"),
                              max_opens=2).entry
    locker.unlock_entry(vault, entry.id, str(workspace / "out1"))
    assert not vault.get(entry.id).key_destroyed

    locker.unlock_entry(vault, entry.id, str(workspace / "out2"))
    assert vault.get(entry.id).key_destroyed
    assert vault.get(entry.id).destruction_reason == REASON_OPENS

    with pytest.raises(KeyDestroyed):
        locker.unlock_entry(vault, entry.id, str(workspace / "out3"))


def test_a_single_opening_works(vault, sample_files, workspace):
    entry = locker.lock_files(vault, sample_files[:1], expires=None,
                              output_dir=str(workspace / "locked"),
                              max_opens=1).entry
    written = locker.unlock_entry(vault, entry.id, str(workspace / "out"))
    assert written and os.path.exists(written[0])
    assert vault.get(entry.id).key_destroyed


def test_a_failed_extraction_does_not_spend_an_opening(vault, sample_files,
                                                       workspace):
    entry = locker.lock_files(vault, sample_files[:1], expires=None,
                              output_dir=str(workspace / "locked"),
                              max_opens=2).entry
    os.unlink(entry.blob_path)
    with pytest.raises(Exception):
        locker.unlock_entry(vault, entry.id, str(workspace / "out"))
    assert vault.get(entry.id).open_count == 0


def test_the_count_survives_a_reopen(vault, sample_files, workspace):
    entry = locker.lock_files(vault, sample_files[:1], expires=None,
                              output_dir=str(workspace / "locked"),
                              max_opens=3).entry
    locker.unlock_entry(vault, entry.id, str(workspace / "out"))
    vault.save()
    vault.lock()

    reopened = Vault.unlock(vault.path, PASSPHRASE)
    assert reopened.get(entry.id).open_count == 1


def test_a_spent_allowance_is_swept_as_due(vault, sample_files, workspace):
    entry = locker.lock_files(vault, sample_files[:1], expires=None,
                              output_dir=str(workspace / "locked"),
                              max_opens=1).entry
    vault.get(entry.id).open_count = 1          # as if counted elsewhere
    report = expiry.sweep(vault)
    assert [e.id for e in report.expired] == [entry.id]
    assert report.reasons[entry.id] == REASON_OPENS


# ==========================================================================
# dead man's switch
# ==========================================================================

def test_the_switch_does_not_fire_early(vault, sample_files, workspace):
    entry = locker.lock_files(vault, sample_files[:1], expires=None,
                              output_dir=str(workspace / "locked"),
                              heartbeat_days=30).entry
    report = expiry.sweep(vault, now=time.time() + 29 * 86400)
    assert report.expired == []
    assert not vault.get(entry.id).key_destroyed


def test_the_switch_fires_when_the_interval_lapses(vault, sample_files, workspace):
    entry = locker.lock_files(vault, sample_files[:1], expires=None,
                              output_dir=str(workspace / "locked"),
                              heartbeat_days=30).entry
    report = expiry.sweep(vault, now=time.time() + 31 * 86400)
    assert [e.id for e in report.expired] == [entry.id]
    assert report.reasons[entry.id] == REASON_HEARTBEAT


def test_checking_in_postpones_it_indefinitely(vault, sample_files, workspace):
    entry = locker.lock_files(vault, sample_files[:1], expires=None,
                              output_dir=str(workspace / "locked"),
                              heartbeat_days=10).entry
    now = time.time()
    for day in (9, 18, 27, 36):
        vault.get(entry.id).last_checkin = now + (day - 9) * 86400
        report = expiry.sweep(vault, now=now + day * 86400)
        assert report.expired == [], f"fired on day {day} despite checking in"
    assert not vault.get(entry.id).key_destroyed


def test_the_sweep_runs_before_the_check_in(vault, sample_files, workspace,
                                            monkeypatch):
    """Otherwise opening the vault to look would itself postpone the switch."""
    from quenchkey.session import Session

    entry = locker.lock_files(vault, sample_files[:1], expires=None,
                              output_dir=str(workspace / "locked"),
                              heartbeat_days=1).entry
    vault.get(entry.id).last_checkin = time.time() - 5 * 86400

    session = Session(vault, auto_lock_seconds=0)
    report = session.sweep()
    assert [e.id for e in report.expired] == [entry.id]
    assert vault.get(entry.id).key_destroyed


def test_opening_the_vault_counts_as_checking_in(vault, sample_files, workspace):
    from quenchkey.session import Session

    entry = locker.lock_files(vault, sample_files[:1], expires=None,
                              output_dir=str(workspace / "locked"),
                              heartbeat_days=30).entry
    before = vault.get(entry.id).last_checkin
    time.sleep(0.01)
    Session(vault, auto_lock_seconds=0).sweep()
    assert vault.get(entry.id).last_checkin > before


def test_a_rolled_back_clock_does_not_postpone_the_switch(vault, sample_files,
                                                          workspace, monkeypatch):
    entry = locker.lock_files(vault, sample_files[:1], expires=None,
                              output_dir=str(workspace / "locked"),
                              heartbeat_days=7).entry
    vault.get(entry.id).last_checkin = time.time() - 10 * 86400
    vault.save()

    real_time = time.time
    monkeypatch.setattr(time, "time", lambda: real_time() - 365 * 86400)
    report = expiry.sweep(vault)
    assert [e.id for e in report.expired] == [entry.id], \
        "the watermark, not the rolled-back clock, decides"


def test_the_earliest_rule_wins(vault, sample_files, workspace):
    now = time.time()
    entry = locker.lock_files(vault, sample_files[:1], expires=now + 100 * 86400,
                              output_dir=str(workspace / "locked"),
                              heartbeat_days=7).entry
    live = vault.get(entry.id)
    assert abs(live.deadline() - live.heartbeat_deadline()) < 1
    assert expiry.describe_deadline(live).endswith("(no check-in)")


# ==========================================================================
# second factors
# ==========================================================================

def test_a_keyfile_vault_still_works(workspace, fast_kdf, sample_files):
    from quenchkey import keyfile

    path = keyfile.generate(str(workspace / "k.keyfile"))
    vault_path = str(workspace / "kf.vk")
    Vault.create(vault_path, PASSPHRASE, path, kdf_params=fast_kdf).lock()
    Vault.unlock(vault_path, PASSPHRASE, path).lock()


def test_a_security_key_protects_a_vault(workspace, fast_kdf):
    """Driven against the simulated authenticator, not real hardware."""
    device = factors.SimulatedAuthenticator()
    factor = factors.Fido2Factor.enrol(device)
    vault_path = str(workspace / "fido.vk")

    created = Vault.create(vault_path, PASSPHRASE, kdf_params=fast_kdf,
                           factor=factor)
    created.lock()

    header = __import__("quenchkey.vault", fromlist=["read_header"]).read_header(
        vault_path)
    assert header.security_key_required
    assert header.factor_kind == factors.FACTOR_FIDO2

    reopened = Vault.unlock(vault_path, PASSPHRASE, authenticator=device)
    assert reopened.is_unlocked
    reopened.lock()


def test_the_passphrase_alone_will_not_open_a_security_key_vault(workspace,
                                                                 fast_kdf):
    device = factors.SimulatedAuthenticator()
    factor = factors.Fido2Factor.enrol(device)
    vault_path = str(workspace / "fido.vk")
    Vault.create(vault_path, PASSPHRASE, kdf_params=fast_kdf, factor=factor).lock()

    with pytest.raises((SecurityKeyRequired, factors.FactorUnavailable,
                        factors.FactorError)):
        Vault.unlock(vault_path, PASSPHRASE)


def test_another_security_key_fails_like_a_wrong_passphrase(workspace, fast_kdf):
    device = factors.SimulatedAuthenticator()
    factor = factors.Fido2Factor.enrol(device)
    vault_path = str(workspace / "fido.vk")
    Vault.create(vault_path, PASSPHRASE, kdf_params=fast_kdf, factor=factor).lock()

    impostor = factors.SimulatedAuthenticator()
    with pytest.raises(factors.FactorUnavailable):
        Vault.unlock(vault_path, PASSPHRASE, authenticator=impostor)


def test_security_key_parameters_are_authenticated(workspace, fast_kdf):
    """The credential id is public, but it is still covered by the tag."""
    device = factors.SimulatedAuthenticator()
    factor = factors.Fido2Factor.enrol(device)
    vault_path = str(workspace / "fido.vk")
    Vault.create(vault_path, PASSPHRASE, kdf_params=fast_kdf, factor=factor).lock()

    data = bytearray(open(vault_path, "rb").read())
    marker = data.find(b"credential_id")
    assert marker > 0, "the parameters are in the cleartext header"
    data[marker + 20] ^= 0x01
    open(vault_path, "wb").write(bytes(data))

    with pytest.raises((AuthenticationError, factors.FactorError,
                        factors.FactorUnavailable)):
        Vault.unlock(vault_path, PASSPHRASE, authenticator=device)


def test_shares_rescue_a_vault_whose_security_key_is_lost(workspace, fast_kdf):
    """The documented answer to losing the hardware."""
    device = factors.SimulatedAuthenticator()
    factor = factors.Fido2Factor.enrol(device)
    vault_path = str(workspace / "fido.vk")

    created = Vault.create(vault_path, PASSPHRASE, kdf_params=fast_kdf,
                           factor=factor)
    shares = recovery.generate(created.master_key(), 2, 3)
    created.save()
    created.lock()

    # The key is gone for good; the shares still work.
    with pytest.raises(factors.FactorUnavailable):
        Vault.unlock(vault_path, PASSPHRASE,
                     authenticator=factors.SimulatedAuthenticator())
    reopened = Vault.unlock_with_master_key(
        vault_path, recovery.combine(shares.shares[:2]))
    assert reopened.is_unlocked


def test_a_factor_changes_the_derived_key():
    device = factors.SimulatedAuthenticator()
    factor = factors.Fido2Factor.enrol(device)
    plain = factors.build_kdf_input("passphrase")
    with_key = factors.build_kdf_input("passphrase", factor)
    assert plain.bytes() != with_key.bytes()


def test_the_simulated_authenticator_is_deterministic():
    device = factors.SimulatedAuthenticator()
    factor = factors.Fido2Factor.enrol(device)
    assert factor.material() == factor.material()
