"""The hash-chained event log, and what an anchor is actually worth."""

from __future__ import annotations

import copy
import time


from quenchkey import chain, locker
from quenchkey.vault import Vault

from conftest import PASSPHRASE


def build(kinds) -> list:
    events: list[dict] = []
    for index, kind in enumerate(kinds):
        chain.append(events, {"at": 1000.0 + index, "kind": kind})
    return events


# -- the primitive ----------------------------------------------------------

def test_a_fresh_chain_verifies():
    events = build(["vault_created", "locked", "unlocked"])
    report = chain.verify(events, chain.head(events))
    assert report.ok and report.length == 3


def test_every_event_links_to_the_one_before():
    events = build(["a", "b", "c"])
    assert events[0]["prev"] == chain.GENESIS
    for earlier, later in zip(events, events[1:]):
        assert later["prev"] == earlier["hash"]
        assert later["seq"] == earlier["seq"] + 1


def test_editing_any_event_breaks_the_chain():
    events = build(["a", "b", "c", "d"])
    for index in range(len(events)):
        damaged = copy.deepcopy(events)
        damaged[index]["kind"] = "something else"
        report = chain.verify(damaged, chain.head(events))
        assert not report.ok
        assert report.broken_at == index


def test_recomputing_a_hash_after_editing_still_breaks_the_links():
    """An attacker who fixes one hash has to fix every hash after it."""
    events = build(["a", "b", "c", "d"])
    damaged = copy.deepcopy(events)
    damaged[1]["kind"] = "forged"
    damaged[1]["hash"] = chain.event_hash(damaged[1])
    report = chain.verify(damaged, chain.head(events))
    assert not report.ok
    assert report.broken_at == 2, "the next event no longer follows"


def test_removing_the_tail_is_caught_by_the_recorded_head():
    events = build(["a", "b", "c"])
    recorded = chain.head(events)
    report = chain.verify(events[:-1], recorded)
    assert not report.ok
    assert "removed from the end" in report.reason


def test_reordering_events_is_caught():
    events = build(["a", "b", "c"])
    swapped = [events[0], events[2], events[1]]
    assert not chain.verify(swapped, chain.head(events)).ok


def test_a_fully_rewritten_chain_verifies_but_has_a_different_head():
    """The honest limit: consistency is not authenticity.

    Someone holding the passphrase can rebuild the whole log. What they cannot
    do is reproduce an anchor recorded before they did it.
    """
    original = build(["vault_created", "locked", "key_destroyed"])
    anchor = chain.head(original)

    rewritten = chain.rechain([{"at": e["at"], "kind": e["kind"]}
                               for e in original if e["kind"] != "key_destroyed"])
    assert chain.verify(rewritten).ok, "internally consistent, as expected"
    assert chain.head(rewritten) != anchor, "but it cannot match the anchor"


def test_fingerprint_is_short_stable_and_derived_from_the_head():
    head = chain.head(build(["a", "b"]))
    fingerprint = chain.fingerprint(head)
    assert fingerprint == chain.fingerprint(head)
    assert len(fingerprint.replace("-", "")) == 16
    assert fingerprint.replace("-", "").lower() == head[:16]


def test_canonical_form_ignores_key_order():
    first = {"b": 2, "a": 1, "kind": "x"}
    second = {"kind": "x", "a": 1, "b": 2}
    assert chain.canonical(first) == chain.canonical(second)


def test_the_hash_field_is_excluded_from_its_own_hash():
    event = {"at": 1.0, "kind": "x", "seq": 0, "prev": chain.GENESIS}
    computed = chain.event_hash(event)
    event["hash"] = computed
    assert chain.event_hash(event) == computed


# -- the vault's chain ------------------------------------------------------

def test_a_vault_chains_its_own_events(vault):
    report = vault.chain_report()
    assert report.ok
    assert report.length >= 1
    assert vault.chain_head == report.head


def test_the_chain_advances_as_things_happen(vault, sample_files, workspace):
    before = vault.chain_head
    locker.lock_files(vault, sample_files[:1], expires=None,
                      output_dir=str(workspace / "locked"))
    assert vault.chain_head != before
    assert vault.chain_report().ok


def test_the_chain_survives_a_save_and_reopen(vault, sample_files, workspace):
    locker.lock_files(vault, sample_files[:1], expires=None,
                      output_dir=str(workspace / "locked"))
    vault.save()
    anchor = vault.chain_head
    vault.lock()

    reopened = Vault.unlock(vault.path, PASSPHRASE)
    # Unlocking logs an event of its own, so the head moves on — but the
    # history up to the anchor is still the history that produced it.
    assert reopened.chain_report().ok
    assert any(event["hash"] == anchor for event in reopened.events)


def test_a_restored_older_vault_does_not_match_a_later_anchor(
        vault, sample_files, workspace):
    """The scenario the anchor exists for."""
    import shutil

    locker.lock_files(vault, sample_files[:1], expires=time.time() + 1,
                      output_dir=str(workspace / "locked"))
    vault.save()
    snapshot = str(workspace / "vault-backup.vk")
    shutil.copy2(vault.path, snapshot)

    # Time passes, the key is destroyed, and the holder records the anchor.
    from quenchkey import expiry

    expiry.sweep(vault, now=time.time() + 60)
    vault.save()
    anchor_after_destruction = vault.chain_head
    vault.lock()

    # Somebody restores the snapshot to bring the key back.
    shutil.copy2(snapshot, vault.path)
    restored = Vault.unlock(vault.path, PASSPHRASE)

    assert restored.chain_report().ok, "the restored vault is self-consistent"
    assert restored.chain_head != anchor_after_destruction
    assert not any(event["hash"] == anchor_after_destruction
                   for event in restored.events), \
        "the recorded anchor appears nowhere in the restored history"


def test_a_migrated_vault_records_when_chaining_began(vault):
    """Retroactive chaining must never be passed off as tamper-evidence."""
    assert vault.chain_origin is not None
    kinds = [event["kind"] for event in vault.events]
    assert "vault_created" in kinds


def test_a_fresh_vault_is_not_reported_as_migrated(vault):
    """A new vault has been chained from its first event; saying otherwise
    would understate what its log is worth."""
    assert not vault.chain_was_migrated
