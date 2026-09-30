"""Backups, watched folders, checkouts and the duress passphrase.

Each of these trades something away, and the tests are mostly about the
trade being honoured rather than the happy path working.
"""

from __future__ import annotations

import os
import time

import pytest

from quenchkey import backup, locker, watch
from quenchkey.crypto import AuthenticationError
from quenchkey.vault import (
    Vault, destroy_vault, duress_matches,
)

from conftest import PASSPHRASE

DURESS = "seventeen-ravens-left-the-tower-at-dawn"


@pytest.fixture()
def locked_entry(vault, workspace):
    source = workspace / "documents" / "report.txt"
    source.write_bytes(b"confidential " * 200)
    return locker.lock_files(vault, [str(source)], time.time() + 7200,
                             output_dir=str(workspace / "locked")).entry


# --------------------------------------------------------------------------
# backups
# --------------------------------------------------------------------------

def test_a_backup_is_readable_without_the_passphrase(vault, workspace,
                                                     locked_entry):
    info = backup.create(vault, str(workspace / "vault.qkvbak"))
    described = backup.describe(info.path)

    assert described.entries == 1
    assert described.vault_id == vault.vault_id
    assert described.chain_head == info.chain_head


def test_a_backup_holds_no_key_in_the_clear(vault, workspace, locked_entry):
    """It is a copy of an encrypted file; the manifest beside it is not."""
    info = backup.create(vault, str(workspace / "vault.qkvbak"))
    manifest = open(info.manifest_path).read()

    assert locked_entry.key.bytes().hex() not in manifest
    assert PASSPHRASE not in manifest
    # The backup is itself an encrypted vault, and opens with the same
    # passphrase — it is a copy, not a re-encryption under something new.
    # (It is not byte-identical to the vault afterwards: taking a backup is
    # recorded in the chain, so the original moves on by one event.)
    assert open(info.path, "rb").read(8) == b"QKEYVALT"
    assert Vault.unlock(info.path, PASSPHRASE) is not None


def test_backing_up_over_the_vault_is_refused(vault):
    with pytest.raises(backup.BackupError):
        backup.create(vault, vault.path)


def test_restoring_brings_back_a_destroyed_key_and_says_so(vault, workspace,
                                                            locked_entry):
    """The trade, stated: a backup is a past state, expiry only runs forward."""
    info = backup.create(vault, str(workspace / "vault.qkvbak"))
    vault.shred_key(locked_entry.id)
    vault.save()

    cost = backup.cost_of_restoring(info, vault.path, vault)
    assert cost.rolls_back
    assert cost.destructions_undone == 1
    assert "would come back" in cost.summary()

    backup.restore(info, vault.path)
    reopened = Vault.unlock(vault.path, PASSPHRASE)
    alive = [e for e in reopened.entries() if not e.key_destroyed]
    assert len(alive) == 1


def test_restoring_keeps_the_vault_it_replaced(vault, workspace, locked_entry):
    """Restoring the wrong backup must not be the unrecoverable mistake."""
    info = backup.create(vault, str(workspace / "vault.qkvbak"))
    before = open(vault.path, "rb").read()
    vault.shred_key(locked_entry.id)
    vault.save()

    displaced = backup.restore(info, vault.path)
    assert displaced and os.path.exists(displaced)
    assert open(displaced, "rb").read() != before  # it is the newer one


def test_a_restore_is_recorded_in_the_restored_vault(vault, workspace,
                                                     locked_entry):
    info = backup.create(vault, str(workspace / "vault.qkvbak"))
    vault.shred_key(locked_entry.id)
    vault.save()
    cost = backup.cost_of_restoring(info, vault.path, vault)
    displaced = backup.restore(info, vault.path)

    reopened = Vault.unlock(vault.path, PASSPHRASE)
    backup.record_restore(reopened, info, cost, displaced)

    events = [e for e in reopened.events if e["kind"] == "vault_restored"]
    assert len(events) == 1
    assert events[0]["destructions_undone"] == 1
    assert reopened.chain_report().ok


def test_a_backup_of_another_vault_is_flagged(vault, workspace, fast_kdf):
    other = Vault.create(str(workspace / "other.qkv"), PASSPHRASE,
                         kdf_params=fast_kdf)
    info = backup.create(other, str(workspace / "other.qkvbak"))

    cost = backup.cost_of_restoring(info, vault.path, vault)
    assert not cost.same_vault
    assert "different" in cost.summary()


def test_backups_are_listed_newest_first(vault, workspace):
    folder = workspace / "backups"
    folder.mkdir()
    first = backup.create(vault, str(folder / "a.qkvbak"))
    time.sleep(0.01)
    second = backup.create(vault, str(folder / "b.qkvbak"))

    found = backup.find(str(folder))
    assert [i.name for i in found] == [second.name, first.name]


# --------------------------------------------------------------------------
# watched folders
# --------------------------------------------------------------------------

def test_a_dropped_file_is_locked_once_it_settles(vault, workspace):
    inbox = workspace / "inbox"
    inbox.mkdir()
    vault.add_watch_rule(watch.WatchRule(path=str(inbox), expires_seconds=3600))
    dropped = inbox / "dropped.txt"
    dropped.write_bytes(b"something" * 100)

    watcher = watch.Watcher()
    now = time.time()
    assert watcher.sweep(vault, vault.watch_rules(), now=now).locked == []
    report = watcher.sweep(vault, vault.watch_rules(),
                           now=now + watch.SETTLE_SECONDS + 1)

    assert report.locked == [str(dropped)]
    assert not dropped.exists()                     # the original was shredded
    assert len(vault.entries()) == 1


def test_a_file_still_being_written_is_left_alone(vault, workspace):
    """A watcher that grabbed files instantly would encrypt half a download."""
    inbox = workspace / "inbox"
    inbox.mkdir()
    vault.add_watch_rule(watch.WatchRule(path=str(inbox)))
    growing = inbox / "growing.bin"
    growing.write_bytes(b"a")

    watcher = watch.Watcher()
    now = time.time()
    watcher.sweep(vault, vault.watch_rules(), now=now)
    growing.write_bytes(b"a" * 5000)               # it changed
    report = watcher.sweep(vault, vault.watch_rules(),
                           now=now + watch.SETTLE_SECONDS + 1)

    assert report.locked == []
    assert growing.exists()


@pytest.mark.parametrize("name", ["big.iso.part", "x.crdownload", ".hidden",
                                  "doc.txt.tmp", "notes~"])
def test_partial_and_scratch_files_are_never_picked_up(vault, workspace, name):
    inbox = workspace / "inbox"
    inbox.mkdir()
    (inbox / name).write_bytes(b"x")
    rule = watch.WatchRule(path=str(inbox))

    assert watch.candidates(rule) == []


def test_a_locked_file_is_not_locked_again(vault, workspace):
    """Or the folder would eat its own output forever."""
    inbox = workspace / "inbox"
    inbox.mkdir()
    (inbox / f"already{locker.QKEY_SUFFIX}").write_bytes(b"x")

    assert watch.candidates(watch.WatchRule(path=str(inbox))) == []


def test_watching_does_nothing_while_the_vault_is_locked(vault, workspace):
    """Locking needs the vault, so this is a convenience, not a guard."""
    inbox = workspace / "inbox"
    inbox.mkdir()
    vault.add_watch_rule(watch.WatchRule(path=str(inbox)))
    (inbox / "dropped.txt").write_bytes(b"x" * 100)
    rules = vault.watch_rules()
    vault.lock()

    report = watch.Watcher().sweep(vault, rules, now=time.time() + 600)
    assert report.locked == []


def test_watch_rules_survive_locking_and_reopening(vault, workspace):
    inbox = workspace / "inbox"
    inbox.mkdir()
    vault.add_watch_rule(watch.WatchRule(path=str(inbox), expires_seconds=60,
                                         max_opens=3))

    reopened = Vault.unlock(vault.path, PASSPHRASE)
    rules = reopened.watch_rules()
    assert len(rules) == 1
    assert rules[0].max_opens == 3
    assert rules[0].path == str(inbox)


def test_watching_the_same_folder_twice_replaces_the_rule(vault, workspace):
    inbox = workspace / "inbox"
    inbox.mkdir()
    vault.add_watch_rule(watch.WatchRule(path=str(inbox), expires_seconds=60))
    vault.add_watch_rule(watch.WatchRule(path=str(inbox), expires_seconds=3600))

    rules = vault.watch_rules()
    assert len(rules) == 1
    assert rules[0].expires_seconds == 3600


# --------------------------------------------------------------------------
# checking out
# --------------------------------------------------------------------------

def test_a_checkout_shreds_what_it_lent_when_the_loan_ends(vault, workspace,
                                                            locked_entry):
    destination = workspace / "desk"
    destination.mkdir()
    written = locker.check_out(vault, locked_entry.id, str(destination),
                               minutes=30)
    assert written and all(os.path.exists(p) for p in written)

    entry = next(e for e in vault.entries() if e.id == locked_entry.id)
    assert entry.checked_out
    entry.checkout_until = time.time() - 1
    vault.save()

    reports = locker.sweep_checkouts(vault)
    assert len(reports) == 1 and len(reports[0].shredded) == len(written)
    assert not any(os.path.exists(p) for p in written)


def test_the_entry_survives_its_own_checkout(vault, workspace, locked_entry):
    """A loan returns the file; it does not destroy the key."""
    destination = workspace / "desk"
    destination.mkdir()
    locker.check_out(vault, locked_entry.id, str(destination), minutes=30)
    entry = next(e for e in vault.entries() if e.id == locked_entry.id)
    entry.checkout_until = time.time() - 1
    vault.save()
    locker.sweep_checkouts(vault)

    entry = next(e for e in vault.entries() if e.id == locked_entry.id)
    assert not entry.checked_out
    assert not entry.key_destroyed


def test_a_loan_that_has_not_run_out_is_left_alone(vault, workspace,
                                                    locked_entry):
    destination = workspace / "desk"
    destination.mkdir()
    written = locker.check_out(vault, locked_entry.id, str(destination),
                               minutes=60)

    assert locker.sweep_checkouts(vault) == []
    assert all(os.path.exists(p) for p in written)


def test_a_checkout_only_reaches_what_it_wrote(vault, workspace, locked_entry):
    """A copy made afterwards is the user's, and is not touched."""
    destination = workspace / "desk"
    destination.mkdir()
    written = locker.check_out(vault, locked_entry.id, str(destination),
                               minutes=30)
    elsewhere = workspace / "my-own-copy.txt"
    elsewhere.write_bytes(open(written[0], "rb").read())

    entry = next(e for e in vault.entries() if e.id == locked_entry.id)
    entry.checkout_until = time.time() - 1
    vault.save()
    locker.sweep_checkouts(vault)

    assert not os.path.exists(written[0])
    assert elsewhere.exists()          # untouched, and honestly so


def test_checking_in_a_file_the_user_already_deleted_is_fine(vault, workspace,
                                                              locked_entry):
    destination = workspace / "desk"
    destination.mkdir()
    written = locker.check_out(vault, locked_entry.id, str(destination),
                               minutes=30)
    os.unlink(written[0])

    report = locker.check_in(vault, locked_entry.id)
    assert report.missing == written
    assert report.failed == []


def test_an_edit_made_on_loan_is_locked_back_in(vault, workspace, locked_entry):
    """The trap this closes: an afternoon's work shredded by a timer."""
    destination = workspace / "desk"
    destination.mkdir()
    written = locker.check_out(vault, locked_entry.id, str(destination),
                               minutes=30)
    with open(written[0], "ab") as fh:
        fh.write(b"\nthe paragraph I spent the afternoon on")

    report = locker.check_in(vault, locked_entry.id)

    assert report.edited == written
    assert report.saved
    assert not os.path.exists(written[0])          # the copy is gone
    out = workspace / "again"
    out.mkdir()
    again = locker.unlock_entry(vault, locked_entry.id, str(out))
    assert b"afternoon" in open(again[0], "rb").read()   # but the work is not


def test_an_untouched_loan_leaves_the_vault_alone(vault, workspace, locked_entry):
    destination = workspace / "desk"
    destination.mkdir()
    before = next(e for e in vault.entries() if e.id == locked_entry.id).blob_sha256
    locker.check_out(vault, locked_entry.id, str(destination), minutes=30)

    report = locker.check_in(vault, locked_entry.id)

    assert report.edited == []
    assert not report.saved
    after = next(e for e in vault.entries() if e.id == locked_entry.id).blob_sha256
    assert after == before
    assert "nothing had been edited" in report.summary()


def test_the_timer_saves_edits_too(vault, workspace, locked_entry):
    """An overdue sweep must not be a quieter way to lose the same work."""
    destination = workspace / "desk"
    destination.mkdir()
    written = locker.check_out(vault, locked_entry.id, str(destination),
                               minutes=30)
    with open(written[0], "ab") as fh:
        fh.write(b"\nedited, then forgotten about")
    entry = next(e for e in vault.entries() if e.id == locked_entry.id)
    entry.checkout_until = time.time() - 1
    vault.save()

    reports = locker.sweep_checkouts(vault)

    assert len(reports) == 1 and reports[0].saved
    out = workspace / "again"
    out.mkdir()
    again = locker.unlock_entry(vault, locked_entry.id, str(out))
    assert b"forgotten about" in open(again[0], "rb").read()


def test_edits_are_refused_rather_than_discarded(vault, workspace, locked_entry):
    """save_edits=False is a decision, and it is reported as one."""
    destination = workspace / "desk"
    destination.mkdir()
    written = locker.check_out(vault, locked_entry.id, str(destination),
                               minutes=30)
    with open(written[0], "ab") as fh:
        fh.write(b"\nscratch work I do not want")

    report = locker.check_in(vault, locked_entry.id, save_edits=False)

    assert report.edited == written
    assert not report.saved
    assert report.not_saved_because
    # Nothing is destroyed on the way to throwing it away.
    assert os.path.exists(written[0])
    assert "left where they are" in report.summary()


def test_a_partly_missing_loan_does_not_lock_back_half_of_it(vault, workspace):
    """Locking back a subset would silently drop the rest."""
    folder = workspace / "documents" / "pair"
    folder.mkdir(parents=True)
    (folder / "one.txt").write_bytes(b"first " * 100)
    (folder / "two.txt").write_bytes(b"second " * 100)
    entry = locker.lock_files(
        vault, [str(folder / "one.txt"), str(folder / "two.txt")],
        time.time() + 7200, output_dir=str(workspace / "locked")).entry

    destination = workspace / "desk"
    destination.mkdir()
    written = locker.check_out(vault, entry.id, str(destination), minutes=30)
    with open(written[0], "ab") as fh:
        fh.write(b"\nedited")
    os.unlink(written[1])

    report = locker.check_in(vault, entry.id)

    assert not report.saved
    assert "part of it" in report.not_saved_because
    assert os.path.exists(written[0])


def test_the_relocked_blob_still_opens_and_keeps_its_deadline(vault, workspace,
                                                              locked_entry):
    destination = workspace / "desk"
    destination.mkdir()
    deadline = next(e for e in vault.entries() if e.id == locked_entry.id).expires
    written = locker.check_out(vault, locked_entry.id, str(destination),
                               minutes=30)
    with open(written[0], "wb") as fh:
        fh.write(b"replaced wholesale")
    locker.check_in(vault, locked_entry.id)

    entry = next(e for e in vault.entries() if e.id == locked_entry.id)
    assert entry.expires == deadline
    assert entry.blob_size == os.path.getsize(entry.blob_path)
    assert locker.read_blob_header(entry.blob_path).entry_id_hex == entry.id
    assert vault.chain_report().ok
    out = workspace / "again"
    out.mkdir()
    again = locker.unlock_entry(vault, locked_entry.id, str(out))
    assert open(again[0], "rb").read() == b"replaced wholesale"


def test_locking_edits_back_is_written_into_the_chain(vault, workspace,
                                                     locked_entry):
    destination = workspace / "desk"
    destination.mkdir()
    written = locker.check_out(vault, locked_entry.id, str(destination),
                               minutes=30)
    with open(written[0], "ab") as fh:
        fh.write(b"\nchanged")
    locker.check_in(vault, locked_entry.id)

    kinds = [e.get("kind") for e in vault.events]
    assert "checkout_edits_locked_back" in kinds
    assert vault.chain_report().ok


# --------------------------------------------------------------------------
# the duress passphrase
# --------------------------------------------------------------------------

def test_the_duress_passphrase_does_not_open_the_vault(vault):
    vault.set_duress_passphrase(DURESS)

    with pytest.raises(AuthenticationError):
        Vault.unlock(vault.path, DURESS)


def test_the_duress_passphrase_is_recognised(vault):
    vault.set_duress_passphrase(DURESS)

    assert duress_matches(vault.path, DURESS)
    assert not duress_matches(vault.path, PASSPHRASE)
    assert not duress_matches(vault.path, DURESS[:-1])


def test_no_duress_means_no_match(vault):
    assert not duress_matches(vault.path, DURESS)
    assert not vault.duress_armed


def test_the_real_passphrase_still_works_once_duress_is_armed(vault):
    vault.set_duress_passphrase(DURESS)
    assert Vault.unlock(vault.path, PASSPHRASE) is not None


def test_arming_survives_locking_and_reopening(vault):
    vault.set_duress_passphrase(DURESS)
    assert Vault.unlock(vault.path, PASSPHRASE).duress_armed


def test_the_duress_passphrase_can_be_removed(vault):
    vault.set_duress_passphrase(DURESS)
    vault.clear_duress_passphrase()

    assert not Vault.unlock(vault.path, PASSPHRASE).duress_armed
    assert not duress_matches(vault.path, DURESS)


def test_destroying_the_vault_removes_it_and_its_sidecars(vault, workspace):
    vault.set_background_expiry(True)
    vault.save()
    schedule_file = vault.path + ".schedule"
    assert os.path.exists(schedule_file)

    assert destroy_vault(vault.path)
    assert not os.path.exists(vault.path)
    assert not os.path.exists(schedule_file)


def test_destroying_the_vault_does_not_reach_a_backup(vault, workspace,
                                                      locked_entry):
    """Stated on the screen, and true: duress reaches one file."""
    info = backup.create(vault, str(workspace / "elsewhere.qkvbak"))
    destroy_vault(vault.path)

    assert not os.path.exists(vault.path)
    assert os.path.exists(info.path)
    backup.restore(info, vault.path)
    assert Vault.unlock(vault.path, PASSPHRASE) is not None


def test_a_duress_digest_is_stored_rather_than_the_passphrase(vault):
    vault.set_duress_passphrase(DURESS)
    raw = open(vault.path, "rb").read()

    assert DURESS.encode() not in raw
    assert PASSPHRASE.encode() not in raw


def test_a_folder_handed_to_create_is_taken_as_a_folder(vault, workspace):
    """Handing create() a directory names the file inside it."""
    folder = workspace / "somewhere"
    folder.mkdir()

    info = backup.create(vault, str(folder))

    assert os.path.dirname(info.path) == str(folder)
    assert info.name.endswith(backup.BACKUP_SUFFIX)
    assert backup.describe(info.path) is not None
