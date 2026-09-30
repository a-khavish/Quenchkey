"""The background sweeper, and the exact limits of what it can do.

The point of these is less that the sweeper works and more that it stays
inside its box: it opens nothing, it learns nothing it was not explicitly
given, and it never claims to have destroyed a key.
"""

from __future__ import annotations

import json
import os
import time

import pytest

from quenchkey import locker, schedule
from quenchkey.session import Session
from quenchkey.vault import Vault

from conftest import PASSPHRASE


@pytest.fixture()
def locked(vault, workspace):
    """A vault opted in to background expiry, with one short-lived entry."""
    vault.set_background_expiry(True)
    source = workspace / "documents" / "notes.txt"
    source.write_bytes(b"something worth a deadline" * 40)
    result = locker.lock_files(vault, [str(source)], time.time() + 3600,
                               output_dir=str(workspace / "locked"),
                               delete_blob_on_expiry=True)
    vault.save()
    return vault, result.entry


# -- what it is given -------------------------------------------------------

def test_no_index_exists_until_it_is_switched_on(vault, workspace):
    source = workspace / "documents" / "notes.txt"
    source.write_bytes(b"x" * 100)
    locker.lock_files(vault, [str(source)], time.time() + 3600,
                      output_dir=str(workspace / "locked"))
    vault.save()

    assert schedule.read_index(vault.path) is None
    assert not os.path.exists(schedule.index_path(vault.path))


def test_switching_it_off_takes_the_index_away(locked):
    vault, _entry = locked
    assert os.path.exists(schedule.index_path(vault.path))

    vault.set_background_expiry(False)
    assert not os.path.exists(schedule.index_path(vault.path))
    assert schedule.read_index(vault.path) is None


def test_the_index_is_readable_only_by_its_owner(locked):
    vault, _entry = locked
    mode = os.stat(schedule.index_path(vault.path)).st_mode & 0o777
    assert mode == 0o600


def test_the_index_carries_no_key_and_no_content(locked):
    """It is metadata in the clear, so what is in it matters."""
    vault, entry = locked
    raw = open(schedule.index_path(vault.path)).read()
    document = json.loads(raw)

    assert set(document["entries"][0]) == {"id", "deadline", "blob_path",
                                           "delete_blob"}
    assert entry.key.bytes().hex() not in raw
    assert PASSPHRASE not in raw
    # Nor the names of what was locked.
    for name in entry.names:
        assert name not in raw


def test_an_entry_with_no_deadline_is_not_listed(vault, workspace):
    """Nothing is given away about items the sweeper has no business in."""
    vault.set_background_expiry(True)
    source = workspace / "documents" / "forever.txt"
    source.write_bytes(b"y" * 100)
    locker.lock_files(vault, [str(source)], None,
                      output_dir=str(workspace / "locked"))
    vault.save()

    assert schedule.read_index(vault.path) == []


# -- what it does -----------------------------------------------------------

def test_a_deadline_that_has_not_passed_is_left_alone(locked):
    vault, entry = locked
    report = schedule.sweep(vault.path)

    assert report.due == []
    assert os.path.exists(entry.blob_path)
    assert schedule.read_pending(vault.path) == {}


def test_a_passed_deadline_deletes_the_file(locked):
    vault, entry = locked
    report = schedule.sweep(vault.path, now=time.time() + 7200)

    assert report.due == [entry.id]
    assert report.deleted == [entry.blob_path]
    assert not os.path.exists(entry.blob_path)


def test_a_file_is_kept_when_the_entry_did_not_ask_for_deletion(vault, workspace):
    vault.set_background_expiry(True)
    source = workspace / "documents" / "keep.txt"
    source.write_bytes(b"z" * 100)
    result = locker.lock_files(vault, [str(source)], time.time() + 60,
                               output_dir=str(workspace / "locked"),
                               delete_blob_on_expiry=False)
    vault.save()

    report = schedule.sweep(vault.path, now=time.time() + 3600)
    assert report.due == [result.entry.id]
    assert report.deleted == []
    assert os.path.exists(result.entry.blob_path)


def test_the_sweeper_never_touches_the_vault(locked):
    """It has no passphrase, so the vault must come through untouched."""
    vault, _entry = locked
    before = open(vault.path, "rb").read()

    schedule.sweep(vault.path, now=time.time() + 7200)

    assert open(vault.path, "rb").read() == before


def test_a_missing_file_is_recorded_rather_than_raised(locked):
    vault, entry = locked
    os.unlink(entry.blob_path)

    report = schedule.sweep(vault.path, now=time.time() + 7200)
    assert report.missing == [entry.blob_path]
    assert report.failed == []


def test_sweeping_twice_is_harmless(locked):
    vault, _entry = locked
    first = schedule.sweep(vault.path, now=time.time() + 7200)
    second = schedule.sweep(vault.path, now=time.time() + 7200)

    assert first.deleted and second.deleted == []
    assert second.missing


# -- handing back to the application ----------------------------------------

def expire_now(vault, entry):
    """Move a deadline into the past and write that to the vault."""
    entry.expires = time.time() - 30
    vault.save()


def test_the_key_is_destroyed_at_the_next_unlock(locked):
    """The sweeper can only delete the file. The key waits for the vault."""
    vault, entry = locked
    expire_now(vault, entry)

    report = schedule.sweep(vault.path)
    assert report.due == [entry.id]
    assert not os.path.exists(entry.blob_path)

    def lookup(opened):
        return next(e for e in opened.entries() if e.id == entry.id)

    # The key is still sitting in the vault: nothing could write to it.
    reopened = Vault.unlock(vault.path, PASSPHRASE)
    assert not lookup(reopened).key_destroyed

    # ... until the application sweeps, which is the first chance it had.
    report = Session(reopened).sweep()

    assert entry.id in {e.id for e in report.expired}
    assert lookup(reopened).key_destroyed
    assert report.swept_in_background == [entry.id]


def test_the_pending_list_is_cleared_once_it_has_been_acted_on(locked):
    vault, entry = locked
    expire_now(vault, entry)
    schedule.sweep(vault.path)
    assert schedule.read_pending(vault.path)

    Session(Vault.unlock(vault.path, PASSPHRASE)).sweep()
    assert schedule.read_pending(vault.path) == {}
    assert not os.path.exists(schedule.pending_path(vault.path))


def test_pending_ids_accumulate_rather_than_replace(vault):
    schedule.record_pending(vault.path, ["aaa"])
    schedule.record_pending(vault.path, ["bbb"])

    assert set(schedule.read_pending(vault.path)) == {"aaa", "bbb"}


def test_a_corrupt_index_is_ignored_rather_than_fatal(locked):
    vault, _entry = locked
    with open(schedule.index_path(vault.path), "w") as fh:
        fh.write("{not json at all")

    assert schedule.read_index(vault.path) is None
    assert schedule.sweep(vault.path).checked == 0


def test_an_index_from_a_future_version_is_ignored(locked):
    vault, _entry = locked
    path = schedule.index_path(vault.path)
    document = json.load(open(path))
    document["version"] = schedule.INDEX_VERSION + 99
    json.dump(document, open(path, "w"))

    assert schedule.read_index(vault.path) is None
