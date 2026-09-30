"""Deadlines: what fires, when, and what the clock can and cannot do."""

from __future__ import annotations

import os
import time

import pytest

from quenchkey import expiry, locker
from quenchkey.session import Session
from quenchkey.vault import KeyDestroyed, Vault

from conftest import PASSPHRASE


@pytest.fixture()
def locked(vault, sample_files, workspace):
    """One entry per sample file, at staggered deadlines."""
    entries = []
    for index, path in enumerate(sample_files):
        entries.append(locker.lock_files(
            vault, [path], expires=time.time() + (index + 1) * 60,
            output_dir=str(workspace / "locked")).entry)
    return entries


def test_nothing_expires_before_its_deadline(vault, locked):
    report = expiry.sweep(vault)
    assert report.expired == []
    assert all(not e.key_destroyed for e in vault.entries())


def test_sweep_destroys_only_what_is_due(vault, locked):
    report = expiry.sweep(vault, now=time.time() + 90)
    assert [e.id for e in report.expired] == [locked[0].id]
    assert vault.get(locked[0].id).key_destroyed
    assert not vault.get(locked[1].id).key_destroyed


def test_a_sweep_is_idempotent(vault, locked):
    first = expiry.sweep(vault, now=time.time() + 90)
    second = expiry.sweep(vault, now=time.time() + 90)
    assert len(first.expired) == 1
    assert second.expired == []


def test_entries_with_no_deadline_are_never_swept(vault, sample_files, workspace):
    entry = locker.lock_files(vault, sample_files[:1], expires=None,
                              output_dir=str(workspace / "locked")).entry
    report = expiry.sweep(vault, now=time.time() + 10 ** 6)
    assert report.expired == []
    assert not vault.get(entry.id).key_destroyed


def test_expiry_survives_the_app_not_running(vault, locked):
    """The lazy sweep on unlock is what catches a month of downtime."""
    vault.save()
    vault.lock()

    reopened = Vault.unlock(vault.path, PASSPHRASE)
    report = expiry.sweep(reopened, now=time.time() + 10 * 86400)
    assert len(report.expired) == 3
    reopened.save()
    reopened.lock()

    again = Vault.unlock(vault.path, PASSPHRASE)
    assert all(e.key_destroyed for e in again.entries())


def test_the_blob_survives_unless_asked_otherwise(vault, locked):
    expiry.sweep(vault, now=time.time() + 10 ** 6)
    assert all(os.path.exists(e.blob_path) for e in locked)


def test_the_blob_is_deleted_when_that_was_requested(vault, sample_files, workspace):
    entry = locker.lock_files(vault, sample_files[:1], expires=time.time() + 1,
                              output_dir=str(workspace / "locked"),
                              delete_blob_on_expiry=True).entry
    report = expiry.sweep(vault, now=time.time() + 60)
    assert report.blobs_deleted == [entry.blob_path]
    assert not os.path.exists(entry.blob_path)


def test_expired_files_cannot_be_opened_afterwards(vault, locked, workspace):
    expiry.sweep(vault, now=time.time() + 10 ** 6)
    for entry in locked:
        with pytest.raises(KeyDestroyed):
            locker.unlock_entry(vault, entry.id, str(workspace / "out"))


def test_manual_expiry_is_immediate(vault, locked):
    report = expiry.expire_now(vault, [locked[2].id])
    assert [e.id for e in report.expired] == [locked[2].id]
    assert vault.get(locked[2].id).key_destroyed


# -- the clock ratchet ------------------------------------------------------

def test_winding_the_clock_back_does_not_extend_a_deadline(vault, sample_files,
                                                           workspace, monkeypatch):
    entry = locker.lock_files(vault, sample_files[:1], expires=time.time() + 30,
                              output_dir=str(workspace / "locked")).entry
    # Move forward past the deadline and record the watermark.
    future = time.time() + 3600
    real_time = time.time
    monkeypatch.setattr(time, "time", lambda: future)
    vault.save()
    vault.lock()

    # Now wind the clock back a year and reopen, accepting the warning.
    monkeypatch.setattr(time, "time", lambda: real_time() - 365 * 86400)
    reopened = Vault.unlock(vault.path, PASSPHRASE, accept_clock_rollback=True)

    report = expiry.sweep(reopened)
    assert [e.id for e in report.expired] == [entry.id], \
        "the deadline is judged against the watermark, not the rolled-back clock"


def test_effective_now_never_precedes_the_watermark(vault, monkeypatch):
    vault.save()
    watermark = vault.last_seen
    monkeypatch.setattr(time, "time", lambda: watermark - 10_000)
    assert vault.effective_now() == watermark


# -- presentation -----------------------------------------------------------

def test_urgency_buckets(vault, sample_files, workspace):
    now = time.time()
    entries = [
        locker.lock_files(vault, [sample_files[0]], expires=now + 60,
                          output_dir=str(workspace / "locked")).entry,
        locker.lock_files(vault, [sample_files[1]], expires=now + 5 * 3600,
                          output_dir=str(workspace / "locked")).entry,
        locker.lock_files(vault, [sample_files[2]], expires=now + 40 * 86400,
                          output_dir=str(workspace / "locked")).entry,
    ]
    assert expiry.urgency(entries[0], now) == expiry.URGENCY_CRITICAL_KEY
    assert expiry.urgency(entries[1], now) == expiry.URGENCY_WARNING_KEY
    assert expiry.urgency(entries[2], now) == expiry.URGENCY_CALM

    vault.shred_key(entries[0].id)
    assert expiry.urgency(vault.get(entries[0].id), now) == expiry.URGENCY_EXPIRED


def test_duration_and_size_formatting():
    assert expiry.format_duration(0) == "0s"
    assert expiry.format_duration(65) == "1m 05s"
    assert expiry.format_duration(3 * 86400 + 7200) == "3d 02h 00m"
    assert expiry.format_size(0) == "0 B"
    assert expiry.format_size(1536) == "1.5 KiB"


def test_remaining_text_reflects_state(vault, sample_files, workspace):
    now = time.time()
    entry = locker.lock_files(vault, sample_files[:1], expires=None,
                              output_dir=str(workspace / "locked")).entry
    assert expiry.format_remaining(entry, now) == "no deadline"
    vault.shred_key(entry.id)
    assert expiry.format_remaining(vault.get(entry.id), now) == "key destroyed"


# -- session --------------------------------------------------------------

def test_session_sweep_and_close(vault, locked):
    session = Session(vault, auto_lock_seconds=0)
    assert session.is_open
    report = session.sweep()
    assert report.expired == []
    session.close()
    assert not session.is_open


def test_session_auto_lock_threshold(vault):
    session = Session(vault, auto_lock_seconds=0)
    assert not session.should_auto_lock()
    session.auto_lock_seconds = 1
    session._last_activity -= 5
    assert session.should_auto_lock()
    session.touch()
    assert not session.should_auto_lock()
