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

"""Checking the locked files are still the locked files, and finding them."""

from __future__ import annotations

import os
import shutil
import time

import pytest

from quenchkey import integrity, locker
from quenchkey.crypto import AuthenticationError


def _lock(vault, workspace, name="report.txt", size=400):
    source = workspace / "documents" / name
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_bytes(name.encode() * size)
    return locker.lock_files(vault, [str(source)], time.time() + 7200,
                             output_dir=str(workspace / "locked")).entry


# --------------------------------------------------------------------------
# checking
# --------------------------------------------------------------------------

def test_an_untouched_vault_comes_back_clean(vault, workspace):
    for name in ("one.txt", "two.txt", "three.txt"):
        _lock(vault, workspace, name)

    report = integrity.check(vault)

    assert report.ok
    assert len(report.intact) == 3
    assert "All 3 locked files match" in report.summary()
    assert report.advice() == ""


def test_a_changed_byte_is_caught(vault, workspace):
    entry = _lock(vault, workspace)
    with open(entry.blob_path, "r+b") as fh:
        fh.seek(-1, os.SEEK_END)
        last = fh.read(1)
        fh.seek(-1, os.SEEK_END)
        fh.write(bytes([last[0] ^ 0x01]))

    report = integrity.check(vault)

    assert not report.ok
    assert len(report.changed) == 1
    assert report.changed[0].found != report.changed[0].recorded
    assert "altered" in report.summary()


def test_a_truncated_file_is_caught(vault, workspace):
    entry = _lock(vault, workspace)
    with open(entry.blob_path, "r+b") as fh:
        fh.truncate(os.path.getsize(entry.blob_path) - 32)

    assert integrity.check(vault).changed


def test_a_file_that_is_simply_gone_is_reported_as_missing_not_altered(
        vault, workspace):
    entry = _lock(vault, workspace)
    os.unlink(entry.blob_path)

    report = integrity.check(vault)

    assert len(report.missing) == 1
    assert report.changed == []
    assert "moved" in report.advice()


def test_what_a_changed_file_actually_means_is_stated(vault, workspace):
    """The claim in the advice has to be true, so the test proves it."""
    entry = _lock(vault, workspace)
    out = workspace / "out"
    out.mkdir()
    with open(entry.blob_path, "r+b") as fh:
        fh.seek(200)
        fh.write(b"\x00\x00\x00\x00")

    report = integrity.check(vault)
    assert "refuses it rather than returning wrong data" in report.advice()
    with pytest.raises(AuthenticationError):
        locker.unlock_entry(vault, entry.id, str(out))


def test_the_check_is_recorded_in_the_chain(vault, workspace):
    _lock(vault, workspace)

    integrity.check(vault)

    assert any(e.get("kind") == "integrity_checked" for e in vault.events)
    assert vault.chain_report().ok


def test_the_vault_remembers_when_it_was_last_checked(vault, workspace):
    _lock(vault, workspace)
    assert integrity.last_check(vault) is None

    integrity.check(vault)

    last = integrity.last_check(vault)
    assert last["checked"] == 1 and last["intact"] == 1


def test_an_empty_vault_says_so_rather_than_claiming_success(vault):
    report = integrity.check(vault)

    assert "nothing in this vault" in report.summary()


def test_progress_is_reported_for_a_long_pass(vault, workspace):
    for name in ("a.txt", "b.txt"):
        _lock(vault, workspace, name)
    seen = []

    integrity.check(vault, progress=lambda name, frac: seen.append(frac))

    assert seen and seen[-1] == 1.0


# --------------------------------------------------------------------------
# finding one that moved
# --------------------------------------------------------------------------

def test_a_moved_file_is_found_by_digest_and_relinked(vault, workspace):
    entry = _lock(vault, workspace)
    elsewhere = workspace / "archive" / "subfolder"
    elsewhere.mkdir(parents=True)
    moved = elsewhere / "renamed-by-hand.qkey"
    shutil.move(entry.blob_path, moved)
    assert integrity.check(vault).missing

    found = integrity.search(vault, str(workspace / "archive"))
    assert len(found.matches) == 1
    assert integrity.relink(vault, found.matches) == 1

    report = integrity.check(vault)
    assert report.ok
    assert vault.get(entry.id).blob_path == str(moved)


def test_relinking_keeps_everything_except_the_path(vault, workspace):
    entry = _lock(vault, workspace)
    deadline, opens, digest = entry.expires, entry.open_count, entry.blob_sha256
    elsewhere = workspace / "archive"
    elsewhere.mkdir()
    shutil.move(entry.blob_path, elsewhere / "moved.qkey")

    integrity.relink(vault, integrity.search(vault, str(elsewhere)).matches)

    after = vault.get(entry.id)
    assert after.expires == deadline
    assert after.open_count == opens
    assert after.blob_sha256 == digest
    out = workspace / "out"
    out.mkdir()
    assert locker.unlock_entry(vault, entry.id, str(out))


def test_a_file_with_the_right_name_but_the_wrong_contents_is_not_accepted(
        vault, workspace):
    """The digest decides. A filename is not evidence of anything."""
    entry = _lock(vault, workspace)
    name = os.path.basename(entry.blob_path)
    os.unlink(entry.blob_path)
    decoy_dir = workspace / "decoy"
    decoy_dir.mkdir()
    (decoy_dir / name).write_bytes(b"not the file " * 500)

    found = integrity.search(vault, str(decoy_dir))

    assert found.matches == []
    assert len(found.unfound) == 1
    assert "found none of the missing" in found.summary()


def test_searching_does_not_change_the_vault(vault, workspace):
    """Looking and committing are separate, so the caller can ask first."""
    entry = _lock(vault, workspace)
    elsewhere = workspace / "archive"
    elsewhere.mkdir()
    shutil.move(entry.blob_path, elsewhere / "moved.qkey")

    integrity.search(vault, str(elsewhere))

    assert vault.get(entry.id).blob_path != str(elsewhere / "moved.qkey")


def test_a_search_that_finds_only_some_says_how_many_are_left(vault, workspace):
    first = _lock(vault, workspace, "one.txt")
    second = _lock(vault, workspace, "two.txt", size=700)
    elsewhere = workspace / "archive"
    elsewhere.mkdir()
    shutil.move(first.blob_path, elsewhere / "a.qkey")
    os.unlink(second.blob_path)

    found = integrity.search(vault, str(elsewhere))

    assert len(found.matches) == 1
    assert len(found.unfound) == 1
    assert "1 still unaccounted for" in found.summary()


def test_a_shallow_search_does_not_descend(vault, workspace):
    entry = _lock(vault, workspace)
    deep = workspace / "archive" / "deeper"
    deep.mkdir(parents=True)
    shutil.move(entry.blob_path, deep / "moved.qkey")

    shallow = integrity.search(vault, str(workspace / "archive"), recursive=False)
    deepened = integrity.search(vault, str(workspace / "archive"), recursive=True)

    assert shallow.matches == []
    assert len(deepened.matches) == 1


def test_relinking_is_recorded_in_the_chain(vault, workspace):
    entry = _lock(vault, workspace)
    elsewhere = workspace / "archive"
    elsewhere.mkdir()
    shutil.move(entry.blob_path, elsewhere / "moved.qkey")

    integrity.relink(vault, integrity.search(vault, str(elsewhere)).matches)

    moves = [e for e in vault.events if e.get("kind") == "blob_relinked"]
    assert len(moves) == 1
    assert moves[0]["matched_on"] == "sha256"
    assert vault.chain_report().ok


def test_nothing_missing_means_nothing_to_search_for(vault, workspace):
    _lock(vault, workspace)

    found = integrity.search(vault, str(workspace))

    assert found.scanned == 0
    assert found.matches == []
