"""Shared files: the ones that carry their own key, and therefore never expire.

Two things are being checked here. That the container is sound — the wrapped
key is bound to its file and cannot be moved, edited or stripped — and that
nothing anywhere pretends a shared file has a deadline.
"""

from __future__ import annotations

import os

import pytest

from quenchkey import locker
from quenchkey.crypto import AuthenticationError, UnsupportedFormat

SHARE_PASSPHRASE = "ephemeral-lantern-above-the-quay"


@pytest.fixture()
def sources(workspace):
    first = workspace / "documents" / "contract.pdf"
    first.write_bytes(b"CONTRACT " * 4000)
    second = workspace / "documents" / "notes.txt"
    second.write_bytes(b"notes\n" * 200)
    return [str(first), str(second)]


@pytest.fixture()
def shared(sources, workspace, fast_kdf):
    return locker.lock_to_share(sources, SHARE_PASSPHRASE,
                                output_dir=str(workspace / "locked"),
                                kdf_params=fast_kdf)


def corrupt(path: str, offset: int) -> None:
    with open(path, "r+b") as fh:
        fh.seek(offset)
        byte = fh.read(1)
        fh.seek(offset)
        fh.write(bytes([byte[0] ^ 0x40]))


# -- the round trip ---------------------------------------------------------

def test_a_shared_file_opens_with_its_own_passphrase(shared, sources, workspace):
    destination = workspace / "out"
    destination.mkdir()
    written = locker.open_shared(shared.path, SHARE_PASSPHRASE, str(destination))

    assert sorted(os.path.basename(p) for p in written) == ["contract.pdf", "notes.txt"]
    assert (destination / "contract.pdf").read_bytes() == b"CONTRACT " * 4000


def test_no_vault_is_involved_anywhere(shared, workspace):
    """The whole point: it opens on a machine that has never seen a vault."""
    destination = workspace / "out"
    destination.mkdir()
    locker.open_shared(shared.path, SHARE_PASSPHRASE, str(destination))

    assert not list(workspace.glob("**/*.qkv"))


def test_the_wrong_passphrase_is_refused(shared, workspace):
    with pytest.raises(AuthenticationError):
        locker.open_shared(shared.path, "not the passphrase", str(workspace))


def test_two_shared_files_never_share_a_key(sources, workspace, fast_kdf):
    """Same passphrase, same files — the file keys must still differ."""
    one = locker.lock_to_share(sources, SHARE_PASSPHRASE, kdf_params=fast_kdf,
                               output_path=str(workspace / "one.qkey"))
    two = locker.lock_to_share(sources, SHARE_PASSPHRASE, kdf_params=fast_kdf,
                               output_path=str(workspace / "two.qkey"))

    first = locker.read_share_block(one.path)
    second = locker.read_share_block(two.path)
    assert first.wrapped_key != second.wrapped_key
    assert first.kdf.salt != second.kdf.salt
    assert open(one.path, "rb").read() != open(two.path, "rb").read()


# -- it says what it is -----------------------------------------------------

def test_the_header_declares_itself_without_a_passphrase(shared):
    """Any tool can tell the two kinds apart before asking for anything."""
    header = locker.read_blob_header(shared.path)
    assert header.self_contained
    assert header.flags & locker.FLAG_SELF_CONTAINED


def test_a_vault_file_does_not_claim_to_be_self_contained(vault, sources, workspace):
    import time
    result = locker.lock_files(vault, sources, time.time() + 3600,
                               output_dir=str(workspace / "locked"))
    assert not locker.read_blob_header(result.entry.blob_path).self_contained


def test_a_vault_file_cannot_be_opened_as_a_shared_one(vault, sources, workspace):
    import time
    result = locker.lock_files(vault, sources, time.time() + 3600,
                               output_dir=str(workspace / "locked"))
    with pytest.raises(UnsupportedFormat):
        locker.open_shared(result.entry.blob_path, SHARE_PASSPHRASE, str(workspace))


def test_a_shared_file_is_not_readable_by_the_vault_path(shared, workspace):
    """No vault holds a key for it, and the vault reader is not a way in."""
    from quenchkey.crypto import SecretBytes

    with pytest.raises(AuthenticationError):
        locker.decrypt_stream(shared.path, str(workspace / "x"),
                              SecretBytes.random())


# -- the key block is bound to its file -------------------------------------

def test_editing_the_wrapped_key_is_caught(shared, workspace):
    corrupt(shared.path, locker.BLOB_HEADER_LEN + locker.SHARE_PREFIX_LEN + 4)
    with pytest.raises(AuthenticationError):
        locker.open_shared(shared.path, SHARE_PASSPHRASE, str(workspace))


def test_editing_the_salt_is_caught(shared, workspace):
    corrupt(shared.path, locker.BLOB_HEADER_LEN + 6)
    with pytest.raises(AuthenticationError):
        locker.open_shared(shared.path, SHARE_PASSPHRASE, str(workspace))


def test_editing_the_derivation_cost_is_caught(shared, workspace):
    # time_cost sits straight after the 16-byte salt.
    corrupt(shared.path, locker.BLOB_HEADER_LEN + 4 + 16 + 3)
    with pytest.raises((AuthenticationError, UnsupportedFormat)):
        locker.open_shared(shared.path, SHARE_PASSPHRASE, str(workspace))


def test_a_key_block_cannot_be_moved_to_another_file(sources, workspace, fast_kdf):
    """Whoever knows one passphrase must not thereby open the other file."""
    one = locker.lock_to_share(sources, SHARE_PASSPHRASE, kdf_params=fast_kdf,
                               output_path=str(workspace / "one.qkey"))
    two = locker.lock_to_share(sources, "a completely different passphrase",
                               kdf_params=fast_kdf,
                               output_path=str(workspace / "two.qkey"))

    start = locker.BLOB_HEADER_LEN
    end = start + locker.SHARE_BLOCK_LEN
    stolen = open(one.path, "rb").read()[start:end]
    body = bytearray(open(two.path, "rb").read())
    body[start:end] = stolen
    hybrid = workspace / "hybrid.qkey"
    hybrid.write_bytes(bytes(body))

    with pytest.raises(AuthenticationError):
        locker.open_shared(str(hybrid), SHARE_PASSPHRASE, str(workspace))


def test_stripping_the_key_block_is_caught(shared, workspace):
    raw = open(shared.path, "rb").read()
    stripped = raw[:locker.BLOB_HEADER_LEN] + raw[locker.BLOB_HEADER_LEN
                                                  + locker.SHARE_BLOCK_LEN:]
    target = workspace / "stripped.qkey"
    target.write_bytes(stripped)

    with pytest.raises((AuthenticationError, UnsupportedFormat)):
        locker.open_shared(str(target), SHARE_PASSPHRASE, str(workspace))


def test_clearing_the_flag_does_not_turn_it_into_a_vault_file(shared, workspace):
    raw = bytearray(open(shared.path, "rb").read())
    raw[10:12] = b"\x00\x00"          # the flags field
    target = workspace / "reflagged.qkey"
    target.write_bytes(bytes(raw))

    with pytest.raises(UnsupportedFormat):
        locker.open_shared(str(target), SHARE_PASSPHRASE, str(workspace))


def test_appending_to_a_shared_file_is_caught(shared, workspace):
    with open(shared.path, "ab") as fh:
        fh.write(b"extra")
    with pytest.raises(AuthenticationError):
        locker.open_shared(shared.path, SHARE_PASSPHRASE, str(workspace))


def test_an_absurd_derivation_cost_is_refused_before_it_is_used(shared, workspace):
    """A doctored header must not be able to ask for terabytes of memory."""
    raw = bytearray(open(shared.path, "rb").read())
    memory_at = locker.BLOB_HEADER_LEN + 4 + 16 + 4
    raw[memory_at:memory_at + 4] = (0xFFFFFFFF).to_bytes(4, "big")
    target = workspace / "greedy.qkey"
    target.write_bytes(bytes(raw))

    with pytest.raises(UnsupportedFormat):
        locker.open_shared(str(target), SHARE_PASSPHRASE, str(workspace))


def test_a_shared_file_needs_a_passphrase(sources, workspace, fast_kdf):
    with pytest.raises(locker.LockError):
        locker.lock_to_share(sources, "", output_dir=str(workspace),
                             kdf_params=fast_kdf)


# --------------------------------------------------------------------------
# the vault's record of what went out
# --------------------------------------------------------------------------

def test_a_shared_file_is_recorded_without_a_key(vault, shared):
    record = vault.record_shared(shared.path, shared.names, shared.size,
                                 shared.plaintext_size, shared.sha256)

    assert record in vault.shared_records()
    assert "key" not in record
    assert set(record) == {"id", "path", "names", "size", "plaintext_size",
                           "sha256", "note", "created"}


def test_a_shared_record_is_not_an_entry(vault, shared):
    """It must never reach code that assumes a key and a deadline."""
    vault.record_shared(shared.path, shared.names, shared.size,
                        shared.plaintext_size, shared.sha256)

    assert vault.entries() == []
    assert len(vault.shared_records()) == 1


def test_forgetting_a_record_leaves_the_file_working(vault, shared, workspace):
    record = vault.record_shared(shared.path, shared.names, shared.size,
                                 shared.plaintext_size, shared.sha256)
    assert vault.forget_shared(record["id"]) is True
    assert vault.shared_records() == []

    destination = workspace / "still-opens"
    destination.mkdir()
    assert locker.open_shared(shared.path, SHARE_PASSPHRASE, str(destination))


def test_records_survive_locking_and_reopening(vault, shared):
    from quenchkey.vault import Vault
    vault.record_shared(shared.path, shared.names, shared.size,
                        shared.plaintext_size, shared.sha256)

    reopened = Vault.unlock(vault.path, "nine-copper-lanterns-above-the-quay")
    assert len(reopened.shared_records()) == 1
    assert reopened.shared_records()[0]["names"] == shared.names


def test_creating_one_is_written_to_the_event_chain(vault, shared):
    vault.record_shared(shared.path, shared.names, shared.size,
                        shared.plaintext_size, shared.sha256)
    kinds = [event["kind"] for event in vault.events]

    assert "shared_file_created" in kinds
    assert vault.chain_report().ok


# --------------------------------------------------------------------------
# unlocking, several at a time
# --------------------------------------------------------------------------

@pytest.fixture()
def bundle(workspace, fast_kdf):
    """One shared file holding a single document, one holding three."""
    folder = workspace / "inbox"
    folder.mkdir()
    single_source = folder / "figures.bin"
    single_source.write_bytes(b"\x01\x02" * 900)
    many = []
    for name in ("notes.txt", "sheet.csv", "photo.jpg"):
        path = folder / name
        path.write_bytes(name.encode() * 120)
        many.append(str(path))

    one = locker.lock_to_share([str(single_source)], SHARE_PASSPHRASE,
                               output_path=str(folder / "single.qkey"),
                               kdf_params=fast_kdf)
    several = locker.lock_to_share(many, SHARE_PASSPHRASE,
                                   output_path=str(folder / "bundle.qkey"),
                                   kdf_params=fast_kdf)
    return folder, one, several


def test_one_passphrase_opens_several_files(bundle):
    folder, one, several = bundle
    outcomes = locker.unlock_shared_files([one.path, several.path],
                                          SHARE_PASSPHRASE)

    assert [o.ok for o in outcomes] == [True, True]
    assert all(o.reason == "" for o in outcomes)


def test_everything_lands_beside_the_locked_file(bundle):
    """Opening a file is not a reason to move somebody's documents."""
    folder, one, several = bundle
    outcomes = locker.unlock_shared_files([one.path, several.path],
                                          SHARE_PASSPHRASE)

    for outcome in outcomes:
        assert os.path.dirname(outcome.destination) == str(folder)
        for written in outcome.written:
            assert str(folder) in written


def test_a_single_document_comes_out_as_a_single_file(bundle):
    folder, one, _several = bundle
    outcome = locker.unlock_shared_file(one.path, SHARE_PASSPHRASE)

    assert os.path.isfile(outcome.destination)
    assert os.path.basename(outcome.destination) == \
        f"figures{locker.UNLOCKED_SUFFIX}.bin"
    assert (folder / f"figures{locker.UNLOCKED_SUFFIX}.bin").read_bytes() == \
        b"\x01\x02" * 900


def test_several_documents_come_out_in_a_folder(bundle):
    """Rather than scattering a dozen files across somebody's Documents."""
    folder, _one, several = bundle
    outcome = locker.unlock_shared_file(several.path, SHARE_PASSPHRASE)

    assert os.path.isdir(outcome.destination)
    assert os.path.basename(outcome.destination) == \
        f"bundle{locker.UNLOCKED_SUFFIX}"
    assert sorted(os.path.basename(p) for p in outcome.written) == \
        ["notes.txt", "photo.jpg", "sheet.csv"]


def test_unlocking_twice_never_overwrites(bundle):
    folder, one, _several = bundle
    first = locker.unlock_shared_file(one.path, SHARE_PASSPHRASE)
    second = locker.unlock_shared_file(one.path, SHARE_PASSPHRASE)

    assert first.destination != second.destination
    assert os.path.exists(first.destination)
    assert "(2)" in os.path.basename(second.destination)


def test_a_wrong_passphrase_stops_only_its_own_file(bundle, workspace, fast_kdf):
    """Nine files must not fail because the tenth had a different passphrase."""
    folder, one, several = bundle
    odd_source = folder / "elsewhere.txt"
    odd_source.write_text("locked with something else")
    odd = locker.lock_to_share([str(odd_source)], "a completely different one",
                               output_path=str(folder / "odd.qkey"),
                               kdf_params=fast_kdf)

    outcomes = locker.unlock_shared_files(
        [one.path, odd.path, several.path], SHARE_PASSPHRASE)

    assert [o.ok for o in outcomes] == [True, False, True]
    assert "wrong passphrase" in outcomes[1].reason
    assert outcomes[1].written == []


def test_a_missing_file_is_reported_not_raised(bundle):
    folder, one, _several = bundle
    outcomes = locker.unlock_shared_files(
        [str(folder / "never-existed.qkey"), one.path], SHARE_PASSPHRASE)

    assert outcomes[0].ok is False
    assert outcomes[0].reason
    assert outcomes[1].ok is True


def test_a_vault_file_in_the_batch_is_reported(vault, bundle, workspace):
    """It has no key inside it, and says so rather than failing obscurely."""
    import time
    folder, one, _several = bundle
    source = workspace / "documents" / "in-the-vault.txt"
    source.write_bytes(b"vault" * 100)
    entry = locker.lock_files(vault, [str(source)], time.time() + 3600,
                              output_dir=str(folder)).entry

    outcomes = locker.unlock_shared_files([entry.blob_path, one.path],
                                          SHARE_PASSPHRASE)
    assert outcomes[0].ok is False
    assert "vault" in outcomes[0].reason
    assert outcomes[1].ok is True


# -- the password-free archive ---------------------------------------------

def test_the_archive_option_produces_something_with_no_password(bundle):
    py7zr = pytest.importorskip("py7zr")
    folder, _one, several = bundle
    outcome = locker.unlock_shared_file(several.path, SHARE_PASSPHRASE,
                                        mode=locker.MODE_ARCHIVE)

    assert outcome.destination.endswith(f"{locker.UNLOCKED_SUFFIX}.7z")
    with py7zr.SevenZipFile(outcome.destination, "r") as sz:
        assert sorted(sz.getnames()) == ["notes.txt", "photo.jpg", "sheet.csv"]


def test_the_archive_lands_beside_the_locked_file_too(bundle):
    folder, _one, several = bundle
    outcome = locker.unlock_shared_file(several.path, SHARE_PASSPHRASE,
                                        mode=locker.MODE_ARCHIVE)
    assert os.path.dirname(outcome.destination) == str(folder)


# -- keeping or removing the locked copy ------------------------------------

def test_the_locked_file_is_kept_by_default(bundle):
    folder, one, _several = bundle
    outcome = locker.unlock_shared_file(one.path, SHARE_PASSPHRASE)

    assert outcome.removed_locked is False
    assert os.path.exists(one.path)


def test_the_locked_file_can_be_removed_once_its_contents_are_out(bundle):
    folder, one, _several = bundle
    outcome = locker.unlock_shared_file(one.path, SHARE_PASSPHRASE,
                                        keep_locked=False)

    assert outcome.ok and outcome.removed_locked
    assert not os.path.exists(one.path)
    assert os.path.exists(outcome.destination)


def test_a_failed_unlock_never_removes_the_locked_file(bundle):
    """The one case where deleting it would lose the contents for good."""
    folder, one, _several = bundle
    outcome = locker.unlock_shared_file(one.path, "the wrong passphrase",
                                        keep_locked=False)

    assert outcome.ok is False
    assert outcome.removed_locked is False
    assert os.path.exists(one.path)


@pytest.mark.parametrize("which,expected", [
    ("one", f"figures{locker.UNLOCKED_SUFFIX}.bin"),
    ("several", f"bundle{locker.UNLOCKED_SUFFIX}"),
])
def test_nothing_is_left_behind_in_the_folder(bundle, which, expected):
    """No staging directories, no partial files, whichever shape came out.

    A single document is moved out of its staging directory rather than the
    directory being moved into place, so the two cases clean up by different
    routes and both have to be checked.
    """
    folder, one, several = bundle
    target = one if which == "one" else several
    before = {p.name for p in folder.iterdir()}

    outcome = locker.unlock_shared_file(target.path, SHARE_PASSPHRASE)

    assert outcome.ok
    added = {p.name for p in folder.iterdir()} - before
    assert added == {expected}, f"left behind: {added - {expected}}"


def test_a_failed_unlock_leaves_the_folder_exactly_as_it_was(bundle):
    folder, one, _several = bundle
    before = {p.name for p in folder.iterdir()}

    locker.unlock_shared_file(one.path, "the wrong passphrase")

    assert {p.name for p in folder.iterdir()} == before


def test_the_archive_mode_leaves_nothing_behind_either(bundle):
    folder, _one, several = bundle
    before = {p.name for p in folder.iterdir()}

    outcome = locker.unlock_shared_file(several.path, SHARE_PASSPHRASE,
                                        mode=locker.MODE_ARCHIVE)

    assert {p.name for p in folder.iterdir()} - before == {
        os.path.basename(outcome.destination)}
