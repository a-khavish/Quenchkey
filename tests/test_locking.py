"""Locking files, opening them again, and what happens once the key is gone."""

from __future__ import annotations

import os
import time

import pytest

from quenchkey import archive, crypto, locker
from quenchkey.crypto import AuthenticationError, SecretBytes, UnsupportedFormat
from quenchkey.locker import BLOB_HEADER_LEN, BlobMismatch
from quenchkey.vault import KeyDestroyed, Vault

from conftest import PASSPHRASE


def contents(paths):
    return {os.path.basename(p): open(p, "rb").read() for p in paths}


# -- round trip -------------------------------------------------------------

def test_lock_then_unlock_returns_identical_bytes(vault, sample_files, workspace):
    before = contents(sample_files)
    result = locker.lock_files(vault, sample_files, expires=None,
                               output_dir=str(workspace / "locked"))
    destination = str(workspace / "out")
    written = locker.unlock_entry(vault, result.entry.id, destination)
    assert contents(written) == before


def test_selection_order_is_preserved(vault, sample_files, workspace):
    """The files were deliberately named out of alphabetical order."""
    assert [os.path.basename(p) for p in sample_files] == \
        ["zebra.txt", "alpha.bin", "middle.md"]

    result = locker.lock_files(vault, sample_files, expires=None,
                               output_dir=str(workspace / "locked"))
    assert result.entry.names == ["zebra.txt", "alpha.bin", "middle.md"]

    written = locker.unlock_entry(vault, result.entry.id, str(workspace / "out"))
    assert [os.path.basename(p) for p in written] == \
        ["zebra.txt", "alpha.bin", "middle.md"]


def test_folders_are_walked_and_flattened_under_their_own_name(vault, workspace):
    folder = workspace / "documents" / "survey"
    (folder / "inner").mkdir(parents=True)
    (folder / "a.txt").write_text("a")
    (folder / "inner" / "b.txt").write_text("b")

    result = locker.lock_files(vault, [str(folder)], expires=None,
                               output_dir=str(workspace / "locked"))
    assert set(result.entry.names) == {"survey/a.txt", "survey/inner/b.txt"}

    written = locker.unlock_entry(vault, result.entry.id, str(workspace / "out"))
    assert len(written) == 2


def test_duplicate_basenames_are_disambiguated(vault, workspace):
    first = workspace / "documents" / "one"
    second = workspace / "documents" / "two"
    first.mkdir()
    second.mkdir()
    (first / "report.pdf").write_text("first")
    (second / "report.pdf").write_text("second")

    result = locker.lock_files(vault, [str(first / "report.pdf"),
                                       str(second / "report.pdf")],
                               expires=None, output_dir=str(workspace / "locked"))
    assert len(set(result.entry.names)) == 2

    written = locker.unlock_entry(vault, result.entry.id, str(workspace / "out"))
    assert {open(p).read() for p in written} == {"first", "second"}


def test_multi_chunk_file_round_trips(vault, workspace):
    """Larger than one chunk, and not a whole number of chunks."""
    big = workspace / "documents" / "big.bin"
    payload = os.urandom(int(crypto.CHUNK_SIZE * 2.5))
    big.write_bytes(payload)

    result = locker.lock_files(vault, [str(big)], expires=None,
                               output_dir=str(workspace / "locked"))
    written = locker.unlock_entry(vault, result.entry.id, str(workspace / "out"))
    assert open(written[0], "rb").read() == payload


def test_empty_file_round_trips(vault, workspace):
    empty = workspace / "documents" / "empty.txt"
    empty.write_bytes(b"")
    result = locker.lock_files(vault, [str(empty)], expires=None,
                               output_dir=str(workspace / "locked"))
    written = locker.unlock_entry(vault, result.entry.id, str(workspace / "out"))
    assert open(written[0], "rb").read() == b""


# -- the key is not in the output file --------------------------------------

def test_the_key_is_nowhere_in_the_locked_file(vault, sample_files, workspace):
    result = locker.lock_files(vault, sample_files, expires=None,
                               output_dir=str(workspace / "locked"))
    key = vault.key_for(result.entry.id).bytes()
    blob = open(result.blob_path, "rb").read()
    assert key not in blob
    # Nor is it recoverable from the archive password derived from it.
    assert archive.archive_password(SecretBytes(key)).encode() not in blob


def test_locked_file_leaks_no_filenames(vault, workspace):
    named = workspace / "documents" / "acquisition-memo.docx"
    named.write_bytes(os.urandom(5000))
    result = locker.lock_files(vault, [str(named)], expires=None,
                               output_dir=str(workspace / "locked"))
    blob = open(result.blob_path, "rb").read()
    assert b"acquisition-memo" not in blob


def test_header_is_readable_without_any_key(vault, sample_files, workspace):
    result = locker.lock_files(vault, sample_files, expires=None,
                               output_dir=str(workspace / "locked"))
    described = locker.inspect_blob(result.blob_path)
    assert described["entry_id"] == result.entry.id
    assert described["cipher"] == "ChaCha20-Poly1305"


def test_no_staging_files_are_left_behind(vault, sample_files, workspace):
    locker.lock_files(vault, sample_files, expires=None,
                      output_dir=str(workspace / "locked"))
    leftovers = [n for n in os.listdir(workspace / "locked") if "staging" in n]
    assert leftovers == []


# -- expiry -----------------------------------------------------------------

def test_expired_entry_cannot_be_opened(vault, sample_files, workspace):
    result = locker.lock_files(vault, sample_files, expires=time.time() + 600,
                               output_dir=str(workspace / "locked"))
    vault.shred_key(result.entry.id)
    vault.save()

    assert os.path.exists(result.blob_path), "the encrypted file is still there"
    with pytest.raises(KeyDestroyed):
        locker.unlock_entry(vault, result.entry.id, str(workspace / "out"))


def test_an_expired_blob_resists_every_other_key(vault, sample_files, workspace):
    """The point of the product: no key, no way in — for anyone."""
    result = locker.lock_files(vault, sample_files, expires=None,
                               output_dir=str(workspace / "locked"))
    vault.shred_key(result.entry.id)
    vault.save()

    for candidate in [SecretBytes.zeros(), SecretBytes.random(), SecretBytes.random()]:
        with pytest.raises(AuthenticationError):
            locker.decrypt_stream(result.blob_path,
                                  str(workspace / "attempt.bin"), candidate)


# -- tampering with the locked file -----------------------------------------

@pytest.mark.parametrize("offset,description", [
    (8, "format version"),
    (9, "cipher id"),
    (12, "entry id"),
    (28, "nonce prefix"),
    (32, "chunk size"),
    (36, "plaintext length"),
    (BLOB_HEADER_LEN + 3, "ciphertext"),
])
def test_a_flipped_byte_in_the_locked_file_is_caught(vault, sample_files,
                                                     workspace, offset, description):
    result = locker.lock_files(vault, sample_files, expires=None,
                               output_dir=str(workspace / "locked"))
    data = bytearray(open(result.blob_path, "rb").read())
    data[offset] ^= 0x01
    open(result.blob_path, "wb").write(bytes(data))

    with pytest.raises((AuthenticationError, UnsupportedFormat, BlobMismatch)):
        locker.unlock_entry(vault, result.entry.id, str(workspace / "out"))


def test_an_inflated_length_header_is_caught_before_any_allocation(vault,
                                                                   sample_files,
                                                                   workspace):
    """A header claiming petabytes must be refused, not acted on."""
    result = locker.lock_files(vault, sample_files, expires=None,
                               output_dir=str(workspace / "locked"))
    data = bytearray(open(result.blob_path, "rb").read())
    data[36:44] = (2 ** 50).to_bytes(8, "big")
    open(result.blob_path, "wb").write(bytes(data))
    with pytest.raises(AuthenticationError):
        locker.unlock_entry(vault, result.entry.id, str(workspace / "out"))


def test_truncated_locked_file_is_caught(vault, sample_files, workspace):
    result = locker.lock_files(vault, sample_files, expires=None,
                               output_dir=str(workspace / "locked"))
    data = open(result.blob_path, "rb").read()
    open(result.blob_path, "wb").write(data[:-32])
    with pytest.raises(AuthenticationError):
        locker.unlock_entry(vault, result.entry.id, str(workspace / "out"))


def test_appended_data_is_caught(vault, sample_files, workspace):
    result = locker.lock_files(vault, sample_files, expires=None,
                               output_dir=str(workspace / "locked"))
    with open(result.blob_path, "ab") as fh:
        fh.write(b"appended")
    with pytest.raises(AuthenticationError):
        locker.unlock_entry(vault, result.entry.id, str(workspace / "out"))


def test_chunks_cannot_be_reordered(vault, workspace):
    """Swapping two whole chunks must break authentication."""
    big = workspace / "documents" / "big.bin"
    big.write_bytes(os.urandom(crypto.CHUNK_SIZE * 3))
    result = locker.lock_files(vault, [str(big)], expires=None,
                               output_dir=str(workspace / "locked"))

    sealed = crypto.CHUNK_SIZE + crypto.TAG_SIZE
    data = bytearray(open(result.blob_path, "rb").read())
    start = BLOB_HEADER_LEN
    first = bytes(data[start:start + sealed])
    second = bytes(data[start + sealed:start + 2 * sealed])
    data[start:start + sealed] = second
    data[start + sealed:start + 2 * sealed] = first
    open(result.blob_path, "wb").write(bytes(data))

    with pytest.raises(AuthenticationError):
        locker.unlock_entry(vault, result.entry.id, str(workspace / "out"))


def test_a_blob_from_another_entry_is_rejected(vault, sample_files, workspace):
    first = locker.lock_files(vault, sample_files[:1], expires=None,
                              output_dir=str(workspace / "locked"))
    second = locker.lock_files(vault, sample_files[1:], expires=None,
                               output_dir=str(workspace / "locked"))
    # Point the first entry at the second entry's file.
    vault.get(first.entry.id).blob_path = second.blob_path
    with pytest.raises(BlobMismatch):
        locker.unlock_entry(vault, first.entry.id, str(workspace / "out"))


def test_a_blob_from_a_different_vault_cannot_be_opened(workspace, fast_kdf,
                                                        sample_files):
    """Two vaults, same passphrase, different random file keys."""
    one = Vault.create(str(workspace / "one.vk"), PASSPHRASE, kdf_params=fast_kdf)
    two = Vault.create(str(workspace / "two.vk"), PASSPHRASE, kdf_params=fast_kdf)
    result = locker.lock_files(one, sample_files, expires=None,
                               output_dir=str(workspace / "locked"))
    with pytest.raises(AuthenticationError):
        locker.decrypt_stream(result.blob_path, str(workspace / "x.bin"),
                              SecretBytes.random())
    assert result.entry.id not in {e.id for e in two.entries()}


# -- originals --------------------------------------------------------------

def test_shredding_originals_removes_them(vault, sample_files, workspace):
    locker.lock_files(vault, sample_files, expires=None,
                      output_dir=str(workspace / "locked"), delete_originals=True)
    assert not any(os.path.exists(path) for path in sample_files)


def test_a_failed_lock_leaves_no_entry_and_no_blob(vault, workspace, monkeypatch):
    target = workspace / "documents" / "doomed.txt"
    target.write_text("content")
    blob_path = str(workspace / "locked" / "doomed.qkey")

    def explode(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(locker, "encrypt_stream", explode)
    with pytest.raises(OSError):
        locker.lock_files(vault, [str(target)], expires=None, blob_path=blob_path)

    assert vault.entries() == []
    assert not os.path.exists(blob_path)
    assert [n for n in os.listdir(workspace / "locked") if "staging" in n] == []
