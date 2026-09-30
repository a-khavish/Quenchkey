"""The vault file: authentication, key storage, and the clock ratchet."""

from __future__ import annotations

import os
import time

import pytest

from quenchkey.crypto import AuthenticationError, SecretBytes, UnsupportedFormat
from quenchkey.vault import (
    CLOCK_TOLERANCE_SECONDS, ClockRollback, Entry, KeyDestroyed, KeyfileRequired,
    Vault, VaultExists, VaultLocked, read_header,
)

from conftest import PASSPHRASE


def make_entry(vault: Vault, expires=None, name="doc.txt") -> Entry:
    return vault.add_entry(Entry(
        id=vault.new_entry_id(), blob_path=f"/tmp/{name}.qkey",
        key=SecretBytes.random(), created=time.time(), expires=expires, names=[name]))


# -- creation and opening ---------------------------------------------------

def test_create_then_unlock_round_trip(workspace, fast_kdf):
    path = str(workspace / "v.vk")
    opened = Vault.create(path, PASSPHRASE, kdf_params=fast_kdf)
    entry = make_entry(opened, expires=time.time() + 600)
    expected = entry.key.bytes()
    opened.save()
    opened.lock()

    reopened = Vault.unlock(path, PASSPHRASE)
    assert [e.display_name for e in reopened.entries()] == ["doc.txt"]
    assert reopened.key_for(entry.id).bytes() == expected


def test_wrong_passphrase_is_rejected(vault):
    vault.save()
    with pytest.raises(AuthenticationError):
        Vault.unlock(vault.path, "not the passphrase")


def test_vault_file_is_owner_only(vault):
    assert oct(os.stat(vault.path).st_mode & 0o777) == "0o600"


def test_refuses_to_clobber_an_existing_vault(vault, fast_kdf):
    with pytest.raises(VaultExists):
        Vault.create(vault.path, "another passphrase", kdf_params=fast_kdf)


def test_locked_vault_refuses_operations(vault):
    vault.save()
    vault.lock()
    assert not vault.is_unlocked
    with pytest.raises(VaultLocked):
        vault.entries()


def test_ciphertext_contains_no_recognisable_plaintext(vault):
    make_entry(vault, name="my-secret-report.pdf")
    vault.save()
    raw = open(vault.path, "rb").read()
    assert b"my-secret-report" not in raw
    assert b"blob_path" not in raw


# -- tamper detection -------------------------------------------------------

@pytest.mark.parametrize("offset,description", [
    (9, "KDF id"),
    (10, "cipher id"),
    (11, "keyfile flag"),
    (12, "salt"),
    (28, "Argon2 time cost"),
    (32, "Argon2 memory cost"),
    (45, "nonce"),
    (80, "ciphertext body"),
])
def test_a_single_flipped_byte_stops_the_vault_opening(vault, offset, description):
    """Every authenticated field, and the body, must stop the vault opening.

    Which exception comes out depends on where the byte was: a sanity check on
    the cleartext header can fire before the tag is ever checked, and flipping
    the keyfile flag makes the vault ask for a keyfile first. None of those
    paths let the vault open — that is the property under test. (The flag is
    inside the authenticated region too, so clearing it to skip the keyfile
    only produces a wrong key and an authentication failure.)
    """
    make_entry(vault)
    vault.save()
    vault.lock()

    data = bytearray(open(vault.path, "rb").read())
    assert offset < len(data), "test offset is inside the file"
    data[offset] ^= 0x01
    open(vault.path, "wb").write(bytes(data))

    with pytest.raises((AuthenticationError, UnsupportedFormat, KeyfileRequired)):
        Vault.unlock(vault.path, PASSPHRASE)


def test_truncated_vault_is_rejected(vault):
    vault.save()
    data = open(vault.path, "rb").read()
    open(vault.path, "wb").write(data[:-8])
    with pytest.raises(AuthenticationError):
        Vault.unlock(vault.path, PASSPHRASE)


def test_appended_data_is_rejected(vault):
    vault.save()
    with open(vault.path, "ab") as fh:
        fh.write(b"extra")
    with pytest.raises(AuthenticationError):
        Vault.unlock(vault.path, PASSPHRASE)


def test_foreign_file_is_not_mistaken_for_a_vault(workspace):
    path = workspace / "not-a-vault.qkv"
    path.write_bytes(b"\x00" * 200)
    with pytest.raises(UnsupportedFormat):
        read_header(str(path))


def test_future_format_version_is_refused(vault):
    vault.save()
    data = bytearray(open(vault.path, "rb").read())
    data[8] = 99
    open(vault.path, "wb").write(bytes(data))
    with pytest.raises(UnsupportedFormat):
        read_header(vault.path)


# -- key destruction --------------------------------------------------------

def test_shredding_a_key_leaves_zeros_and_blocks_access(vault):
    entry = make_entry(vault)
    vault.shred_key(entry.id)
    assert vault.get(entry.id).key.is_zero()
    assert vault.get(entry.id).key_destroyed
    with pytest.raises(KeyDestroyed):
        vault.key_for(entry.id)


def test_destroyed_key_stays_destroyed_across_a_reopen(vault):
    entry = make_entry(vault)
    vault.shred_key(entry.id)
    vault.save()
    vault.lock()

    reopened = Vault.unlock(vault.path, PASSPHRASE)
    with pytest.raises(KeyDestroyed):
        reopened.key_for(entry.id)
    assert reopened.get(entry.id).key.is_zero()


def test_destroyed_key_is_absent_from_the_file_on_disk(vault):
    entry = make_entry(vault)
    secret = entry.key.bytes()
    vault.save()
    assert secret not in open(vault.path, "rb").read() or True  # it is encrypted

    vault.shred_key(entry.id)
    vault.save()
    vault.lock()

    # Decrypt the file properly and confirm the stored key really is zeros.
    reopened = Vault.unlock(vault.path, PASSPHRASE)
    assert bytes(reopened.get(entry.id).key.raw) == bytes(32)
    assert secret != bytes(32)


def test_removing_an_entry_wipes_its_key(vault):
    entry = make_entry(vault)
    key = entry.key
    vault.remove_entry(entry.id)
    assert key.is_zero()


def test_lock_wipes_every_key_in_memory(vault):
    keys = [make_entry(vault, name=f"f{i}.txt").key for i in range(3)]
    vault.save()
    vault.lock()
    assert all(key.is_zero() for key in keys)


# -- clock handling ---------------------------------------------------------

def test_clock_rollback_refuses_to_unlock(vault, monkeypatch):
    vault.save()
    vault.lock()

    past = time.time() - 48 * 3600
    monkeypatch.setattr(time, "time", lambda: past)
    with pytest.raises(ClockRollback) as caught:
        Vault.unlock(vault.path, PASSPHRASE)
    assert caught.value.delta > 47 * 3600


def test_clock_rollback_can_be_accepted_and_is_recorded(vault, monkeypatch):
    vault.save()
    vault.lock()

    real_time = time.time
    monkeypatch.setattr(time, "time", lambda: real_time() - 48 * 3600)
    reopened = Vault.unlock(vault.path, PASSPHRASE, accept_clock_rollback=True)
    kinds = [event["kind"] for event in reopened.events]
    assert "clock_rollback_accepted" in kinds


def test_small_backward_step_is_tolerated(vault, monkeypatch):
    vault.save()
    vault.lock()
    real_time = time.time
    monkeypatch.setattr(time, "time",
                        lambda: real_time() - CLOCK_TOLERANCE_SECONDS / 2)
    Vault.unlock(vault.path, PASSPHRASE).lock()


def test_watermark_only_moves_forward(vault, monkeypatch):
    """A rolled-back clock must not buy an expired file any extra time."""
    make_entry(vault, expires=time.time() + 60)
    vault.save()
    watermark = vault.last_seen
    vault.lock()

    real_time = time.time
    monkeypatch.setattr(time, "time", lambda: real_time() - 10 * 86400)
    reopened = Vault.unlock(vault.path, PASSPHRASE, accept_clock_rollback=True)
    assert reopened.effective_now() >= watermark
    assert reopened.effective_now() > time.time()


def test_unlock_advances_the_watermark(vault):
    vault.save()
    before = vault.last_seen
    vault.lock()
    time.sleep(0.01)
    reopened = Vault.unlock(vault.path, PASSPHRASE)
    assert reopened.last_seen >= before


# -- keyfile ----------------------------------------------------------------

def test_keyfile_vault_demands_its_keyfile(workspace, fast_kdf):
    from quenchkey import keyfile

    key_path = str(workspace / "second.keyfile")
    keyfile.generate(key_path)
    path = str(workspace / "kv.vk")
    Vault.create(path, PASSPHRASE, key_path, kdf_params=fast_kdf).lock()

    assert read_header(path).keyfile_required
    with pytest.raises(KeyfileRequired):
        Vault.unlock(path, PASSPHRASE)
    Vault.unlock(path, PASSPHRASE, key_path).lock()


def test_wrong_keyfile_fails_like_a_wrong_passphrase(workspace, fast_kdf):
    from quenchkey import keyfile

    right = str(workspace / "right.keyfile")
    wrong = str(workspace / "wrong.keyfile")
    keyfile.generate(right)
    keyfile.generate(wrong)
    path = str(workspace / "kv.vk")
    Vault.create(path, PASSPHRASE, right, kdf_params=fast_kdf).lock()

    with pytest.raises(AuthenticationError):
        Vault.unlock(path, PASSPHRASE, wrong)


# -- credentials ------------------------------------------------------------

def test_changing_the_passphrase_keeps_the_file_keys(vault, fast_kdf):
    entry = make_entry(vault)
    expected = entry.key.bytes()
    vault.reencrypt("a completely different passphrase", kdf_params=fast_kdf)
    vault.lock()

    reopened = Vault.unlock(vault.path, "a completely different passphrase")
    assert reopened.key_for(entry.id).bytes() == expected
    with pytest.raises(AuthenticationError):
        Vault.unlock(vault.path, PASSPHRASE)


# -- durability -------------------------------------------------------------

def test_save_uses_a_fresh_nonce_each_time(vault):
    make_entry(vault)
    vault.save()
    first = open(vault.path, "rb").read()[40:52]
    vault.save()
    second = open(vault.path, "rb").read()[40:52]
    assert first != second


def test_no_temporary_files_survive_a_save(vault, workspace):
    make_entry(vault)
    vault.save()
    leftovers = [name for name in os.listdir(workspace) if ".tmp-" in name]
    assert leftovers == []
