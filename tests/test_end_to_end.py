"""One long scenario, start to finish, the way it actually gets used."""

from __future__ import annotations

import os
import time

import pytest

from quenchkey import crypto, expiry, keyfile, locker, passphrase as pp
from quenchkey.crypto import AuthenticationError, SecretBytes
from quenchkey.vault import ClockRollback, KeyDestroyed, Vault


def test_the_whole_story(tmp_path, monkeypatch):
    """Create, lock, share, expire, and confirm the file is gone for good."""
    vault_path = str(tmp_path / "vault.qkv")
    key_path = keyfile.generate(str(tmp_path / "second.keyfile"))
    fast = crypto.KdfParams.create(time_cost=1, memory_kib=8192, parallelism=1)

    # 1. A passphrase the app generated, so its strength is known exactly.
    passphrase = pp.generate_passphrase(pp.RECOMMENDED_WORDS)
    assert pp.estimate(passphrase).meets_minimum

    # 2. A vault, protected by that passphrase and a keyfile.
    vault = Vault.create(vault_path, passphrase, key_path, kdf_params=fast)

    # 3. Two documents, locked for one hour, originals left in place.
    documents = tmp_path / "documents"
    documents.mkdir()
    payloads = {}
    for name in ("term-sheet.pdf", "cap-table.xlsx"):
        payloads[name] = os.urandom(300_000)
        (documents / name).write_bytes(payloads[name])

    result = locker.lock_files(
        vault, [str(documents / "term-sheet.pdf"), str(documents / "cap-table.xlsx")],
        expires=time.time() + 3600, output_dir=str(tmp_path))
    blob = result.blob_path
    entry_id = result.entry.id
    vault.lock()

    # 4. The .qkey file is handed over. It contains no key and no filenames.
    shared = tmp_path / "shared-copy.qkey"
    shared.write_bytes(open(blob, "rb").read())
    raw = open(shared, "rb").read()
    assert b"term-sheet" not in raw and b"cap-table" not in raw

    # 5. The recipient, without the vault, cannot open it at any price.
    for attempt in range(3):
        with pytest.raises(AuthenticationError):
            locker.decrypt_stream(str(shared), str(tmp_path / f"try{attempt}"),
                                  SecretBytes.random())

    # 6. The holder reopens the vault and reads the files back intact.
    vault = Vault.unlock(vault_path, passphrase, key_path)
    written = locker.unlock_entry(vault, entry_id, str(tmp_path / "extracted"))
    assert {os.path.basename(p): open(p, "rb").read() for p in written} == payloads

    # 7. The wrong passphrase, and the right passphrase with the wrong
    #    keyfile, both fail — and look identical from outside.
    vault.save()
    vault.lock()
    decoy = keyfile.generate(str(tmp_path / "decoy.keyfile"))
    with pytest.raises(AuthenticationError):
        Vault.unlock(vault_path, "the wrong passphrase entirely", key_path)
    with pytest.raises(AuthenticationError):
        Vault.unlock(vault_path, passphrase, decoy)

    # 8. Someone winds the clock back to keep the file alive. It is refused.
    real_time = time.time
    monkeypatch.setattr(time, "time", lambda: real_time() - 7 * 86400)
    with pytest.raises(ClockRollback):
        Vault.unlock(vault_path, passphrase, key_path)

    # ...and even when forced through, the deadline is unchanged, because the
    # watermark only ever moves forward.
    vault = Vault.unlock(vault_path, passphrase, key_path, accept_clock_rollback=True)
    assert vault.effective_now() > time.time()
    monkeypatch.undo()

    # 9. The hour passes. The sweep destroys the key.
    report = expiry.sweep(vault, now=time.time() + 7200)
    assert [e.id for e in report.expired] == [entry_id]
    vault.save()
    vault.lock()

    # 10. The shared copy still exists, byte for byte, and is now unreadable —
    #     by the recipient, by the holder, and by this application.
    assert open(shared, "rb").read() == raw
    vault = Vault.unlock(vault_path, passphrase, key_path)
    with pytest.raises(KeyDestroyed):
        locker.unlock_entry(vault, entry_id, str(tmp_path / "too-late"))
    assert bytes(vault.get(entry_id).key.raw) == bytes(32)

    # 11. And the event log records what happened, in order.
    kinds = [event["kind"] for event in vault.events]
    assert kinds.index("vault_created") < kinds.index("locked")
    assert kinds.index("locked") < kinds.index("key_destroyed")
    assert "clock_rollback_accepted" in kinds
    vault.lock()
