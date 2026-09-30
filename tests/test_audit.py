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

"""An auditor sees the retention and none of the documents.

The claim worth testing is a negative one — that a holder of the audit record
cannot get at a single file key however long they hold it — so most of this
file is spent trying to find one.
"""

from __future__ import annotations

import json
import os
import stat
import time

import pytest

from quenchkey import audit, expiry, locker
from quenchkey.vault import Vault

AUDITOR = "the-auditors-own-passphrase-here"


def _lock(vault, workspace, name="client-file.pdf", **rules):
    source = workspace / "documents" / name
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_bytes(name.encode() * 200)
    return locker.lock_files(vault, [str(source)],
                             output_dir=str(workspace / "locked"),
                             **rules).entry


@pytest.fixture()
def armed(vault, workspace, fast_kdf):
    _lock(vault, workspace, "still-live.pdf", expires=time.time() + 7200)
    spent = _lock(vault, workspace, "already-gone.pdf", expires=time.time() + 1)
    expiry.sweep(vault, now=time.time() + 10)
    assert vault.get(spent.id).key_destroyed
    path = audit.arm(vault, AUDITOR, kdf_params=fast_kdf)
    return path


# --------------------------------------------------------------------------
# what an auditor gets
# --------------------------------------------------------------------------

def test_the_record_opens_with_its_own_passphrase_and_no_vault(vault, armed):
    record = audit.read(armed, AUDITOR, public_key=vault.public_key)

    assert len(record.entries) == 2
    assert {e.name for e in record.entries} == {"still-live.pdf", "already-gone.pdf"}
    assert len(record.destroyed) == 1
    assert record.destroyed[0].name == "already-gone.pdf"


def test_it_says_when_and_why_a_key_was_destroyed(vault, armed):
    record = audit.read(armed, AUDITOR, public_key=vault.public_key)

    gone = record.destroyed[0]
    assert gone.destroyed_at is not None
    assert "deadline" in gone.reason.lower() or gone.reason


def test_the_events_verify_in_the_auditors_hands(vault, armed):
    """Handing somebody the chain is pointless if they must take it on trust."""
    record = audit.read(armed, AUDITOR, public_key=vault.public_key)

    assert record.chain_ok
    assert record.events
    assert record.anchor == vault.chain_fingerprint


def test_the_record_is_signed_by_the_vault(vault, armed):
    record = audit.read(armed, AUDITOR, public_key=vault.public_key)

    assert record.signature_ok
    assert record.signed_by == vault.vault_id
    assert "verifies from end to end" in record.verdict()


def test_a_record_checked_against_the_wrong_key_does_not_verify(vault, armed,
                                                                workspace,
                                                                fast_kdf):
    stranger = Vault.create(str(workspace / "stranger.qkv"),
                            "another-vault-entirely-here", kdf_params=fast_kdf)

    record = audit.read(armed, AUDITOR, public_key=stranger.public_key)

    assert not record.signature_ok
    assert "cannot be shown to have come from" in record.verdict()


def test_checking_against_the_key_inside_says_what_that_is_worth(vault, armed):
    """Self-consistency is not provenance, and the verdict must not pretend."""
    record = audit.read(armed, AUDITOR)

    assert record.signature_ok
    assert "internally consistent" in record.chain_note


def test_an_edited_record_does_not_open(vault, armed):
    document = json.loads(open(armed).read())
    body = bytearray(bytes.fromhex(document["body"]))
    body[40] ^= 0x01
    document["body"] = bytes(body).hex()
    open(armed, "w").write(json.dumps(document))

    with pytest.raises(audit.AuditError, match="wrong passphrase"):
        audit.read(armed, AUDITOR)


def test_an_edited_header_does_not_open_either(vault, armed):
    """The header is the associated data, so it cannot be changed quietly."""
    document = json.loads(open(armed).read())
    header = json.loads(document["header"])
    header["vault_id"] = "0" * 32
    document["header"] = json.dumps(header, separators=(",", ":"), sort_keys=True)
    open(armed, "w").write(json.dumps(document))

    with pytest.raises(audit.AuditError):
        audit.read(armed, AUDITOR)


# --------------------------------------------------------------------------
# what an auditor does not get, which is what it is for
# --------------------------------------------------------------------------

def test_no_file_key_is_anywhere_in_the_record(vault, armed):
    """The decisive test. A live entry's key, looked for in the plaintext."""
    live = [e for e in vault.entries() if not e.key_destroyed]
    assert live, "the fixture must leave at least one key alive to look for"
    keys = [entry.key.bytes().hex() for entry in live]

    raw = open(armed).read()
    record = audit.read(armed, AUDITOR, public_key=vault.public_key)
    body = json.dumps(audit._record_body(record))

    for key in keys:
        assert key not in raw
        assert key not in body


def test_nothing_of_key_shape_is_unaccounted_for(vault, armed):
    record = audit.read(armed, AUDITOR, public_key=vault.public_key)

    assert audit.key_material_in(record) == []


def test_the_master_key_is_not_in_it(vault, armed):
    raw = open(armed).read()

    assert vault.master_key().bytes().hex() not in raw


def test_the_signing_seed_is_not_in_it(vault, armed):
    """The public key belongs there; the seed behind it does not."""
    raw = open(armed).read()

    assert vault.signing_seed().bytes().hex() not in raw
    assert vault.public_key.hex() in raw       # and this one is meant to be


def test_the_record_does_not_open_with_the_vaults_passphrase(vault, armed):
    """Two passphrases, two doors. Handing over one is not handing over both."""
    from conftest import PASSPHRASE

    with pytest.raises(audit.AuditError):
        audit.read(armed, PASSPHRASE)


def test_the_record_is_owner_only(vault, armed):
    assert stat.S_IMODE(os.stat(armed).st_mode) == 0o600


# --------------------------------------------------------------------------
# arming and disarming
# --------------------------------------------------------------------------

def test_arming_is_recorded_in_the_chain(vault, armed):
    assert audit.is_armed(vault)
    assert any(e.get("kind") == "audit_record_armed" for e in vault.events)
    assert vault.chain_report().ok


def test_disarming_removes_the_record(vault, armed):
    assert audit.disarm(vault)

    assert not audit.is_armed(vault)
    assert not os.path.exists(armed)
    assert any(e.get("kind") == "audit_record_disarmed" for e in vault.events)


def test_writing_without_arming_first_is_refused(vault):
    with pytest.raises(audit.NotArmed):
        audit.write(vault, AUDITOR)


def test_an_empty_passphrase_is_refused(vault):
    with pytest.raises(audit.AuditError):
        audit.arm(vault, "")


def test_the_record_can_be_rewritten_as_the_vault_changes(vault, armed,
                                                          workspace):
    before = audit.read(armed, AUDITOR, public_key=vault.public_key)
    _lock(vault, workspace, "newer.pdf", expires=time.time() + 7200)

    audit.write(vault, AUDITOR)
    after = audit.read(armed, AUDITOR, public_key=vault.public_key)

    assert len(after.entries) == len(before.entries) + 1
    assert after.written >= before.written


def test_the_record_says_when_it_was_written(vault, armed):
    when = audit.written_at(vault.path)

    assert when is not None
    assert abs(when - time.time()) < 300


def test_a_stale_record_is_a_snapshot_and_says_so(vault, armed, workspace):
    """An auditor reading March is reading March, and can tell."""
    record = audit.read(armed, AUDITOR, public_key=vault.public_key)
    _lock(vault, workspace, "after-the-snapshot.pdf", expires=time.time() + 7200)

    assert record.anchor != vault.chain_fingerprint
    assert "Compare the anchor" in record.verdict()
