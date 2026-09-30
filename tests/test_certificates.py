"""Certificates of destruction: what they prove, and what they cannot."""

from __future__ import annotations

import copy
import json
import time

import pytest

from quenchkey import certificate, expiry, locker
from quenchkey.certificate import Custodian
from quenchkey.crypto import KdfParams
from quenchkey.vault import REASON_OPENS, REASON_REMOVED, Vault

from conftest import PASSPHRASE


@pytest.fixture()
def destroyed(vault, sample_files, workspace):
    """One entry whose key has been destroyed by a deadline."""
    entry = locker.lock_files(vault, sample_files[:1], expires=time.time() + 1,
                              output_dir=str(workspace / "locked")).entry
    expiry.sweep(vault, now=time.time() + 60)
    vault.save()
    return entry


# -- issuing ----------------------------------------------------------------

def test_a_certificate_is_issued_automatically(vault, destroyed):
    document = vault.certificate_for(destroyed.id)
    assert document is not None
    assert document["certificate"]["item"]["entry_id"] == destroyed.id


def test_every_destruction_route_issues_one(vault, sample_files, workspace):
    by_opens = locker.lock_files(vault, sample_files[:1], expires=None,
                                 output_dir=str(workspace / "locked"),
                                 max_opens=1).entry
    locker.unlock_entry(vault, by_opens.id, str(workspace / "out"))

    manual = locker.lock_files(vault, sample_files[1:2], expires=None,
                               output_dir=str(workspace / "locked")).entry
    expiry.expire_now(vault, [manual.id])

    removed = locker.lock_files(vault, sample_files[2:3], expires=None,
                                output_dir=str(workspace / "locked")).entry
    vault.remove_entry(removed.id)

    reasons = {document["certificate"]["item"]["entry_id"]:
               document["certificate"]["destruction"]["reason"]
               for document in vault.certificates}
    assert reasons[by_opens.id] == REASON_OPENS
    assert reasons[removed.id] == REASON_REMOVED
    assert manual.id in reasons


def test_the_certificate_names_the_method_and_the_standard(vault, destroyed):
    destruction = vault.certificate_for(destroyed.id)["certificate"]["destruction"]
    assert "Cryptographic Erase" in destruction["method"]
    assert "800-88" in destruction["method"]
    assert destruction["key_length_bits"] == 256


def test_the_certificate_identifies_the_file_by_hash(vault, destroyed):
    document = vault.certificate_for(destroyed.id)
    recorded = document["certificate"]["item"]["locked_file_sha256"]
    assert recorded and len(recorded) == 64
    ok, message = certificate.check_file(document, destroyed.blob_path)
    assert ok, message


def test_a_different_file_does_not_match(vault, destroyed, workspace):
    document = vault.certificate_for(destroyed.id)
    impostor = workspace / "not-it.qkey"
    impostor.write_bytes(b"different bytes entirely")
    ok, message = certificate.check_file(document, str(impostor))
    assert not ok
    assert "NOT the one" in message


def test_the_certificate_carries_its_own_limitations(vault, destroyed):
    text = vault.certificate_for(destroyed.id)["certificate"]["limitations"]
    assert "does not prove" in text
    assert "no copy of the key was taken before" in text


def test_custodian_details_reach_the_certificate(vault, sample_files, workspace):
    vault.set_custodian(Custodian("A. Mensah", "Data Protection Officer",
                                  "dpo@example.org", "Example Ltd"))
    entry = locker.lock_files(vault, sample_files[:1], expires=None,
                              output_dir=str(workspace / "locked")).entry
    vault.shred_key(entry.id)
    custodian = vault.certificate_for(entry.id)["certificate"]["custodian"]
    assert custodian["name"] == "A. Mensah"
    assert custodian["organisation"] == "Example Ltd"


def test_the_certificate_records_its_place_in_the_chain(vault, destroyed):
    evidence = vault.certificate_for(destroyed.id)["certificate"]["evidence"]
    assert any(event["hash"] == evidence["chain_head"] for event in vault.events)


def test_the_destruction_time_never_precedes_the_watermark(vault, sample_files,
                                                           workspace, monkeypatch):
    """A wound-back clock must not produce a certificate dated in the past."""
    entry = locker.lock_files(vault, sample_files[:1], expires=None,
                              output_dir=str(workspace / "locked")).entry
    vault.save()
    watermark = vault.last_seen

    real_time = time.time
    monkeypatch.setattr(time, "time", lambda: real_time() - 10 * 86400)
    vault.shred_key(entry.id)

    stamped = vault.certificate_for(entry.id)["certificate"]["destruction"][
        "destroyed_at"]
    assert stamped >= watermark


# -- verifying --------------------------------------------------------------

def test_a_fresh_certificate_verifies(vault, destroyed):
    result = certificate.verify(vault.certificate_for(destroyed.id),
                                vault.public_key)
    assert result.ok


@pytest.mark.parametrize("path", [
    ("certificate", "item", "names"),
    ("certificate", "destruction", "reason"),
    ("certificate", "destruction", "destroyed_at"),
    ("certificate", "vault_id"),
    ("certificate", "custodian", "name"),
    ("certificate", "limitations"),
])
def test_altering_any_field_invalidates_the_signature(vault, destroyed, path):
    document = copy.deepcopy(vault.certificate_for(destroyed.id))
    target = document
    for key in path[:-1]:
        target = target[key]
    current = target[path[-1]]
    target[path[-1]] = ("tampered" if isinstance(current, str)
                        else 0 if isinstance(current, (int, float))
                        else ["tampered"])

    result = certificate.verify(document, vault.public_key)
    assert not result.ok
    assert "altered" in result.reason or "does not match" in result.reason


def test_a_certificate_from_another_vault_is_rejected(vault, destroyed, workspace,
                                                      sample_files):
    other = Vault.create(str(workspace / "other.vk"), PASSPHRASE,
                         kdf_params=KdfParams.create(1, 8192, 1))
    document = vault.certificate_for(destroyed.id)

    # It verifies on its own terms, because it is really signed...
    assert certificate.verify(document).ok
    # ...but not as having come from a vault it did not come from.
    result = certificate.verify(document, other.public_key)
    assert not result.ok
    assert "different vault" in result.reason
    other.lock()


def test_a_forged_certificate_signed_by_a_new_key_is_caught(vault, destroyed):
    """Re-signing with your own key produces a valid-looking document.

    This is exactly why verification against an expected vault matters, and
    why the app says so when no expected vault is given.
    """
    from quenchkey.certificate import (
        SIGNATURE_DOMAIN, new_signing_seed, private_key, public_key_bytes,
        vault_id,
    )
    from quenchkey import chain

    document = copy.deepcopy(vault.certificate_for(destroyed.id))
    document["certificate"]["destruction"]["reason"] = "a reason of my choosing"

    seed = new_signing_seed()
    document["certificate"]["vault_id"] = vault_id(public_key_bytes(seed))
    document["public_key"] = public_key_bytes(seed).hex()
    document["signature"] = private_key(seed).sign(
        SIGNATURE_DOMAIN + chain.canonical(document["certificate"])).hex()

    assert certificate.verify(document).ok, "internally consistent, as warned"
    assert not certificate.verify(document, vault.public_key).ok, \
        "but not from the vault it claims to describe"


def test_verification_without_an_expected_vault_says_so(vault, destroyed):
    result = certificate.verify(vault.certificate_for(destroyed.id))
    assert result.ok
    assert "no expected vault" in result.reason


def test_a_malformed_document_is_refused():
    for rubbish in ({}, {"certificate": {}}, {"certificate": {}, "public_key": "zz",
                                              "signature": "zz"}):
        assert not certificate.verify(rubbish).ok


def test_certificates_survive_a_reopen(vault, destroyed):
    vault.save()
    public = vault.public_key
    vault.lock()

    reopened = Vault.unlock(vault.path, PASSPHRASE)
    assert len(reopened.certificates) == 1
    assert certificate.verify(reopened.certificates[0], public).ok
    assert reopened.public_key == public, "the vault identity is stable"


def test_a_certificate_serialises_to_stable_json(vault, destroyed):
    document = vault.certificate_for(destroyed.id)
    reloaded = json.loads(certificate.to_json(document))
    assert certificate.verify(reloaded, vault.public_key).ok
