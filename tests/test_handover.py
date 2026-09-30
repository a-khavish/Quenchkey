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

"""Sending a locked file to somebody else's vault, deadline and all.

The claim being tested is narrow and worth stating: a handed-over file's key
ends up inside the recipient's vault, so the recipient's own sweep destroys it
on the sender's schedule without anything having to reach across a network.
And the claim being tested *against* is equally narrow: nothing here reaches a
copy the recipient has already extracted.
"""

from __future__ import annotations

import base64
import json
import os
import time

import pytest

from quenchkey import expiry, handover, locker
from quenchkey.crypto import UnsupportedFormat
from quenchkey.vault import Vault

SENDER_PASSPHRASE = "eleven-otters-carried-the-lantern"
RECIPIENT_PASSPHRASE = "nineteen-kettles-below-the-orchard"


@pytest.fixture()
def sender(workspace, fast_kdf) -> Vault:
    return Vault.create(str(workspace / "sender.qkv"), SENDER_PASSPHRASE,
                        kdf_params=fast_kdf)


@pytest.fixture()
def recipient(workspace, fast_kdf) -> Vault:
    return Vault.create(str(workspace / "recipient.qkv"), RECIPIENT_PASSPHRASE,
                        kdf_params=fast_kdf)


@pytest.fixture()
def document(workspace):
    path = workspace / "documents" / "term-sheet.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"the agreed terms " * 300)
    return path


# --------------------------------------------------------------------------
# identity cards
# --------------------------------------------------------------------------

def test_a_card_vouches_for_its_own_key(recipient):
    card = handover.my_card(recipient, label="Accounts")

    assert card.verify()
    assert card.vault_id == recipient.vault_id
    assert len(card.agreement_key) == 32


def test_a_card_carries_no_secret(recipient, workspace):
    """The worst somebody can do with it is send you a file only you can open."""
    path = handover.write_card(handover.my_card(recipient), str(workspace / "id.qkid"))
    raw = open(path).read()

    assert "private" not in raw.lower()
    for word in (RECIPIENT_PASSPHRASE, recipient.master_key().bytes().hex()):
        assert word not in raw


def test_the_card_is_the_same_every_time(recipient):
    """Derived from the seed, not stored, so it cannot drift."""
    first = handover.my_card(recipient)
    second = handover.my_card(recipient)

    assert first.agreement_key == second.agreement_key


def test_the_agreement_key_is_not_the_signing_key(recipient):
    """Using one key for signatures and key agreement is the classic mistake."""
    card = handover.my_card(recipient)

    assert card.agreement_key != card.signing_key


def test_a_card_edited_in_transit_is_refused(recipient, workspace):
    path = workspace / "id.qkid"
    handover.write_card(handover.my_card(recipient), str(path))
    document = json.loads(path.read_text())
    document["agreement_key"] = base64.b64encode(os.urandom(32)).decode()
    path.write_text(json.dumps(document))

    with pytest.raises(handover.HandoverError, match="does not verify"):
        handover.read_card(str(path))


def test_the_fingerprint_is_readable_aloud(recipient):
    fingerprint = handover.my_card(recipient).fingerprint

    assert len(fingerprint.split("-")) == 4
    assert fingerprint == fingerprint.upper()


def test_two_vaults_have_different_fingerprints(sender, recipient):
    assert handover.my_card(sender).fingerprint != \
        handover.my_card(recipient).fingerprint


# --------------------------------------------------------------------------
# what a recipient can see before deciding
# --------------------------------------------------------------------------

def test_the_terms_are_readable_with_no_key_at_all(sender, recipient,
                                                   document, workspace):
    deadline = time.time() + 7200
    path = handover.lock_for([str(document)], handover.my_card(recipient),
                             expires=deadline, max_opens=3,
                             output_dir=str(workspace), sender=sender)

    described = handover.describe(path)

    assert described["terms"].max_opens == 3
    assert abs(described["terms"].expires - deadline) < 1
    assert described["terms"].sender_vault_id == sender.vault_id


def test_an_addressed_file_says_so_in_its_header(sender, recipient,
                                                 document, workspace):
    """A reader with neither passphrase nor vault can tell the kinds apart."""
    path = handover.lock_for([str(document)], handover.my_card(recipient),
                             output_dir=str(workspace), sender=sender)

    header = locker.read_blob_header(path)

    assert header.addressed
    assert not header.self_contained
    assert header.kind == "addressed"


def test_a_shared_file_is_not_mistaken_for_an_addressed_one(document, workspace):
    shared = locker.lock_to_share([str(document)], "a-passphrase-for-sharing",
                                  output_dir=str(workspace))

    header = locker.read_blob_header(shared.path)

    assert header.kind == "shared"
    with pytest.raises(handover.HandoverError, match="not addressed"):
        handover.describe(shared.path)


def test_a_recipient_is_told_which_vault_it_is_for(sender, recipient,
                                                   document, workspace):
    path = handover.lock_for([str(document)], handover.my_card(recipient),
                             output_dir=str(workspace), sender=sender)

    assert handover.addressed_to_me(recipient, path)
    assert not handover.addressed_to_me(sender, path)


# --------------------------------------------------------------------------
# the whole point: the deadline lands in the recipient's vault
# --------------------------------------------------------------------------

def test_accepting_puts_the_key_in_the_recipients_vault(sender, recipient,
                                                        document, workspace):
    deadline = time.time() + 7200
    path = handover.lock_for([str(document)], handover.my_card(recipient),
                             expires=deadline, max_opens=2,
                             output_dir=str(workspace), sender=sender)

    entry = handover.accept(recipient, path)

    assert entry.id in {e.id for e in recipient.entries()}
    assert abs(entry.expires - deadline) < 1
    assert entry.max_opens == 2
    assert entry.display_name == "term-sheet.txt"


def test_the_recipients_own_sweep_enforces_the_senders_deadline(
        sender, recipient, document, workspace):
    """This is the entire feature. Nothing reaches across a network."""
    path = handover.lock_for([str(document)], handover.my_card(recipient),
                             expires=time.time() + 60,
                             output_dir=str(workspace), sender=sender)
    entry = handover.accept(recipient, path)

    report = expiry.sweep(recipient, now=time.time() + 120)

    assert [e.id for e in report.expired] == [entry.id]
    assert recipient.get(entry.id).key_destroyed


def test_an_accepted_file_opens_to_the_original_bytes(sender, recipient,
                                                      document, workspace):
    path = handover.lock_for([str(document)], handover.my_card(recipient),
                             output_dir=str(workspace), sender=sender)
    entry = handover.accept(recipient, path)
    out = workspace / "opened"
    out.mkdir()

    written = locker.unlock_entry(recipient, entry.id, str(out))

    assert open(written[0], "rb").read() == document.read_bytes()


def test_the_sender_cannot_open_what_they_addressed_elsewhere(
        sender, recipient, document, workspace):
    """Wrapped to the recipient's key, so the sender is not a second holder."""
    path = handover.lock_for([str(document)], handover.my_card(recipient),
                             output_dir=str(workspace), sender=sender)

    with pytest.raises(handover.NotAddressedToYou):
        handover.accept(sender, path)


def test_a_third_party_cannot_open_it_either(sender, recipient, document,
                                             workspace, fast_kdf):
    stranger = Vault.create(str(workspace / "stranger.qkv"),
                            "twenty-three-crows-on-the-wire",
                            kdf_params=fast_kdf)
    path = handover.lock_for([str(document)], handover.my_card(recipient),
                             output_dir=str(workspace), sender=sender)

    with pytest.raises(handover.NotAddressedToYou):
        handover.accept(stranger, path)


def test_there_is_no_way_to_read_it_without_accepting(sender, recipient,
                                                      document, workspace):
    """Accepting is what puts the deadline in your vault, so it is the only door."""
    path = handover.lock_for([str(document)], handover.my_card(recipient),
                             expires=time.time() + 7200,
                             output_dir=str(workspace), sender=sender)
    out = workspace / "opened"
    out.mkdir()

    with pytest.raises((UnsupportedFormat, locker.LockError)):
        locker.open_shared(path, RECIPIENT_PASSPHRASE, str(out))
    assert not any(out.iterdir())


def test_moving_the_deadline_in_transit_breaks_the_file(sender, recipient,
                                                        document, workspace):
    """The terms are inside the associated data, so they cannot be edited."""
    path = handover.lock_for([str(document)], handover.my_card(recipient),
                             expires=time.time() + 60,
                             output_dir=str(workspace), sender=sender)

    raw = bytearray(open(path, "rb").read())
    start = raw.find(b'"expires":')
    assert start > 0
    end = raw.find(b",", start)
    replacement = b'"expires":9999999999.0'
    raw[start:end] = replacement.ljust(end - start, b" ")
    open(path, "wb").write(bytes(raw))

    with pytest.raises(handover.HandoverError, match="could not be unwrapped"):
        handover.accept(recipient, path)


def test_accepting_is_recorded_on_both_sides(sender, recipient, document,
                                             workspace):
    path = handover.lock_for([str(document)], handover.my_card(recipient),
                             output_dir=str(workspace), sender=sender)
    handover.accept(recipient, path)

    assert any(e.get("kind") == "handover_sent" for e in sender.events)
    assert any(e.get("kind") == "handover_accepted" for e in recipient.events)
    assert sender.chain_report().ok
    assert recipient.chain_report().ok


def test_an_accepted_entry_behaves_like_any_other(sender, recipient, document,
                                                  workspace):
    """Openings counted, certificate issued, the lot."""
    path = handover.lock_for([str(document)], handover.my_card(recipient),
                             expires=time.time() + 7200, max_opens=1,
                             output_dir=str(workspace), sender=sender)
    entry = handover.accept(recipient, path)
    out = workspace / "opened"
    out.mkdir()

    locker.unlock_entry(recipient, entry.id, str(out))
    expiry.sweep(recipient)

    assert recipient.get(entry.id).key_destroyed
    assert recipient.certificates


def test_a_card_that_does_not_verify_is_refused_at_send_time(sender, document,
                                                             workspace, recipient):
    card = handover.my_card(recipient)
    forged = handover.IdentityCard(
        vault_id=card.vault_id, signing_key=card.signing_key,
        agreement_key=os.urandom(32), signature=card.signature)

    with pytest.raises(handover.HandoverError, match="does not verify"):
        handover.lock_for([str(document)], forged, output_dir=str(workspace),
                          sender=sender)


def test_several_files_travel_together(sender, recipient, workspace):
    folder = workspace / "documents"
    folder.mkdir(parents=True, exist_ok=True)
    paths = []
    for name in ("one.txt", "two.txt", "three.txt"):
        path = folder / name
        path.write_bytes(name.encode() * 200)
        paths.append(str(path))

    out = handover.lock_for(paths, handover.my_card(recipient),
                            output_dir=str(workspace), sender=sender)
    entry = handover.accept(recipient, out)

    assert len(entry.names) == 3
    assert handover.describe.__doc__  # the terms list them, readable first


def test_the_sender_does_not_need_a_vault(recipient, document, workspace):
    """A card is enough to send. Passing a vault only records who sent it."""
    path = handover.lock_for([str(document)], handover.my_card(recipient),
                             output_dir=str(workspace))

    entry = handover.accept(recipient, path)

    assert entry.id in {e.id for e in recipient.entries()}


def test_what_this_does_not_reach_is_the_extracted_copy(sender, recipient,
                                                        document, workspace):
    """Stated in the module docstring, so it is proved here rather than assumed."""
    path = handover.lock_for([str(document)], handover.my_card(recipient),
                             expires=time.time() + 60,
                             output_dir=str(workspace), sender=sender)
    entry = handover.accept(recipient, path)
    out = workspace / "opened"
    out.mkdir()
    written = locker.unlock_entry(recipient, entry.id, str(out))

    expiry.sweep(recipient, now=time.time() + 120)

    assert recipient.get(entry.id).key_destroyed
    assert os.path.exists(written[0])            # untouched, and honestly so
    assert open(written[0], "rb").read() == document.read_bytes()
