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

A shared file carries its own key, wrapped by a passphrase, and that is why it
can never expire: expiry destroys a key that lives somewhere the holder of the
file does not control, and a self-contained file has nothing that can be taken
away from it. That limitation is stated everywhere in this tool, and it is
real.

A handover is the way out of it, and it needs the other person to be running
Quenchkey too. Instead of wrapping the file key to a passphrase, it is wrapped
to the *recipient's vault* — so when they accept it, the key lands inside their
vault as an ordinary entry, with the deadline the sender proposed, and their
own background sweep destroys it on time. Nothing has to reach across the
network at the deadline, because nothing has to: the key was already in the
place that expires.

**How it is addressed.** Each vault derives an X25519 key pair from the
signing seed it already keeps for certificates, so no new secret is stored and
a vault has one identity with two uses. The recipient exports an *identity
card*: their vault id, their Ed25519 public key, their X25519 public key, and
an Ed25519 signature binding the second to the first. Anyone can check that
signature with no passphrase and no vault, which is what stops a card being
edited in transit to name somebody else's key.

**What the sender can and cannot do.** The rules — deadline, opening
allowance, check-in interval — travel inside the file's authenticated header,
so the recipient reads them *before* deciding, and neither side can change
them afterwards without the file failing to open. What the sender cannot do is
make the recipient keep them. The three things this does not buy, which the
interface says in as many words:

* The recipient can decline. A file they never accept is a file they cannot
  read, which is the honest failure mode, but it is their choice.
* Once they accept and open it, the copy that comes out is an ordinary file.
  Expiry destroys their key to the locked copy; it cannot reach a document
  they have already extracted, printed or forwarded.
* It is their machine. They can back their vault up and restore it after the
  deadline, exactly as you can with yours. That is tamper-evident — the
  rollback is written into their event chain — and it is not tamper-proof.

What it does buy is the ordinary case, which is most cases: a colleague who
wants the same thing you do, and a file that stops being readable on the day
you both agreed on, without either of you having to remember.
"""

from __future__ import annotations

import base64
import json
import os
import struct
import time
from dataclasses import dataclass
from typing import Optional, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from . import archive, certificate, crypto
from .crypto import AuthenticationError, SecretBytes, UnsupportedFormat
from .locker import (
    BLOB_HEADER_LEN, FLAG_ADDRESSED, BlobHeader, LockError, ProgressFn,
    _delete_original, _staging_path, encrypt_stream, free_path,
    read_blob_header, shred_file,
)
from .vault import Entry, Vault

HANDOVER_SUFFIX = ".qkey"
CARD_SUFFIX = ".qkid"

#: Domain separators. Each keeps one derivation from ever colliding with
#: another that happens to take the same input.
X25519_INFO = b"quenchkey/handover/x25519/v1"
SHARED_INFO = b"quenchkey/handover/shared/v1"
CARD_DOMAIN = b"quenchkey/identity-card/v1"

CARD_VERSION = 1
BLOCK_VERSION = 1

#: version, reserved, ephemeral public key, nonce, rules length
BLOCK_STRUCT = ">BB32s12sH"
BLOCK_PREFIX_LEN = struct.calcsize(BLOCK_STRUCT)

#: A 32-byte file key plus its authentication tag.
WRAPPED_KEY_LEN = 32 + crypto.TAG_SIZE


class HandoverError(LockError):
    """A handover could not be prepared, read or accepted."""


class NotAddressedToYou(HandoverError):
    """This file is addressed to a different vault."""


# --------------------------------------------------------------------------
# identity
# --------------------------------------------------------------------------

def _x25519_private(seed: SecretBytes) -> X25519PrivateKey:
    """The vault's key-agreement key, derived from the seed it already has.

    Derived rather than stored, so an existing vault gains a handover identity
    the moment this code runs and nothing has to be migrated. The separate
    HKDF info string is what keeps this key and the Ed25519 signing key from
    being the same 32 bytes used two ways, which is the mistake that makes
    signature and key-agreement keys unsafe to share.
    """
    material = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                    info=X25519_INFO).derive(seed.bytes())
    return X25519PrivateKey.from_private_bytes(material)


def _public_bytes(key) -> bytes:
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


@dataclass(frozen=True)
class IdentityCard:
    """Who a file can be addressed to. Public, and safe to send anywhere.

    Holds no secret. The worst somebody can do with your card is send you a
    file only you can open.
    """

    vault_id: str
    signing_key: bytes          # Ed25519, the vault's long-standing identity
    agreement_key: bytes        # X25519, derived from the same seed
    signature: bytes            # Ed25519 over the agreement key
    label: str = ""
    issued: float = 0.0

    @property
    def fingerprint(self) -> str:
        """Four groups a person can read out over the telephone."""
        raw = _fingerprint_bytes(self.agreement_key)
        return "-".join(raw[i:i + 4] for i in range(0, 16, 4))

    def verify(self) -> bool:
        """Check the card signed its own agreement key. No vault needed.

        This is what stops a card being edited in transit: swap the agreement
        key for your own and the signature no longer matches the signing key
        printed beside it.
        """
        try:
            Ed25519PublicKey.from_public_bytes(self.signing_key).verify(
                self.signature, CARD_DOMAIN + self.agreement_key)
        except (InvalidSignature, ValueError):
            return False
        return certificate.vault_id(self.signing_key) == self.vault_id

    def to_dict(self) -> dict:
        return {
            "format": "quenchkey-identity-card",
            "version": CARD_VERSION,
            "vault_id": self.vault_id,
            "label": self.label,
            "issued": self.issued,
            "signing_key": base64.b64encode(self.signing_key).decode(),
            "agreement_key": base64.b64encode(self.agreement_key).decode(),
            "signature": base64.b64encode(self.signature).decode(),
            "fingerprint": self.fingerprint,
        }

    @classmethod
    def from_dict(cls, raw: dict) -> "IdentityCard":
        if raw.get("format") != "quenchkey-identity-card":
            raise HandoverError("that is not a Quenchkey identity card")
        if raw.get("version") != CARD_VERSION:
            raise HandoverError(
                f"identity card version {raw.get('version')}; this build "
                f"understands {CARD_VERSION}")
        try:
            return cls(
                vault_id=str(raw["vault_id"]),
                signing_key=base64.b64decode(raw["signing_key"]),
                agreement_key=base64.b64decode(raw["agreement_key"]),
                signature=base64.b64decode(raw["signature"]),
                label=str(raw.get("label", "")),
                issued=float(raw.get("issued", 0.0)),
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise HandoverError(f"this identity card is malformed: {exc}") from exc


def _fingerprint_bytes(agreement_key: bytes) -> str:
    import hashlib
    return hashlib.sha256(
        b"quenchkey/card-fingerprint/v1" + agreement_key).hexdigest()[:16].upper()


def my_card(vault: Vault, label: str = "") -> IdentityCard:
    """This vault's identity card. Needs the vault open; holds no secret."""
    seed = vault.signing_seed()
    agreement = _public_bytes(_x25519_private(seed).public_key())
    signature = certificate.private_key(seed).sign(CARD_DOMAIN + agreement)
    return IdentityCard(
        vault_id=vault.vault_id,
        signing_key=vault.public_key,
        agreement_key=agreement,
        signature=signature,
        label=label,
        issued=time.time(),
    )


def write_card(card: IdentityCard, path: str) -> str:
    target = os.path.abspath(path)
    os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
    with open(target, "w") as fh:
        json.dump(card.to_dict(), fh, indent=2, sort_keys=True)
        fh.write("\n")
    return target


def read_card(path: str) -> IdentityCard:
    """Read a card and refuse it if it does not vouch for itself."""
    try:
        with open(path) as fh:
            card = IdentityCard.from_dict(json.load(fh))
    except (OSError, ValueError) as exc:
        raise HandoverError(f"could not read that identity card: {exc}") from exc
    if not card.verify():
        raise HandoverError(
            "that identity card does not verify — the key in it is not the "
            "one its signature covers, so it has been altered or was not "
            "written by Quenchkey")
    return card


# --------------------------------------------------------------------------
# the rules that travel with the file
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Terms:
    """What the sender proposes. Readable before accepting, fixed after."""

    expires: Optional[float] = None
    max_opens: Optional[int] = None
    heartbeat_days: Optional[float] = None
    names: tuple = ()
    sender_vault_id: str = ""
    sender_label: str = ""
    note: str = ""
    sent: float = 0.0

    def to_dict(self) -> dict:
        return {
            "expires": self.expires,
            "max_opens": self.max_opens,
            "heartbeat_days": self.heartbeat_days,
            "names": list(self.names),
            "sender_vault_id": self.sender_vault_id,
            "sender_label": self.sender_label,
            "note": self.note,
            "sent": self.sent,
        }

    @classmethod
    def from_dict(cls, raw: dict) -> "Terms":
        return cls(
            expires=raw.get("expires"),
            max_opens=raw.get("max_opens"),
            heartbeat_days=raw.get("heartbeat_days"),
            names=tuple(raw.get("names", [])),
            sender_vault_id=str(raw.get("sender_vault_id", "")),
            sender_label=str(raw.get("sender_label", "")),
            note=str(raw.get("note", "")),
            sent=float(raw.get("sent", 0.0)),
        )

    def describe(self) -> str:
        """The rules in a line, for a recipient deciding whether to accept."""
        parts = []
        if self.expires is not None:
            from . import expiry as expiry_mod
            parts.append(f"key destroyed {expiry_mod.format_time(self.expires)}")
        if self.max_opens is not None:
            parts.append(f"{self.max_opens} opening"
                         f"{'s' if self.max_opens != 1 else ''}")
        if self.heartbeat_days is not None:
            parts.append(f"check in every {self.heartbeat_days:g} days")
        return ", ".join(parts) if parts else "no deadline, no limit"


@dataclass
class HandoverBlock:
    """The addressed key block that sits after the blob header."""

    ephemeral_key: bytes
    nonce: bytes
    terms_json: bytes
    wrapped_key: bytes

    def prefix(self) -> bytes:
        return struct.pack(BLOCK_STRUCT, BLOCK_VERSION, 0,
                           self.ephemeral_key, self.nonce,
                           len(self.terms_json))

    def pack(self) -> bytes:
        return self.prefix() + self.terms_json + self.wrapped_key

    @property
    def length(self) -> int:
        return len(self.pack())


def _read_block(path: str) -> HandoverBlock:
    with open(path, "rb") as fh:
        fh.seek(BLOB_HEADER_LEN)
        prefix = fh.read(BLOCK_PREFIX_LEN)
        if len(prefix) < BLOCK_PREFIX_LEN:
            raise UnsupportedFormat("truncated key block in an addressed file")
        version, _reserved, ephemeral, nonce, terms_len = struct.unpack(
            BLOCK_STRUCT, prefix)
        if version != BLOCK_VERSION:
            raise UnsupportedFormat(
                f"addressed-file key block version {version}; this build "
                f"understands {BLOCK_VERSION}")
        if terms_len > 64 * 1024:
            raise UnsupportedFormat("implausible terms block in an addressed file")
        terms_json = fh.read(terms_len)
        wrapped = fh.read(WRAPPED_KEY_LEN)
    if len(terms_json) != terms_len or len(wrapped) != WRAPPED_KEY_LEN:
        raise UnsupportedFormat("truncated key block in an addressed file")
    return HandoverBlock(ephemeral, nonce, terms_json, wrapped)


def block_bytes(path: str) -> bytes:
    """The raw addressed key block, for callers that need it as bytes.

    Used by the read paths in :mod:`quenchkey.locker`, which have to fold the
    block into the associated data of every chunk without caring what is in it.
    """
    return _read_block(path).pack()


def describe(path: str) -> dict:
    """Everything an addressed file says about itself with no key at all.

    A recipient can run this before deciding, and so can somebody who is not
    the recipient — which is deliberate. The terms are not a secret; the file
    is.
    """
    header = read_blob_header(path)
    if not header.addressed:
        raise HandoverError("this locked file is not addressed to a vault")
    block = _read_block(path)
    terms = Terms.from_dict(json.loads(block.terms_json.decode("utf-8")))
    return {
        "path": os.path.abspath(path),
        "addressed_to": _addressee_hint(path),
        "terms": terms,
        "plaintext_size": header.plaintext_len,
        "blob_size": os.path.getsize(path),
        "cipher": crypto.cipher_name(header.cipher_id),
    }


def _addressee_hint(path: str) -> str:
    """Which vault this is for, as the short id, read from the header.

    Stored rather than derived, so a recipient with several vaults is told
    which one to open instead of being made to try each.
    """
    header = read_blob_header(path)
    return header.entry_id.hex()[:16]


# --------------------------------------------------------------------------
# sending
# --------------------------------------------------------------------------

def _shared_key(private: X25519PrivateKey, peer: bytes,
                context: bytes) -> SecretBytes:
    shared = private.exchange(X25519PublicKey.from_public_bytes(peer))
    material = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                    info=SHARED_INFO + context).derive(shared)
    return SecretBytes(bytearray(material))


def lock_for(paths: Sequence[str], card: IdentityCard,
             expires: Optional[float] = None,
             max_opens: Optional[int] = None,
             heartbeat_days: Optional[float] = None,
             output_path: Optional[str] = None,
             output_dir: Optional[str] = None,
             note: str = "",
             sender: Optional[Vault] = None,
             delete_originals: bool = False,
             cipher_id: int = crypto.DEFAULT_CIPHER,
             progress: Optional[ProgressFn] = None) -> str:
    """Lock a selection addressed to one vault, on terms it can read first.

    The sender does not need their own vault open — a card is all that is
    required — but passing one records who sent it, which is what lets a
    recipient tell two senders apart.
    """
    if not paths:
        raise HandoverError("no files selected")
    if not card.verify():
        raise HandoverError("that identity card does not verify")

    if output_path is None:
        stem = (os.path.splitext(os.path.basename(str(paths[0])))[0]
                if len(paths) == 1 else f"{len(paths)} items")
        directory = output_dir or os.path.dirname(os.path.abspath(str(paths[0])))
        output_path = free_path(directory, f"{stem} for {card.vault_id[:8]}",
                                HANDOVER_SUFFIX)
    output_path = os.path.abspath(output_path)
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    file_key = SecretBytes.random()
    staging = _staging_path(output_path)
    # The addressee's short id goes in the entry-id field of the header, so a
    # recipient is told which vault this is for rather than made to guess.
    addressee = bytes.fromhex(card.vault_id[:32].ljust(32, "0"))

    try:
        if progress:
            progress("packing", 0.0)
        plans, plaintext_size = archive.pack(
            paths, staging, file_key,
            progress=lambda name, frac: progress and progress(
                f"packing {name}", frac * 0.4))

        terms = Terms(
            expires=expires,
            max_opens=max_opens,
            heartbeat_days=heartbeat_days,
            names=tuple(p.arcname for p in plans),
            sender_vault_id=sender.vault_id if sender is not None else "",
            sender_label=_sender_label(sender),
            note=note,
            sent=time.time(),
        )
        terms_json = json.dumps(terms.to_dict(), separators=(",", ":"),
                                sort_keys=True).encode("utf-8")

        ephemeral = X25519PrivateKey.generate()
        block = HandoverBlock(_public_bytes(ephemeral.public_key()),
                              os.urandom(crypto.NONCE_SIZE), terms_json, b"")

        # Built here with the same values encrypt_stream will use, so the two
        # stay in step. The nonce prefix is zeroed because encrypt_stream
        # chooses its own, exactly as the shared-file path does.
        bare = BlobHeader(cipher_id, addressee, b"\x00" * 4,
                          crypto.CHUNK_SIZE, os.path.getsize(staging),
                          FLAG_ADDRESSED)

        # The terms are inside the associated data, so changing a deadline in
        # transit makes the key refuse to unwrap rather than quietly moving it.
        kek = _shared_key(ephemeral, card.agreement_key, card.agreement_key)
        try:
            _, sealed = crypto.encrypt(
                kek, file_key.bytes(),
                bare.pack() + block.prefix() + terms_json,
                cipher_id, block.nonce)
        finally:
            kek.wipe()
        block.wrapped_key = sealed

        if progress:
            progress("encrypting", 0.4)
        encrypt_stream(staging, output_path, file_key, addressee.hex(),
                       cipher_id=cipher_id, extra_header=block.pack(),
                       flags=FLAG_ADDRESSED,
                       progress=lambda _n, frac: progress and progress(
                           "encrypting", 0.4 + frac * 0.6))
    except BaseException:
        if os.path.exists(output_path):
            shred_file(output_path)
        raise
    finally:
        file_key.wipe()
        if os.path.exists(staging):
            shred_file(staging)

    if delete_originals:
        for path in paths:
            _delete_original(path)

    if sender is not None:
        sender.log_event("handover_sent",
                         to=card.vault_id, files=len(plans),
                         expires=expires, max_opens=max_opens,
                         path=os.path.basename(output_path))
        sender.save()

    if progress:
        progress("done", 1.0)
    return output_path


def _sender_label(sender: Optional[Vault]) -> str:
    if sender is None:
        return ""
    custodian = sender.custodian
    return getattr(custodian, "name", "") or ""


# --------------------------------------------------------------------------
# receiving
# --------------------------------------------------------------------------

def addressed_to_me(vault: Vault, path: str) -> bool:
    """Whether this vault is the one a file is addressed to.

    Cheap and certain: the check is the vault id in the header, not a trial
    decryption, so a folder of files for several people can be sorted without
    the expensive part.
    """
    try:
        header = read_blob_header(path)
    except (OSError, UnsupportedFormat):
        return False
    if not header.addressed:
        return False
    return header.entry_id.hex().startswith(vault.vault_id[:32].lower())


def accept(vault: Vault, path: str,
           keep_file: bool = True) -> Entry:
    """Take the key into this vault, on the terms the file states.

    After this the entry is an ordinary one: it appears in the table, its
    deadline is enforced by this vault's own sweep, and its destruction issues
    a certificate like any other. That is the whole point — the deadline is
    no longer somebody else's business.
    """
    header = read_blob_header(path)
    if not header.addressed:
        raise HandoverError("this locked file is not addressed to a vault")
    if not addressed_to_me(vault, path):
        raise NotAddressedToYou(
            "this file is addressed to a different vault, and no passphrase "
            "will change that — ask the sender for one addressed to yours")

    block = _read_block(path)
    terms = Terms.from_dict(json.loads(block.terms_json.decode("utf-8")))

    private = _x25519_private(vault.signing_seed())
    my_public = _public_bytes(private.public_key())
    bare = BlobHeader(header.cipher_id, header.entry_id, b"\x00" * 4,
                      header.chunk_size, header.plaintext_len, header.flags)
    kek = _shared_key(private, block.ephemeral_key, my_public)
    try:
        plain = crypto.decrypt(
            kek, block.nonce, block.wrapped_key,
            bare.pack() + block.prefix() + block.terms_json,
            header.cipher_id)
    except AuthenticationError as exc:
        raise HandoverError(
            "the key in this file could not be unwrapped. Either it was "
            "altered in transit, or it was addressed to a vault that shares "
            "this one's short id but not its key.") from exc
    finally:
        kek.wipe()

    file_key = SecretBytes(bytearray(plain))
    destination = os.path.abspath(path)
    if not keep_file:
        destination = free_path(
            os.path.dirname(os.path.abspath(vault.path)),
            os.path.splitext(os.path.basename(path))[0], HANDOVER_SUFFIX)
        os.replace(path, destination)

    entry = Entry(
        id=header.entry_id_hex,
        blob_path=destination,
        key=file_key,
        created=time.time(),
        expires=terms.expires,
        names=list(terms.names),
        blob_size=os.path.getsize(destination),
        plaintext_size=header.plaintext_len,
        cipher_id=header.cipher_id,
        blob_sha256=certificate.file_digest(destination) or "",
        max_opens=terms.max_opens,
        heartbeat_days=terms.heartbeat_days,
    )
    vault.add_entry(entry)
    vault.log_event("handover_accepted",
                    entry=entry.id,
                    sender=terms.sender_vault_id or "unidentified",
                    expires=terms.expires,
                    max_opens=terms.max_opens,
                    files=len(terms.names))
    vault.save()
    return entry
