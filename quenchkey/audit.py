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

"""Letting somebody check the retention without letting them read anything.

A retention policy is somebody else's business as often as it is your own: a
data protection officer who has to confirm that last year's files really did
expire, an auditor who wants the event log, a client who wants evidence their
documents were destroyed. Handing any of them the vault passphrase is absurd —
it opens every document in it. Handing them nothing means they take your word.

So this writes a **separate record** beside the vault, under a passphrase of
its own, holding the things an auditor needs and nothing else:

* every entry's name, size, rules, opening count, deadline and — if it has
  happened — the moment its key was destroyed and why;
* the whole hash-chained event log, which they can verify independently;
* the certificates of destruction the vault has issued;
* the vault's own identity and the anchor.

And not, anywhere, a file key. Not wrapped, not derived, not in a form that
could be turned into one. The record is *built from* the vault rather than
being a partial view of it, so there is no key in the file for an auditor to
attack, however patient they are. That is a stronger statement than "we did
not give them the key", and it is the reason for doing it this way rather than
by re-encrypting a slice of the vault.

The record is also **signed** with the vault's own signing key, the one that
signs certificates of destruction. An auditor holding any certificate from
this vault already has the public key, so they can confirm the record came
from the vault it claims to and was not typed up afterwards by somebody with
an interest in what it says.

What it cannot do, stated here because the interface states it too: it is a
snapshot, refreshed when the vault is saved. An auditor reading a record from
a vault that has not been opened since March is reading March. The record says
when it was written, and comparing its anchor against one you published is how
they tell whether they are looking at the current history or an old one.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import certificate, chain, crypto
from .crypto import AuthenticationError

#: Written beside the vault, like the expiry index.
RECORD_SUFFIX = ".audit"

RECORD_MAGIC = b"QKEYAUDT"
RECORD_VERSION = 1

#: Owner-only. The contents are encrypted, so this is belt and braces.
FILE_MODE = 0o600

#: Where the salt and cost for the audit passphrase live, inside the vault.
NOTE_KEY = "audit_record"

SIGNATURE_DOMAIN = b"quenchkey/audit-record/v1"

#: Ed25519 signatures are a fixed 64 bytes, which is how the body and the
#: signature are told apart on the way back in.
SIGNATURE_LEN = 64


class AuditError(Exception):
    """An audit record could not be written or read."""


class NotArmed(AuditError):
    """This vault does not publish an audit record."""


# --------------------------------------------------------------------------
# what an auditor gets
# --------------------------------------------------------------------------

@dataclass
class AuditEntry:
    """One entry, as far as somebody without the keys is concerned."""

    id: str
    name: str
    created: float
    expires: Optional[float]
    heartbeat_days: Optional[float]
    max_opens: Optional[int]
    open_count: int
    plaintext_size: int
    blob_size: int
    blob_sha256: str
    destroyed: bool
    destroyed_at: Optional[float] = None
    reason: str = ""

    def to_dict(self) -> dict:
        return dict(self.__dict__)

    @classmethod
    def from_dict(cls, raw: dict) -> "AuditEntry":
        return cls(**{k: raw.get(k) for k in cls.__dataclass_fields__})

    def state(self) -> str:
        if self.destroyed:
            return "key destroyed"
        if self.expires is None and self.heartbeat_days is None \
                and self.max_opens is None:
            return "held, no rules"
        return "live"


@dataclass
class AuditRecord:
    """Everything the record says, once it has been opened."""

    vault_id: str
    written: float
    anchor: str
    chain_head: str
    entries: list = field(default_factory=list)
    events: list = field(default_factory=list)
    certificates: list = field(default_factory=list)
    custodian: dict = field(default_factory=dict)
    chain_ok: bool = False
    chain_note: str = ""
    signature_ok: bool = False
    signed_by: str = ""

    @property
    def destroyed(self) -> list:
        return [e for e in self.entries if e.destroyed]

    @property
    def live(self) -> list:
        return [e for e in self.entries if not e.destroyed]

    def summary(self) -> str:
        total = len(self.entries)
        gone = len(self.destroyed)
        from . import expiry as expiry_mod
        return (f"{total} entr{'ies' if total != 1 else 'y'}, {gone} with the "
                f"key destroyed, {len(self.events)} events, "
                f"{len(self.certificates)} certificate"
                f"{'s' if len(self.certificates) != 1 else ''}. Written "
                f"{expiry_mod.format_time(self.written)}.")

    def verdict(self) -> str:
        """Whether this record can be relied on, and what would improve it."""
        if not self.signature_ok:
            return ("The signature on this record does not verify against the "
                    "key supplied, so it cannot be shown to have come from "
                    "that vault. Treat it as an unsigned document.")
        if not self.chain_ok:
            return (f"Signed by vault {self.signed_by[:16]}, but the event "
                    f"chain inside it does not verify: {self.chain_note}")
        return (f"Signed by vault {self.signed_by[:16]}, and the event chain "
                f"inside it verifies from end to end. Compare the anchor "
                f"{self.anchor} against one published independently to "
                f"confirm this is the current history rather than an older "
                f"one.")


def _record_body(record: AuditRecord) -> dict:
    return {
        "vault_id": record.vault_id,
        "written": record.written,
        "anchor": record.anchor,
        "chain_head": record.chain_head,
        "entries": [e.to_dict() for e in record.entries],
        "events": record.events,
        "certificates": record.certificates,
        "custodian": record.custodian,
    }


# --------------------------------------------------------------------------
# arming it
# --------------------------------------------------------------------------

def record_path(vault_path: str) -> str:
    return vault_path + RECORD_SUFFIX


def is_armed(vault) -> bool:
    return bool(vault.note(NOTE_KEY))


def arm(vault, passphrase: str,
        kdf_params: Optional[crypto.KdfParams] = None) -> str:
    """Start publishing an audit record, under a passphrase of its own.

    The passphrase is never stored. What is stored is the salt and cost used
    to derive a key from it, exactly as the vault does for its own — so
    guessing at the record costs an attacker the same Argon2id work per guess
    that guessing at the vault does.

    Nothing here can stop you choosing the vault's own passphrase for this,
    because the vault does not keep its passphrase and so has nothing to
    compare against. Choosing it anyway would hand an auditor the vault, which
    is the one thing this feature exists to avoid; the dialog says so.
    """
    if not passphrase:
        raise AuditError("an audit record needs a passphrase of its own")
    kdf = kdf_params or crypto.calibrate_kdf()
    vault.set_note(NOTE_KEY, {
        "salt": kdf.salt.hex(),
        "time_cost": kdf.time_cost,
        "memory_kib": kdf.memory_kib,
        "parallelism": kdf.parallelism,
        "armed": time.time(),
    })
    vault.log_event("audit_record_armed",
                    argon2_time=kdf.time_cost, argon2_memory_kib=kdf.memory_kib)
    vault.save()
    return write(vault, passphrase)


def disarm(vault) -> bool:
    """Stop publishing, and remove the record that is already there."""
    if not is_armed(vault):
        return False
    vault.set_note(NOTE_KEY, None)
    vault.log_event("audit_record_disarmed")
    vault.save()
    target = record_path(vault.path)
    if os.path.exists(target):
        try:
            os.unlink(target)
        except OSError:
            return False
    return True


def _kdf_for(vault) -> crypto.KdfParams:
    stored = vault.note(NOTE_KEY)
    if not stored:
        raise NotArmed("this vault does not publish an audit record")
    return crypto.KdfParams(
        salt=bytes.fromhex(stored["salt"]),
        time_cost=int(stored["time_cost"]),
        memory_kib=int(stored["memory_kib"]),
        parallelism=int(stored["parallelism"]),
    )


# --------------------------------------------------------------------------
# writing one
# --------------------------------------------------------------------------

def build(vault) -> AuditRecord:
    """Assemble the record from an open vault. Nothing is written."""
    report = vault.chain_report()
    entries = []
    for entry in vault.entries():
        entries.append(AuditEntry(
            id=entry.id,
            name=entry.display_name,
            created=entry.created,
            expires=entry.expires,
            heartbeat_days=entry.heartbeat_days,
            max_opens=entry.max_opens,
            open_count=entry.open_count,
            plaintext_size=entry.plaintext_size,
            blob_size=entry.blob_size,
            blob_sha256=entry.blob_sha256,
            destroyed=entry.key_destroyed,
            destroyed_at=entry.expired_at,
            reason=_reason_for(vault, entry.id),
        ))
    return AuditRecord(
        vault_id=vault.vault_id,
        written=time.time(),
        anchor=vault.chain_fingerprint,
        chain_head=vault.chain_head,
        entries=entries,
        events=list(vault.events),
        certificates=list(vault.certificates),
        custodian=vault.custodian.to_dict(),
        chain_ok=report.ok,
        chain_note=report.summary(),
    )


def _reason_for(vault, entry_id: str) -> str:
    for event in reversed(vault.events):
        if event.get("kind") == "key_destroyed" and event.get("entry") == entry_id:
            return str(event.get("reason", ""))
    return ""


def write(vault, passphrase: str) -> str:
    """Write the record beside the vault, encrypted and signed."""
    kdf = _kdf_for(vault)
    record = build(vault)
    body = _record_body(record)
    plain = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")

    signature = certificate.private_key(vault.signing_seed()).sign(
        SIGNATURE_DOMAIN + plain)

    secret = crypto.build_kdf_input(passphrase)
    key = crypto.derive_master_key(secret, kdf)
    try:
        header = json.dumps({
            "magic": RECORD_MAGIC.decode(),
            "version": RECORD_VERSION,
            "vault_id": vault.vault_id,
            "public_key": vault.public_key.hex(),
            "written": record.written,
            "salt": kdf.salt.hex(),
            "time_cost": kdf.time_cost,
            "memory_kib": kdf.memory_kib,
            "parallelism": kdf.parallelism,
        }, separators=(",", ":"), sort_keys=True).encode("utf-8")
        # The signature goes last and is always 64 bytes, so the split on
        # the way back is by length. A separator byte would be ambiguous: an
        # Ed25519 signature is raw bytes and contains whichever it likes.
        nonce, sealed = crypto.encrypt(key, plain + signature, header)
    finally:
        key.wipe()
        secret.wipe()

    document = {
        "header": header.decode("utf-8"),
        "nonce": nonce.hex(),
        "body": sealed.hex(),
    }
    target = record_path(vault.path)
    handle = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, FILE_MODE)
    with os.fdopen(handle, "w") as fh:
        json.dump(document, fh, separators=(",", ":"))
    return target


def written_at(vault_path: str) -> Optional[float]:
    """When the record beside this vault was last written. None if there is none."""
    try:
        with open(record_path(vault_path)) as fh:
            header = json.loads(json.load(fh)["header"])
        return float(header.get("written", 0)) or None
    except (OSError, ValueError, KeyError):
        return None


# --------------------------------------------------------------------------
# reading one, with no vault anywhere
# --------------------------------------------------------------------------

def read(path: str, passphrase: str,
         public_key: Optional[bytes] = None) -> AuditRecord:
    """Open an audit record. Needs its passphrase and nothing else.

    ``public_key`` is the vault's, from any certificate it has issued. Supply
    it and the signature is checked against a key you brought yourself, which
    is the only version of that check worth anything. Leave it out and the key
    inside the record is used, which proves the record is internally
    consistent and nothing more — stated in the verdict rather than glossed.
    """
    try:
        with open(path) as fh:
            document = json.load(fh)
        header_raw = document["header"].encode("utf-8")
        header = json.loads(document["header"])
        nonce = bytes.fromhex(document["nonce"])
        sealed = bytes.fromhex(document["body"])
    except (OSError, ValueError, KeyError) as exc:
        raise AuditError(f"could not read that audit record: {exc}") from exc

    if header.get("magic") != RECORD_MAGIC.decode():
        raise AuditError("that is not a Quenchkey audit record")
    if header.get("version") != RECORD_VERSION:
        raise AuditError(
            f"audit record version {header.get('version')}; this build "
            f"understands {RECORD_VERSION}")

    kdf = crypto.KdfParams(
        salt=bytes.fromhex(header["salt"]),
        time_cost=int(header["time_cost"]),
        memory_kib=int(header["memory_kib"]),
        parallelism=int(header["parallelism"]),
    )
    secret = crypto.build_kdf_input(passphrase)
    key = crypto.derive_master_key(secret, kdf)
    try:
        plain = crypto.decrypt(key, nonce, sealed, header_raw)
    except AuthenticationError:
        raise AuditError(
            "wrong passphrase for this audit record, or it has been "
            "altered — there is no way to tell those apart and no reason "
            "to guess") from None
    finally:
        key.wipe()
        secret.wipe()

    if len(plain) <= SIGNATURE_LEN:
        raise AuditError("this audit record is truncated")
    body_raw, signature = plain[:-SIGNATURE_LEN], plain[-SIGNATURE_LEN:]
    body = json.loads(body_raw.decode("utf-8"))

    claimed = bytes.fromhex(header.get("public_key", ""))
    checking_against = public_key or claimed
    signature_ok = False
    if checking_against:
        try:
            Ed25519PublicKey.from_public_bytes(checking_against).verify(
                signature, SIGNATURE_DOMAIN + body_raw)
            signature_ok = True
        except (InvalidSignature, ValueError):
            signature_ok = False

    record = AuditRecord(
        vault_id=str(body.get("vault_id", "")),
        written=float(body.get("written", 0)),
        anchor=str(body.get("anchor", "")),
        chain_head=str(body.get("chain_head", "")),
        entries=[AuditEntry.from_dict(e) for e in body.get("entries", [])],
        events=list(body.get("events", [])),
        certificates=list(body.get("certificates", [])),
        custodian=dict(body.get("custodian", {})),
        signature_ok=signature_ok,
        signed_by=certificate.vault_id(checking_against) if checking_against else "",
    )

    # Verified here rather than trusted from the record: the point of handing
    # somebody the events is that they can check them themselves.
    report = chain.verify(record.events)
    record.chain_ok = report.ok
    record.chain_note = report.summary()
    if public_key is None:
        record.chain_note += (
            " The signature was checked against the key inside the record, "
            "which shows only that the record is internally consistent. "
            "Supply the vault's public key from a certificate to check it "
            "against a key you brought yourself.")
    return record


def key_material_in(record: AuditRecord) -> list:
    """Any 64-character hex string in the record that is not accounted for.

    A blunt instrument on purpose. It is looking for something that should not
    be there at all, so it errs towards flagging, and everything it does *not*
    flag is excluded by name with a reason:

    * ``blob_sha256`` — the digest of a locked file, which an auditor checking
      that a file has not been swapped needs, and which is a hash of
      ciphertext rather than a key;
    * the ``hash`` and ``prev`` of each event, which are the chain itself and
      are what makes it verifiable;
    * the vault's Ed25519 public key, which appears on every certificate it
      issues and is public by definition;
    * the digests certificates record of the files they cover.

    Anything else of that shape is unexplained, and the tests treat an
    unexplained one as a failure.
    """
    import re

    allowed = set()
    for entry in record.entries:
        if entry.blob_sha256:
            allowed.add(entry.blob_sha256)
    for event in record.events:
        for field_name in ("hash", "prev", "sha256", "blob_sha256", "chain_head"):
            value = event.get(field_name)
            if isinstance(value, str):
                allowed.add(value)
    for document in record.certificates:
        for field_name in ("public_key", "locked_file_sha256", "sha256",
                           "vault_public_key"):
            value = document.get(field_name)
            if isinstance(value, str):
                allowed.add(value)
    allowed.add(record.chain_head)

    blob = json.dumps(_record_body(record), default=str)
    return sorted({found for found in re.findall(r"\b[0-9a-f]{64}\b", blob)
                   if found not in allowed})
