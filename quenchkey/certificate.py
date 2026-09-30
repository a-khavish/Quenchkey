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

"""Certificates of destruction.

NIST SP 800-88 classifies **Cryptographic Erase** — sanitising data by
destroying its key rather than overwriting the bytes — as a *Purge*-level
technique, one that "renders Target Data recovery infeasible using state of the
art laboratory techniques". That is precisely what Quenchkey does when a
deadline passes.

The same document names the weakness of the method: it is hard to *verify*. It
asks for a record of sanitization carrying the method, the tool, the date, the
verification approach and the person responsible, and it warns that anyone
unable to verify a cryptographic erase should use a method they can verify
instead.

This module produces that record. When a key is destroyed, the vault signs a
statement of what was destroyed and when, with an Ed25519 key belonging to the
vault. Anyone can check the signature — with the bundled recovery script, or
twenty lines of their own — without the passphrase, without the vault, and
without this application.

What a certificate does and does not prove
------------------------------------------

It **does** prove, to anyone holding the vault's public key:

* that this vault, and not some other, issued the statement;
* that the statement has not been altered by a single byte since;
* which file it refers to, by SHA-256 of the encrypted blob;
* where the destruction sits in the vault's event chain.

It **does not** prove that no copy of the key was taken before the destruction,
that no copy of the plaintext exists elsewhere, or that the machine's clock was
honest. A certificate is evidence produced by the vault about itself. That is
worth a great deal more than an assertion in an email, and a great deal less
than an independent audit — so every certificate carries that caveat in its own
text, where it travels with the document rather than living in a manual.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

from . import chain
from .crypto import SecretBytes

CERTIFICATE_FORMAT = "quenchkey-destruction-certificate"
CERTIFICATE_VERSION = 1
SIGNATURE_DOMAIN = b"quenchkey/certificate/v1"

#: Reproduced on every certificate. Written to be read by somebody who has
#: never heard of this tool and is deciding how much the document is worth.
LIMITATIONS = (
    "This certificate is evidence produced by the vault about its own actions. "
    "It proves that the vault identified below destroyed the key for the named "
    "item at the stated time, and that this document has not been altered "
    "since. It does not prove that no copy of the key was taken before that "
    "moment, that no copy of the unencrypted content exists elsewhere, or that "
    "the clock of the machine involved was accurate. Sanitization of the "
    "encrypted file itself was not performed unless stated; the method relies "
    "on the destruction of the key, per NIST SP 800-88 Cryptographic Erase."
)

METHOD = (
    "Cryptographic Erase (NIST SP 800-88 Rev. 1, Purge). The 256-bit content "
    "encryption key was overwritten with zeros inside the vault and the vault "
    "was rewritten. No other copy of that key was ever stored."
)

#: Restated on the certificate, because a reader has to judge whether the
#: erase was applicable at all.
APPLICABILITY = (
    "The content was encrypted before being written to the .qkey file, with a "
    "key generated for that item alone. NIST SP 800-88 cautions against relying "
    "on Cryptographic Erase where data was stored unencrypted before encryption "
    "was enabled; that does not apply here, but it does apply to any copy of "
    "the original content that existed outside the .qkey file."
)


class CertificateError(Exception):
    """A certificate failed to verify."""


# --------------------------------------------------------------------------
# vault identity
# --------------------------------------------------------------------------

def new_signing_seed() -> SecretBytes:
    return SecretBytes(os.urandom(32))


def private_key(seed: SecretBytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(seed.bytes())


def public_key_bytes(seed: SecretBytes) -> bytes:
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat,
    )
    return private_key(seed).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)


def vault_id(public_key: bytes) -> str:
    """A short, stable name for a vault, derived from its public key.

    Printed on certificates so a recipient can tell two vaults apart, and can
    confirm that a batch of certificates all came from the same one.
    """
    return hashlib.sha256(b"quenchkey/vault-id/v1" + public_key).hexdigest()[:32]


def file_digest(path: str) -> Optional[str]:
    """SHA-256 of a file, or None if it is not there any more."""
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as fh:
            for block in iter(lambda: fh.read(1 << 20), b""):
                digest.update(block)
        return digest.hexdigest()
    except OSError:
        return None


# --------------------------------------------------------------------------
# issuing
# --------------------------------------------------------------------------

@dataclass
class Custodian:
    """The person answerable for the destruction, as NIST asks for.

    Entirely optional, and empty by default — a personal vault has no need of
    it. It exists so that a certificate produced inside an organisation can
    carry the same fields its auditors already expect.
    """

    name: str = ""
    title: str = ""
    contact: str = ""
    organisation: str = ""

    def to_dict(self) -> dict:
        return {"name": self.name, "title": self.title,
                "contact": self.contact, "organisation": self.organisation}

    @classmethod
    def from_dict(cls, data: Optional[dict]) -> "Custodian":
        data = data or {}
        return cls(data.get("name", ""), data.get("title", ""),
                   data.get("contact", ""), data.get("organisation", ""))

    @property
    def is_set(self) -> bool:
        return any((self.name, self.title, self.contact, self.organisation))


def issue(seed: SecretBytes, entry, *, destroyed_at: float, reason: str,
          cipher: str, kdf_description: str, chain_seq: int, chain_head: str,
          tool: str, custodian: Optional[Custodian] = None,
          blob_sha256: Optional[str] = None,
          blob_present_at_destruction: bool = False,
          blob_deleted: bool = False) -> dict:
    """Build and sign a certificate for one destroyed entry."""
    public = public_key_bytes(seed)

    body = {
        "format": CERTIFICATE_FORMAT,
        "version": CERTIFICATE_VERSION,
        "vault_id": vault_id(public),
        "issued_at": destroyed_at,
        "item": {
            "entry_id": entry.id,
            "names": list(entry.names),
            "label": entry.label,
            "locked_file": entry.blob_path,
            "locked_file_sha256": blob_sha256 or entry.blob_sha256 or None,
            "locked_file_present_at_destruction": blob_present_at_destruction,
            "locked_file_deleted_by_quenchkey": blob_deleted,
            "encrypted_size_bytes": entry.blob_size,
            "content_size_bytes": entry.plaintext_size,
            "locked_at": entry.created,
            "scheduled_destruction": entry.expires,
        },
        "destruction": {
            "destroyed_at": destroyed_at,
            "reason": reason,
            "method": METHOD,
            "applicability": APPLICABILITY,
            "cipher": cipher,
            "key_derivation": kdf_description,
            "key_length_bits": 256,
        },
        "evidence": {
            "chain_seq": chain_seq,
            "chain_head": chain_head,
            "chain_fingerprint": chain.fingerprint(chain_head),
        },
        "custodian": (custodian or Custodian()).to_dict(),
        "tool": tool,
        "limitations": LIMITATIONS,
    }

    signature = private_key(seed).sign(
        SIGNATURE_DOMAIN + chain.canonical(body))
    return {
        "certificate": body,
        "public_key": public.hex(),
        "signature": signature.hex(),
    }


# --------------------------------------------------------------------------
# verifying
# --------------------------------------------------------------------------

@dataclass
class VerificationResult:
    ok: bool
    reason: str
    vault_id: str = ""
    entry_id: str = ""
    destroyed_at: Optional[float] = None

    def summary(self) -> str:
        return ("Signature valid. " + self.reason) if self.ok else \
            ("Signature INVALID. " + self.reason)


def verify(document: dict, expected_public_key: Optional[bytes] = None) -> VerificationResult:
    """Check a certificate's signature, and optionally who signed it.

    Passing ``expected_public_key`` is what turns "this is internally
    consistent" into "this came from the vault I already know about". Without
    it, a certificate only proves that *whoever holds the embedded public key*
    signed it — which anybody could arrange for a vault of their own.
    """
    try:
        body = document["certificate"]
        public = bytes.fromhex(document["public_key"])
        signature = bytes.fromhex(document["signature"])
    except (KeyError, TypeError, ValueError) as exc:
        return VerificationResult(False, f"malformed certificate: {exc}")

    if body.get("format") != CERTIFICATE_FORMAT:
        return VerificationResult(False, "not a Quenchkey destruction certificate.")
    if body.get("version") != CERTIFICATE_VERSION:
        return VerificationResult(
            False, f"certificate version {body.get('version')} is not supported.")

    try:
        Ed25519PublicKey.from_public_bytes(public).verify(
            signature, SIGNATURE_DOMAIN + chain.canonical(body))
    except (InvalidSignature, ValueError):
        return VerificationResult(
            False, "the contents do not match the signature: this document has "
                   "been altered, or was not signed by the key it names.")

    if body.get("vault_id") != vault_id(public):
        return VerificationResult(
            False, "the vault id does not match the public key it was signed with.")

    if expected_public_key is not None and public != expected_public_key:
        return VerificationResult(
            False, "signed by a different vault than the one expected.",
            body.get("vault_id", ""), body["item"]["entry_id"])

    trust = ("It was signed by the vault you specified."
             if expected_public_key is not None else
             "Note that no expected vault was given, so this confirms only "
             "that the document is internally consistent and unaltered — not "
             "that it came from any particular vault.")
    return VerificationResult(True, trust, body.get("vault_id", ""),
                              body["item"]["entry_id"],
                              body["destruction"]["destroyed_at"])


def check_file(document: dict, path: str) -> tuple[bool, str]:
    """Confirm a .qkey file on disk is the one a certificate describes."""
    recorded = document["certificate"]["item"].get("locked_file_sha256")
    if not recorded:
        return False, "the certificate records no hash for the locked file."
    actual = file_digest(path)
    if actual is None:
        return False, f"cannot read {path}."
    if actual != recorded:
        return False, ("this file is NOT the one the certificate describes: "
                       f"its hash is {actual[:16]}..., the certificate says "
                       f"{recorded[:16]}...")
    return True, ("This file is the one the certificate describes, and its key "
                  "was destroyed. It cannot be decrypted by anything.")


def to_json(document: dict) -> str:
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False)


def filename_for(document: dict) -> str:
    body = document["certificate"]
    import time as _time
    stamp = _time.strftime("%Y%m%d-%H%M%S",
                           _time.localtime(body["destruction"]["destroyed_at"]))
    return f"quenchkey-destruction-{stamp}-{body['item']['entry_id'][:8]}.json"
