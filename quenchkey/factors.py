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

"""Second factors: what gets mixed into the KDF besides the passphrase.

Three kinds, behind one interface:

``none``
    The passphrase alone.

``keyfile``
    A 4 KiB file Quenchkey generates, with a banner and a checksum so
    corruption is reported rather than discovered when it is too late. Simple,
    portable, and entirely dependent on the file surviving unchanged.

``fido2``
    A hardware security key — YubiKey and similar — using the CTAP2
    ``hmac-secret`` extension. The authenticator holds a secret that never
    leaves it and returns a 32-byte value derived from that secret and a salt
    stored in the vault header. Touching the key is required, and the secret
    cannot be copied off the device, so this is the only factor here that
    resists an attacker who has read every file on the machine.

The parameters a FIDO2 factor needs — credential id and salt — are **not
secret**, and they have to be readable before the vault can be opened, so they
live in the vault's cleartext header. That header is passed to the cipher as
associated data, so they cannot be altered without breaking authentication.

A note on what has been verified
--------------------------------

The keyfile path is covered by the test suite. The FIDO2 path is exercised in
``tests/test_features.py`` through :class:`SimulatedAuthenticator`, which checks
the vault-side logic — that the derived secret reaches the KDF, that a wrong
device fails like a wrong passphrase, that the credential parameters survive a
round trip and are covered by the authentication tag, and that recovery shares
rescue a vault whose key is lost.

None of that proves the code drives real hardware correctly. Everything below
:class:`_HidAuthenticator` has been written against the CTAP2 specification and
has never been run against a physical security key, because no automated suite
can do it. Treat FIDO2 support as needing a hardware check before you rely on
it — test it with a file you can afford to lose — and note that the interface
says the same thing at the point of use.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from dataclasses import dataclass, field
from typing import Optional, Protocol

from . import keyfile as keyfile_module
from .crypto import KEYFILE_DOMAIN, SecretBytes

FACTOR_NONE = "none"
FACTOR_KEYFILE = "keyfile"
FACTOR_FIDO2 = "fido2"

FIDO2_DOMAIN = b"quenchkey/fido2/v1"
FIDO2_RP_ID = "quenchkey.local"
FIDO2_RP_NAME = "Quenchkey"
FIDO2_ORIGIN = "https://quenchkey.local"


class FactorError(Exception):
    """A second factor could not be used."""


class FactorUnavailable(FactorError):
    """The factor is configured but not present right now — no key plugged in."""


class SecondFactor(Protocol):
    """Anything that contributes bytes to the key derivation."""

    kind: str

    def material(self) -> Optional[bytes]:
        """The bytes folded into the KDF, or None for no second factor."""

    def describe(self) -> str:
        """One line for the interface."""

    def public_parameters(self) -> dict:
        """Non-secret state stored in the vault's cleartext header."""


@dataclass
class NoFactor:
    kind: str = FACTOR_NONE

    def material(self) -> Optional[bytes]:
        return None

    def describe(self) -> str:
        return "passphrase only"

    def public_parameters(self) -> dict:
        return {}


@dataclass
class KeyfileFactor:
    path: str
    kind: str = FACTOR_KEYFILE

    def material(self) -> bytes:
        info = keyfile_module.verify(self.path)
        if info.is_quenchkey_keyfile and not info.intact:
            raise FactorError(info.message)
        try:
            digest = hashlib.sha256()
            digest.update(KEYFILE_DOMAIN)
            with open(self.path, "rb") as fh:
                digest.update(fh.read(keyfile_module.KEYFILE_SIZE * 256))
            return digest.digest()
        except OSError as exc:
            raise FactorUnavailable(f"cannot read the keyfile: {exc}") from exc

    def describe(self) -> str:
        return f"keyfile ({os.path.basename(self.path)})"

    def public_parameters(self) -> dict:
        return {}


# --------------------------------------------------------------------------
# FIDO2
# --------------------------------------------------------------------------

class Authenticator(Protocol):
    """The slice of CTAP2 this application needs.

    Narrow on purpose: it keeps the hardware behind one seam, so the vault
    logic can be tested against a simulator without pretending that proves the
    hardware path works.
    """

    def register(self, rp_id: str, user_name: str) -> bytes:
        """Create a credential with hmac-secret and return its credential id."""

    def derive(self, rp_id: str, credential_id: bytes, salt: bytes) -> bytes:
        """Return the 32-byte hmac-secret output for this salt."""

    def describe(self) -> str:
        """Which device this is."""


@dataclass
class Fido2Factor:
    credential_id: bytes
    salt: bytes
    rp_id: str = FIDO2_RP_ID
    device_hint: str = ""
    authenticator: Optional[Authenticator] = field(default=None, repr=False)
    kind: str = FACTOR_FIDO2

    def material(self) -> bytes:
        device = self.authenticator or hardware_authenticator()
        raw = device.derive(self.rp_id, self.credential_id, self.salt)
        if len(raw) != 32:
            raise FactorError(
                f"the security key returned {len(raw)} bytes, expected 32")
        # Domain-separated so the authenticator's output can never be confused
        # with a keyfile digest occupying the same position in the KDF input.
        return hashlib.sha256(FIDO2_DOMAIN + raw).digest()

    def describe(self) -> str:
        return f"security key ({self.device_hint or 'FIDO2'})"

    def public_parameters(self) -> dict:
        return {
            "kind": FACTOR_FIDO2,
            "credential_id": self.credential_id.hex(),
            "salt": self.salt.hex(),
            "rp_id": self.rp_id,
            "device_hint": self.device_hint,
        }

    @classmethod
    def from_parameters(cls, params: dict,
                        authenticator: Optional[Authenticator] = None) -> "Fido2Factor":
        try:
            return cls(
                credential_id=bytes.fromhex(params["credential_id"]),
                salt=bytes.fromhex(params["salt"]),
                rp_id=params.get("rp_id", FIDO2_RP_ID),
                device_hint=params.get("device_hint", ""),
                authenticator=authenticator,
            )
        except (KeyError, ValueError) as exc:
            raise FactorError(
                f"the vault's security-key parameters are malformed: {exc}") from exc

    @classmethod
    def enrol(cls, authenticator: Optional[Authenticator] = None,
              user_name: str = "quenchkey") -> "Fido2Factor":
        """Register a new credential on a security key."""
        device = authenticator or hardware_authenticator()
        credential_id = device.register(FIDO2_RP_ID, user_name)
        return cls(credential_id=credential_id, salt=secrets.token_bytes(32),
                   device_hint=device.describe(), authenticator=device)


def fido2_available() -> tuple[bool, str]:
    """Whether the library is installed and a key appears to be plugged in."""
    try:
        from fido2.hid import CtapHidDevice
    except ImportError:
        return False, ("the fido2 package is not installed "
                       "(pip install fido2)")
    try:
        devices = list(CtapHidDevice.list_devices())
    except Exception as exc:  # noqa: BLE001 - hardware enumeration is fragile
        return False, f"could not look for security keys: {exc}"
    if not devices:
        return False, "no security key is plugged in"
    return True, f"{len(devices)} security key{'s' if len(devices) != 1 else ''} found"


def hardware_authenticator() -> Authenticator:
    """The real CTAP2 authenticator. Raises if none is usable."""
    ok, reason = fido2_available()
    if not ok:
        raise FactorUnavailable(reason)
    return _HidAuthenticator()


class _HidAuthenticator:
    """Drives a physical security key over USB HID.

    Untested against hardware from the environment this was built in — see the
    module docstring. The logic around it is covered; this part is not.
    """

    def _client(self):
        from fido2.client import Fido2Client
        from fido2.hid import CtapHidDevice

        devices = list(CtapHidDevice.list_devices())
        if not devices:
            raise FactorUnavailable("no security key is plugged in")
        return Fido2Client(devices[0], FIDO2_ORIGIN), devices[0]

    def describe(self) -> str:
        try:
            from fido2.hid import CtapHidDevice

            device = next(iter(CtapHidDevice.list_devices()), None)
            return getattr(device, "product_name", None) or "FIDO2 security key"
        except Exception:  # noqa: BLE001
            return "FIDO2 security key"

    def register(self, rp_id: str, user_name: str) -> bytes:
        from fido2.webauthn import (
            PublicKeyCredentialCreationOptions, PublicKeyCredentialParameters,
            PublicKeyCredentialRpEntity, PublicKeyCredentialType,
            PublicKeyCredentialUserEntity, UserVerificationRequirement,
        )

        client, _device = self._client()
        options = PublicKeyCredentialCreationOptions(
            rp=PublicKeyCredentialRpEntity(id=rp_id, name=FIDO2_RP_NAME),
            user=PublicKeyCredentialUserEntity(
                id=os.urandom(16), name=user_name, display_name=user_name),
            challenge=os.urandom(32),
            pub_key_cred_params=[
                PublicKeyCredentialParameters(
                    type=PublicKeyCredentialType.PUBLIC_KEY, alg=-7),
                PublicKeyCredentialParameters(
                    type=PublicKeyCredentialType.PUBLIC_KEY, alg=-8),
            ],
            user_verification=UserVerificationRequirement.DISCOURAGED,
            extensions={"hmacCreateSecret": True},
        )
        try:
            result = client.make_credential(options)
        except Exception as exc:  # noqa: BLE001
            raise FactorError(f"the security key refused to register: {exc}") from exc

        extensions = getattr(result, "extension_results", None) or {}
        if not extensions.get("hmacCreateSecret"):
            raise FactorError(
                "this security key does not support the hmac-secret extension, "
                "which is what Quenchkey needs in order to derive a key from "
                "it. Most YubiKey 5 and later models do; older and simpler "
                "U2F-only keys do not.")
        return result.attestation_object.auth_data.credential_data.credential_id

    def derive(self, rp_id: str, credential_id: bytes, salt: bytes) -> bytes:
        from fido2.webauthn import (
            PublicKeyCredentialDescriptor, PublicKeyCredentialRequestOptions,
            PublicKeyCredentialType, UserVerificationRequirement,
        )

        client, _device = self._client()
        options = PublicKeyCredentialRequestOptions(
            challenge=os.urandom(32),
            rp_id=rp_id,
            allow_credentials=[PublicKeyCredentialDescriptor(
                type=PublicKeyCredentialType.PUBLIC_KEY, id=credential_id)],
            user_verification=UserVerificationRequirement.DISCOURAGED,
            extensions={"hmacGetSecret": {"salt1": salt}},
        )
        try:
            assertion = client.get_assertion(options)
            response = assertion.get_response(0)
        except Exception as exc:  # noqa: BLE001
            raise FactorError(
                f"the security key would not produce a secret: {exc}") from exc

        extensions = getattr(response, "extension_results", None) or {}
        secret = (extensions.get("hmacGetSecret") or {}).get("output1")
        if not secret:
            raise FactorError(
                "the security key did not return an hmac-secret value. It may "
                "be a different key from the one this vault was created with.")
        return bytes(secret)


class SimulatedAuthenticator:
    """A deterministic stand-in for a security key, for tests and demos.

    It reproduces the *contract* — a per-device secret that never leaves it,
    an HMAC over the salt — without any hardware. It is emphatically not a
    security device: its "device secret" is an ordinary value in memory. It
    exists so the vault-side logic can be tested, and it is never reachable
    from the application.
    """

    def __init__(self, device_secret: Optional[bytes] = None, name: str = "simulated key"):
        self._secret = device_secret or os.urandom(32)
        self._credentials: dict[bytes, bytes] = {}
        self._name = name

    def describe(self) -> str:
        return self._name

    def register(self, rp_id: str, user_name: str) -> bytes:
        credential_id = os.urandom(32)
        self._credentials[credential_id] = hashlib.sha256(
            self._secret + rp_id.encode() + credential_id).digest()
        return credential_id

    def derive(self, rp_id: str, credential_id: bytes, salt: bytes) -> bytes:
        import hmac

        seed = self._credentials.get(credential_id)
        if seed is None:
            # A real authenticator cannot answer for a credential it does not
            # hold, and neither does this.
            raise FactorUnavailable(
                "this security key does not hold the credential the vault "
                "expects: it is a different key")
        return hmac.new(seed, salt, hashlib.sha256).digest()


# --------------------------------------------------------------------------
# assembling the KDF input
# --------------------------------------------------------------------------

def build_kdf_input(passphrase: str, factor: Optional[SecondFactor] = None) -> SecretBytes:
    """Combine the passphrase with a second factor, if there is one.

    The factor's contribution is a fixed-length digest appended after a
    separator byte, so no passphrase can ever be confused with a
    passphrase-plus-factor, and the two factors cannot be swapped for one
    another.
    """
    parts = bytearray(passphrase.encode("utf-8"))
    material = factor.material() if factor is not None else None
    if material is not None:
        parts += b"\x00"
        parts += material
    secret = SecretBytes(parts)
    for index in range(len(parts)):
        parts[index] = 0
    return secret


def from_parameters(kind: str, params: dict, keyfile_path: Optional[str] = None,
                    authenticator: Optional[Authenticator] = None) -> SecondFactor:
    """Rebuild the factor a vault expects, given what its header records."""
    if kind == FACTOR_NONE:
        return NoFactor()
    if kind == FACTOR_KEYFILE:
        if not keyfile_path:
            raise FactorError("this vault requires its keyfile")
        return KeyfileFactor(keyfile_path)
    if kind == FACTOR_FIDO2:
        return Fido2Factor.from_parameters(params, authenticator)
    raise FactorError(f"unknown second factor {kind!r}")
