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

"""Cryptographic primitives for Quenchkey.

Nothing here is hand-rolled. Argon2id comes from ``argon2-cffi``; the
authenticated ciphers come from ``cryptography`` (which wraps OpenSSL).

Two ciphers are supported so that the on-disk format can migrate later:

===  =========================  ===================================
id   name                       notes
===  =========================  ===================================
1    ChaCha20-Poly1305          default; fast without AES hardware
2    AES-256-GCM                for CPUs with AES-NI
===  =========================  ===================================

Both are AEAD constructions: every byte of associated data is covered by the
authentication tag, so flipping a bit in a header field makes decryption fail
loudly instead of silently returning wrong metadata.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import struct
import time
from dataclasses import dataclass
from typing import Optional

from argon2.low_level import Type as Argon2Type
from argon2.low_level import hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

# --------------------------------------------------------------------------
# constants
# --------------------------------------------------------------------------

KEY_SIZE = 32          # 256-bit keys throughout
NONCE_SIZE = 12        # 96-bit nonces, as both ciphers expect
TAG_SIZE = 16          # Poly1305 / GCM tag
SALT_SIZE = 16

CIPHER_CHACHA20_POLY1305 = 1
CIPHER_AES_256_GCM = 2
DEFAULT_CIPHER = CIPHER_CHACHA20_POLY1305

KDF_ARGON2ID = 1

#: Domain separator mixed in when a keyfile is used, so that a passphrase
#: alone can never produce the same KDF input as passphrase + keyfile.
KEYFILE_DOMAIN = b"quenchkey/keyfile/v1"

#: How much of a keyfile is read. VeraCrypt uses the same limit; it keeps the
#: KDF input bounded and makes the behaviour predictable for large files.
KEYFILE_READ_BYTES = 1024 * 1024


class CryptoError(Exception):
    """Base class for cryptographic failures."""


class AuthenticationError(CryptoError):
    """Ciphertext or associated data failed authentication.

    Raised for a wrong passphrase, a wrong or missing keyfile, a corrupted
    file, and a deliberately edited one. The cause is indistinguishable by
    design: an attacker learns nothing from the error.
    """


class UnsupportedFormat(CryptoError):
    """The file was written by a version of Quenchkey this build cannot read."""


# --------------------------------------------------------------------------
# secret buffers
# --------------------------------------------------------------------------

class SecretBytes:
    """A mutable byte buffer that can be wiped.

    Python's ``bytes`` objects are immutable and may be copied freely by the
    interpreter, so key material is held in ``bytearray`` and overwritten as
    soon as it is no longer needed. This is a best-effort measure — see the
    "What this does not protect against" section of the README — but it does
    shorten the window in which a key sits in the process heap, and it keeps
    keys out of tracebacks and logs.
    """

    __slots__ = ("_buf", "_wiped")

    def __init__(self, data: bytes | bytearray):
        self._buf = bytearray(data)
        self._wiped = False

    @classmethod
    def random(cls, size: int = KEY_SIZE) -> "SecretBytes":
        return cls(os.urandom(size))

    @classmethod
    def zeros(cls, size: int = KEY_SIZE) -> "SecretBytes":
        return cls(bytes(size))

    def bytes(self) -> bytes:
        if self._wiped:
            raise CryptoError("secret has been wiped")
        return bytes(self._buf)

    @property
    def raw(self) -> bytearray:
        if self._wiped:
            raise CryptoError("secret has been wiped")
        return self._buf

    def is_zero(self) -> bool:
        """True when every byte is zero, i.e. the key has been shredded."""
        if self._wiped:
            return True
        return not any(self._buf)

    def wipe(self) -> None:
        for i in range(len(self._buf)):
            self._buf[i] = 0
        self._wiped = True

    @property
    def wiped(self) -> bool:
        return self._wiped

    def __len__(self) -> int:
        return len(self._buf)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SecretBytes):
            return NotImplemented
        return secrets.compare_digest(bytes(self._buf), bytes(other._buf))

    def __repr__(self) -> str:  # never leak the value
        state = "wiped" if self._wiped else f"{len(self._buf)} bytes"
        return f"<SecretBytes {state}>"

    __str__ = __repr__

    def __del__(self):
        try:
            if not self._wiped:
                self.wipe()
        except Exception:
            pass


# --------------------------------------------------------------------------
# key derivation
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class KdfParams:
    """Argon2id cost parameters, stored in the clear in the vault header.

    They live inside the header's authenticated region, so an attacker cannot
    weaken them by editing the file — the tag check fails first.
    """

    salt: bytes
    time_cost: int
    memory_kib: int
    parallelism: int
    kdf_id: int = KDF_ARGON2ID

    @staticmethod
    def create(time_cost: int = 3, memory_kib: int = 262144, parallelism: int = 4) -> "KdfParams":
        return KdfParams(os.urandom(SALT_SIZE), time_cost, memory_kib, parallelism)

    def validate(self) -> None:
        if self.kdf_id != KDF_ARGON2ID:
            raise UnsupportedFormat(f"unknown KDF id {self.kdf_id}")
        if len(self.salt) != SALT_SIZE:
            raise UnsupportedFormat("bad salt length")
        # Guards against a malformed file asking for an absurd allocation.
        if not (1 <= self.time_cost <= 64):
            raise UnsupportedFormat("time cost out of range")
        if not (8 <= self.memory_kib <= 4 * 1024 * 1024):
            raise UnsupportedFormat("memory cost out of range")
        if not (1 <= self.parallelism <= 64):
            raise UnsupportedFormat("parallelism out of range")


def keyfile_digest(path: str) -> bytes:
    """Digest of the first :data:`KEYFILE_READ_BYTES` of a keyfile."""
    h = hashlib.sha256()
    h.update(KEYFILE_DOMAIN)
    with open(path, "rb") as fh:
        h.update(fh.read(KEYFILE_READ_BYTES))
    return h.digest()


def build_kdf_input(passphrase: str, keyfile_path: Optional[str] = None) -> SecretBytes:
    """Combine passphrase and optional keyfile into one KDF secret.

    The keyfile is folded in as a fixed-length digest with a domain separator,
    so a keyfile can never be confused with passphrase bytes and the two
    factors cannot be swapped for each other.
    """
    parts = bytearray(passphrase.encode("utf-8"))
    if keyfile_path:
        parts += b"\x00"
        parts += keyfile_digest(keyfile_path)
    secret = SecretBytes(parts)
    for i in range(len(parts)):
        parts[i] = 0
    return secret


def derive_master_key(secret: SecretBytes, params: KdfParams) -> SecretBytes:
    """Run Argon2id over the KDF input and return a 256-bit master key."""
    params.validate()
    raw = hash_secret_raw(
        secret=secret.bytes(),
        salt=params.salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_kib,
        parallelism=params.parallelism,
        hash_len=KEY_SIZE,
        type=Argon2Type.ID,
    )
    key = SecretBytes(raw)
    del raw
    return key


def calibrate_kdf(target_seconds: float = 1.0, memory_kib: int = 262144,
                  parallelism: int = 4, max_time_cost: int = 12) -> KdfParams:
    """Pick Argon2id costs that take roughly ``target_seconds`` on this machine.

    Memory is held at a fixed, generous value (256 MiB by default) because
    memory hardness is what actually frustrates GPU and ASIC attacks; the
    time cost is then tuned to reach the target. If even one pass is already
    slower than the target, memory is stepped down rather than going below a
    single pass.
    """
    salt = os.urandom(SALT_SIZE)
    probe = SecretBytes(b"quenchkey-calibration-probe")

    def measure(t: int, m: int) -> float:
        start = time.perf_counter()
        hash_secret_raw(secret=probe.bytes(), salt=salt, time_cost=t, memory_cost=m,
                        parallelism=parallelism, hash_len=KEY_SIZE, type=Argon2Type.ID)
        return time.perf_counter() - start

    one_pass = measure(1, memory_kib)
    while one_pass > target_seconds * 1.35 and memory_kib > 65536:
        memory_kib //= 2
        one_pass = measure(1, memory_kib)

    time_cost = max(1, min(max_time_cost, round(target_seconds / max(one_pass, 1e-6))))
    probe.wipe()
    return KdfParams(salt, time_cost, memory_kib, parallelism)


# --------------------------------------------------------------------------
# authenticated encryption
# --------------------------------------------------------------------------

def _aead(cipher_id: int, key: bytes):
    if cipher_id == CIPHER_CHACHA20_POLY1305:
        return ChaCha20Poly1305(key)
    if cipher_id == CIPHER_AES_256_GCM:
        return AESGCM(key)
    raise UnsupportedFormat(f"unknown cipher id {cipher_id}")


def cipher_name(cipher_id: int) -> str:
    return {
        CIPHER_CHACHA20_POLY1305: "ChaCha20-Poly1305",
        CIPHER_AES_256_GCM: "AES-256-GCM",
    }.get(cipher_id, f"cipher#{cipher_id}")


def encrypt(key: SecretBytes, plaintext: bytes, associated_data: bytes,
            cipher_id: int = DEFAULT_CIPHER, nonce: Optional[bytes] = None) -> tuple[bytes, bytes]:
    """Encrypt ``plaintext``, returning ``(nonce, ciphertext_with_tag)``."""
    nonce = nonce if nonce is not None else os.urandom(NONCE_SIZE)
    if len(nonce) != NONCE_SIZE:
        raise CryptoError("nonce must be 12 bytes")
    aead = _aead(cipher_id, key.bytes())
    return nonce, aead.encrypt(nonce, plaintext, associated_data)


def decrypt(key: SecretBytes, nonce: bytes, ciphertext: bytes, associated_data: bytes,
            cipher_id: int = DEFAULT_CIPHER) -> bytes:
    """Decrypt and verify. Raises :class:`AuthenticationError` on any mismatch."""
    aead = _aead(cipher_id, key.bytes())
    try:
        return aead.decrypt(nonce, ciphertext, associated_data)
    except InvalidTag as exc:
        raise AuthenticationError(
            "authentication failed: wrong passphrase or keyfile, or the file has been altered"
        ) from exc


# --------------------------------------------------------------------------
# chunked streaming AEAD, used for file payloads
# --------------------------------------------------------------------------

#: 1 MiB plaintext per chunk keeps memory flat for arbitrarily large files.
CHUNK_SIZE = 1024 * 1024


def chunk_nonce(prefix: bytes, index: int) -> bytes:
    """Nonce for chunk ``index``: a random 4-byte prefix plus a counter.

    Because the prefix is fresh for every file and the counter never repeats
    within a file, no (key, nonce) pair is ever reused.
    """
    if len(prefix) != 4:
        raise CryptoError("nonce prefix must be 4 bytes")
    return prefix + struct.pack(">Q", index)


def chunk_aad(header: bytes, index: int, final: bool) -> bytes:
    """Associated data for a chunk.

    Binding the chunk index and the end-of-stream flag into the tag means a
    chunk cannot be reordered, duplicated, dropped, or spliced in from another
    file, and the stream cannot be silently truncated.
    """
    return header + struct.pack(">Q?", index, final)
