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

"""The vault: the only place a file key ever exists.

A Quenchkey vault is one file (``~/.quenchkey/vault.qkv`` by default). It
holds a small cleartext header — format magic, version, KDF parameters, and the
non-secret parameters of any second factor — and a single authenticated
encrypted region containing everything else: the per-file keys, the deadlines,
the clock watermark, the vault's signing identity, the certificates it has
issued and its hash-chained event log.

The whole header is passed to the cipher as associated data, so it is covered
by the authentication tag even though it is not encrypted. Editing the version
byte, weakening the Argon2 cost parameters, or swapping in another security
key's credential does not produce a vault that opens with degraded security; it
produces a vault that refuses to open.

File layout (format version 2)
------------------------------

::

    offset  size  field
    0       8     magic  b"QKEYVALT"
    8       1     format version
    9       1     KDF id           (1 = Argon2id)
    10      1     cipher id        (1 = ChaCha20-Poly1305, 2 = AES-256-GCM)
    11      1     flags            bit 0 = keyfile, bit 1 = security key
    12      16    Argon2 salt                    }
    28      4     Argon2 time cost               } authenticated
    32      4     Argon2 memory cost (KiB)       } as associated
    36      4     Argon2 parallelism             } data
    40      2     length of the factor block     }
    42      N     factor parameters, JSON        }
    42+N    12    nonce
    54+N    ...   ciphertext || 16-byte tag

Format version 1 had no factor block: its nonce sat at offset 40. Version 1
vaults are still read, and are rewritten as version 2 the first time they are
saved.

The encrypted payload is a length-prefixed binary structure rather than plain
JSON, so that raw key bytes are read straight into a ``bytearray`` that can be
wiped afterwards instead of passing through immutable ``str`` objects.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import struct
import time
from dataclasses import dataclass, field
from typing import Iterable, Optional

from . import certificate as certificate_module
from . import chain, crypto, factors, schedule
from .certificate import Custodian
from .crypto import (
    AuthenticationError,
    KdfParams,
    SecretBytes,
    UnsupportedFormat,
)
from .factors import NoFactor, SecondFactor

MAGIC = b"QKEYVALT"
FORMAT_VERSION = 2
FORMAT_VERSION_LEGACY = 1
HEADER_FIXED_LEN = 40
LEGACY_HEADER_LEN = HEADER_FIXED_LEN + crypto.NONCE_SIZE  # 52

FLAG_KEYFILE_REQUIRED = 0x01
FLAG_FIDO2_REQUIRED = 0x02

PAYLOAD_VERSION = 2
PAYLOAD_VERSION_LEGACY = 1

#: Slack allowed before a backwards clock step is treated as a rollback.
#: Covers ordinary NTP corrections without covering a deliberate change.
CLOCK_TOLERANCE_SECONDS = 120.0

#: How many events the log keeps. Old events are dropped from the front, which
#: necessarily truncates the chain — see :meth:`Vault.chain_report`.
MAX_EVENTS = 2000

DEFAULT_VAULT_DIR = os.path.join(os.path.expanduser("~"), ".quenchkey")
DEFAULT_VAULT_PATH = os.path.join(DEFAULT_VAULT_DIR, "vault.qkv")

STATUS_ACTIVE = "active"
STATUS_EXPIRED = "expired"

#: Reasons a key gets destroyed, as they appear on certificates.
REASON_DEADLINE = "the scheduled deadline was reached"
REASON_OPENS = "the permitted number of openings was used up"
REASON_HEARTBEAT = "the vault was not opened within the required interval"
REASON_MANUAL = "destroyed manually, ahead of schedule, by the vault holder"
REASON_REMOVED = "the entry was removed from the vault, which destroys its key"


class VaultError(Exception):
    """Base class for vault failures."""


class VaultLocked(VaultError):
    """An operation needing the master key was attempted while locked."""


class VaultExists(VaultError):
    """Refusing to overwrite an existing vault."""


class VaultNotFound(VaultError):
    """No vault at the given path."""


class KeyfileRequired(VaultError):
    """This vault was created with a keyfile and none was supplied."""


class SecurityKeyRequired(VaultError):
    """This vault was created with a security key and none was supplied."""


class ClockRollback(VaultError):
    """The system clock is earlier than the last time this vault was opened.

    The vault decrypted correctly — the passphrase was right — but the clock
    moved backwards, which is how someone would try to keep an expired file
    alive. Carries the two timestamps so the UI can show the size of the jump.
    """

    def __init__(self, last_seen: float, now: float):
        self.last_seen = last_seen
        self.now = now
        self.delta = last_seen - now
        super().__init__(
            f"system clock is {self.delta:.0f}s behind the last recorded unlock"
        )


class EntryNotFound(VaultError):
    """No entry with that id."""


class KeyDestroyed(VaultError):
    """The key for this entry has been destroyed; the file cannot be opened.

    This is the terminal state Quenchkey exists to produce. There is no
    recovery path, by design.
    """


# --------------------------------------------------------------------------
# entries
# --------------------------------------------------------------------------

@dataclass
class Entry:
    """One locked file: its key, the rules that end it, and where its blob lives.

    Three independent rules can end an entry, and any of them is enough:

    * ``expires``        — a fixed moment in time;
    * ``heartbeat_days`` — a dead man's switch: destroyed if the vault is not
      opened within that many days;
    * ``max_opens``      — an allowance of openings, after which the key goes.

    :meth:`deadline` folds the two time-based rules into a single moment so the
    interface only ever has to show one countdown.
    """

    id: str
    blob_path: str
    key: SecretBytes
    created: float
    expires: Optional[float]
    names: list[str] = field(default_factory=list)
    blob_size: int = 0
    plaintext_size: int = 0
    cipher_id: int = crypto.DEFAULT_CIPHER
    status: str = STATUS_ACTIVE
    expired_at: Optional[float] = None
    delete_blob_on_expiry: bool = False
    label: str = ""
    order: int = 0
    blob_sha256: str = ""
    max_opens: Optional[int] = None
    open_count: int = 0
    heartbeat_days: Optional[float] = None
    last_checkin: Optional[float] = None
    destruction_reason: str = ""

    #: A checked-out entry has been opened on loan: the extracted copies are
    #: listed here and shredded when the loan runs out. None means it was
    #: opened normally, and those copies are ordinary files for good.
    checkout_until: Optional[float] = None
    checkout_paths: list = field(default_factory=list)
    #: sha256 of each file as it was lent out, so check-in can tell what
    #: was edited and lock the edits back in rather than shredding them.
    checkout_digests: dict = field(default_factory=dict)

    @property
    def checked_out(self) -> bool:
        return self.checkout_until is not None

    # -- derived state ----------------------------------------------------

    @property
    def key_destroyed(self) -> bool:
        return self.status == STATUS_EXPIRED or self.key.is_zero()

    @property
    def display_name(self) -> str:
        if self.label:
            return self.label
        if len(self.names) == 1:
            return self.names[0]
        if self.names:
            return f"{self.names[0]} + {len(self.names) - 1} more"
        return os.path.basename(self.blob_path)

    @property
    def opens_remaining(self) -> Optional[int]:
        if self.max_opens is None:
            return None
        return max(0, self.max_opens - self.open_count)

    @property
    def has_rules(self) -> bool:
        return any((self.expires is not None, self.max_opens is not None,
                    self.heartbeat_days is not None))

    def heartbeat_deadline(self) -> Optional[float]:
        if self.heartbeat_days is None:
            return None
        base = self.last_checkin if self.last_checkin is not None else self.created
        return base + self.heartbeat_days * 86400.0

    def deadline(self) -> Optional[float]:
        """The earliest time-based moment at which this key dies."""
        candidates = [t for t in (self.expires, self.heartbeat_deadline())
                      if t is not None]
        return min(candidates) if candidates else None

    def due_reason(self, now: float) -> Optional[str]:
        """Why this entry is due right now, or None if it is not."""
        if self.key_destroyed:
            return None
        if self.max_opens is not None and self.open_count >= self.max_opens:
            return REASON_OPENS
        heartbeat = self.heartbeat_deadline()
        if heartbeat is not None and now >= heartbeat:
            return REASON_HEARTBEAT
        if self.expires is not None and now >= self.expires:
            return REASON_DEADLINE
        return None

    def is_due(self, now: float) -> bool:
        return self.due_reason(now) is not None

    def seconds_remaining(self, now: float) -> Optional[float]:
        deadline = self.deadline()
        return None if deadline is None else deadline - now

    def rule_summary(self) -> str:
        """The rules in one short line, for the table and the certificate."""
        parts = []
        if self.expires is not None:
            parts.append("deadline")
        if self.heartbeat_days is not None:
            days = self.heartbeat_days
            parts.append(f"check in every {days:g}d")
        if self.max_opens is not None:
            parts.append(f"{self.open_count}/{self.max_opens} opens")
        return ", ".join(parts) if parts else "no rules"

    def to_meta(self) -> dict:
        return {
            "id": self.id,
            "blob_path": self.blob_path,
            "created": self.created,
            "expires": self.expires,
            "names": self.names,
            "blob_size": self.blob_size,
            "plaintext_size": self.plaintext_size,
            "cipher_id": self.cipher_id,
            "status": self.status,
            "expired_at": self.expired_at,
            "delete_blob_on_expiry": self.delete_blob_on_expiry,
            "label": self.label,
            "order": self.order,
            "blob_sha256": self.blob_sha256,
            "max_opens": self.max_opens,
            "open_count": self.open_count,
            "heartbeat_days": self.heartbeat_days,
            "last_checkin": self.last_checkin,
            "destruction_reason": self.destruction_reason,
            "checkout_until": self.checkout_until,
            "checkout_paths": list(self.checkout_paths),
            "checkout_digests": dict(self.checkout_digests),
        }

    @classmethod
    def from_meta(cls, meta: dict, key: SecretBytes) -> "Entry":
        return cls(
            id=meta["id"],
            blob_path=meta["blob_path"],
            key=key,
            created=meta["created"],
            expires=meta.get("expires"),
            names=list(meta.get("names", [])),
            blob_size=meta.get("blob_size", 0),
            plaintext_size=meta.get("plaintext_size", 0),
            cipher_id=meta.get("cipher_id", crypto.DEFAULT_CIPHER),
            status=meta.get("status", STATUS_ACTIVE),
            expired_at=meta.get("expired_at"),
            delete_blob_on_expiry=meta.get("delete_blob_on_expiry", False),
            label=meta.get("label", ""),
            order=meta.get("order", 0),
            blob_sha256=meta.get("blob_sha256", ""),
            max_opens=meta.get("max_opens"),
            open_count=meta.get("open_count", 0),
            heartbeat_days=meta.get("heartbeat_days"),
            last_checkin=meta.get("last_checkin"),
            destruction_reason=meta.get("destruction_reason", ""),
            checkout_until=meta.get("checkout_until"),
            checkout_paths=list(meta.get("checkout_paths", [])),
            checkout_digests=dict(meta.get("checkout_digests", {})),
        )


# --------------------------------------------------------------------------
# header
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class VaultHeader:
    """The cleartext part of a vault file."""

    format_version: int
    cipher_id: int
    flags: int
    kdf: KdfParams
    nonce: bytes
    factor_params: dict = field(default_factory=dict)

    @property
    def keyfile_required(self) -> bool:
        return bool(self.flags & FLAG_KEYFILE_REQUIRED)

    @property
    def security_key_required(self) -> bool:
        return bool(self.flags & FLAG_FIDO2_REQUIRED)

    @property
    def factor_kind(self) -> str:
        if self.security_key_required:
            return factors.FACTOR_FIDO2
        if self.keyfile_required:
            return factors.FACTOR_KEYFILE
        return factors.FACTOR_NONE

    def factor_block(self) -> bytes:
        if not self.factor_params:
            return b""
        return json.dumps(self.factor_params, sort_keys=True,
                          separators=(",", ":")).encode("utf-8")

    def aad(self) -> bytes:
        fixed = MAGIC + struct.pack(
            ">BBBB16sIII",
            self.format_version, self.kdf.kdf_id, self.cipher_id, self.flags,
            self.kdf.salt, self.kdf.time_cost, self.kdf.memory_kib,
            self.kdf.parallelism)
        if self.format_version == FORMAT_VERSION_LEGACY:
            return fixed
        block = self.factor_block()
        return fixed + struct.pack(">H", len(block)) + block

    def body_offset(self) -> int:
        """Where the ciphertext starts."""
        return len(self.aad()) + crypto.NONCE_SIZE


def read_header(path: str) -> VaultHeader:
    """Read a vault's cleartext header without needing the passphrase.

    Used to find out which second factor a vault wants before prompting for it.
    """
    try:
        with open(path, "rb") as fh:
            raw = fh.read(HEADER_FIXED_LEN + 2)
    except FileNotFoundError as exc:
        raise VaultNotFound(f"no vault at {path}") from exc
    if len(raw) < HEADER_FIXED_LEN:
        raise UnsupportedFormat("vault file is truncated")
    if raw[:8] != MAGIC:
        raise UnsupportedFormat("not a Quenchkey vault")

    (fmt, kdf_id, cipher_id, flags, salt, t_cost, mem, par) = struct.unpack(
        ">BBBB16sIII", raw[8:HEADER_FIXED_LEN])
    if fmt not in (FORMAT_VERSION_LEGACY, FORMAT_VERSION):
        raise UnsupportedFormat(
            f"vault format version {fmt}; this build understands "
            f"{FORMAT_VERSION_LEGACY} and {FORMAT_VERSION}")
    kdf = KdfParams(salt, t_cost, mem, par, kdf_id)
    kdf.validate()

    if fmt == FORMAT_VERSION_LEGACY:
        with open(path, "rb") as fh:
            head = fh.read(LEGACY_HEADER_LEN)
        if len(head) < LEGACY_HEADER_LEN:
            raise UnsupportedFormat("vault file is truncated")
        return VaultHeader(fmt, cipher_id, flags, kdf,
                           head[HEADER_FIXED_LEN:LEGACY_HEADER_LEN], {})

    if len(raw) < HEADER_FIXED_LEN + 2:
        raise UnsupportedFormat("vault file is truncated")
    (block_len,) = struct.unpack(">H", raw[HEADER_FIXED_LEN:HEADER_FIXED_LEN + 2])
    with open(path, "rb") as fh:
        head = fh.read(HEADER_FIXED_LEN + 2 + block_len + crypto.NONCE_SIZE)
    if len(head) < HEADER_FIXED_LEN + 2 + block_len + crypto.NONCE_SIZE:
        raise UnsupportedFormat("vault file is truncated")

    block = head[HEADER_FIXED_LEN + 2:HEADER_FIXED_LEN + 2 + block_len]
    try:
        params = json.loads(block.decode("utf-8")) if block else {}
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UnsupportedFormat(f"malformed factor parameters: {exc}") from exc
    nonce = head[HEADER_FIXED_LEN + 2 + block_len:]
    return VaultHeader(fmt, cipher_id, flags, kdf, nonce, params)


# --------------------------------------------------------------------------
# payload serialisation
# --------------------------------------------------------------------------

def _pack_payload(created: float, last_seen: float, signing_seed: SecretBytes,
                  entries: Iterable[Entry], extras: dict) -> bytearray:
    """Serialise the payload into a wipeable buffer."""
    buf = bytearray()
    entries = list(entries)
    buf += struct.pack(">Bdd", PAYLOAD_VERSION, created, last_seen)
    buf += signing_seed.raw if not signing_seed.wiped else bytearray(32)
    buf += struct.pack(">I", len(entries))
    for entry in entries:
        meta = json.dumps(entry.to_meta(), separators=(",", ":")).encode("utf-8")
        buf += struct.pack(">I", len(meta))
        buf += meta
        raw = entry.key.raw if not entry.key.wiped else bytearray(crypto.KEY_SIZE)
        if len(raw) != crypto.KEY_SIZE:
            raise VaultError("entry key must be 32 bytes")
        buf += raw
    blob = json.dumps(extras, separators=(",", ":")).encode("utf-8")
    buf += struct.pack(">I", len(blob))
    buf += blob
    return buf


def _unpack_payload(buf: bytes) -> tuple:
    """Read a payload of either version. Returns the v2 shape either way."""
    view = memoryview(buf)
    pos = 0

    def take(n: int) -> bytes:
        nonlocal pos
        if pos + n > len(view):
            raise UnsupportedFormat("vault payload is truncated")
        chunk = view[pos:pos + n].tobytes()
        pos += n
        return chunk

    (payload_version,) = struct.unpack(">B", take(1))
    if payload_version == PAYLOAD_VERSION_LEGACY:
        created, last_seen, count = struct.unpack(">ddI", take(20))
        entries = _take_entries(take, count)
        events: list[dict] = []
        (event_count,) = struct.unpack(">I", take(4))
        for _ in range(event_count):
            (blob_len,) = struct.unpack(">I", take(4))
            events.append(json.loads(take(blob_len).decode("utf-8")))
        return created, last_seen, None, entries, {"events": events}, True

    if payload_version != PAYLOAD_VERSION:
        raise UnsupportedFormat(f"unknown payload version {payload_version}")

    created, last_seen = struct.unpack(">dd", take(16))
    signing_seed = SecretBytes(take(32))
    (count,) = struct.unpack(">I", take(4))
    entries = _take_entries(take, count)
    (extras_len,) = struct.unpack(">I", take(4))
    extras = json.loads(take(extras_len).decode("utf-8")) if extras_len else {}
    return created, last_seen, signing_seed, entries, extras, False


def _take_entries(take, count: int) -> list[Entry]:
    entries: list[Entry] = []
    for _ in range(count):
        (meta_len,) = struct.unpack(">I", take(4))
        meta = json.loads(take(meta_len).decode("utf-8"))
        entries.append(Entry.from_meta(meta, SecretBytes(take(crypto.KEY_SIZE))))
    return entries


# --------------------------------------------------------------------------
# the vault
# --------------------------------------------------------------------------

class Vault:
    """An open (or closed) Quenchkey vault.

    While unlocked, the master key, the signing seed and the per-file keys all
    live in :class:`SecretBytes` buffers. :meth:`lock` wipes every one of them
    and drops the entry list.
    """

    def __init__(self, path: str, header: VaultHeader, master_key: SecretBytes,
                 created: float, last_seen: float, entries: list[Entry],
                 extras: dict, signing_seed: Optional[SecretBytes] = None,
                 upgraded: bool = False):
        self.path = path
        self._header = header
        self._master_key: Optional[SecretBytes] = master_key
        self._signing_seed = signing_seed or certificate_module.new_signing_seed()
        self.created = created
        self._last_seen = last_seen
        self._entries: dict[str, Entry] = {e.id: e for e in entries}

        self._events: list[dict] = list(extras.get("events", []))
        self._certificates: list[dict] = list(extras.get("certificates", []))
        self._custodian = Custodian.from_dict(extras.get("custodian"))
        self._chain_head: str = extras.get("chain_head", chain.GENESIS)
        self._chain_origin: Optional[float] = extras.get("chain_origin")
        self._events_truncated: bool = extras.get("events_truncated", False)
        self._background_expiry: bool = bool(extras.get("background_expiry", False))
        self._shared: list[dict] = list(extras.get("shared", []))
        self._watch_rules: list[dict] = list(extras.get("watch_rules", []))
        # A general slot for small pieces of bookkeeping that belong to the
        # vault but do not deserve a field and a migration each: which
        # deadline warnings have gone out, when the last integrity sweep
        # ran, and so on. Written inside the authenticated payload like
        # everything else, so it is neither readable nor editable from
        # outside.
        self._notes: dict = dict(extras.get("notes", {}))

        if upgraded:
            self._upgrade_chain()

    # -- lifecycle --------------------------------------------------------

    @classmethod
    def create(cls, path: str, passphrase: str,
               keyfile_path: Optional[str] = None,
               cipher_id: int = crypto.DEFAULT_CIPHER,
               kdf_params: Optional[KdfParams] = None,
               overwrite: bool = False,
               factor: Optional[SecondFactor] = None) -> "Vault":
        """Create a new vault and return it unlocked.

        ``keyfile_path`` is kept as a convenience for the common case; pass a
        :class:`~quenchkey.factors.SecondFactor` for anything else.
        """
        if os.path.exists(path) and not overwrite:
            raise VaultExists(f"a vault already exists at {path}")
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)

        factor = _resolve_factor(factor, keyfile_path)
        kdf = kdf_params or crypto.calibrate_kdf()
        secret = factors.build_kdf_input(passphrase, factor)
        try:
            master_key = crypto.derive_master_key(secret, kdf)
        finally:
            secret.wipe()

        now = time.time()
        header = VaultHeader(FORMAT_VERSION, cipher_id, _flags_for(factor), kdf,
                             b"\x00" * crypto.NONCE_SIZE,
                             factor.public_parameters())
        vault = cls(path, header, master_key, now, now, [],
                    {"chain_origin": now})
        vault._log("vault_created", cipher=crypto.cipher_name(cipher_id),
                   second_factor=factor.kind, argon2_time=kdf.time_cost,
                   argon2_memory_kib=kdf.memory_kib,
                   vault_id=vault.vault_id)
        vault.save()
        return vault

    @classmethod
    def unlock(cls, path: str, passphrase: str,
               keyfile_path: Optional[str] = None,
               accept_clock_rollback: bool = False,
               factor: Optional[SecondFactor] = None,
               authenticator=None) -> "Vault":
        """Open an existing vault with its passphrase and second factor."""
        header = read_header(path)
        resolved = _factor_for_header(header, keyfile_path, factor, authenticator)

        secret = factors.build_kdf_input(passphrase, resolved)
        try:
            master_key = crypto.derive_master_key(secret, header.kdf)
        finally:
            secret.wipe()
        return cls._open(path, header, master_key, accept_clock_rollback,
                         how="passphrase")

    # -- the duress passphrase --------------------------------------------
    #
    # A second passphrase that destroys this vault instead of opening it.
    #
    # It cannot do anything subtler than that, and the reason is worth
    # understanding rather than working around: the duress passphrase does not
    # derive the master key. Nothing derived from it can decrypt the payload,
    # so it cannot shred entries one at a time or hand back an emptied vault.
    # What it can do is overwrite the vault file, which needs no key at all —
    # and which is, for the situation this exists for, the whole of the job.
    #
    # The digest is kept in the header's authenticated block. It is a hash of
    # the key the duress passphrase derives, under the *same* salt and cost as
    # the real one, so a single derivation answers both questions and an
    # attacker guessing at the file pays the same price either way.

    def set_duress_passphrase(self, passphrase: str,
                              keyfile_path: Optional[str] = None) -> None:
        """Arm a passphrase that destroys this vault when it is typed."""
        if not passphrase:
            raise ValueError("a duress passphrase cannot be empty")
        digest = _duress_digest(passphrase, self._header, keyfile_path)
        params = dict(self._header.factor_params)
        params["duress"] = digest.hex()
        self._header = VaultHeader(
            self._header.format_version, self._header.cipher_id,
            self._header.flags, self._header.kdf, self._header.nonce, params)
        self._log("duress_armed")
        self.save()

    def clear_duress_passphrase(self) -> None:
        params = dict(self._header.factor_params)
        if params.pop("duress", None) is None:
            return
        self._header = VaultHeader(
            self._header.format_version, self._header.cipher_id,
            self._header.flags, self._header.kdf, self._header.nonce, params)
        self._log("duress_cleared")
        self.save()

    @property
    def duress_armed(self) -> bool:
        return bool(self._header.factor_params.get("duress"))

    @classmethod
    def unlock_with_master_key(cls, path: str, master_key: SecretBytes,
                               accept_clock_rollback: bool = False) -> "Vault":
        """Open a vault directly with its master key.

        This is the path recovery shares take: a quorum reconstructs the master
        key, which skips the passphrase and the second factor entirely. That is
        the point of them, and it is why a quorum of shares must be treated as
        being exactly as sensitive as the passphrase itself.
        """
        header = read_header(path)
        return cls._open(path, header, SecretBytes(master_key.bytes()),
                         accept_clock_rollback, how="recovery shares")

    @classmethod
    def _open(cls, path: str, header: VaultHeader, master_key: SecretBytes,
              accept_clock_rollback: bool, how: str) -> "Vault":
        with open(path, "rb") as fh:
            raw = fh.read()
        body = raw[header.body_offset():]

        try:
            plain = crypto.decrypt(master_key, header.nonce, body,
                                   header.aad(), header.cipher_id)
        except AuthenticationError:
            master_key.wipe()
            raise

        buf = bytearray(plain)
        try:
            created, last_seen, seed, entries, extras, upgraded = \
                _unpack_payload(bytes(buf))
        finally:
            for i in range(len(buf)):
                buf[i] = 0

        vault = cls(path, header, master_key, created, last_seen, entries,
                    extras, seed, upgraded)

        now = time.time()
        rolled_back = now < last_seen - CLOCK_TOLERANCE_SECONDS
        if rolled_back and not accept_clock_rollback:
            vault.lock()
            raise ClockRollback(last_seen, now)
        if rolled_back:
            vault._log("clock_rollback_accepted", last_seen=last_seen, clock=now,
                       behind_seconds=round(last_seen - now, 3))

        # The watermark only ever moves forward. A file's deadline is judged
        # against the highest clock this vault has ever seen, so winding the
        # system clock back does not buy an expired file any more time.
        vault._last_seen = max(last_seen, now)
        vault._log("unlocked", clock=now, method=how)
        return vault

    def lock(self) -> None:
        """Wipe all key material and drop the entry list."""
        if self._master_key is not None:
            self._master_key.wipe()
            self._master_key = None
        if self._signing_seed is not None and not self._signing_seed.wiped:
            self._signing_seed.wipe()
        for entry in self._entries.values():
            entry.key.wipe()
        self._entries = {}

    def __enter__(self) -> "Vault":
        return self

    def __exit__(self, *exc) -> None:
        self.lock()

    # -- state ------------------------------------------------------------

    @property
    def is_unlocked(self) -> bool:
        return self._master_key is not None

    @property
    def header(self) -> VaultHeader:
        return self._header

    @property
    def last_seen(self) -> float:
        return self._last_seen

    @property
    def events(self) -> list[dict]:
        return list(self._events)

    @property
    def certificates(self) -> list[dict]:
        return list(self._certificates)

    @property
    def custodian(self) -> Custodian:
        return self._custodian

    @property
    def chain_head(self) -> str:
        return self._chain_head

    @property
    def chain_origin(self) -> Optional[float]:
        return self._chain_origin

    @property
    def chain_was_migrated(self) -> bool:
        """True if this vault's early events were chained after the fact.

        A vault created by this version has been chained from its first event.
        One upgraded from format version 1 had its existing history linked
        retroactively, which proves nothing about those events — so the two
        cases must never be described in the same words.
        """
        return any(event.get("kind") == "chain_established"
                   for event in self._events)

    @property
    def chain_fingerprint(self) -> str:
        return chain.fingerprint(self._chain_head)

    @property
    def public_key(self) -> bytes:
        return certificate_module.public_key_bytes(self._require_seed())

    @property
    def vault_id(self) -> str:
        return certificate_module.vault_id(self.public_key)

    def effective_now(self) -> float:
        """The clock used for expiry decisions: never earlier than the watermark."""
        return max(time.time(), self._last_seen)

    def observe_time(self, when: float, source: str = "",
                     verified: bool = False) -> float:
        """Take somebody else's reading of the time, and move forward on it.

        Forward only. A reading earlier than the watermark is either a replay
        or a broken source, and in both cases the ratchet is what protects the
        vault, so it is recorded and ignored rather than obeyed. Returns how
        far the watermark moved, which is how far this machine's clock was
        behind whoever was asked.
        """
        if when <= self._last_seen:
            return 0.0
        moved = when - self._last_seen
        self._last_seen = when
        self._log("clock_observed", source=source or "unnamed",
                  verified=bool(verified), moved_seconds=round(moved, 3))
        self.save()
        return moved

    def _require_unlocked(self) -> SecretBytes:
        if self._master_key is None:
            raise VaultLocked("the vault is locked")
        return self._master_key

    def _require_seed(self) -> SecretBytes:
        self._require_unlocked()
        return self._signing_seed

    def signing_seed(self) -> SecretBytes:
        """The seed behind this vault's identity.

        A method rather than a property for the same reason as
        :meth:`master_key`: handing out a secret should look like a decision
        at the call site. Used to sign certificates and to derive the
        key-agreement key a handover is addressed to.
        """
        return self._require_seed()

    def master_key(self) -> SecretBytes:
        """The master key itself, for generating recovery shares.

        Deliberately a method rather than a property: handing this out is a
        significant act, and the one caller that needs it should look like it
        meant to ask.
        """
        return self._require_unlocked()

    # -- the event chain --------------------------------------------------

    def _log(self, kind: str, **fields) -> dict:
        event = chain.append(self._events, {"at": time.time(), "kind": kind, **fields})
        self._chain_head = event["hash"]
        if len(self._events) > MAX_EVENTS:
            # Dropping the oldest events necessarily breaks verification from
            # the genesis event; the vault records that so it is never passed
            # off as an intact chain.
            self._events = self._events[-MAX_EVENTS:]
            self._events_truncated = True
        return event

    def log_event(self, kind: str, **fields) -> dict:
        """Record something in the vault's hash-chained event log."""
        return self._log(kind, **fields)

    def _upgrade_chain(self) -> None:
        """Bring a vault written before chaining existed up to date."""
        self._events = chain.rechain(self._events)
        self._chain_head = chain.head(self._events)
        self._chain_origin = time.time()
        self._log("chain_established",
                  note="events before this point were linked retroactively "
                       "during an upgrade and carry no tamper-evidence")

    def chain_report(self) -> chain.ChainReport:
        """Verify the event chain against its recorded head."""
        if self._events_truncated:
            report = chain.verify(self._events)
            return chain.ChainReport(
                report.ok, report.head, report.length, report.broken_at,
                (report.reason + " (note: the oldest events have been dropped "
                 "to bound the log, so verification starts mid-chain)")
                if not report.ok else "")
        return chain.verify(self._events, self._chain_head)

    # -- entries ----------------------------------------------------------

    def entries(self, include_expired: bool = True) -> list[Entry]:
        self._require_unlocked()
        items = list(self._entries.values())
        if not include_expired:
            items = [e for e in items if not e.key_destroyed]
        items.sort(key=lambda e: (e.created, e.order))
        return items

    def get(self, entry_id: str) -> Entry:
        self._require_unlocked()
        try:
            return self._entries[entry_id]
        except KeyError as exc:
            raise EntryNotFound(entry_id) from exc

    def key_for(self, entry_id: str) -> SecretBytes:
        """Fetch the key for an entry, refusing if it has been destroyed."""
        entry = self.get(entry_id)
        if entry.key_destroyed:
            raise KeyDestroyed(
                f"the key for {entry.display_name!r} was destroyed"
                + (f" at {time.ctime(entry.expired_at)}" if entry.expired_at else "")
                + "; this file can no longer be decrypted by anything"
            )
        if entry.max_opens is not None and entry.open_count >= entry.max_opens:
            raise KeyDestroyed(
                f"{entry.display_name!r} has used all {entry.max_opens} of its "
                "permitted openings")
        return entry.key

    def new_entry_id(self) -> str:
        return secrets.token_hex(16)

    def add_entry(self, entry: Entry) -> Entry:
        self._require_unlocked()
        if entry.id in self._entries:
            raise VaultError(f"duplicate entry id {entry.id}")
        if entry.heartbeat_days is not None and entry.last_checkin is None:
            entry.last_checkin = time.time()
        self._entries[entry.id] = entry
        self._log("locked", entry=entry.id, names=entry.names,
                  expires=entry.expires, blob=entry.blob_path,
                  sha256=entry.blob_sha256, max_opens=entry.max_opens,
                  heartbeat_days=entry.heartbeat_days)
        return entry

    def record_open(self, entry_id: str) -> Entry:
        """Count one opening, and destroy the key if that was the last one."""
        entry = self.get(entry_id)
        entry.open_count += 1
        self._log("entry_opened", entry=entry.id, count=entry.open_count,
                  max_opens=entry.max_opens)
        if entry.max_opens is not None and entry.open_count >= entry.max_opens:
            self.shred_key(entry.id, reason=REASON_OPENS)
        return entry

    def check_in(self) -> list[Entry]:
        """Reset every dead man's switch. Called when the vault is opened."""
        now = self.effective_now()
        refreshed = []
        for entry in self._entries.values():
            if entry.heartbeat_days is not None and not entry.key_destroyed:
                entry.last_checkin = now
                refreshed.append(entry)
        if refreshed:
            self._log("checked_in", entries=[e.id for e in refreshed])
        return refreshed

    def shred_key(self, entry_id: str, reason: str = REASON_DEADLINE) -> Entry:
        """Overwrite an entry's key with zeros and issue a certificate.

        After this returns and :meth:`save` has run, no copy of the key exists
        in the vault. The encrypted blob may still exist anywhere in the world
        and is now permanently unreadable.
        """
        entry = self.get(entry_id)
        if entry.key_destroyed:
            return entry

        blob_present = os.path.exists(entry.blob_path)
        digest = entry.blob_sha256 or (
            certificate_module.file_digest(entry.blob_path) if blob_present else None)

        entry.key.wipe()
        entry.key = SecretBytes.zeros()
        entry.status = STATUS_EXPIRED
        # The ratchet, not the raw clock: a certificate must never carry a
        # timestamp earlier than one this vault has already recorded.
        entry.expired_at = self.effective_now()
        entry.destruction_reason = reason

        event = self._log("key_destroyed", entry=entry.id, names=entry.names,
                          reason=reason, sha256=digest)
        self._issue_certificate(entry, event, digest, blob_present)
        return entry

    def _issue_certificate(self, entry: Entry, event: dict,
                           digest: Optional[str], blob_present: bool) -> dict:
        from . import __version__

        document = certificate_module.issue(
            self._require_seed(), entry,
            destroyed_at=entry.expired_at,
            reason=entry.destruction_reason,
            cipher=crypto.cipher_name(entry.cipher_id),
            kdf_description=(
                f"Argon2id, {self._header.kdf.memory_kib // 1024} MiB, "
                f"{self._header.kdf.time_cost} pass"
                f"{'es' if self._header.kdf.time_cost != 1 else ''}, "
                f"parallelism {self._header.kdf.parallelism}"),
            chain_seq=event["seq"],
            chain_head=event["hash"],
            tool=f"Quenchkey {__version__}",
            custodian=self._custodian,
            blob_sha256=digest,
            blob_present_at_destruction=blob_present,
            blob_deleted=entry.delete_blob_on_expiry,
        )
        self._certificates.append(document)
        return document

    def certificate_for(self, entry_id: str) -> Optional[dict]:
        for document in reversed(self._certificates):
            if document["certificate"]["item"]["entry_id"] == entry_id:
                return document
        return None

    def set_custodian(self, custodian: Custodian) -> None:
        """Record who is answerable for destructions, for the certificates."""
        self._require_unlocked()
        self._custodian = custodian
        self._log("custodian_set", name=custodian.name,
                  organisation=custodian.organisation)

    def remove_entry(self, entry_id: str, shred: bool = True) -> None:
        """Drop an entry from the vault, destroying its key on the way out.

        Removing a live entry destroys a key just as surely as a deadline does,
        so it goes through the same path and produces the same certificate.
        Anything else would leave a gap in the record exactly where someone
        might want one.
        """
        entry = self.get(entry_id)
        if shred and not entry.key_destroyed:
            self.shred_key(entry_id, reason=REASON_REMOVED)
        elif shred:
            entry.key.wipe()
        del self._entries[entry_id]
        self._log("entry_removed", entry=entry_id, names=entry.names)

    def set_expiry(self, entry_id: str, expires: Optional[float]) -> Entry:
        entry = self.get(entry_id)
        if entry.key_destroyed:
            raise KeyDestroyed("the key for this entry is already gone")
        previous, entry.expires = entry.expires, expires
        self._log("expiry_changed", entry=entry.id, was=previous, now=expires)
        return entry

    # -- persistence ------------------------------------------------------

    def _extras(self) -> dict:
        return {
            "events": self._events,
            "certificates": self._certificates,
            "custodian": self._custodian.to_dict(),
            "chain_head": self._chain_head,
            "chain_origin": self._chain_origin,
            "events_truncated": self._events_truncated,
            "background_expiry": self._background_expiry,
            "shared": self._shared,
            "watch_rules": self._watch_rules,
            "notes": self._notes,
        }

    # -- small bookkeeping ------------------------------------------------

    def note(self, key: str, default=None):
        """Read one piece of the vault's own bookkeeping."""
        return self._notes.get(key, default)

    def set_note(self, key: str, value) -> None:
        """Write one piece of bookkeeping. The caller saves."""
        self._notes[key] = value

    # -- watched folders --------------------------------------------------

    def watch_rules(self) -> list:
        """The folders being watched, as rules."""
        from .watch import WatchRule
        return [WatchRule.from_dict(raw) for raw in self._watch_rules]

    def set_watch_rules(self, rules) -> None:
        self._watch_rules = [rule.to_dict() for rule in rules]
        self._log("watch_rules_changed", folders=len(self._watch_rules))
        self.save()

    def add_watch_rule(self, rule) -> None:
        rules = [r for r in self.watch_rules()
                 if os.path.abspath(r.path) != os.path.abspath(rule.path)]
        rules.append(rule)
        self.set_watch_rules(rules)

    def remove_watch_rule(self, path: str) -> bool:
        target = os.path.abspath(path)
        rules = [r for r in self.watch_rules() if os.path.abspath(r.path) != target]
        if len(rules) == len(self._watch_rules):
            return False
        self.set_watch_rules(rules)
        return True

    # -- shared files -----------------------------------------------------
    #
    # A shared file is not an entry. It has no key here, no deadline and
    # nothing this vault can do to it — recording one is bookkeeping, so you
    # can see later what you sent out and to whom you gave a passphrase. The
    # record is kept in its own list rather than as an Entry precisely so that
    # no code path can treat it as something with a lifespan.

    def shared_records(self) -> list[dict]:
        """What has been locked for sharing from this vault, newest first."""
        return sorted(self._shared, key=lambda r: r.get("created", 0), reverse=True)

    def record_shared(self, path: str, names: Iterable[str], size: int,
                      plaintext_size: int, sha256: str = "",
                      note: str = "") -> dict:
        """Note that a self-contained file was written. No key is stored."""
        record = {
            "id": secrets.token_hex(16),
            "path": os.path.abspath(path),
            "names": list(names),
            "size": int(size),
            "plaintext_size": int(plaintext_size),
            "sha256": sha256,
            "note": note,
            "created": time.time(),
        }
        self._shared.append(record)
        self._log("shared_file_created", shared=record["id"],
                  count=len(record["names"]), sha256=sha256)
        self.save()
        return record

    def forget_shared(self, record_id: str) -> bool:
        """Drop the record. The file itself is untouched and still opens."""
        before = len(self._shared)
        self._shared = [r for r in self._shared if r.get("id") != record_id]
        if len(self._shared) == before:
            return False
        self._log("shared_file_forgotten", shared=record_id)
        self.save()
        return True

    @property
    def background_expiry(self) -> bool:
        """Whether an index is kept outside the vault for the sweeper."""
        return self._background_expiry

    def set_background_expiry(self, enabled: bool) -> None:
        """Turn the outside index on or off, and write or remove it now.

        Off is the default and the safe answer: the index is metadata in the
        clear. :mod:`quenchkey.schedule` says exactly what it gives away.
        """
        enabled = bool(enabled)
        if enabled == self._background_expiry:
            return
        self._background_expiry = enabled
        self._log("background_expiry", enabled=enabled)
        self.save()
        if not enabled:
            schedule.remove_index(self.path)

    def _refresh_schedule(self) -> None:
        """Keep the sweeper's index in step with the vault it describes."""
        if not self._background_expiry:
            return
        scheduled = []
        for entry in self._entries.values():
            if entry.key_destroyed:
                continue
            deadline = entry.deadline()
            if deadline is None:
                continue
            scheduled.append(schedule.ScheduledEntry(
                entry.id, deadline, entry.blob_path, entry.delete_blob_on_expiry))
        try:
            schedule.write_index(self.path, scheduled)
        except OSError:
            # An index that cannot be written is a missed cleanup, not a lost
            # vault. The save itself has already succeeded by this point.
            pass

    def save(self) -> None:
        """Re-encrypt and write the vault atomically.

        A fresh nonce is used on every write. The previous contents are
        overwritten with random bytes before the replacement is moved into
        place — best effort, since copy-on-write filesystems, SSD wear
        levelling and backups all defeat it.
        """
        master_key = self._require_unlocked()
        self._last_seen = max(self._last_seen, time.time())

        payload = _pack_payload(self.created, self._last_seen, self._signing_seed,
                                self._entries.values(), self._extras())
        try:
            nonce = os.urandom(crypto.NONCE_SIZE)
            header = VaultHeader(FORMAT_VERSION, self._header.cipher_id,
                                 self._header.flags, self._header.kdf, nonce,
                                 self._header.factor_params)
            _, body = crypto.encrypt(master_key, bytes(payload), header.aad(),
                                     header.cipher_id, nonce)
        finally:
            for i in range(len(payload)):
                payload[i] = 0

        blob = header.aad() + nonce + body
        directory = os.path.dirname(os.path.abspath(self.path)) or "."
        os.makedirs(directory, exist_ok=True)
        tmp = self.path + f".tmp-{secrets.token_hex(6)}"
        try:
            with open(tmp, "wb") as fh:
                fh.write(blob)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp, 0o600)
            _overwrite_in_place(self.path)
            os.replace(tmp, self.path)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise
        _fsync_dir(directory)
        self._header = header
        self._refresh_schedule()

    def reencrypt(self, passphrase: str, keyfile_path: Optional[str] = None,
                  kdf_params: Optional[KdfParams] = None,
                  factor: Optional[SecondFactor] = None) -> None:
        """Change the passphrase and/or second factor, keeping every entry.

        Per-file keys are untouched, so already-locked files stay openable.
        Recovery shares, however, reconstruct the *master* key — which this
        replaces — so any shares issued before this call stop working.
        """
        self._require_unlocked()
        factor = _resolve_factor(factor, keyfile_path)
        kdf = kdf_params or crypto.calibrate_kdf()
        secret = factors.build_kdf_input(passphrase, factor)
        try:
            new_key = crypto.derive_master_key(secret, kdf)
        finally:
            secret.wipe()
        old_key, self._master_key = self._master_key, new_key
        if old_key is not None:
            old_key.wipe()
        self._header = VaultHeader(FORMAT_VERSION, self._header.cipher_id,
                                   _flags_for(factor), kdf, self._header.nonce,
                                   factor.public_parameters())
        self._log("credentials_changed", second_factor=factor.kind,
                  note="any recovery shares issued before this no longer work")
        self.save()


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _resolve_factor(factor: Optional[SecondFactor],
                    keyfile_path: Optional[str]) -> SecondFactor:
    if factor is not None:
        return factor
    if keyfile_path:
        return factors.KeyfileFactor(keyfile_path)
    return NoFactor()


def _flags_for(factor: SecondFactor) -> int:
    if factor.kind == factors.FACTOR_KEYFILE:
        return FLAG_KEYFILE_REQUIRED
    if factor.kind == factors.FACTOR_FIDO2:
        return FLAG_FIDO2_REQUIRED
    return 0


def _factor_for_header(header: VaultHeader, keyfile_path: Optional[str],
                       factor: Optional[SecondFactor],
                       authenticator) -> SecondFactor:
    """Work out which second factor a vault wants, and complain usefully."""
    if factor is not None:
        return factor
    if header.security_key_required:
        if not header.factor_params:
            raise SecurityKeyRequired(
                "this vault expects a security key but records no parameters "
                "for it; the header has been damaged")
        return factors.Fido2Factor.from_parameters(header.factor_params,
                                                   authenticator)
    if header.keyfile_required:
        if not keyfile_path:
            raise KeyfileRequired(
                "this vault was created with a keyfile; supply it to unlock")
        return factors.KeyfileFactor(keyfile_path)
    return NoFactor()


#: Domain separator, so the stored digest cannot be confused with any other
#: hash of the same key.
DURESS_DOMAIN = b"quenchkey/duress/v1"


class DuressTriggered(Exception):
    """Raised when the passphrase given was the duress one.

    The vault is gone by the time this is raised. It carries no vault and no
    key because there is nothing left to carry.
    """

    def __init__(self, path: str, destroyed: bool):
        super().__init__("the duress passphrase was used")
        self.path = path
        self.destroyed = destroyed


def _duress_digest(passphrase: str, header: "VaultHeader",
                   keyfile_path: Optional[str] = None) -> bytes:
    resolved = _factor_for_header(header, keyfile_path, None, None) \
        if header.factor_kind != factors.FACTOR_NONE else None
    secret = factors.build_kdf_input(passphrase, resolved)
    try:
        derived = crypto.derive_master_key(secret, header.kdf)
    finally:
        secret.wipe()
    try:
        return hashlib.sha256(DURESS_DOMAIN + derived.bytes()).digest()
    finally:
        derived.wipe()


def duress_matches(path: str, passphrase: str,
                   keyfile_path: Optional[str] = None) -> bool:
    """Whether this passphrase is the vault's duress passphrase.

    Checked only after a normal unlock has already failed, so a correct
    passphrase never takes this path and a mistyped one is simply wrong.
    """
    try:
        header = read_header(path)
    except (OSError, UnsupportedFormat):
        return False
    stored = header.factor_params.get("duress")
    if not stored:
        return False
    try:
        candidate = _duress_digest(passphrase, header, keyfile_path)
    except Exception:  # noqa: BLE001 - a failure here is simply "no match"
        return False
    return hmac.compare_digest(bytes.fromhex(stored), candidate)


def destroy_vault(path: str) -> bool:
    """Overwrite and remove a vault file. Needs no key, and cannot be undone.

    What this reaches is one file on one machine. Copies elsewhere — a backup,
    a snapshot, a filesystem that never really overwrites anything — are
    untouched, and nothing here can pretend otherwise.
    """
    try:
        _overwrite_in_place(path)
        os.unlink(path)
    except OSError:
        return False
    for extra in (path + ".schedule", path + ".pending"):
        try:
            os.unlink(extra)
        except OSError:
            pass
    return True


def _overwrite_in_place(path: str) -> None:
    """Best-effort overwrite of a file's bytes with random data."""
    try:
        size = os.path.getsize(path)
    except OSError:
        return
    try:
        with open(path, "r+b") as fh:
            remaining = size
            while remaining > 0:
                step = min(remaining, 1 << 20)
                fh.write(os.urandom(step))
                remaining -= step
            fh.flush()
            os.fsync(fh.fileno())
    except OSError:
        pass


def _fsync_dir(directory: str) -> None:
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)
