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

"""Locking files into ``.qkey`` blobs and opening them again.

The output file contains the ciphertext and nothing else that is secret. Its
key is generated fresh from ``os.urandom`` for every locked item and is written
only into the vault. That separation is the whole point of Quenchkey: copies
of a ``.qkey`` file can be scattered across machines and backups, and when the
key is destroyed every one of them becomes permanently unreadable at the same
instant.

Blob layout
-----------

::

    offset  size  field
    0       8     magic  b"QKEYLOCK"
    8       1     format version
    9       1     cipher id
    10      2     reserved
    12      16    entry id (links the blob to its vault entry)
    28      4     nonce prefix
    32      4     chunk size
    36      8     plaintext length
    44      ...   chunk 0 || chunk 1 || ...   each ciphertext + 16-byte tag

The 44-byte header is passed as associated data for every chunk, so it cannot
be edited. Each chunk additionally authenticates its own index and whether it
is the last one, which means chunks cannot be reordered, duplicated, dropped or
spliced in from another file, and the stream cannot be truncated unnoticed.

Chunking keeps memory flat: a 40 GB file is encrypted a megabyte at a time.
"""

from __future__ import annotations

import os
import secrets
import shutil
import struct
import tempfile
import time
from dataclasses import dataclass
from typing import Callable, Optional, Sequence

from . import archive, crypto
from .crypto import AuthenticationError, SecretBytes, UnsupportedFormat
from .vault import Entry, Vault

BLOB_MAGIC = b"QKEYLOCK"
BLOB_VERSION = 1
BLOB_HEADER_LEN = 44

#: Header flag: the key for this file is inside this file, wrapped by a
#: passphrase of its own, rather than in a vault.
#:
#: Which means this file can never expire. Expiry works by destroying a key
#: that lives somewhere the holder of the file does not control; a file that
#: carries its own key has nothing that can be taken away from it. The flag
#: exists so that no tool reading this file has to guess, and so that none of
#: them can be made to show a deadline that could not be enforced.
FLAG_SELF_CONTAINED = 0x0001

#: Header flag: the key for this file is wrapped to one particular vault.
#:
#: Defined here rather than in :mod:`quenchkey.handover` so that every reader
#: of a ``.qkey`` header knows all three kinds without importing the module
#: that writes one of them. See that module for what an addressed file is for.
FLAG_ADDRESSED = 0x0002
QKEY_SUFFIX = ".qkey"

ProgressFn = Callable[[str, float], None]


class LockError(Exception):
    """A lock or unlock operation failed."""


class BlobMismatch(LockError):
    """This blob does not belong to the vault entry it was matched against."""


@dataclass(frozen=True)
class BlobHeader:
    cipher_id: int
    entry_id: bytes
    nonce_prefix: bytes
    chunk_size: int
    plaintext_len: int
    flags: int = 0

    def pack(self) -> bytes:
        return BLOB_MAGIC + struct.pack(
            ">BBH16s4sIQ",
            BLOB_VERSION,
            self.cipher_id,
            self.flags,
            self.entry_id,
            self.nonce_prefix,
            self.chunk_size,
            self.plaintext_len,
        )

    @property
    def entry_id_hex(self) -> str:
        return self.entry_id.hex()

    @property
    def self_contained(self) -> bool:
        """Whether this file carries its own key, wrapped by a passphrase.

        The flag is in the clear and authenticated, so every tool that can
        read the header can say which kind of file this is without a
        passphrase — including that a self-contained one has no deadline and
        never will.
        """
        return bool(self.flags & FLAG_SELF_CONTAINED)

    @property
    def addressed(self) -> bool:
        """Whether this file's key is wrapped to one particular vault.

        The opposite of :attr:`self_contained` in the way that matters: a
        self-contained file can never expire, and an addressed one is made so
        that it can, once the vault it is addressed to has taken its key in.
        """
        return bool(self.flags & FLAG_ADDRESSED)

    @property
    def kind(self) -> str:
        """One word for what sort of locked file this is."""
        if self.addressed:
            return "addressed"
        if self.self_contained:
            return "shared"
        return "vault"


def read_blob_header(path: str) -> BlobHeader:
    """Read a ``.qkey`` header. Needs no key — it holds no secrets."""
    with open(path, "rb") as fh:
        raw = fh.read(BLOB_HEADER_LEN)
    if len(raw) < BLOB_HEADER_LEN:
        raise UnsupportedFormat("this .qkey file is truncated")
    if raw[:8] != BLOB_MAGIC:
        raise UnsupportedFormat("not a Quenchkey locked file")
    version, cipher_id, flags, entry_id, prefix, chunk_size, plain_len = struct.unpack(
        ">BBH16s4sIQ", raw[8:BLOB_HEADER_LEN]
    )
    if version != BLOB_VERSION:
        raise UnsupportedFormat(
            f"locked-file format version {version}; this build understands {BLOB_VERSION}"
        )
    if not (4096 <= chunk_size <= 64 * 1024 * 1024):
        raise UnsupportedFormat("implausible chunk size")
    return BlobHeader(cipher_id, entry_id, prefix, chunk_size, plain_len, flags)


# --------------------------------------------------------------------------
# streaming encryption
# --------------------------------------------------------------------------

def encrypt_stream(source_path: str, destination_path: str, key: SecretBytes,
                   entry_id_hex: str, cipher_id: int = crypto.DEFAULT_CIPHER,
                   chunk_size: int = crypto.CHUNK_SIZE,
                   progress: Optional[ProgressFn] = None,
                   flags: int = 0, extra_header: bytes = b"") -> BlobHeader:
    """Encrypt a file chunk by chunk.

    ``extra_header`` is written straight after the fixed header and folded
    into the associated data of every chunk, so anything carried there — the
    wrapped key of a shared file, for instance — cannot be swapped, stripped
    or moved between files without every chunk failing to authenticate.
    """
    plaintext_len = os.path.getsize(source_path)
    header = BlobHeader(cipher_id, bytes.fromhex(entry_id_hex), os.urandom(4),
                        chunk_size, plaintext_len, flags)
    packed = header.pack() + extra_header
    written = 0
    with open(source_path, "rb") as src, open(destination_path, "wb") as dst:
        os.chmod(destination_path, 0o600)
        dst.write(packed)
        index = 0
        while True:
            chunk = src.read(chunk_size)
            at_end = written + len(chunk) >= plaintext_len
            if not chunk and index > 0:
                break
            nonce = crypto.chunk_nonce(header.nonce_prefix, index)
            _, sealed = crypto.encrypt(key, chunk, crypto.chunk_aad(packed, index, at_end),
                                       cipher_id, nonce)
            dst.write(sealed)
            written += len(chunk)
            index += 1
            if progress and plaintext_len:
                progress("encrypting", min(1.0, written / plaintext_len))
            if at_end:
                break
        dst.flush()
        os.fsync(dst.fileno())
    return header


def expected_blob_size(header: BlobHeader, extra_header_len: int = 0) -> int:
    """How large a well-formed blob with this header must be."""
    chunks = max(1, -(-header.plaintext_len // header.chunk_size))
    return (BLOB_HEADER_LEN + extra_header_len + header.plaintext_len
            + chunks * crypto.TAG_SIZE)


def decrypt_stream(source_path: str, destination_path: str, key: SecretBytes,
                   progress: Optional[ProgressFn] = None,
                   extra_header: bytes = b"") -> BlobHeader:
    header = read_blob_header(source_path)

    # Check the header's claimed length against the file before allocating
    # anything, so an edited header cannot steer the read loop.
    actual = os.path.getsize(source_path)
    if actual != expected_blob_size(header, len(extra_header)):
        raise AuthenticationError(
            "this locked file does not match the length recorded in its own "
            "header: it is truncated, padded, or has been edited"
        )

    packed = header.pack() + extra_header
    sealed_size = header.chunk_size + crypto.TAG_SIZE
    remaining = header.plaintext_len
    with open(source_path, "rb") as src, open(destination_path, "wb") as dst:
        os.chmod(destination_path, 0o600)
        src.seek(BLOB_HEADER_LEN + len(extra_header))
        index = 0
        produced = 0
        while True:
            at_end = remaining <= header.chunk_size
            want = (remaining + crypto.TAG_SIZE) if at_end else sealed_size
            sealed = src.read(want)
            if len(sealed) != want:
                raise AuthenticationError(
                    "this locked file is truncated or corrupt: it does not "
                    "match the length recorded in its own header"
                )
            plain = crypto.decrypt(key, crypto.chunk_nonce(header.nonce_prefix, index),
                                   sealed, crypto.chunk_aad(packed, index, at_end),
                                   header.cipher_id)
            dst.write(plain)
            produced += len(plain)
            remaining -= len(plain)
            index += 1
            if progress and header.plaintext_len:
                progress("decrypting", min(1.0, produced / header.plaintext_len))
            if at_end:
                break
        # Anything after the final authenticated chunk is not part of the file.
        if src.read(1):
            raise AuthenticationError("this locked file has trailing data appended to it")
        dst.flush()
        os.fsync(dst.fileno())
    return header


# --------------------------------------------------------------------------
# high-level operations
# --------------------------------------------------------------------------

@dataclass
class LockResult:
    entry: Entry
    blob_path: str
    member_count: int


def default_blob_path(paths: Sequence[str], output_dir: str) -> str:
    """Pick a non-clashing ``.qkey`` filename for a selection."""
    if len(paths) == 1:
        stem = os.path.splitext(os.path.basename(os.path.abspath(paths[0]).rstrip(os.sep)))[0]
    else:
        stem = f"{len(paths)} items"
    stem = stem or "locked"
    candidate = os.path.join(output_dir, stem + QKEY_SUFFIX)
    n = 2
    while os.path.exists(candidate):
        candidate = os.path.join(output_dir, f"{stem} ({n}){QKEY_SUFFIX}")
        n += 1
    return candidate


def lock_files(vault: Vault, paths: Sequence[str], expires: Optional[float],
               blob_path: Optional[str] = None, output_dir: Optional[str] = None,
               label: str = "", delete_originals: bool = False,
               delete_blob_on_expiry: bool = False,
               max_opens: Optional[int] = None,
               heartbeat_days: Optional[float] = None,
               progress: Optional[ProgressFn] = None) -> LockResult:
    """Lock a selection of files and register the key in the vault.

    Order of operations matters. The key is generated, the archive built, the
    blob written and only then is the entry saved to the vault. If anything
    fails before the vault is written, the partial blob is shredded and no
    entry exists — there is never a vault entry pointing at a file that was
    not completely written.
    """
    if not paths:
        raise LockError("no files selected")
    if blob_path is None:
        blob_path = default_blob_path(paths, output_dir or os.path.dirname(
            os.path.abspath(paths[0])))
    blob_path = os.path.abspath(blob_path)
    os.makedirs(os.path.dirname(blob_path) or ".", exist_ok=True)

    entry_id = vault.new_entry_id()
    file_key = SecretBytes.random()
    staging = _staging_path(blob_path)
    try:
        if progress:
            progress("packing", 0.0)
        plans, plaintext_size = archive.pack(
            paths, staging, file_key,
            progress=lambda name, frac: progress and progress(f"packing {name}", frac * 0.5))
        if progress:
            progress("encrypting", 0.5)
        encrypt_stream(staging, blob_path, file_key, entry_id,
                       cipher_id=vault.header.cipher_id,
                       progress=lambda _n, frac: progress and progress("encrypting",
                                                                       0.5 + frac * 0.5))
        # Hashed now, while the file is certainly the one just written, so a
        # certificate issued years later can still say which file it means.
        from .certificate import file_digest

        entry = Entry(
            id=entry_id,
            blob_path=blob_path,
            key=file_key,
            created=time.time(),
            expires=expires,
            names=[p.arcname for p in plans],
            blob_size=os.path.getsize(blob_path),
            plaintext_size=plaintext_size,
            cipher_id=vault.header.cipher_id,
            delete_blob_on_expiry=delete_blob_on_expiry,
            label=label,
            blob_sha256=file_digest(blob_path) or "",
            max_opens=max_opens,
            heartbeat_days=heartbeat_days,
        )
        vault.add_entry(entry)
        vault.save()
    except BaseException:
        file_key.wipe()
        if os.path.exists(blob_path):
            shred_file(blob_path)
        raise
    finally:
        if os.path.exists(staging):
            shred_file(staging)

    if delete_originals:
        for path in paths:
            _delete_original(path)
        vault.log_event("originals_deleted", entry=entry_id, count=len(paths))
        vault.save()

    if progress:
        progress("done", 1.0)
    return LockResult(entry, blob_path, len(plans))


def unlock_entry(vault: Vault, entry_id: str, destination_dir: str,
                 progress: Optional[ProgressFn] = None) -> list[str]:
    """Decrypt and extract an entry's files into ``destination_dir``.

    Raises :class:`~quenchkey.vault.KeyDestroyed` if the key has expired —
    there is no fallback path, because there is no key.
    """
    entry = vault.get(entry_id)
    key = vault.key_for(entry_id)  # raises KeyDestroyed
    if not os.path.exists(entry.blob_path):
        raise LockError(f"the locked file is missing from {entry.blob_path}")

    header = read_blob_header(entry.blob_path)
    if header.entry_id_hex != entry.id:
        raise BlobMismatch(
            "this .qkey file belongs to a different vault entry; its key is not here"
        )

    staging = _staging_path(entry.blob_path)
    try:
        if progress:
            progress("decrypting", 0.0)
        decrypt_stream(entry.blob_path, staging, key,
                       progress=lambda _n, frac: progress and progress("decrypting",
                                                                       frac * 0.6),
                       extra_header=extra_header_bytes(entry.blob_path))
        if progress:
            progress("extracting", 0.6)
        written = archive.unpack(staging, destination_dir, key,
                                 progress=lambda _n, frac: progress and progress(
                                     "extracting", 0.6 + frac * 0.4))
    finally:
        if os.path.exists(staging):
            shred_file(staging)
    if progress:
        progress("done", 1.0)
    vault.log_event("unlocked_entry", entry=entry_id, destination=destination_dir)
    # Counted only once the files are actually out, so a failed extraction does
    # not spend one of a limited allowance.
    vault.record_open(entry_id)
    vault.save()
    return written


def inspect_blob(path: str) -> dict:
    """Describe a ``.qkey`` file without a key, for the UI's 'identify' action."""
    header = read_blob_header(path)
    return {
        "path": path,
        "entry_id": header.entry_id_hex,
        "cipher": crypto.cipher_name(header.cipher_id),
        "plaintext_size": header.plaintext_len,
        "blob_size": os.path.getsize(path),
        "chunk_size": header.chunk_size,
    }


# --------------------------------------------------------------------------
# file hygiene
# --------------------------------------------------------------------------

def _staging_path(near: str) -> str:
    directory = os.path.dirname(os.path.abspath(near)) or "."
    return os.path.join(directory, f".qkey-staging-{secrets.token_hex(8)}.7z")


def shred_file(path: str, passes: int = 1) -> bool:
    """Overwrite a file with random bytes, then delete it.

    Best effort only. On a copy-on-write or log-structured filesystem, or an
    SSD doing wear levelling, the original blocks may survive untouched. The
    README says so plainly; this is here because it is better than nothing on
    a plain overwrite-in-place filesystem, not because it is a guarantee.
    """
    try:
        size = os.path.getsize(path)
    except OSError:
        return False
    try:
        with open(path, "r+b") as fh:
            for _ in range(max(1, passes)):
                fh.seek(0)
                remaining = size
                while remaining > 0:
                    step = min(remaining, 1 << 20)
                    fh.write(os.urandom(step))
                    remaining -= step
                fh.flush()
                os.fsync(fh.fileno())
    except OSError:
        pass
    try:
        os.unlink(path)
        return True
    except OSError:
        return False


def _delete_original(path: str) -> None:
    if os.path.isdir(path):
        for dirpath, _dirnames, filenames in os.walk(path, topdown=False):
            for name in filenames:
                shred_file(os.path.join(dirpath, name))
            try:
                os.rmdir(dirpath)
            except OSError:
                pass
    else:
        shred_file(path)


# --------------------------------------------------------------------------
# shared files: the key travels with the file, so there is no deadline
# --------------------------------------------------------------------------
#
# Everything above keeps the key in the vault and the ciphertext wherever you
# like. That separation is the whole mechanism: destroy the one key and every
# copy of the file, everywhere, becomes unreadable at once.
#
# A shared file gives that up on purpose. Its key is generated the same way
# and is just as strong, but it is wrapped by a passphrase and written into
# the file itself, so whoever has the file and the passphrase can open it on
# any machine, with no vault, no account and no network — and can go on
# opening it forever. There is nothing left to destroy.
#
# So a shared file is not a Quenchkey file with a different setting. It is a
# different thing that happens to share a container, and the flag in its
# header exists so that nothing downstream can blur the two.

#: Layout of the key-wrap block that follows the fixed header, big-endian:
#: kdf id, cipher id, two reserved bytes, salt, the three Argon2 cost
#: parameters, and the nonce the file key is wrapped under.
SHARE_STRUCT = ">BBH16sIII12s"
SHARE_PREFIX_LEN = struct.calcsize(SHARE_STRUCT)          # 44
SHARE_WRAPPED_LEN = crypto.KEY_SIZE + crypto.TAG_SIZE     # 48
SHARE_BLOCK_LEN = SHARE_PREFIX_LEN + SHARE_WRAPPED_LEN    # 92


@dataclass
class ShareBlock:
    """The wrapped key a shared file carries, and how to unwrap it."""

    kdf: crypto.KdfParams
    cipher_id: int
    nonce: bytes
    wrapped_key: bytes

    def prefix(self) -> bytes:
        """Everything except the wrapped key, which is what authenticates it."""
        return struct.pack(
            SHARE_STRUCT, self.kdf.kdf_id, self.cipher_id, 0, self.kdf.salt,
            self.kdf.time_cost, self.kdf.memory_kib, self.kdf.parallelism,
            self.nonce)

    def pack(self) -> bytes:
        return self.prefix() + self.wrapped_key

    @classmethod
    def unpack(cls, raw: bytes) -> "ShareBlock":
        if len(raw) != SHARE_BLOCK_LEN:
            raise UnsupportedFormat("truncated key block in a shared file")
        (kdf_id, cipher_id, _reserved, salt, time_cost, memory_kib,
         parallelism, nonce) = struct.unpack(SHARE_STRUCT, raw[:SHARE_PREFIX_LEN])
        if kdf_id != crypto.KDF_ARGON2ID:
            raise UnsupportedFormat(f"unknown key derivation {kdf_id} in a shared file")
        # Refuse implausible cost parameters before handing them to Argon2: a
        # doctored header could otherwise ask for terabytes of memory and take
        # the machine down instead of failing to open a file.
        if not (1 <= time_cost <= 64) or not (8 <= memory_kib <= 4 * 1024 * 1024) \
                or not (1 <= parallelism <= 64):
            raise UnsupportedFormat("implausible key derivation cost in a shared file")
        kdf = crypto.KdfParams(salt=salt, time_cost=time_cost,
                               memory_kib=memory_kib, parallelism=parallelism,
                               kdf_id=kdf_id)
        return cls(kdf, cipher_id, nonce, raw[SHARE_PREFIX_LEN:])


def extra_header_bytes(path: str) -> bytes:
    """Whatever key block sits between the fixed header and the payload.

    Every chunk of a blob authenticates the fixed header *and* this block, so
    a reader that does not know it is there gets an authentication failure
    rather than a file. Keeping the knowledge of how long each kind of block
    is in one function means a new kind is added here once, instead of at
    every read path.
    """
    header = read_blob_header(path)
    if header.self_contained:
        with open(path, "rb") as fh:
            fh.seek(BLOB_HEADER_LEN)
            return fh.read(SHARE_BLOCK_LEN)
    if header.addressed:
        from .handover import block_bytes
        return block_bytes(path)
    return b""


def read_share_block(path: str) -> ShareBlock:
    """The key block of a shared file, without deriving anything."""
    header = read_blob_header(path)
    if not header.self_contained:
        raise UnsupportedFormat("this locked file keeps its key in a vault")
    with open(path, "rb") as fh:
        fh.seek(BLOB_HEADER_LEN)
        return ShareBlock.unpack(fh.read(SHARE_BLOCK_LEN))


def _wrap_key(file_key: SecretBytes, passphrase: str, kdf: crypto.KdfParams,
              cipher_id: int, header_bytes: bytes) -> ShareBlock:
    nonce = os.urandom(crypto.NONCE_SIZE)
    block = ShareBlock(kdf, cipher_id, nonce, b"")
    secret = crypto.build_kdf_input(passphrase)
    kek = crypto.derive_master_key(secret, kdf)
    try:
        # The fixed header and the block's own parameters are the associated
        # data, so neither can be altered without the unwrap failing.
        _, sealed = crypto.encrypt(kek, file_key.bytes(),
                                   header_bytes + block.prefix(), cipher_id, nonce)
    finally:
        kek.wipe()
        secret.wipe()
    block.wrapped_key = sealed
    return block


def lock_to_share(paths: Sequence[str], passphrase: str,
                  output_path: Optional[str] = None,
                  output_dir: Optional[str] = None,
                  cipher_id: int = crypto.DEFAULT_CIPHER,
                  kdf_params: Optional[crypto.KdfParams] = None,
                  delete_originals: bool = False,
                  progress: Optional[ProgressFn] = None) -> "ShareResult":
    """Pack files into one `.qkey` file that opens with its own passphrase.

    No vault is involved, on this machine or any other. The result is a
    self-contained file: give someone a copy and the passphrase and they can
    open it, forever, with this application or with ``quenchkey-recover``.

    It has no deadline, and setting one is not a feature that was left out —
    there would be nowhere to enforce it from.
    """
    if not paths:
        raise LockError("no files selected")
    if not passphrase:
        raise LockError("a shared file needs a passphrase of its own")

    if output_path is None:
        output_path = default_blob_path(paths, output_dir or os.path.dirname(
            os.path.abspath(paths[0])))
    output_path = os.path.abspath(output_path)
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    # Cost parameters may be supplied — by a caller that has already
    # calibrated, or by a test that wants them cheap — but never the salt.
    # Two shared files made with the same passphrase must not derive the same
    # key, or opening one would mean precomputing against the other.
    base = kdf_params or crypto.calibrate_kdf()
    kdf = crypto.KdfParams(os.urandom(crypto.SALT_SIZE), base.time_cost,
                           base.memory_kib, base.parallelism, base.kdf_id)
    kdf.validate()
    file_id = os.urandom(16).hex()
    file_key = SecretBytes.random()
    staging = _staging_path(output_path)
    try:
        if progress:
            progress("packing", 0.0)
        plans, plaintext_size = archive.pack(
            paths, staging, file_key,
            progress=lambda name, frac: progress and progress(f"packing {name}",
                                                              frac * 0.4))
        if progress:
            progress("deriving a key from the passphrase", 0.4)

        # The header has to exist before the key can be wrapped against it,
        # and its length has to be final. Building it here with the same
        # values encrypt_stream will use keeps the two in step; the nonce
        # prefix is the only field that differs, and it is not in the AAD of
        # the wrap because encrypt_stream chooses it.
        head = BlobHeader(cipher_id, bytes.fromhex(file_id), b"\x00" * 4,
                          crypto.CHUNK_SIZE, os.path.getsize(staging),
                          FLAG_SELF_CONTAINED)
        block = _wrap_key(file_key, passphrase, kdf, cipher_id, head.pack())

        if progress:
            progress("encrypting", 0.5)
        header = encrypt_stream(
            staging, output_path, file_key, file_id, cipher_id=cipher_id,
            progress=lambda _n, frac: progress and progress("encrypting",
                                                            0.5 + frac * 0.5),
            flags=FLAG_SELF_CONTAINED, extra_header=block.pack())
    finally:
        shred_file(staging)
        file_key.wipe()

    if delete_originals:
        for path in paths:
            _delete_original(path)

    from .certificate import file_digest
    return ShareResult(
        path=output_path,
        names=[p.arcname for p in plans],
        size=os.path.getsize(output_path),
        plaintext_size=plaintext_size,
        created=time.time(),
        sha256=file_digest(output_path) or "",
        kdf=kdf,
        cipher_id=header.cipher_id,
    )


@dataclass
class ShareResult:
    """What was written, for the record kept beside it."""

    path: str
    names: list
    size: int
    plaintext_size: int
    created: float
    sha256: str
    kdf: crypto.KdfParams
    cipher_id: int


def open_shared(source_path: str, passphrase: str, destination_dir: str,
                progress: Optional[ProgressFn] = None) -> list:
    """Open a shared file with its own passphrase. No vault, no network.

    Raises :class:`AuthenticationError` for a wrong passphrase, which is
    indistinguishable from a tampered file and is reported as such — there is
    no way to tell the two apart and no reason to guess.
    """
    header = read_blob_header(source_path)
    if not header.self_contained:
        raise UnsupportedFormat(
            "this locked file keeps its key in a vault; open it from the vault")

    block = read_share_block(source_path)
    bare = BlobHeader(header.cipher_id, header.entry_id, b"\x00" * 4,
                      header.chunk_size, header.plaintext_len, header.flags)

    if progress:
        progress("deriving the key from the passphrase", 0.0)
    secret = crypto.build_kdf_input(passphrase)
    kek = crypto.derive_master_key(secret, block.kdf)
    try:
        raw = crypto.decrypt(kek, block.nonce, block.wrapped_key,
                             bare.pack() + block.prefix(), block.cipher_id)
    finally:
        kek.wipe()
        secret.wipe()

    file_key = SecretBytes(bytearray(raw))
    staging = _staging_path(source_path)
    try:
        decrypt_stream(source_path, staging, file_key,
                       progress=lambda _n, frac: progress and progress(
                           "decrypting", frac * 0.6),
                       extra_header=block.pack())
        written = archive.unpack(
            staging, destination_dir, file_key,
            progress=lambda name, frac: progress and progress(
                f"extracting {name}", 0.6 + frac * 0.4))
    finally:
        shred_file(staging)
        file_key.wipe()
    return written


# --------------------------------------------------------------------------
# unlocking shared files, several at a time
# --------------------------------------------------------------------------
#
# Shared files usually arrive in batches and usually share a passphrase, so
# unlocking them one at a time through a file chooser is the wrong shape. The
# result goes back where the locked file already is — moving somebody's files
# somewhere else as a side effect of opening them is not a decision this
# application should be making — and carries a suffix so that a folder with
# both versions in it can be read at a glance.

#: Added to whatever comes out, so it is obvious which files were locked.
UNLOCKED_SUFFIX = "_quenchkeyunlocked"

#: Output shapes. ``extract`` puts the files back as files; ``archive`` makes
#: one 7z with no password at all, for passing on to somebody who should not
#: need a passphrase.
MODE_EXTRACT = "extract"
MODE_ARCHIVE = "archive"


@dataclass
class UnlockOutcome:
    """What happened to one file. Never raises — the batch reports instead."""

    source: str
    ok: bool = False
    reason: str = ""
    written: list = None
    destination: str = ""
    removed_locked: bool = False

    def __post_init__(self):
        if self.written is None:
            self.written = []

    @property
    def name(self) -> str:
        return os.path.basename(self.source)


def free_path(directory: str, stem: str, extension: str = "") -> str:
    """A path in ``directory`` that does not exist yet.

    Unlocking must never overwrite anything. Somebody who unlocks the same
    file twice gets a second copy, not a silently replaced first one.
    """
    candidate = os.path.join(directory, f"{stem}{extension}")
    if not os.path.exists(candidate):
        return candidate
    index = 2
    while True:
        candidate = os.path.join(directory, f"{stem} ({index}){extension}")
        if not os.path.exists(candidate):
            return candidate
        index += 1


def _place_extracted(staging_dir: str, source_path: str,
                     directory: Optional[str] = None) -> tuple:
    """Move an extracted tree next to its locked file, suitably named.

    One file comes out as one file, named after itself. Several come out in a
    folder named after the locked file, because scattering a dozen documents
    into somebody's Documents folder is not "extracting" so much as "making a
    mess".
    """
    directory = directory or os.path.dirname(os.path.abspath(source_path)) or "."
    os.makedirs(directory, exist_ok=True)
    stem = os.path.splitext(os.path.basename(source_path))[0]

    members = []
    for current, _dirs, files in os.walk(staging_dir):
        for name in files:
            members.append(os.path.join(current, name))

    if len(members) == 1 and os.path.dirname(
            os.path.relpath(members[0], staging_dir)) == "":
        only = members[0]
        base, extension = os.path.splitext(os.path.basename(only))
        target = free_path(directory, f"{base}{UNLOCKED_SUFFIX}", extension)
        shutil.move(only, target)
        return target, [target]

    folder = free_path(directory, f"{stem}{UNLOCKED_SUFFIX}")
    shutil.move(staging_dir, folder)
    written = []
    for current, _dirs, files in os.walk(folder):
        for name in sorted(files):
            written.append(os.path.join(current, name))
    return folder, sorted(written)


def unlock_shared_file(source_path: str, passphrase: str,
                       mode: str = MODE_EXTRACT, keep_locked: bool = True,
                       destination_dir: Optional[str] = None,
                       progress: Optional[ProgressFn] = None) -> UnlockOutcome:
    """Open one shared file. The result goes beside it unless told otherwise.

    Returns an :class:`UnlockOutcome` rather than raising, so one wrong
    passphrase in a batch of ten does not stop the other nine.
    """
    outcome = UnlockOutcome(source=os.path.abspath(source_path))
    staging = tempfile.mkdtemp(prefix="quenchkey-unlock-",
                               dir=os.path.dirname(outcome.source) or None)
    try:
        open_shared(outcome.source, passphrase, staging, progress=progress)

        directory = destination_dir or os.path.dirname(outcome.source) or "."
        os.makedirs(directory, exist_ok=True)
        if mode == MODE_ARCHIVE:
            stem = os.path.splitext(os.path.basename(outcome.source))[0]
            target = free_path(directory, f"{stem}{UNLOCKED_SUFFIX}", ".7z")
            archive.pack_plain(staging, target)
            outcome.destination = target
            outcome.written = [target]
        else:
            destination, written = _place_extracted(staging, outcome.source,
                                                    destination_dir)
            outcome.destination = destination
            outcome.written = written

        if not keep_locked:
            outcome.removed_locked = shred_file(outcome.source)
        outcome.ok = True
    except AuthenticationError:
        outcome.reason = ("wrong passphrase, or the file has been altered — "
                          "there is no way to tell which apart")
    except UnsupportedFormat as exc:
        outcome.reason = str(exc)
    except (OSError, LockError, Exception) as exc:  # noqa: BLE001
        outcome.reason = str(exc)
    finally:
        # Always, and unconditionally. A single extracted document is *moved*
        # out of the staging directory rather than the directory being moved
        # into place, so skipping this when the extraction succeeded leaves an
        # empty quenchkey-unlock-xxxx folder sitting in the user's own folder.
        shutil.rmtree(staging, ignore_errors=True)
    return outcome


def unlock_shared_files(paths: Sequence[str], passphrase: str,
                        mode: str = MODE_EXTRACT, keep_locked: bool = True,
                        destination_dir: Optional[str] = None,
                        progress: Optional[ProgressFn] = None) -> list:
    """Try one passphrase against several shared files.

    Deriving the key is deliberately slow, and it is derived once per file
    because each carries its own salt — which is the point of the salt. A
    batch of ten therefore takes ten times as long as one, and the progress
    reported here is per file rather than a guess at the whole.
    """
    outcomes = []
    total = len(paths) or 1
    for index, path in enumerate(paths):
        def step(stage: str, fraction: float, _i=index) -> None:
            if progress:
                progress(f"{os.path.basename(path)}: {stage}",
                         (_i + fraction) / total)
        outcomes.append(unlock_shared_file(path, passphrase, mode=mode,
                                           keep_locked=keep_locked,
                                           destination_dir=destination_dir,
                                           progress=step))
    if progress:
        progress("done", 1.0)
    return outcomes


# --------------------------------------------------------------------------
# checking a file out, on loan
# --------------------------------------------------------------------------
#
# Opening a locked file normally is a one-way door: the copies that come out
# are ordinary files, with no deadline and nothing this application can do to
# them. That is stated everywhere, and for most uses it is the right
# behaviour — you asked for your file, here is your file.
#
# A checkout is the other option. The files come out the same way, but their
# paths are recorded against the entry, and when the loan runs out they are
# shredded and the entry goes back to being merely locked.
#
# What that does and does not reach is the whole of the honesty here. It
# reaches the copies *this* extraction made, at the paths it wrote them to. It
# does not reach a copy you made afterwards, a file your editor wrote to a
# different directory, a backup that ran in the meantime, or anything on
# another machine. A checkout is tidying, not control.

#: Offered in the interface. A loan longer than a day is not really a loan.
CHECKOUT_MINUTES = (5, 15, 30, 60, 120, 240, 480, 1440)

DEFAULT_CHECKOUT_MINUTES = 30


@dataclass
class CheckoutReport:
    """What a finished loan did."""

    entry_id: str
    shredded: list = None
    missing: list = None
    failed: list = None
    #: Files whose contents differed from what went out.
    edited: list = None
    #: True when those edits were written back into the vault.
    saved: bool = False
    #: Why they were not, when they were not.
    not_saved_because: str = ""

    def __post_init__(self):
        for name in ("shredded", "missing", "failed", "edited"):
            if getattr(self, name) is None:
                setattr(self, name, [])

    @property
    def changed(self) -> bool:
        return bool(self.shredded or self.missing)

    def summary(self) -> str:
        """One line, in the terms a person would use."""
        if self.failed:
            return (f"{len(self.failed)} file"
                    f"{'s' if len(self.failed) != 1 else ''} could not be "
                    f"removed and are still on disk.")
        if self.edited and self.saved:
            return (f"{len(self.edited)} edited file"
                    f"{'s were' if len(self.edited) != 1 else ' was'} locked "
                    f"back in, and the working copies removed.")
        if self.edited and not self.saved:
            return (f"{len(self.edited)} file"
                    f"{'s were' if len(self.edited) != 1 else ' was'} edited "
                    f"and left where they are: {self.not_saved_because}")
        if self.missing and not self.shredded:
            return "Nothing was there to bring back."
        return (f"{len(self.shredded)} working cop"
                f"{'ies' if len(self.shredded) != 1 else 'y'} removed; "
                f"nothing had been edited, so the vault is unchanged.")


def check_out(vault: Vault, entry_id: str, destination_dir: str,
              minutes: int = DEFAULT_CHECKOUT_MINUTES,
              progress: Optional[ProgressFn] = None) -> list:
    """Open an entry on loan, recording what came out and until when."""
    if minutes <= 0:
        raise LockError("a checkout needs a length")
    written = unlock_entry(vault, entry_id, destination_dir, progress=progress)

    from .certificate import file_digest

    entry = _entry_or_raise(vault, entry_id)
    entry.checkout_until = time.time() + minutes * 60
    entry.checkout_paths = [os.path.abspath(p) for p in written]
    # Fingerprinted as it goes out, so check-in can tell an edit from an
    # untouched copy without keeping the plaintext anywhere.
    entry.checkout_digests = {
        os.path.abspath(p): (file_digest(p) or "") for p in written}
    vault.log_event("checked_out", entry=entry_id, minutes=minutes,
                    files=len(written))
    vault.save()
    return written


def _relock(vault: Vault, entry: Entry, paths: Sequence[str],
            progress: Optional[ProgressFn] = None) -> None:
    """Rewrite an entry's blob from ``paths``, keeping its key and its id.

    The key and the entry id are what every deadline, certificate and log
    line already refers to, so both are kept. The new blob is written beside
    the old one and moved into place, so a failure halfway leaves the blob
    that was already there.
    """
    key = vault.key_for(entry.id)
    staging = _staging_path(entry.blob_path)
    pending = f"{entry.blob_path}.pending-{os.getpid()}"
    try:
        plans, plaintext_size = archive.pack(
            paths, staging, key,
            progress=lambda name, frac: progress and progress(
                f"packing {name}", frac * 0.5))
        encrypt_stream(staging, pending, key, entry.id,
                       cipher_id=entry.cipher_id,
                       progress=lambda _n, frac: progress and progress(
                           "encrypting", 0.5 + frac * 0.5))
        os.replace(pending, entry.blob_path)
    except BaseException:
        if os.path.exists(pending):
            shred_file(pending)
        raise
    finally:
        if os.path.exists(staging):
            shred_file(staging)

    from .certificate import file_digest

    entry.names = [p.arcname for p in plans]
    entry.blob_size = os.path.getsize(entry.blob_path)
    entry.plaintext_size = plaintext_size
    entry.blob_sha256 = file_digest(entry.blob_path) or ""


def check_in(vault: Vault, entry_id: str, save_edits: bool = True,
             progress: Optional[ProgressFn] = None) -> CheckoutReport:
    """End a loan: lock any edits back in, then remove the working copies.

    An edited file is written back into the entry before its copy is
    shredded, because a checkout that quietly destroyed an afternoon's work
    would be a trap rather than a feature. Pass ``save_edits=False`` to throw
    the changes away on purpose; the report says which happened either way.
    """
    from .certificate import file_digest

    entry = _entry_or_raise(vault, entry_id)
    report = CheckoutReport(entry_id)
    if not entry.checked_out:
        return report

    present = [p for p in entry.checkout_paths if os.path.exists(p)]
    for path in entry.checkout_paths:
        was = entry.checkout_digests.get(path)
        now = file_digest(path)
        if now is not None and was and now != was:
            report.edited.append(path)

    if report.edited:
        if not save_edits:
            report.not_saved_because = "you chose not to keep them"
        elif entry.key_destroyed:
            report.not_saved_because = (
                "this entry's key has been destroyed, so there is nothing "
                "left to lock them back into")
        elif len(present) != len(entry.checkout_paths):
            report.not_saved_because = (
                "some of what went out is missing, and locking back only "
                "part of it would quietly lose the rest")
        else:
            try:
                _relock(vault, entry, present, progress=progress)
                report.saved = True
                vault.log_event("checkout_edits_locked_back",
                                entry=entry_id, files=len(report.edited),
                                blob_sha256=entry.blob_sha256)
            except (OSError, LockError, archive.ArchiveError) as exc:
                report.not_saved_because = f"writing them back failed: {exc}"

    # Working copies are removed only once any edit in them is safely inside
    # the vault. Edits that could not be saved are left exactly where they are.
    if report.edited and not report.saved:
        for path in entry.checkout_paths:
            if not os.path.exists(path):
                report.missing.append(path)
        entry.checkout_until = None
        entry.checkout_paths = []
        entry.checkout_digests = {}
        vault.log_event("checked_in", entry=entry_id, shredded=0,
                        missing=len(report.missing),
                        edits_left_on_disk=len(report.edited))
        vault.save()
        return report

    for path in list(entry.checkout_paths):
        if not os.path.exists(path):
            report.missing.append(path)
            continue
        try:
            if shred_file(path):
                report.shredded.append(path)
            else:
                report.failed.append(path)
        except OSError:
            report.failed.append(path)

    # Directories the extraction created, removed only when they are empty —
    # anything the user put there in the meantime is theirs, not ours.
    for directory in sorted({os.path.dirname(p) for p in entry.checkout_paths},
                            key=len, reverse=True):
        try:
            os.rmdir(directory)
        except OSError:
            pass

    entry.checkout_until = None
    entry.checkout_paths = []
    entry.checkout_digests = {}
    vault.log_event("checked_in", entry=entry_id,
                    shredded=len(report.shredded),
                    missing=len(report.missing),
                    edits_locked_back=len(report.edited) if report.saved else 0)
    vault.save()
    return report


def due_checkouts(vault: Vault, now: Optional[float] = None) -> list:
    """Entries whose loan has run out."""
    moment = vault.effective_now() if now is None else now
    return [entry for entry in vault.entries()
            if entry.checked_out and entry.checkout_until <= moment]


def sweep_checkouts(vault: Vault, now: Optional[float] = None) -> list:
    """Check in everything that is overdue. Returns one report each."""
    return [check_in(vault, entry.id) for entry in due_checkouts(vault, now)]


def _entry_or_raise(vault: Vault, entry_id: str) -> Entry:
    for entry in vault.entries():
        if entry.id == entry_id:
            return entry
    raise LockError(f"no entry {entry_id}")
