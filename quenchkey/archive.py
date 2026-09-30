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

"""Bundling several files into one stream, and taking them apart again.

A locked Quenchkey item may hold any number of files, so the selection is
first packed into a 7z archive. Two choices are worth explaining:

**No compression.** The archive is about to be encrypted, and ciphertext does
not compress. Compressing first would only burn CPU — and, for an attacker who
can supply part of the plaintext, compression-then-encryption leaks information
about the rest through the output length.

**Archive-level encryption with encrypted headers** (``-mhe=on`` in 7-Zip
terms). The whole archive, filenames included, is already inside Quenchkey's
own authenticated ciphertext, so this inner layer adds nothing to the security
of the finished ``.qkey`` file. It exists for the intermediate: packing has to
produce a seekable file before it can be encrypted, and this way that temporary
file is never plaintext on disk. The archive password is derived from the
per-file key, so it dies with it — no separate secret, and no way to open the
inner layer once the key is destroyed.

A small JSON manifest is stored alongside the files recording the original
paths and the order they were selected in, so that order survives a round trip.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from typing import Callable, Iterable, Optional, Sequence

import py7zr
from py7zr import FILTER_COPY, FILTER_CRYPTO_AES256_SHA256

from .crypto import SecretBytes

MANIFEST_NAME = ".qkey-manifest.json"
MANIFEST_VERSION = 1

ARCHIVE_PASSWORD_INFO = b"quenchkey/archive-password/v1"

#: Store-only plus AES-256; 7-Zip's own KDF is weak by modern standards, which
#: is exactly why it is not relied on for anything — see the module docstring.
ARCHIVE_FILTERS = [
    {"id": FILTER_COPY},
    {"id": FILTER_CRYPTO_AES256_SHA256},
]

#: The same, minus the encryption, for an archive that on purpose has no
#: password. Leaving the AES filter in with no password to feed it makes py7zr
#: fail deep inside its own writer with an unhelpful message.
PLAIN_FILTERS = [
    {"id": FILTER_COPY},
]

ProgressFn = Callable[[str, float], None]


class ArchiveError(Exception):
    """Packing or unpacking failed."""


@dataclass
class MemberPlan:
    """One file as it will appear inside the archive."""

    source: str
    arcname: str
    size: int
    order: int


def archive_password(file_key: SecretBytes) -> str:
    """Derive the inner archive password from the per-file key.

    HKDF-SHA256 with a distinct ``info`` string, so this value cannot collide
    with any other use of the same key.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    raw = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
               info=ARCHIVE_PASSWORD_INFO).derive(file_key.bytes())
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _expand(paths: Sequence[str]) -> list[tuple[str, str, int]]:
    """Expand a selection into ``(source, relative name, size)`` triples.

    Directories are walked; ordering follows the selection, and within a
    directory, sorted names.
    """
    out: list[tuple[str, str, int]] = []
    for path in paths:
        path = os.path.abspath(path)
        if os.path.isdir(path):
            root_name = os.path.basename(path.rstrip(os.sep)) or "folder"
            for dirpath, dirnames, filenames in os.walk(path):
                dirnames.sort()
                for name in sorted(filenames):
                    full = os.path.join(dirpath, name)
                    if not os.path.isfile(full) or os.path.islink(full):
                        continue
                    rel = os.path.relpath(full, path)
                    out.append((full, os.path.join(root_name, rel), os.path.getsize(full)))
        elif os.path.isfile(path):
            out.append((path, os.path.basename(path), os.path.getsize(path)))
        else:
            raise ArchiveError(f"not a file or folder: {path}")
    return out


def plan_members(paths: Sequence[str]) -> list[MemberPlan]:
    """Resolve a selection into archive members with unique names."""
    plans: list[MemberPlan] = []
    used: set[str] = set()
    for index, (source, arcname, size) in enumerate(_expand(paths), start=1):
        candidate = arcname
        if candidate.lower() in used:
            stem, ext = os.path.splitext(arcname)
            n = 2
            while f"{stem} ({n}){ext}".lower() in used:
                n += 1
            candidate = f"{stem} ({n}){ext}"
        used.add(candidate.lower())
        plans.append(MemberPlan(source, candidate, size, index))
    if not plans:
        raise ArchiveError("nothing to lock: the selection contained no files")
    return plans


def build_manifest(plans: Iterable[MemberPlan]) -> dict:
    return {
        "version": MANIFEST_VERSION,
        "members": [
            {"order": p.order, "arcname": p.arcname,
             "original_path": p.source, "size": p.size}
            for p in plans
        ],
    }


def pack(paths: Sequence[str], destination: str, file_key: SecretBytes,
         progress: Optional[ProgressFn] = None) -> tuple[list[MemberPlan], int]:
    """Pack ``paths`` into an encrypted 7z archive at ``destination``.

    Returns the member plans (in selection order) and the total plaintext size.
    """
    plans = plan_members(paths)
    total = sum(p.size for p in plans) or 1
    done = 0
    password = archive_password(file_key)
    try:
        with py7zr.SevenZipFile(destination, "w", password=password,
                                header_encryption=True, filters=ARCHIVE_FILTERS) as sz:
            sz.writestr(json.dumps(build_manifest(plans), indent=2), MANIFEST_NAME)
            for plan in plans:
                if progress:
                    progress(plan.arcname, done / total)
                sz.write(plan.source, plan.arcname)
                done += plan.size
    except Exception as exc:  # noqa: BLE001 - surfaced to the UI as one error
        if os.path.exists(destination):
            os.unlink(destination)
        raise ArchiveError(f"could not pack the selection: {exc}") from exc
    if progress:
        progress("", 1.0)
    return plans, sum(p.size for p in plans)


def read_manifest(archive_path: str, file_key: SecretBytes) -> Optional[dict]:
    password = archive_password(file_key)
    try:
        with py7zr.SevenZipFile(archive_path, "r", password=password) as sz:
            found = sz.read([MANIFEST_NAME])
            if not found:
                return None
            return json.loads(found[MANIFEST_NAME].read().decode("utf-8"))
    except Exception:  # noqa: BLE001 - a missing manifest is not fatal
        return None


def unpack(archive_path: str, destination_dir: str, file_key: SecretBytes,
           progress: Optional[ProgressFn] = None) -> list[str]:
    """Extract an archive, returning the written paths in manifest order."""
    os.makedirs(destination_dir, exist_ok=True)
    password = archive_password(file_key)
    manifest = read_manifest(archive_path, file_key)
    if progress:
        progress("extracting", 0.1)
    try:
        with py7zr.SevenZipFile(archive_path, "r", password=password) as sz:
            names = [n for n in sz.getnames() if n != MANIFEST_NAME]
            sz.extract(path=destination_dir, targets=names)
    except Exception as exc:  # noqa: BLE001
        raise ArchiveError(f"could not extract the archive: {exc}") from exc
    if progress:
        progress("extracting", 1.0)

    ordered: list[str] = []
    if manifest:
        for member in sorted(manifest.get("members", []), key=lambda m: m.get("order", 0)):
            candidate = os.path.join(destination_dir, member["arcname"])
            if os.path.exists(candidate):
                ordered.append(candidate)
    for name in names:
        candidate = os.path.join(destination_dir, name)
        if candidate not in ordered and os.path.exists(candidate):
            ordered.append(candidate)
    return ordered


def pack_plain(root_dir: str, destination: str,
               progress: Optional[ProgressFn] = None) -> list[str]:
    """Repack an extracted tree as a 7z archive with **no password**.

    For somebody who wants one file back rather than a folder, and does not
    want to need a passphrase — or Quenchkey — to open it again. The result is an
    ordinary 7z that any archive manager will read, which is exactly the point
    and exactly the risk: nothing protects it any more.
    """
    members: list[str] = []
    for current, _dirs, files in os.walk(root_dir):
        for name in sorted(files):
            full = os.path.join(current, name)
            members.append(os.path.relpath(full, root_dir))
    members.sort()
    total = len(members) or 1
    try:
        with py7zr.SevenZipFile(destination, "w", filters=PLAIN_FILTERS) as sz:
            for index, arcname in enumerate(members):
                if progress:
                    progress(arcname, index / total)
                sz.write(os.path.join(root_dir, arcname), arcname)
    except Exception as exc:  # noqa: BLE001 - surfaced to the UI as one error
        if os.path.exists(destination):
            os.unlink(destination)
        raise ArchiveError(f"could not build the archive: {exc}") from exc
    if progress:
        progress("", 1.0)
    return members
