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

"""The optional keyfile: a second factor Quenchkey generates itself.

Some tools let you nominate any existing file — a holiday photo, an mp3 — as a
keyfile. Quenchkey does not, and the reason is not purity. Those files get
edited by the things that touch them: cloud clients re-encode images, photo
apps strip EXIF, music players rewrite tags, an editor normalises line endings.
Any of that changes the bytes, and the moment the bytes change the keyfile no
longer opens the vault. The failure shows up long after the change, looks
exactly like a wrong passphrase, and the data is unrecoverable.

So the keyfile is created here, with a fixed size, a recognisable banner, and a
checksum that lets :func:`verify` say "this file has been altered" *before* it
is relied on.

Only the first :data:`~quenchkey.crypto.KEYFILE_READ_BYTES` (1 MiB) of a
keyfile is ever read — the same bound VeraCrypt uses — so the KDF input stays a
fixed cost regardless of file size.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import Optional

BANNER = b"QUENCHKEY KEYFILE v1 - do not edit, convert or sync\n"
BANNER_FIELD = 64
KEYFILE_SIZE = 4096
CHECKSUM_SIZE = 32
MATERIAL_END = KEYFILE_SIZE - CHECKSUM_SIZE

SUGGESTED_NAME = "quenchkey.keyfile"

#: Shown next to the keyfile controls in the UI. On purpose blunt.
ADVICE = (
    "Keep the keyfile somewhere the vault is not: a USB stick, a different "
    "machine. Back it up. Do not put it in a folder that syncs to cloud "
    "storage, and never open it in an editor — if its bytes change, every file "
    "locked with it becomes unopenable, and there is no recovery."
)


class KeyfileError(Exception):
    """The keyfile is missing, malformed, or has been altered."""


@dataclass
class KeyfileInfo:
    path: str
    size: int
    intact: bool
    is_quenchkey_keyfile: bool
    message: str


def generate(path: str, overwrite: bool = False) -> str:
    """Write a new keyfile of :data:`KEYFILE_SIZE` bytes.

    Layout: a 64-byte ASCII banner, random bytes to fill, then a SHA-256 of
    everything before it. The banner makes the file identifiable a year later;
    the checksum makes corruption detectable rather than silent.
    """
    path = os.path.abspath(path)
    if os.path.exists(path) and not overwrite:
        raise KeyfileError(f"a file already exists at {path}")
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    banner = BANNER.ljust(BANNER_FIELD, b"\x00")
    material = banner + os.urandom(MATERIAL_END - BANNER_FIELD)
    body = material + hashlib.sha256(material).digest()
    assert len(body) == KEYFILE_SIZE

    tmp = path + ".partial"
    try:
        with open(tmp, "wb") as fh:
            fh.write(body)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o400)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    return path


def verify(path: str) -> KeyfileInfo:
    """Check a keyfile's banner and checksum without needing the vault."""
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            body = fh.read(KEYFILE_SIZE + 1)
    except OSError as exc:
        return KeyfileInfo(path, 0, False, False, f"Cannot read the keyfile: {exc}")

    is_ours = body[:len(BANNER)] == BANNER
    if not is_ours:
        return KeyfileInfo(
            path, size, True, False,
            "This is not a Quenchkey keyfile. It can still be used, but "
            "Quenchkey cannot tell you whether its bytes have changed.")
    if len(body) != KEYFILE_SIZE:
        return KeyfileInfo(path, size, False, True,
                           f"Wrong size: expected {KEYFILE_SIZE} bytes, found {size}. "
                           "This keyfile has been altered and will not unlock the vault.")
    material, checksum = body[:MATERIAL_END], body[MATERIAL_END:]
    if hashlib.sha256(material).digest() != checksum:
        return KeyfileInfo(path, size, False, True,
                           "Checksum mismatch: the contents have changed since this "
                           "keyfile was created. It will not unlock the vault.")
    return KeyfileInfo(path, size, True, True, "Keyfile is intact.")


def require_usable(path: Optional[str]) -> Optional[str]:
    """Validate a keyfile before it is used, raising if it is known-broken."""
    if not path:
        return None
    info = verify(path)
    if info.is_quenchkey_keyfile and not info.intact:
        raise KeyfileError(info.message)
    return path
