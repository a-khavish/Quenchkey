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

"""Backups of the vault, and the honest price of having them.

Losing the vault file loses everything. Recovery shares do not save you from
that — they reconstruct the master key, but the per-file keys live *inside*
the vault, so with the file gone there is nothing for that master key to
open. Somebody who deletes ``~/.quenchkey`` by accident, or on purpose,
destroys every locked file at once and no amount of paper in a drawer helps.

A backup is a copy of the vault file. That is all it is, and it needs no new
cryptography: the vault is already one encrypted blob under the passphrase, so
a copy of it is exactly as protected as the original. What a backup does need
is honesty about what it costs.

**A backup is a time machine, and expiry is a one-way door.**

Restore a backup taken before a deadline and the keys it contained come back —
including keys this vault destroyed on purpose. That is not a flaw that can be
engineered away while also having backups: a backup is by definition a copy of
a past state, and a past state is one where the key still existed.

So the deal here is: backups are allowed, and restoring one is *loud*. Every
backup records the event chain's head at the moment it was taken. Restoring
compares that against where the vault had got to, says exactly how many events
and how many destructions are about to be undone, and makes you type a
confirmation. Afterwards the restored vault carries a permanent, chained
record that it was restored, from when, and what it rolled back — so an audit
of that vault later shows the gap rather than hiding it.

The alternative designs are worse. Refusing backups means one `rm` destroys
everything. Silently merging is a lie about which state is true. Making
restore quiet turns expiry into a suggestion.
"""

from __future__ import annotations

import json
import os
import shutil
import time
from dataclasses import dataclass
from typing import Optional

#: Written next to the copied vault, in the clear. It holds no keys — only
#: what is needed to tell somebody what restoring it would cost.
MANIFEST_SUFFIX = ".manifest.json"
MANIFEST_VERSION = 1

BACKUP_SUFFIX = ".qkvbak"


@dataclass
class BackupInfo:
    """What a backup says about itself, readable without the passphrase."""

    path: str
    manifest_path: str
    taken: float
    vault_id: str
    chain_head: str
    chain_length: int
    entries: int
    live_entries: int
    destroyed_entries: int
    size: int
    source_path: str = ""

    @property
    def name(self) -> str:
        return os.path.basename(self.path)

    def to_dict(self) -> dict:
        return {
            "version": MANIFEST_VERSION,
            "taken": self.taken,
            "vault_id": self.vault_id,
            "chain_head": self.chain_head,
            "chain_length": self.chain_length,
            "entries": self.entries,
            "live_entries": self.live_entries,
            "destroyed_entries": self.destroyed_entries,
            "size": self.size,
            "source_path": self.source_path,
        }

    @classmethod
    def from_dict(cls, raw: dict, path: str, manifest_path: str) -> "BackupInfo":
        return cls(
            path=path,
            manifest_path=manifest_path,
            taken=float(raw.get("taken", 0)),
            vault_id=str(raw.get("vault_id", "")),
            chain_head=str(raw.get("chain_head", "")),
            chain_length=int(raw.get("chain_length", 0)),
            entries=int(raw.get("entries", 0)),
            live_entries=int(raw.get("live_entries", 0)),
            destroyed_entries=int(raw.get("destroyed_entries", 0)),
            size=int(raw.get("size", 0)),
            source_path=str(raw.get("source_path", "")),
        )


class BackupError(Exception):
    pass


def default_name(vault_path: str, when: Optional[float] = None) -> str:
    moment = time.localtime(time.time() if when is None else when)
    stamp = time.strftime("%Y%m%d-%H%M%S", moment)
    stem = os.path.splitext(os.path.basename(vault_path))[0]
    return f"{stem}-{stamp}{BACKUP_SUFFIX}"


def manifest_path_for(backup_path: str) -> str:
    return backup_path + MANIFEST_SUFFIX


# --------------------------------------------------------------------------
# making one
# --------------------------------------------------------------------------

def create(vault, destination: str) -> BackupInfo:
    """Copy an open vault to ``destination`` and describe what was copied.

    ``destination`` is the file to write. An existing directory is taken as
    the folder to write into, under a timestamped name, because that is the
    other thing people reasonably hand this.

    The vault is saved first, so the copy is the state on screen rather than
    the state at the last write. The copy itself is byte-for-byte: it is
    already encrypted, and re-encrypting it under a second passphrase would
    only add another thing to forget.
    """
    if not vault.is_unlocked:
        raise BackupError("the vault has to be unlocked to back it up")

    vault.save()
    destination = os.path.abspath(destination)
    if os.path.isdir(destination):
        destination = os.path.join(destination, default_name(vault.path))
    if os.path.abspath(vault.path) == destination:
        raise BackupError("that is the vault itself, not a backup of it")
    os.makedirs(os.path.dirname(destination) or ".", exist_ok=True)

    tmp = f"{destination}.part-{os.getpid()}"
    try:
        shutil.copy2(vault.path, tmp)
        os.chmod(tmp, 0o600)
        os.replace(tmp, destination)
    except OSError as exc:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise BackupError(f"could not write the backup: {exc}") from exc

    entries = vault.entries()
    info = BackupInfo(
        path=destination,
        manifest_path=manifest_path_for(destination),
        taken=time.time(),
        vault_id=vault.vault_id,
        chain_head=vault.chain_head,
        chain_length=len(vault.events),
        entries=len(entries),
        live_entries=sum(1 for e in entries if not e.key_destroyed),
        destroyed_entries=sum(1 for e in entries if e.key_destroyed),
        size=os.path.getsize(destination),
        source_path=os.path.abspath(vault.path),
    )
    _write_manifest(info)

    vault.log_event("backup_created", backup=os.path.basename(destination),
                    entries=info.entries, chain_length=info.chain_length)
    vault.save()
    return info


def _write_manifest(info: BackupInfo) -> None:
    handle = os.open(info.manifest_path,
                     os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(handle, "w") as fh:
        json.dump(info.to_dict(), fh, indent=2, sort_keys=True)


def describe(backup_path: str) -> Optional[BackupInfo]:
    """Read a backup's manifest. No passphrase, no decryption."""
    manifest = manifest_path_for(backup_path)
    try:
        with open(manifest) as fh:
            raw = json.load(fh)
    except (FileNotFoundError, ValueError, OSError):
        return None
    if raw.get("version") != MANIFEST_VERSION:
        return None
    return BackupInfo.from_dict(raw, backup_path, manifest)


def find(directory: str) -> list:
    """Every backup in a folder, newest first."""
    found = []
    try:
        names = os.listdir(directory)
    except OSError:
        return []
    for name in names:
        if not name.endswith(BACKUP_SUFFIX):
            continue
        info = describe(os.path.join(directory, name))
        if info is not None:
            found.append(info)
    return sorted(found, key=lambda i: i.taken, reverse=True)


# --------------------------------------------------------------------------
# putting one back
# --------------------------------------------------------------------------

@dataclass
class RestoreCost:
    """What restoring this backup over this vault would undo."""

    backup: BackupInfo
    vault_exists: bool
    same_vault: bool
    events_lost: int
    destructions_undone: int
    entries_lost: int
    current_chain_length: int = 0

    @property
    def rolls_back(self) -> bool:
        return self.events_lost > 0 or self.destructions_undone > 0

    def summary(self) -> str:
        if not self.vault_exists:
            return ("There is no vault at that path, so this restores one "
                    "rather than replacing one. Nothing is rolled back.")
        if not self.same_vault:
            return ("This backup is of a *different* vault. Restoring it "
                    "replaces the vault that is there now, and whatever that "
                    "one held becomes unreadable.")
        if not self.rolls_back:
            return ("The backup matches the vault as it stands. Restoring it "
                    "changes nothing.")
        parts = [f"{self.events_lost} recorded event"
                 f"{'s' if self.events_lost != 1 else ''} would be undone"]
        if self.destructions_undone:
            parts.append(
                f"{self.destructions_undone} key"
                f"{'s' if self.destructions_undone != 1 else ''} this vault "
                f"destroyed would come back")
        if self.entries_lost:
            parts.append(f"{self.entries_lost} newer entr"
                         f"{'ies' if self.entries_lost != 1 else 'y'} would be lost")
        return "; ".join(parts) + "."


def cost_of_restoring(info: BackupInfo, vault_path: str,
                      current: Optional[object] = None) -> RestoreCost:
    """Price a restore before anybody commits to it.

    ``current`` is the open vault being replaced, when there is one. Without
    it only the manifest can be compared, which still catches the important
    case: a backup of a different vault entirely.
    """
    exists = os.path.exists(vault_path)
    if current is None:
        return RestoreCost(info, exists, True, 0, 0, 0)

    entries = current.entries()
    destroyed_now = sum(1 for e in entries if e.key_destroyed)
    return RestoreCost(
        backup=info,
        vault_exists=exists,
        same_vault=(current.vault_id == info.vault_id),
        events_lost=max(0, len(current.events) - info.chain_length),
        destructions_undone=max(0, destroyed_now - info.destroyed_entries),
        entries_lost=max(0, len(entries) - info.entries),
        current_chain_length=len(current.events),
    )


def restore(info: BackupInfo, vault_path: str,
            keep_replaced_as: Optional[str] = None) -> str:
    """Put a backup back, keeping the vault it replaced.

    The displaced vault is never simply deleted. Restoring the wrong backup is
    an easy mistake and an unrecoverable one if the thing it overwrote is
    gone, so it is moved aside and its path returned.
    """
    if not os.path.exists(info.path):
        raise BackupError(f"{info.path} is not there any more")

    vault_path = os.path.abspath(vault_path)
    displaced = ""
    if os.path.exists(vault_path):
        displaced = keep_replaced_as or (
            f"{vault_path}.replaced-{time.strftime('%Y%m%d-%H%M%S')}")
        os.replace(vault_path, displaced)

    tmp = f"{vault_path}.part-{os.getpid()}"
    try:
        os.makedirs(os.path.dirname(vault_path) or ".", exist_ok=True)
        shutil.copy2(info.path, tmp)
        os.chmod(tmp, 0o600)
        os.replace(tmp, vault_path)
    except OSError as exc:
        if os.path.exists(tmp):
            os.unlink(tmp)
        if displaced and os.path.exists(displaced):
            os.replace(displaced, vault_path)
        raise BackupError(f"could not restore the backup: {exc}") from exc
    return displaced


def record_restore(vault, info: BackupInfo, cost: RestoreCost,
                   displaced: str = "") -> dict:
    """Write the restore into the restored vault's own chain.

    Called after reopening the restored vault. The point is that the gap shows
    up in an audit rather than being smoothed over: a vault that was rolled
    back says so, permanently, in the record that everything else is checked
    against.
    """
    event = vault.log_event(
        "vault_restored",
        backup=os.path.basename(info.path),
        taken=info.taken,
        events_undone=cost.events_lost,
        destructions_undone=cost.destructions_undone,
        entries_lost=cost.entries_lost,
        displaced=os.path.basename(displaced) if displaced else "",
    )
    vault.save()
    return event
