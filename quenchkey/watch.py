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

"""Folders where anything dropped in gets locked on its own.

Drag a file into a watched folder and it is packed, encrypted under a fresh
key, and the original shredded — with whatever deadline the folder was set up
with. No dialog, no decision at the moment of dropping.

Two limits, both structural, both stated in the interface rather than left to
be discovered:

**It only runs while the vault is unlocked.** Locking needs the vault, so a
file dropped into a watched folder while Quenchkey is closed sits there in the
clear until the next time you open it. The folder is a convenience, not a
guard on the folder.

**A file is locked once it has stopped changing.** A watcher that grabbed
files the instant they appeared would encrypt half a download. Each candidate
has to keep the same size and modification time across two consecutive
passes before it is touched, which means a file appears, sits for a few
seconds, and then goes.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Optional

#: How long a file must look unchanged before it is considered finished.
SETTLE_SECONDS = 6.0

#: Never picked up: partial downloads, editor scratch files, and the locked
#: files the watcher itself writes.
IGNORED_SUFFIXES = (".part", ".crdownload", ".download", ".tmp", ".swp",
                    ".partial", "~")
IGNORED_PREFIXES = (".", "~$")


@dataclass
class WatchRule:
    """One folder, and what happens to what lands in it."""

    path: str
    expires_seconds: Optional[float] = None
    max_opens: Optional[int] = None
    heartbeat_days: Optional[float] = None
    delete_originals: bool = True
    delete_blob_on_expiry: bool = False
    output_dir: str = ""
    enabled: bool = True
    include_folders: bool = False

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "expires_seconds": self.expires_seconds,
            "max_opens": self.max_opens,
            "heartbeat_days": self.heartbeat_days,
            "delete_originals": self.delete_originals,
            "delete_blob_on_expiry": self.delete_blob_on_expiry,
            "output_dir": self.output_dir,
            "enabled": self.enabled,
            "include_folders": self.include_folders,
        }

    @classmethod
    def from_dict(cls, raw: dict) -> "WatchRule":
        return cls(
            path=str(raw.get("path", "")),
            expires_seconds=raw.get("expires_seconds"),
            max_opens=raw.get("max_opens"),
            heartbeat_days=raw.get("heartbeat_days"),
            delete_originals=bool(raw.get("delete_originals", True)),
            delete_blob_on_expiry=bool(raw.get("delete_blob_on_expiry", False)),
            output_dir=str(raw.get("output_dir", "")),
            enabled=bool(raw.get("enabled", True)),
            include_folders=bool(raw.get("include_folders", False)),
        )

    @property
    def destination(self) -> str:
        return self.output_dir or self.path

    def describe(self) -> str:
        parts = []
        if self.expires_seconds:
            from . import expiry as expiry_mod
            parts.append(f"key dies after {expiry_mod.format_duration(self.expires_seconds)}")
        if self.max_opens:
            parts.append(f"{self.max_opens} opening"
                         f"{'s' if self.max_opens != 1 else ''}")
        if self.heartbeat_days:
            parts.append(f"check in every {self.heartbeat_days:g} days")
        if not parts:
            parts.append("no deadline")
        if self.delete_originals:
            parts.append("original shredded")
        return ", ".join(parts)


@dataclass
class WatchReport:
    """What one pass over the watched folders did."""

    locked: list = field(default_factory=list)
    waiting: list = field(default_factory=list)
    failed: list = field(default_factory=list)
    skipped_folders: list = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.locked)

    def summary(self) -> str:
        if not self.locked:
            return "Nothing new in the watched folders."
        count = len(self.locked)
        names = ", ".join(os.path.basename(p) for p in self.locked[:3])
        more = "" if count <= 3 else f" and {count - 3} more"
        return (f"Locked {count} new file{'s' if count != 1 else ''} "
                f"automatically: {names}{more}.")


def _ignored(name: str) -> bool:
    lowered = name.lower()
    return (lowered.endswith(IGNORED_SUFFIXES)
            or name.startswith(IGNORED_PREFIXES))


def candidates(rule: WatchRule) -> list:
    """Everything in the folder that might be lockable."""
    from .locker import QKEY_SUFFIX

    found = []
    try:
        names = sorted(os.listdir(rule.path))
    except OSError:
        return []
    for name in names:
        if _ignored(name) or name.endswith(QKEY_SUFFIX):
            continue
        full = os.path.join(rule.path, name)
        if os.path.islink(full):
            continue
        if os.path.isdir(full):
            if rule.include_folders:
                found.append(full)
            continue
        if os.path.isfile(full):
            found.append(full)
    return found


def _fingerprint(path: str) -> Optional[tuple]:
    """Size and mtime, or None if it cannot be read."""
    try:
        if os.path.isdir(path):
            total = 0
            latest = 0.0
            for current, _dirs, files in os.walk(path):
                for name in files:
                    try:
                        stat = os.stat(os.path.join(current, name))
                    except OSError:
                        continue
                    total += stat.st_size
                    latest = max(latest, stat.st_mtime)
            return (total, latest)
        stat = os.stat(path)
        return (stat.st_size, stat.st_mtime)
    except OSError:
        return None


class Watcher:
    """Locks what appears in the watched folders, once it has settled."""

    def __init__(self):
        #: path -> (fingerprint, first time it looked like this)
        self._seen: dict = {}

    def forget(self, path: str) -> None:
        self._seen.pop(path, None)

    def sweep(self, vault, rules, now: Optional[float] = None) -> WatchReport:
        """One pass. Locks what has stopped changing, waits on the rest."""
        from . import locker

        moment = time.time() if now is None else now
        report = WatchReport()
        if not vault.is_unlocked:
            return report

        live = set()
        for rule in rules:
            if not rule.enabled or not os.path.isdir(rule.path):
                continue
            for path in candidates(rule):
                live.add(path)
                mark = _fingerprint(path)
                if mark is None:
                    continue
                previous = self._seen.get(path)
                if previous is None or previous[0] != mark:
                    # New, or still being written to: start the clock again.
                    self._seen[path] = (mark, moment)
                    report.waiting.append(path)
                    continue
                if moment - previous[1] < SETTLE_SECONDS:
                    report.waiting.append(path)
                    continue
                try:
                    locker.lock_files(
                        vault, [path],
                        None if not rule.expires_seconds
                        else moment + rule.expires_seconds,
                        output_dir=rule.destination,
                        delete_originals=rule.delete_originals,
                        delete_blob_on_expiry=rule.delete_blob_on_expiry,
                        max_opens=rule.max_opens,
                        heartbeat_days=rule.heartbeat_days)
                    # On purpose no label: a label replaces the name in the
                    # list, and "watched folder" is less use than knowing
                    # which file it was. The event log records the origin.
                    vault.log_event("watched_folder_locked",
                                    folder=rule.path,
                                    name=os.path.basename(path))
                    vault.save()
                    report.locked.append(path)
                except Exception as exc:  # noqa: BLE001 - one bad file, not a stop
                    report.failed.append((path, str(exc)))
                self._seen.pop(path, None)

        # Anything that has gone is no longer worth remembering.
        for path in list(self._seen):
            if path not in live:
                del self._seen[path]
        return report
