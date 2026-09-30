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

"""The open vault, and the timers that watch it.

One :class:`Session` exists while the application runs. It owns the unlocked
:class:`~quenchkey.vault.Vault`, serialises access to it, runs the periodic
expiry check, and locks the vault again after a period of inactivity.
"""

from __future__ import annotations

import os
import threading
import time

from . import expiry, locker, schedule
from .watch import Watcher
from .vault import DEFAULT_VAULT_PATH, Vault

#: How often the timer looks for entries that have fallen due.
SWEEP_INTERVAL_SECONDS = 15

#: Inactivity before the vault re-locks itself and the keys leave memory.
AUTO_LOCK_SECONDS = 15 * 60


class Session:
    """Holds the unlocked vault for the lifetime of the window."""

    def __init__(self, vault: Vault, auto_lock_seconds: int = AUTO_LOCK_SECONDS):
        #: Remembers what it has seen in the watched folders, so a file is
        #: only locked once it has stopped changing.
        self._watcher = Watcher()
        self.vault = vault
        self.auto_lock_seconds = auto_lock_seconds
        self._guard = threading.RLock()
        self._last_activity = time.monotonic()

    # -- access -----------------------------------------------------------

    @property
    def guard(self) -> threading.RLock:
        """Held for the duration of any operation that touches the vault."""
        return self._guard

    def touch(self) -> None:
        self._last_activity = time.monotonic()

    def idle_seconds(self) -> float:
        return time.monotonic() - self._last_activity

    def should_auto_lock(self) -> bool:
        if not self.auto_lock_seconds:
            return False
        return self.is_open and self.idle_seconds() >= self.auto_lock_seconds

    @property
    def is_open(self) -> bool:
        return self.vault is not None and self.vault.is_unlocked

    # -- operations -------------------------------------------------------

    def sweep(self, check_in: bool = True) -> "expiry.SweepReport":
        """Destroy the keys of anything past its deadline, then check in.

        The order is deliberate and load-bearing. Anything already overdue is
        destroyed first; only the survivors have their dead man's switches
        reset. Checking in first would mean a switch could never fire, because
        opening the vault to look would itself postpone it.
        """
        with self._guard:
            if not self.is_open:
                return expiry.SweepReport()
            # Loans first: a checkout that has run out should be tidied away
            # even if the entry itself is also expiring in the same pass, and
            # shredding the lent-out copies is the part that has to happen
            # while the vault can still be written.
            report = expiry.sweep(self.vault)
            report.checkins = locker.sweep_checkouts(self.vault)

            # And anything that has landed in a watched folder and settled.
            rules = self.vault.watch_rules()
            if rules:
                report.watched = self._watcher.sweep(self.vault, rules)

            # Anything the background sweeper saw fall due while nothing was
            # unlocked has just been destroyed by the sweep above, because a
            # passed deadline is a passed deadline. The pending list is what
            # lets the application say so rather than leaving the user to
            # notice a file had quietly gone.
            pending = schedule.read_pending(self.vault.path)
            if pending:
                expired_ids = {entry.id for entry in report.expired}
                report.swept_in_background = [
                    entry_id for entry_id in pending if entry_id in expired_ids
                ]
                schedule.clear_pending(self.vault.path, list(pending))

            if check_in and self.vault.check_in():
                self.vault.save()
            return report

    def close(self) -> None:
        """Wipe key material and drop the vault."""
        with self._guard:
            if self.vault is not None:
                try:
                    if self.vault.is_unlocked:
                        self.vault.save()
                except Exception:  # noqa: BLE001 - losing the save must not block the wipe
                    pass
                self.vault.lock()

    def __enter__(self) -> "Session":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def vault_exists(path: str = DEFAULT_VAULT_PATH) -> bool:
    return os.path.exists(path)
