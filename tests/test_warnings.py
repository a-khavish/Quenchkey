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

"""A deadline should never be the first you hear of it."""

from __future__ import annotations

import time

from quenchkey import locker, schedule, warnings as warnings_mod
from quenchkey.vault import Vault

from conftest import PASSPHRASE

HOUR = 3600.0
DAY = 86400.0


def _lock(vault, workspace, name="report.txt", **rules):
    source = workspace / "documents" / name
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_bytes(b"content " * 200)
    return locker.lock_files(vault, [str(source)],
                             output_dir=str(workspace / "locked"),
                             **rules).entry


class Collector:
    """Stands in for the tray, or notify-send, or a terminal."""

    def __init__(self, explode: bool = False):
        self.sent: list = []
        self.explode = explode

    def __call__(self, title, message, urgency="notice"):
        if self.explode:
            raise RuntimeError("the desktop notification daemon is not running")
        self.sent.append((title, message, urgency))


# --------------------------------------------------------------------------
# what is worth saying
# --------------------------------------------------------------------------

def test_a_deadline_a_month_out_is_not_worth_mentioning(vault, workspace):
    _lock(vault, workspace, expires=time.time() + 30 * DAY)

    assert warnings_mod.pending(vault).due == []


def test_a_week_out_is(vault, workspace):
    _lock(vault, workspace, expires=time.time() + 6 * DAY)

    report = warnings_mod.pending(vault)

    assert len(report.due) == 1
    assert report.due[0].level == "week"
    assert "report.txt" in report.due[0].message()


def test_the_most_urgent_level_is_the_one_that_is_said(vault, workspace):
    """A vault left closed for a fortnight should say one thing, not three."""
    _lock(vault, workspace, expires=time.time() + 40 * 60)

    report = warnings_mod.pending(vault)

    assert [w.level for w in report.due] == ["hour"]


def test_something_already_past_its_deadline_is_not_warned_about(vault, workspace):
    """That is the sweep's business, and a warning then would be a lie."""
    _lock(vault, workspace, expires=time.time() - 60)

    assert warnings_mod.pending(vault).due == []


def test_a_destroyed_key_is_not_warned_about(vault, workspace):
    entry = _lock(vault, workspace, expires=time.time() + HOUR / 2)
    vault.shred_key(entry.id)

    assert warnings_mod.pending(vault).due == []


def test_a_heartbeat_says_what_to_do_about_it(vault, workspace):
    """"Open Quenchkey" is the whole remedy, so it has to be in the words."""
    _lock(vault, workspace, expires=None, heartbeat_days=1)
    # The check-in clock starts now, so the deadline is a day away.
    report = warnings_mod.pending(vault, now=time.time() + 23 * HOUR)

    assert len(report.due) == 1
    assert report.due[0].reason == "heartbeat"
    assert "open quenchkey" in report.due[0].message().lower()


def test_a_plain_deadline_says_what_it_costs(vault, workspace):
    _lock(vault, workspace, expires=time.time() + 23 * HOUR)

    message = warnings_mod.pending(vault).due[0].message()

    assert "cannot be opened" in message


# --------------------------------------------------------------------------
# saying it once
# --------------------------------------------------------------------------

def test_a_warning_goes_out_once(vault, workspace):
    _lock(vault, workspace, expires=time.time() + 20 * HOUR)
    tray = Collector()

    first = warnings_mod.send(vault, tray)
    second = warnings_mod.send(vault, tray)

    assert len(first.due) == 1
    assert second.due == []
    assert len(tray.sent) == 1
    assert second.already_sent == 1


def test_it_survives_the_vault_being_closed_and_reopened(vault, workspace):
    _lock(vault, workspace, expires=time.time() + 20 * HOUR)
    warnings_mod.send(vault, Collector())
    vault.lock()

    reopened = Vault.unlock(vault.path, PASSPHRASE)
    tray = Collector()
    warnings_mod.send(reopened, tray)

    assert tray.sent == []


def test_moving_a_deadline_arms_the_warning_again(vault, workspace):
    """A different moment is a different thing to be told about."""
    entry = _lock(vault, workspace, expires=time.time() + 20 * HOUR)
    warnings_mod.send(vault, Collector())

    vault.set_expiry(entry.id, time.time() + 22 * HOUR)
    tray = Collector()
    warnings_mod.send(vault, tray)

    assert len(tray.sent) == 1


def test_crossing_into_a_closer_level_is_said_again(vault, workspace):
    _lock(vault, workspace, expires=time.time() + 6 * DAY)
    tray = Collector()

    warnings_mod.send(vault, tray)                                  # week
    warnings_mod.send(vault, tray, now=time.time() + 5 * DAY)       # day
    warnings_mod.send(vault, tray, now=time.time() + 6 * DAY - 600)  # hour

    assert [urgency for _t, _m, urgency in tray.sent] == [
        "notice", "warning", "critical"]


def test_a_broken_notifier_does_not_lose_the_warning(vault, workspace):
    """Failing closed here would silently swallow the only warning sent."""
    _lock(vault, workspace, expires=time.time() + 20 * HOUR)

    warnings_mod.send(vault, Collector(explode=True))
    working = Collector()
    warnings_mod.send(vault, working)

    assert len(working.sent) == 1


def test_looking_does_not_count_as_saying(vault, workspace):
    _lock(vault, workspace, expires=time.time() + 20 * HOUR)

    warnings_mod.pending(vault)
    tray = Collector()
    warnings_mod.send(vault, tray)

    assert len(tray.sent) == 1


def test_what_was_said_is_recorded_in_the_chain(vault, workspace):
    _lock(vault, workspace, expires=time.time() + 20 * HOUR)

    warnings_mod.send(vault, Collector())

    assert any(e.get("kind") == "deadline_warnings_sent" for e in vault.events)
    assert vault.chain_report().ok


def test_removing_an_entry_forgets_its_warnings(vault, workspace):
    """Or the record grows a line per warning forever."""
    entry = _lock(vault, workspace, expires=time.time() + 20 * HOUR)
    _lock(vault, workspace, "second.txt", expires=time.time() + 20 * HOUR)
    warnings_mod.send(vault, Collector())
    assert len(vault.note(warnings_mod.EXTRA_KEY)) == 2

    vault.remove_entry(entry.id)
    warnings_mod.send(vault, Collector())

    assert len(vault.note(warnings_mod.EXTRA_KEY)) == 1


# --------------------------------------------------------------------------
# the keyless sweeper, which has no passphrase and must not leak names
# --------------------------------------------------------------------------

def test_the_background_warning_never_names_a_file(vault, workspace):
    """The index lives outside the vault in the clear. Names stay inside it."""
    vault.set_background_expiry(True)
    _lock(vault, workspace, "salary-review.xlsx", expires=time.time() + 20 * HOUR)

    coming = schedule.upcoming(vault.path)

    assert len(coming) == 1
    assert "salary" not in (coming[0].title() + coming[0].message()).lower()
    assert "open quenchkey" in coming[0].message().lower()


def test_several_deadlines_at_one_level_are_one_message(vault, workspace):
    vault.set_background_expiry(True)
    for name in ("one.txt", "two.txt", "three.txt"):
        _lock(vault, workspace, name, expires=time.time() + 20 * HOUR)

    coming = schedule.upcoming(vault.path)

    assert len(coming) == 1
    assert coming[0].count == 3
    assert "3 locked items" in coming[0].message()


def test_the_sweeper_says_it_once_too(vault, workspace, tmp_path):
    vault.set_background_expiry(True)
    _lock(vault, workspace, expires=time.time() + 20 * HOUR)
    seen: list = []

    first = schedule.warn_upcoming(vault.path, lambda t, m: seen.append(t))
    second = schedule.warn_upcoming(vault.path, lambda t, m: seen.append(t))

    assert len(first) == 1 and second == []
    assert len(seen) == 1


def test_the_sweeper_record_is_owner_only(vault, workspace):
    import os
    import stat

    vault.set_background_expiry(True)
    _lock(vault, workspace, expires=time.time() + 20 * HOUR)
    schedule.warn_upcoming(vault.path, lambda t, m: None)

    mode = os.stat(schedule.warned_path(vault.path)).st_mode
    assert stat.S_IMODE(mode) == 0o600
