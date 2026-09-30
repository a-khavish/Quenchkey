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

"""Colour, and when not to use it.

Colour earns its place here for one reason: this tool destroys things, and a
line that says so should not look like a line that says a file was written.
Red is for something that has just become unreadable or is about to; amber for
something that wants a decision; green for a thing that went as asked; and
nothing else is coloured at all, because a terminal where everything is
coloured carries no more information than one where nothing is.

It switches itself off, without being asked, when:

* output is not a terminal — a pipe, a log file, a cron mail;
* ``NO_COLOR`` is set to anything at all, which is the
  `convention <https://no-color.org>`_;
* ``TERM`` is unset or ``dumb``;
* ``--json`` was asked for, because a JSON document with escape codes in it is
  not a JSON document.

``QUENCHKEY_COLOR=always`` forces it on for the case where somebody is piping
into ``less -R`` on purpose, and ``never`` forces it off.
"""

from __future__ import annotations

import os
import sys

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

RED = "\033[31m"
GREEN = "\033[32m"
AMBER = "\033[33m"
BLUE = "\033[34m"
CYAN = "\033[36m"

#: Resolved once, on first use, so a command does not change its mind halfway.
_enabled: bool = False
_decided: bool = False


def decide(stream=None, machine_readable: bool = False) -> bool:
    """Work out whether to colour, and remember the answer."""
    global _enabled, _decided
    forced = os.environ.get("QUENCHKEY_COLOR", "").strip().lower()
    if forced in ("always", "force", "1", "yes"):
        _enabled, _decided = True, True
        return _enabled
    if forced in ("never", "none", "0", "no") or machine_readable:
        _enabled, _decided = False, True
        return _enabled
    if os.environ.get("NO_COLOR") is not None:
        _enabled, _decided = False, True
        return _enabled
    if os.environ.get("TERM", "") in ("", "dumb"):
        _enabled, _decided = False, True
        return _enabled
    target = stream if stream is not None else sys.stdout
    try:
        _enabled = bool(target.isatty())
    except (AttributeError, ValueError):
        _enabled = False
    _decided = True
    return _enabled


def enabled() -> bool:
    if not _decided:
        decide()
    return _enabled


def paint(text: str, *codes: str) -> str:
    if not text or not enabled() or not codes:
        return text
    return "".join(codes) + text + RESET


# -- the four things worth distinguishing ---------------------------------

def gone(text: str) -> str:
    """Something is now unreadable, or is about to be. Red."""
    return paint(text, BOLD, RED)


def decide_this(text: str) -> str:
    """Something wants a decision before it goes further. Amber."""
    return paint(text, AMBER)


def done(text: str) -> str:
    """It happened, as asked. Green."""
    return paint(text, GREEN)


def name(text: str) -> str:
    """An identifier: a command, an entry id, a path. Cyan."""
    return paint(text, CYAN)


def heading(text: str) -> str:
    return paint(text, BOLD)


def faint(text: str) -> str:
    return paint(text, DIM)


def rule(width: int = 68) -> str:
    return faint("─" * width)
