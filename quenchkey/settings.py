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

"""Preferences — where things get saved, and how the window behaves.

These live in ``~/.config/quenchkey/settings.json``, **outside the vault and
unencrypted**, and that is not an oversight. Most of them have to be read
before anything is unlocked: whether to start minimised, whether to sit in the
tray, where the vault file is. A setting that could only be read after unlock
would be useless for deciding how to show the unlock screen.

So nothing secret goes in here, ever. No passphrase, no key, no list of what
is locked — only preferences, and the folders somebody chose to save things
into. Those folder names are the one thing here worth a thought: they say
where you keep your documents. The file is written 0600 and that is the whole
of its protection, which is the same protection your shell history gets.

Nothing in this module affects what is encrypted, how, or whether a deadline
is enforced. Deleting the file loses your preferences and nothing else.
"""

from __future__ import annotations

import json
import os
from typing import Any, Optional

#: Where each kind of output can go. ``ask`` opens the desktop's own file
#: chooser every time — which is also how somebody renames the file on the way
#: out. ``fixed`` sends it straight to a remembered folder without asking.
ASK = "ask"
FIXED = "fixed"

#: ``beside`` means next to the file it came from, which only makes sense for
#: things that *have* a source file.
BESIDE = "beside"

#: Each kind of file the application writes, with a label for the settings
#: screen and the modes it can sensibly offer.
OUTPUT_KINDS: dict = {
    "extracted": {
        "label": "Files opened from the vault",
        "modes": (ASK, FIXED),
        "default_mode": ASK,
        "help": "Where documents go when you open a locked entry.",
    },
    "unlocked_shared": {
        "label": "Files opened from a shared .qkey",
        "modes": (BESIDE, ASK, FIXED),
        "default_mode": BESIDE,
        "help": "Beside the locked file keeps things where you found them.",
    },
    "locked": {
        "label": "New locked files (.qkey)",
        "modes": (BESIDE, ASK, FIXED),
        "default_mode": BESIDE,
        "help": "Beside the first file you chose to lock.",
    },
    "shared": {
        "label": "New shared files",
        "modes": (BESIDE, ASK, FIXED),
        "default_mode": BESIDE,
        "help": "The ones with their own passphrase, for sending to people.",
    },
    "certificates": {
        "label": "Certificates of destruction",
        "modes": (ASK, FIXED),
        "default_mode": ASK,
        "help": "Signed records of a key being destroyed.",
    },
    "timestamps": {
        "label": "Timestamp tokens",
        "modes": (ASK, FIXED),
        "default_mode": ASK,
        "help": "Third-party proof of when the anchor stood as it did.",
    },
    "shares": {
        "label": "Recovery shares",
        "modes": (ASK, FIXED),
        "default_mode": ASK,
        "help": "Keep these somewhere you would not keep the vault.",
    },
    "backups": {
        "label": "Vault backups",
        "modes": (ASK, FIXED),
        "default_mode": ASK,
        "help": "Keep these somewhere the vault is not.",
    },
    "keyfile": {
        "label": "Generated keyfiles",
        "modes": (ASK, FIXED),
        "default_mode": ASK,
        "help": "The optional second factor, made when a vault is created.",
    },
}

#: What closing the window does.
CLOSE_ASK = "ask"
CLOSE_TRAY = "tray"
CLOSE_QUIT = "quit"

DEFAULTS: dict = {
    "close_action": CLOSE_ASK,
    "tray_enabled": True,
    "start_minimised": False,
    "autostart": False,
    "fill_screen": True,
    "outputs": {},
}

FILE_MODE = 0o600


def config_dir() -> str:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return os.path.join(base, "quenchkey")


def settings_path() -> str:
    return os.path.join(config_dir(), "settings.json")


class Settings:
    """Preferences, read once and written whenever something changes."""

    def __init__(self, path: Optional[str] = None):
        self.path = path or settings_path()
        self._data: dict = json.loads(json.dumps(DEFAULTS))
        self.load()

    # -- storage ----------------------------------------------------------

    def load(self) -> None:
        try:
            with open(self.path) as fh:
                stored = json.load(fh)
        except (FileNotFoundError, ValueError, OSError):
            return
        if not isinstance(stored, dict):
            return
        for key, value in stored.items():
            if key in DEFAULTS:
                self._data[key] = value

    def save(self) -> None:
        directory = os.path.dirname(os.path.abspath(self.path)) or "."
        os.makedirs(directory, exist_ok=True)
        tmp = f"{self.path}.tmp-{os.getpid()}"
        handle = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, FILE_MODE)
        try:
            with os.fdopen(handle, "w") as fh:
                json.dump(self._data, fh, indent=2, sort_keys=True)
            os.replace(tmp, self.path)
            os.chmod(self.path, FILE_MODE)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    # -- simple values ----------------------------------------------------

    def get(self, key: str, fallback: Any = None) -> Any:
        return self._data.get(key, DEFAULTS.get(key, fallback))

    def set(self, key: str, value: Any) -> None:
        if self._data.get(key) == value:
            return
        self._data[key] = value
        self.save()

    # -- output locations -------------------------------------------------

    def output_rule(self, kind: str) -> tuple:
        """``(mode, path)`` for one kind of output.

        A remembered folder that has since been deleted falls back to asking
        rather than failing at the moment somebody is trying to save
        something.
        """
        spec = OUTPUT_KINDS.get(kind)
        if spec is None:
            raise KeyError(f"unknown output kind {kind!r}")
        stored = self._data.get("outputs", {}).get(kind) or {}
        mode = stored.get("mode")
        path = stored.get("path") or ""
        if mode not in spec["modes"]:
            mode = spec["default_mode"]
        if mode == FIXED and not (path and os.path.isdir(path)):
            mode = ASK if ASK in spec["modes"] else spec["default_mode"]
            path = ""
        return mode, path

    def set_output_rule(self, kind: str, mode: str, path: str = "") -> None:
        spec = OUTPUT_KINDS.get(kind)
        if spec is None:
            raise KeyError(f"unknown output kind {kind!r}")
        if mode not in spec["modes"]:
            raise ValueError(f"{kind} cannot be set to {mode!r}")
        outputs = dict(self._data.get("outputs", {}))
        outputs[kind] = {"mode": mode, "path": os.path.abspath(path) if path else ""}
        self._data["outputs"] = outputs
        self.save()

    def reset_outputs(self) -> None:
        self._data["outputs"] = {}
        self.save()


_current: Optional[Settings] = None


def current() -> Settings:
    """The one Settings instance the application uses."""
    global _current
    if _current is None:
        _current = Settings()
    return _current


def use(settings: Optional[Settings]) -> None:
    """Replace the shared instance. For tests, and for a custom config path."""
    global _current
    _current = settings
