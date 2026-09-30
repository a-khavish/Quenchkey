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

"""Removing the application from inside it.

A convenience, and only that. **Uninstalling is not a security control.**
There is no lock in this application for anybody to bypass by deleting it:
what protects a locked file is that it is encrypted and that the key is
somewhere else, or gone. With Quenchkey removed you are left with unreadable
files and a recovery script that still asks for the passphrase.

The vault is never touched. Removing the application destroys no keys — that
happens on a deadline, or when somebody asks for it, and nowhere else.

Only an installation this process can write to is removed. A system-wide one
under ``/usr/local`` needs root, and a graphical application quietly acquiring
root to delete files is not a thing this will do; it says so and gives the
command instead.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import Optional

#: Checked in order, matching install.sh.
PREFIXES = (os.path.expanduser("~/.local"), "/usr/local")


@dataclass
class Report:
    found: bool
    prefix: str = ""
    writable: bool = False
    detail: str = ""


@dataclass
class Result:
    ok: bool
    detail: str = ""


def _installed_prefix() -> Optional[str]:
    for prefix in PREFIXES:
        if os.path.isdir(os.path.join(prefix, "lib", "quenchkey")) or \
                os.path.isfile(os.path.join(prefix, "bin", "quenchkey")):
            return prefix
    return None


def describe() -> Report:
    """Where Quenchkey is installed, and whether this process can remove it."""
    prefix = _installed_prefix()
    if prefix is None:
        return Report(False, detail=(
            "Nothing was found under " + " or ".join(PREFIXES) + "."))
    writable = os.access(prefix, os.W_OK)
    if not writable:
        return Report(True, prefix, False, detail=(
            f"Quenchkey is installed in {prefix}, which needs root to change. "
            f"Run ./install.sh --uninstall from a terminal instead."))
    return Report(True, prefix, True,
                  detail=f"Quenchkey is installed in {prefix}.")


def targets(prefix: str) -> list:
    """Everything the installer puts down, so this takes the same things away."""
    config = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    paths = [
        os.path.join(prefix, "lib", "quenchkey"),
        os.path.join(prefix, "bin", "quenchkey"),
        os.path.join(prefix, "bin", "quenchkey-recover"),
        os.path.join(prefix, "share", "applications", "quenchkey.desktop"),
        os.path.join(prefix, "share", "icons", "hicolor", "scalable", "apps",
                     "quenchkey.svg"),
        os.path.join(prefix, "share", "mime", "packages", "quenchkey.xml"),
        os.path.join(config, "systemd", "user", "quenchkey-sweep.service"),
        os.path.join(config, "systemd", "user", "quenchkey-sweep.timer"),
        os.path.join(prefix, "lib", "systemd", "user", "quenchkey-sweep.service"),
        os.path.join(prefix, "lib", "systemd", "user", "quenchkey-sweep.timer"),
        os.path.join(config, "autostart", "quenchkey.desktop"),
    ]
    for size in (16, 32, 64, 256):
        paths.append(os.path.join(prefix, "share", "icons", "hicolor",
                                  f"{size}x{size}", "apps", "quenchkey.png"))
    return paths


def run() -> Result:
    """Remove it. Returns what happened rather than raising."""
    report = describe()
    if not report.found:
        return Result(False, report.detail)
    if not report.writable:
        return Result(False, report.detail)

    _stop_timer()
    removed, failed = [], []
    for path in targets(report.prefix):
        try:
            if os.path.isdir(path) and not os.path.islink(path):
                shutil.rmtree(path)
                removed.append(path)
            elif os.path.exists(path) or os.path.islink(path):
                os.unlink(path)
                removed.append(path)
        except OSError as exc:
            failed.append(f"{path}: {exc}")

    _refresh_caches(report.prefix)

    if failed:
        return Result(False, "Some of it could not be removed:\n  "
                             + "\n  ".join(failed))
    return Result(True, f"Removed {len(removed)} files and folders from "
                        f"{report.prefix}.")


def _stop_timer() -> None:
    binary = shutil.which("systemctl")
    if not binary:
        return
    try:
        subprocess.run([binary, "--user", "disable", "--now",
                        "quenchkey-sweep.timer"], capture_output=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        pass


def _refresh_caches(prefix: str) -> None:
    for command, argument in (
        ("update-desktop-database", os.path.join(prefix, "share", "applications")),
        ("update-mime-database", os.path.join(prefix, "share", "mime")),
    ):
        binary = shutil.which(command)
        if binary and os.path.isdir(argument):
            try:
                subprocess.run([binary, argument], capture_output=True, timeout=60)
            except (OSError, subprocess.SubprocessError):
                pass
    binary = shutil.which("gtk-update-icon-cache")
    icons = os.path.join(prefix, "share", "icons", "hicolor")
    if binary and os.path.isdir(icons):
        try:
            subprocess.run([binary, "-f", "-t", icons], capture_output=True,
                           timeout=60)
        except (OSError, subprocess.SubprocessError):
            pass


def running_from_checkout() -> bool:
    """Whether this is a source tree rather than an installed copy."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.isfile(os.path.join(root, "install.sh"))


if __name__ == "__main__":  # pragma: no cover - a convenience
    outcome = run()
    print(outcome.detail)
    sys.exit(0 if outcome.ok else 1)
