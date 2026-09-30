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

"""Starting on login, through the desktop's own autostart folder.

One ``.desktop`` file in ``~/.config/autostart``. Every desktop that follows
the freedesktop specification reads that folder — GNOME, KDE, Xfce, Cinnamon —
so there is nothing here that is specific to any of them, no service to
register and no daemon.

**Starting on login does not unlock anything.** Quenchkey opens at the passphrase
screen exactly as it would if launched by hand. There is no stored passphrase,
so there is nothing that could skip it.
"""

from __future__ import annotations

import os
import shutil
import sys

DESKTOP_NAME = "quenchkey.desktop"


def autostart_dir() -> str:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return os.path.join(base, "autostart")


def desktop_path() -> str:
    return os.path.join(autostart_dir(), DESKTOP_NAME)


def command() -> str:
    """How to launch Quenchkey again, as an absolute path where possible.

    An installed copy is on the PATH as ``quenchkey``; a checkout is run through
    the interpreter that is running now, which is also the one holding the
    dependencies.
    """
    installed = shutil.which("quenchkey")
    if installed:
        return installed
    launcher = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "quenchkey.py")
    if os.path.isfile(launcher):
        return f"{sys.executable} {launcher}"
    return f"{sys.executable} -m quenchkey.ui.app"


def entry(minimised: bool = False) -> str:
    exec_line = command()
    if minimised:
        exec_line += " --minimised"
    return (
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Name=Quenchkey\n"
        "Comment=The key goes out\n"
        f"Exec={exec_line}\n"
        "Icon=quenchkey\n"
        "Terminal=false\n"
        "X-GNOME-Autostart-enabled=true\n"
        # A moment after the desktop settles, so the tray exists by the time
        # Quenchkey looks for one.
        "X-GNOME-Autostart-Delay=5\n"
    )


def enabled() -> bool:
    return os.path.isfile(desktop_path())


def enable(minimised: bool = False) -> str:
    os.makedirs(autostart_dir(), exist_ok=True)
    path = desktop_path()
    with open(path, "w") as fh:
        fh.write(entry(minimised))
    os.chmod(path, 0o644)
    return path


def disable() -> None:
    try:
        os.unlink(desktop_path())
    except FileNotFoundError:
        pass
