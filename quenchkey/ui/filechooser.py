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

"""One place that decides which file chooser opens.

Qt draws its own file dialog by default. It works, but it is not the file
manager anyone on the desktop actually knows: no bookmarks, no recent files,
no search, no thumbnails, and none of the places the desktop has been told
about. Choosing a file to lock away forever is a bad moment to hand somebody
an unfamiliar list of paths.

So Quenchkey asks the desktop to put up its own chooser, through the
`XDG desktop portal <https://flatpak.github.io/xdg-desktop-portal/>`_. On
GNOME that is the GTK file chooser; on KDE it is the Plasma one. Qt ships a
platform theme (``xdgdesktopportal``) that routes every ``QFileDialog`` call
through that portal, so the work here is deciding *when* to switch it on and
making sure a dialog still appears when it cannot be used.

The layers, in order:

1. ``QUENCHKEY_FILE_DIALOG`` overrides everything — ``portal`` or ``qt``. The
   demo recorder sets ``qt`` because it drives the dialog's widgets by name,
   and the portal's dialog belongs to another process entirely.
2. Otherwise, before the QApplication exists, :func:`configure` looks for a
   session bus and an installed portal service. If both are there it sets
   ``QT_QPA_PLATFORMTHEME`` so Qt uses the portal.
3. Once the QApplication is up, :func:`portal_responds` actually pings the
   portal. If the service file was there but nothing answers, every call here
   falls back to Qt's own dialog rather than risk a chooser that never opens.

Nothing in this module can leave the user without a dialog, which is the only
property that really matters.
"""

from __future__ import annotations

import os
from typing import Optional, Sequence

from PyQt5.QtWidgets import QFileDialog, QWidget

#: Set to ``portal`` or ``qt`` to take the decision out of Quenchkey's hands.
MODE_ENV = "QUENCHKEY_FILE_DIALOG"

#: The bus name the desktop portal answers on.
PORTAL_SERVICE = "org.freedesktop.portal.Desktop"

#: Qt's platform theme that forwards file dialogs to the portal.
PORTAL_THEME = "xdgdesktopportal"

#: Platform plugins that mean there is no desktop to ask.
HEADLESS_PLATFORMS = ("offscreen", "minimal", "vnc", "linuxfb")

_portal_reachable: Optional[bool] = None


# -- deciding ---------------------------------------------------------------

def mode() -> str:
    """``portal``, ``qt`` or ``auto`` — whatever the environment asked for."""
    value = os.environ.get(MODE_ENV, "").strip().lower()
    return value if value in ("portal", "qt") else "auto"


def _data_dirs() -> list[str]:
    home = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    rest = os.environ.get("XDG_DATA_DIRS") or "/usr/local/share:/usr/share"
    return [home, *(part for part in rest.split(":") if part)]


def portal_installed() -> bool:
    """True when a session bus exists and the portal can be started on it.

    This is deliberately a look at the filesystem rather than a call. It runs
    before the QApplication is built, where opening a D-Bus connection to ask
    properly is not something to be doing.
    """
    bus = os.environ.get("DBUS_SESSION_BUS_ADDRESS")
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    if not bus and not (runtime and os.path.exists(os.path.join(runtime, "bus"))):
        return False
    service = f"{PORTAL_SERVICE}.service"
    return any(os.path.isfile(os.path.join(directory, "dbus-1", "services", service))
               for directory in _data_dirs())


def headless() -> bool:
    platform = os.environ.get("QT_QPA_PLATFORM", "").split(":")[0].strip().lower()
    return platform in HEADLESS_PLATFORMS


def configure() -> Optional[str]:
    """Point Qt at the portal, if that is the right thing to do.

    Call this before constructing the QApplication — Qt picks its platform
    theme while it is being built and never looks again. Returns the theme it
    set, or None if it left the environment alone.

    A theme the user set themselves is never overwritten. Somebody running
    with ``QT_QPA_PLATFORMTHEME=gtk3`` has already said what they want.
    """
    chosen = mode()
    if chosen == "qt" or headless():
        return None
    if os.environ.get("QT_QPA_PLATFORMTHEME"):
        return None
    if chosen != "portal" and not portal_installed():
        return None
    os.environ["QT_QPA_PLATFORMTHEME"] = PORTAL_THEME
    return PORTAL_THEME


def portal_responds(timeout_ms: int = 2000) -> bool:
    """Ping the portal and cache the answer.

    An installed service file only says the portal *can* start. This asks it
    to, which is the difference between a chooser that opens and one that
    never does. The result is cached because the answer will not change
    within a session and the first call costs a round trip.
    """
    global _portal_reachable
    if _portal_reachable is not None:
        return _portal_reachable
    _portal_reachable = _ping_portal(timeout_ms)
    return _portal_reachable


def _ping_portal(timeout_ms: int) -> bool:
    try:
        from PyQt5.QtDBus import QDBusConnection, QDBusInterface
    except ImportError:
        return False
    try:
        bus = QDBusConnection.sessionBus()
        if not bus.isConnected():
            return False
        probe = QDBusInterface(PORTAL_SERVICE, "/org/freedesktop/portal/desktop",
                               "org.freedesktop.DBus.Peer", bus)
        probe.setTimeout(timeout_ms)
        return not probe.call("Ping").errorName()
    except Exception:  # noqa: BLE001 - a broken bus must not stop a dialog opening
        return False


def using_portal() -> bool:
    """Whether the next dialog will be the desktop's own."""
    chosen = mode()
    if chosen == "qt" or headless():
        return False
    if os.environ.get("QT_QPA_PLATFORMTHEME") != PORTAL_THEME:
        return False
    return portal_responds()


def _options(extra: QFileDialog.Options = QFileDialog.Options()) -> QFileDialog.Options:
    """Qt's own dialog unless the portal is genuinely answering."""
    options = QFileDialog.Options(extra)
    if not using_portal():
        options |= QFileDialog.DontUseNativeDialog
    return options


def reset_cache() -> None:
    """Forget whether the portal answered. For tests."""
    global _portal_reachable
    _portal_reachable = None


# -- the choosers -----------------------------------------------------------

def _filter(patterns: Optional[Sequence[str]]) -> str:
    return ";;".join(patterns) if patterns else "All files (*)"


def open_files(parent: Optional[QWidget], title: str, directory: str = "",
               patterns: Optional[Sequence[str]] = None) -> list[str]:
    """Choose any number of existing files."""
    paths, _ = QFileDialog.getOpenFileNames(
        parent, title, directory or os.path.expanduser("~"),
        _filter(patterns), options=_options())
    return [path for path in paths if path]


def open_file(parent: Optional[QWidget], title: str, directory: str = "",
              patterns: Optional[Sequence[str]] = None) -> Optional[str]:
    """Choose one existing file."""
    path, _ = QFileDialog.getOpenFileName(
        parent, title, directory or os.path.expanduser("~"),
        _filter(patterns), options=_options())
    return path or None


def save_file(parent: Optional[QWidget], title: str, suggested: str = "",
              patterns: Optional[Sequence[str]] = None,
              confirm_overwrite: bool = True) -> Optional[str]:
    """Choose where to write a file.

    ``confirm_overwrite=False`` is honoured by Qt's dialog. The portal always
    asks, and there is no way to talk it out of that — which is the right
    behaviour anyway when the file being written is a vault.
    """
    extra = QFileDialog.Options()
    if not confirm_overwrite:
        extra |= QFileDialog.DontConfirmOverwrite
    path, _ = QFileDialog.getSaveFileName(
        parent, title, suggested or os.path.expanduser("~"),
        _filter(patterns), options=_options(extra))
    return path or None


def choose_directory(parent: Optional[QWidget], title: str,
                     directory: str = "") -> Optional[str]:
    """Choose an existing folder."""
    path = QFileDialog.getExistingDirectory(
        parent, title, directory or os.path.expanduser("~"),
        options=_options(QFileDialog.ShowDirsOnly))
    return path or None
