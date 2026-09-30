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

"""The tray icon, and an honest answer about whether there is a tray.

GNOME removed the system tray in 2017 and has not brought it back; what looks
like one is an extension. Qt reports a tray as available on GNOME anyway,
because a StatusNotifier host may appear later, so "available" here means Qt
says yes *and* the desktop is one where that answer is usually true.

Getting this wrong has a specific cost: somebody closes the window expecting
it to carry on in the tray, and it vanishes instead. So where the answer is
doubtful the settings screen says so, and closing quits.
"""

from __future__ import annotations

import os
from typing import Optional

from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QAction, QMenu, QSystemTrayIcon

from . import theme


def availability() -> tuple:
    """``(available, reason)`` — whether an icon put in the tray will show."""
    if not QSystemTrayIcon.isSystemTrayAvailable():
        return False, "no system tray on this desktop"

    desktop = (os.environ.get("XDG_CURRENT_DESKTOP", "")
               + " " + os.environ.get("DESKTOP_SESSION", "")).lower()
    if "gnome" in desktop and "unity" not in desktop:
        # Qt answers yes here whether or not anything is listening. An
        # AppIndicator extension makes it true; a stock GNOME does not.
        return True, "GNOME needs a tray extension such as AppIndicator"
    return True, ""


def looks_reliable() -> bool:
    available, reason = availability()
    return available and not reason


class Tray:
    """A tray icon with a small menu, or nothing at all.

    Constructed either way so callers do not have to branch; :attr:`active`
    says whether anything actually appeared.
    """

    def __init__(self, window, on_quit):
        self.window = window
        self.icon: Optional[QSystemTrayIcon] = None
        available, _reason = availability()
        if not available:
            return

        self.icon = QSystemTrayIcon(QIcon(theme.logo_pixmap(64)), window)
        self.icon.setToolTip("Quenchkey — data with a lifespan")

        menu = QMenu()
        self.show_action = QAction("Show Quenchkey", menu)
        self.show_action.triggered.connect(self.show_window)
        menu.addAction(self.show_action)

        self.lock_action = QAction("Lock the vault", menu)
        self.lock_action.triggered.connect(self._lock)
        menu.addAction(self.lock_action)

        menu.addSeparator()
        quit_action = QAction("Quit", menu)
        quit_action.triggered.connect(on_quit)
        menu.addAction(quit_action)

        self.icon.setContextMenu(menu)
        self.icon.activated.connect(self._activated)
        self.icon.show()

    @property
    def active(self) -> bool:
        return self.icon is not None and self.icon.isVisible()

    def _activated(self, reason) -> None:
        if reason in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick):
            self.show_window()

    def show_window(self) -> None:
        self.window.showNormal()
        self.window.raise_()
        self.window.activateWindow()

    def _lock(self) -> None:
        locker = getattr(self.window, "_lock_vault", None)
        if callable(locker):
            locker()

    def notify(self, title: str, message: str) -> None:
        if self.icon is not None:
            self.icon.showMessage(title, message,
                                  QSystemTrayIcon.Information, 8000)

    def hide(self) -> None:
        if self.icon is not None:
            self.icon.hide()
