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

"""Preferences: where files go, and how the window behaves."""

from __future__ import annotations

import os
from typing import Optional

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QButtonGroup, QCheckBox, QComboBox, QHBoxLayout, QPushButton, QRadioButton,
    QVBoxLayout, QWidget,
)

from .. import autostart, settings as settings_mod
from . import filechooser, theme, tray
from .dialogs import _Base
from .widgets import Banner, Card, Divider, label


class OutputRow(QWidget):
    """One kind of output, and the rule for where it lands."""

    def __init__(self, kind: str, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.kind = kind
        spec = settings_mod.OUTPUT_KINDS[kind]

        column = QVBoxLayout(self)
        column.setContentsMargins(0, 6, 0, 6)
        column.setSpacing(6)
        column.addWidget(label(spec["label"], "Section"))
        hint = label(spec["help"], "Faint", wrap=True)
        hint.setMinimumWidth(1)
        column.addWidget(hint)

        row = QHBoxLayout()
        row.setSpacing(10)
        self.choice = QComboBox()
        self.choice.setMinimumWidth(theme.scaled(220))
        self._modes = list(spec["modes"])
        for mode in self._modes:
            self.choice.addItem({
                settings_mod.BESIDE: "Beside the file it came from",
                settings_mod.ASK: "Ask me every time",
                settings_mod.FIXED: "Always this folder…",
            }[mode], mode)
        self.choice.currentIndexChanged.connect(self._on_changed)
        row.addWidget(self.choice)

        self.folder_button = QPushButton("Choose folder…")
        self.folder_button.setCursor(Qt.PointingHandCursor)
        self.folder_button.clicked.connect(self._choose_folder)
        row.addWidget(self.folder_button)

        self.folder_label = label("", "Faint", wrap=True)
        self.folder_label.setMinimumWidth(1)
        row.addWidget(self.folder_label, 1)
        column.addLayout(row)

        self._load()

    def _load(self) -> None:
        mode, path = settings_mod.current().output_rule(self.kind)
        self.choice.blockSignals(True)
        self.choice.setCurrentIndex(self._modes.index(mode))
        self.choice.blockSignals(False)
        self._path = path
        self._refresh()

    def _refresh(self) -> None:
        mode = self.choice.currentData()
        fixed = mode == settings_mod.FIXED
        self.folder_button.setVisible(fixed)
        self.folder_label.setVisible(fixed)
        if fixed:
            self.folder_label.setText(
                self._path.replace(os.path.expanduser("~"), "~")
                if self._path else "no folder chosen yet")

    def _on_changed(self, _index: int) -> None:
        mode = self.choice.currentData()
        if mode == settings_mod.FIXED and not self._path:
            self._choose_folder()
            if not self._path:
                # Nothing chosen, so nothing to remember — fall back rather
                # than storing a rule that cannot be honoured.
                self.choice.setCurrentIndex(
                    self._modes.index(settings_mod.ASK)
                    if settings_mod.ASK in self._modes else 0)
                return
        self._store()

    def _choose_folder(self) -> None:
        chosen = filechooser.choose_directory(
            self, f"Where should {settings_mod.OUTPUT_KINDS[self.kind]['label'].lower()} go?",
            self._path or os.path.expanduser("~"))
        if chosen:
            self._path = chosen
            self._store()

    def _store(self) -> None:
        mode = self.choice.currentData()
        settings_mod.current().set_output_rule(self.kind, mode, self._path)
        self._refresh()


class SettingsDialog(_Base):
    """Everything configurable, in one place."""

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__("Settings", parent, 820, 760)
        current = settings_mod.current()

        self.body.addWidget(label(
            "These are preferences, not security. They are kept in "
            f"{settings_mod.settings_path().replace(os.path.expanduser('~'), '~')}, "
            "outside the vault and unencrypted, because most of them have to "
            "be read before anything is unlocked. Nothing secret is stored "
            "there.", "Faint", wrap=True))

        # -- where things are saved
        saving = Card()
        saving.body.addWidget(label("WHERE FILES ARE SAVED", "Section"))
        saving.body.addWidget(label(
            "“Ask me every time” opens your desktop's own file chooser, which "
            "is also where you rename a file on the way out. A fixed folder "
            "skips the question — nothing is ever overwritten either way.",
            "Faint", wrap=True))
        self.rows = []
        for index, kind in enumerate(settings_mod.OUTPUT_KINDS):
            if index:
                saving.body.addWidget(Divider())
            row = OutputRow(kind)
            self.rows.append(row)
            saving.body.addWidget(row)
        self.body.addWidget(saving)

        # -- window behaviour
        window = Card()
        window.body.addWidget(label("THE WINDOW", "Section"))
        self.fill_check = QCheckBox("Open filling the screen")
        self.fill_check.setChecked(current.get("fill_screen", True))
        self.fill_check.toggled.connect(
            lambda on: current.set("fill_screen", on))
        window.body.addWidget(self.fill_check)
        window.body.addWidget(label(
            "It can still be resized and moved; this only decides the size it "
            "opens at.", "Faint", wrap=True))

        window.body.addWidget(Divider())
        window.body.addWidget(label("WHEN YOU CLOSE THE WINDOW", "Section"))
        self.close_group = QButtonGroup(self)
        self._close_buttons = {}
        for value, text, hint in (
            (settings_mod.CLOSE_ASK, "Ask me",
             "A short prompt with both options."),
            (settings_mod.CLOSE_TRAY, "Keep running in the tray",
             "Deadlines keep being checked while it runs, and the vault still "
             "auto-locks on idle."),
            (settings_mod.CLOSE_QUIT, "Quit",
             "The vault locks and every key leaves memory."),
        ):
            button = QRadioButton(text)
            button.setChecked(current.get("close_action") == value)
            self.close_group.addButton(button)
            self._close_buttons[value] = button
            button.toggled.connect(
                lambda on, v=value: on and current.set("close_action", v))
            window.body.addWidget(button)
            note = label(hint, "Faint", wrap=True)
            note.setMinimumWidth(1)
            window.body.addWidget(note)

        available, reason = tray.availability()
        if not available:
            window.body.addWidget(Banner(
                f"This desktop has nowhere to put a tray icon ({reason}). "
                f"Closing the window will quit, whatever is chosen here — on "
                f"GNOME an extension such as AppIndicator adds the tray back.",
                "warning"))
        self.body.addWidget(window)

        # -- starting up
        startup = Card()
        startup.body.addWidget(label("STARTING UP", "Section"))
        self.autostart_check = QCheckBox("Start Quenchkey when I log in")
        self.autostart_check.setChecked(autostart.enabled())
        self.autostart_check.toggled.connect(self._set_autostart)
        startup.body.addWidget(self.autostart_check)

        self.minimised_check = QCheckBox("Start minimised to the tray")
        self.minimised_check.setChecked(current.get("start_minimised", False))
        self.minimised_check.setEnabled(available)
        self.minimised_check.toggled.connect(
            lambda on: current.set("start_minimised", on))
        startup.body.addWidget(self.minimised_check)

        self.autostart_note = label("", "Faint", wrap=True)
        self.autostart_note.setMinimumWidth(1)
        startup.body.addWidget(self.autostart_note)
        startup.body.addWidget(label(
            "Starting on login does not unlock anything. Quenchkey opens at the "
            "passphrase screen exactly as it would otherwise — there is no "
            "way to skip that and no stored passphrase to skip it with.",
            "Faint", wrap=True))
        self.body.addWidget(startup)

        self._refresh_autostart_note()
        self.body.addStretch(1)
        self.add_close("Done")

    def _set_autostart(self, enabled: bool) -> None:
        try:
            if enabled:
                autostart.enable()
            else:
                autostart.disable()
        except OSError as exc:
            self.autostart_note.setText(f"Could not change that: {exc}")
            return
        settings_mod.current().set("autostart", enabled)
        self._refresh_autostart_note()

    def _refresh_autostart_note(self) -> None:
        if autostart.enabled():
            self.autostart_note.setText(
                f"Written to {autostart.desktop_path().replace(os.path.expanduser('~'), '~')}. "
                f"Delete that file and it stops, with or without this "
                f"application.")
        else:
            self.autostart_note.setText("")
