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

"""The unlock flow: choose where the files land, then let them out."""

from __future__ import annotations

import os
from typing import Optional

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QAbstractItemView, QComboBox, QDialog, QHBoxLayout, QHeaderView,
    QPushButton, QRadioButton, QScrollArea, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget,
)

from .. import expiry as expiry_mod, locker
from ..session import Session
from ..vault import Entry
from . import destinations, theme
from .widgets import Banner, Card, Divider, ProgressPanel, label
from .workers import Task


def _loan_length(minutes: int) -> str:
    """'30 minutes', '4 hours', 'a day' — how a person says it."""
    if minutes < 60:
        return f"{minutes} minutes"
    if minutes == 60:
        return "an hour"
    if minutes % 1440 == 0:
        days = minutes // 1440
        return "a day" if days == 1 else f"{days} days"
    return f"{minutes // 60} hours"


class UnlockDialog(QDialog):
    """Decrypt one entry into a folder of the user's choosing."""

    def __init__(self, session: Session, entry: Entry,
                 parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.session = session
        self.entry = entry
        self.written: list[str] = []
        self.on_loan = False
        self._task: Optional[Task] = None
        self.destination = os.path.join(os.path.expanduser("~"), "Quenchkey")

        self.setWindowTitle("Open locked file")
        self.setModal(True)
        theme.fit(self, 800, 860, 690, 500)
        self._build()

    def _build(self) -> None:
        self.setObjectName("Root")
        shell = QVBoxLayout(self)
        shell.setContentsMargins(0, 0, 0, 0)
        shell.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        shell.addWidget(scroll, 1)

        canvas = QWidget()
        scroll.setWidget(canvas)
        outer = QVBoxLayout(canvas)
        outer.setContentsMargins(theme.GUTTER, theme.GUTTER, theme.GUTTER, 8)
        outer.setSpacing(theme.GAP)

        outer.addWidget(label("Open locked file", "Title"))
        outer.addWidget(label(self.entry.display_name, "Subtitle"))

        details = Card(padding=18, spacing=12)
        details.body.addWidget(label("CONTENTS", "SectionHeading"))

        table = QTableWidget(len(self.entry.names), 2)
        table.setHorizontalHeaderLabels(["#", "Name"])
        table.setSelectionMode(QAbstractItemView.NoSelection)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setAlternatingRowColors(True)
        table.verticalHeader().setVisible(False)
        table.setShowGrid(False)
        table.horizontalHeader().setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Fixed)
        table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        table.setColumnWidth(0, 46)
        for row, name in enumerate(self.entry.names):
            number = QTableWidgetItem(str(row + 1))
            number.setTextAlignment(Qt.AlignCenter)
            table.setItem(row, 0, number)
            table.setItem(row, 1, QTableWidgetItem(name))
        table.setMinimumHeight(140)
        details.body.addWidget(table)

        facts = [
            f"Locked {expiry_mod.format_time(self.entry.created)}",
            f"{expiry_mod.format_size(self.entry.plaintext_size)} of content",
            (f"Key destroyed {expiry_mod.format_time(self.entry.expires)}"
             if self.entry.expires else "No deadline set"),
        ]
        details.body.addWidget(label("  ·  ".join(facts), "Faint"))
        outer.addWidget(details, 1)

        loan = Card(padding=18, spacing=12)
        loan.body.addWidget(label("FOR HOW LONG", "SectionHeading"))
        self.keep_radio = QRadioButton("Open for good")
        self.keep_radio.setChecked(True)
        self.keep_radio.setCursor(Qt.PointingHandCursor)
        loan.body.addWidget(self.keep_radio)
        keep_note = label(
            "The extracted copies are yours. Nothing here tracks them or "
            "tidies them up afterwards.", "Faint")
        keep_note.setWordWrap(True)
        keep_note.setMinimumWidth(1)
        loan.body.addWidget(keep_note)
        loan.body.addWidget(Divider())

        self.loan_radio = QRadioButton("Open on loan, and bring it back")
        self.loan_radio.setCursor(Qt.PointingHandCursor)
        loan.body.addWidget(self.loan_radio)
        loan_row = QHBoxLayout()
        loan_row.setSpacing(10)
        loan_row.addWidget(label("Bring it back after", "Muted"))
        self.minutes = QComboBox()
        for value in locker.CHECKOUT_MINUTES:
            self.minutes.addItem(_loan_length(value), value)
        self.minutes.setCurrentIndex(
            list(locker.CHECKOUT_MINUTES).index(locker.DEFAULT_CHECKOUT_MINUTES))
        self.minutes.setEnabled(False)
        loan_row.addWidget(self.minutes)
        loan_row.addStretch(1)
        loan.body.addLayout(loan_row)
        loan_note = label(
            "The paths written out are recorded. When the loan runs out — or "
            "when you bring it back yourself — anything you edited is locked "
            "back into the vault and the working copies are shredded. Edits "
            "are never thrown away without saying so. This reaches only the "
            "copies extraction made, not one you moved elsewhere in the "
            "meantime.", "Faint")
        loan_note.setWordWrap(True)
        loan_note.setMinimumWidth(1)
        loan.body.addWidget(loan_note)
        self.loan_radio.toggled.connect(self.minutes.setEnabled)
        self.loan_radio.toggled.connect(self._retitle_open_button)
        outer.addWidget(loan)

        destination = Card(padding=18, spacing=12)
        destination.body.addWidget(label("EXTRACT TO", "SectionHeading"))
        row = QHBoxLayout()
        row.setSpacing(10)
        choose = QPushButton("Choose folder…")
        choose.setCursor(Qt.PointingHandCursor)
        choose.clicked.connect(self._choose_destination)
        row.addWidget(choose)
        self.destination_label = label(
            self.destination.replace(os.path.expanduser("~"), "~"), "Muted")
        row.addWidget(self.destination_label, 1)
        destination.body.addLayout(row)
        destination.body.addWidget(Divider())
        destination.body.addWidget(Banner(
            "Once these files are written out they are ordinary files, and "
            "Quenchkey has no further hold on them. Expiry destroys the key to "
            "the locked copy; it cannot reach anything that has already been "
            "extracted, copied or sent on.", "muted"))
        outer.addWidget(destination)

        self.error = Banner("", "danger")
        self.error.setVisible(False)
        outer.addWidget(self.error)

        self.progress = ProgressPanel()
        outer.addWidget(self.progress)

        footer = QWidget()
        footer.setObjectName("Root")
        buttons = QHBoxLayout(footer)
        buttons.setContentsMargins(theme.GUTTER, 10, theme.GUTTER, theme.GUTTER)
        buttons.addStretch(1)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setCursor(Qt.PointingHandCursor)
        self.cancel_button.clicked.connect(self.reject)
        buttons.addWidget(self.cancel_button)
        self.open_button = QPushButton("Decrypt and extract")
        self.open_button.setObjectName("Primary")
        self.open_button.setMinimumHeight(42)
        self.open_button.setCursor(Qt.PointingHandCursor)
        self.open_button.clicked.connect(self._start)
        buttons.addWidget(self.open_button)
        shell.addWidget(footer)

    def _retitle_open_button(self, on_loan: bool) -> None:
        self.open_button.setText(
            "Decrypt and lend out" if on_loan else "Decrypt and extract")

    def _choose_destination(self) -> None:
        path = destinations.folder_for("extracted", self, "Extract to",
                                       suggested=self.destination)
        if path:
            self.destination = path
            self.destination_label.setText(path.replace(os.path.expanduser("~"), "~"))

    def _start(self) -> None:
        self.open_button.setEnabled(False)
        self.cancel_button.setEnabled(False)
        self.error.setVisible(False)
        self.progress.start("Decrypting…")

        session = self.session
        entry_id = self.entry.id
        destination = self.destination
        self.on_loan = self.loan_radio.isChecked()
        minutes = int(self.minutes.currentData())
        on_loan = self.on_loan

        def work(progress=None):
            with session.guard:
                if on_loan:
                    return locker.check_out(session.vault, entry_id,
                                            destination, minutes,
                                            progress=progress)
                return locker.unlock_entry(session.vault, entry_id, destination,
                                           progress=progress)

        self._task = Task(work, error_title="Could not open the file")
        self._task.progress.connect(self.progress.update_progress)
        self._task.succeeded.connect(self._on_done)
        self._task.failed.connect(self._on_failed)
        self._task.start()

    def _on_done(self, written: list) -> None:
        self.progress.finish()
        self.written = list(written)
        self.accept()

    def _on_failed(self, title: str, message: str) -> None:
        self.progress.finish()
        self.open_button.setEnabled(True)
        self.cancel_button.setEnabled(True)
        self.error.show_message(f"{title}: {message}", "danger")
