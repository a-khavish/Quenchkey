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

"""Backups, watched folders, the duress passphrase and integrity checks."""

from __future__ import annotations

import os
import time
from typing import Optional

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QHBoxLayout, QHeaderView,
    QPlainTextEdit, QPushButton, QTableWidget, QTableWidgetItem, QWidget,
)

from .. import audit as audit_mod, backup as backup_mod
from .. import expiry as expiry_mod
from .. import handover as handover_mod, integrity as integrity_mod
from .. import watch as watch_mod
from ..session import Session
from . import destinations, filechooser, theme
from .dialogs import _Base
from .widgets import (
    Banner, Card, ConfirmDialog, Divider, PassphraseField,
    PassphraseStrengthPanel, label,
)


# --------------------------------------------------------------------------
# backups
# --------------------------------------------------------------------------

class BackupDialog(_Base):
    """Take a copy of the vault, and put one back."""

    def __init__(self, session: Session, parent: Optional[QWidget] = None):
        super().__init__("Vault backups", parent, 880, 760)
        self.session = session
        self.restored = False
        self.folder = ""

        self.body.addWidget(label(
            "Losing the vault file loses everything in it. Recovery shares do "
            "not cover this: they rebuild the master key, but the per-file "
            "keys live inside the vault, so with the file gone there is "
            "nothing for that key to open.", "Muted", wrap=True))

        self.body.addWidget(Banner(
            "A backup is a copy of a past state, and expiry only runs "
            "forwards. Restoring one brings back the keys it held — including "
            "keys this vault destroyed on purpose. That cannot be engineered "
            "away while also having backups, so restoring is made loud "
            "instead: it tells you exactly what it would undo, and the "
            "restored vault carries a permanent record that it was rolled "
            "back.", "warning"))

        make = Card()
        make.body.addWidget(label("TAKE A BACKUP", "Section"))
        make.body.addWidget(label(
            "A byte-for-byte copy. It is already encrypted under your "
            "passphrase, so it needs no second one — and keeping it beside "
            "the vault protects against nothing, so keep it somewhere else.",
            "Faint", wrap=True))
        row = QHBoxLayout()
        row.setSpacing(10)
        self.make_button = QPushButton("Back up now…")
        self.make_button.setObjectName("Primary")
        self.make_button.setMinimumHeight(theme.scaled(38))
        self.make_button.setCursor(Qt.PointingHandCursor)
        self.make_button.clicked.connect(self._create)
        row.addWidget(self.make_button)
        row.addStretch(1)
        make.body.addLayout(row)
        self.make_note = label("", "Faint", wrap=True)
        self.make_note.setMinimumWidth(1)
        make.body.addWidget(self.make_note)
        self.body.addWidget(make)

        listing = Card()
        listing.body.addWidget(label("BACKUPS FOUND", "Section"))
        row = QHBoxLayout()
        row.setSpacing(10)
        browse = QPushButton("Look in a folder…")
        browse.setCursor(Qt.PointingHandCursor)
        browse.clicked.connect(self._browse)
        row.addWidget(browse)
        row.addStretch(1)
        self.restore_button = QPushButton("Restore the selected one…")
        self.restore_button.setObjectName("Danger")
        self.restore_button.setCursor(Qt.PointingHandCursor)
        self.restore_button.clicked.connect(self._restore)
        row.addWidget(self.restore_button)
        listing.body.addLayout(row)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Taken", "Entries", "Keys destroyed",
                                              "File"])
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setShowGrid(False)
        self.table.setMinimumHeight(theme.scaled(150))
        header = self.table.horizontalHeader()
        for column in (0, 1, 2):
            header.setSectionResizeMode(column, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        self.table.itemSelectionChanged.connect(self._refresh_buttons)
        listing.body.addWidget(self.table)

        self.listing_note = label("", "Faint", wrap=True)
        self.listing_note.setMinimumWidth(1)
        listing.body.addWidget(self.listing_note)
        self.body.addWidget(listing)

        self.body.addStretch(1)
        self.add_close()

        self.backups: list = []
        self._load(os.path.dirname(os.path.abspath(session.vault.path)))

    # -- taking one -------------------------------------------------------

    def _create(self) -> None:
        name = backup_mod.default_name(self.session.vault.path)
        target = destinations.file_for(
            "backups", self, "Save the vault backup as", name,
            patterns=["Quenchkey vault backup (*.qkvbak)", "All files (*)"])
        if not target:
            return
        try:
            with self.session.guard:
                info = backup_mod.create(self.session.vault, target)
        except backup_mod.BackupError as exc:
            self.make_note.setText(str(exc))
            self.make_note.setStyleSheet(f"color: {theme.DANGER};")
            return
        self.make_note.setText(
            f"Wrote {info.name} — {info.entries} entr"
            f"{'ies' if info.entries != 1 else 'y'}, "
            f"{info.live_entries} still live. Keep it somewhere the vault is "
            f"not.")
        self.make_note.setStyleSheet(f"color: {theme.SUCCESS};")
        self._load(os.path.dirname(info.path))

    # -- listing and restoring --------------------------------------------

    def _browse(self) -> None:
        folder = filechooser.choose_directory(
            self, "Where are the backups?",
            self.folder or os.path.expanduser("~"))
        if folder:
            self._load(folder)

    def _load(self, folder: str) -> None:
        self.folder = folder
        self.backups = backup_mod.find(folder)
        self.table.setRowCount(len(self.backups))
        for row, info in enumerate(self.backups):
            cells = [expiry_mod.format_time(info.taken), str(info.entries),
                     str(info.destroyed_entries), info.name]
            for column, text in enumerate(cells):
                self.table.setItem(row, column, QTableWidgetItem(text))
        shown = folder.replace(os.path.expanduser("~"), "~")
        self.listing_note.setText(
            f"{len(self.backups)} backup"
            f"{'s' if len(self.backups) != 1 else ''} in {shown}."
            if self.backups else
            f"No backups in {shown}. They are read without a passphrase — the "
            f"file beside each one says what it holds.")
        self._refresh_buttons()

    def _selected(self):
        rows = {i.row() for i in self.table.selectedIndexes()}
        if not rows:
            return None
        row = min(rows)
        return self.backups[row] if row < len(self.backups) else None

    def _refresh_buttons(self) -> None:
        self.restore_button.setEnabled(self._selected() is not None)

    def _restore(self) -> None:
        info = self._selected()
        if info is None:
            return
        vault_path = self.session.vault.path
        cost = backup_mod.cost_of_restoring(info, vault_path, self.session.vault)

        confirmed = ConfirmDialog.ask(
            self, "Restore this backup?",
            f"{cost.summary()}\n\nThe vault as it stands is moved aside rather "
            f"than deleted, so this is undoable — but everything that happened "
            f"since {expiry_mod.format_time(info.taken)} goes with it.",
            confirm_text="Restore it",
            acknowledgement="I understand this can bring back keys that were "
                            "destroyed on purpose.",
            detail="The restored vault records permanently that it was rolled "
                   "back, and by how much. An audit of it later will show the "
                   "gap rather than hiding it.",
            require_typed="ROLL BACK" if cost.rolls_back else None)
        if not confirmed:
            return

        try:
            displaced = backup_mod.restore(info, vault_path)
        except backup_mod.BackupError as exc:
            self.listing_note.setText(str(exc))
            self.listing_note.setStyleSheet(f"color: {theme.DANGER};")
            return
        self.restored = True
        self.restore_info = info
        self.restore_cost = cost
        self.displaced = displaced
        self.accept()


# --------------------------------------------------------------------------
# watched folders
# --------------------------------------------------------------------------

class WatchFoldersDialog(_Base):
    """Folders where anything dropped in is locked on its own."""

    def __init__(self, session: Session, parent: Optional[QWidget] = None):
        super().__init__("Watched folders", parent, 900, 780)
        self.session = session
        self.changed = False

        self.body.addWidget(label(
            "Drop a file into a watched folder and it is locked where it "
            "lies, with the rule you set here, and the original shredded. No "
            "dialog at the moment of dropping.", "Muted", wrap=True))

        self.body.addWidget(Banner(
            "It only runs while the vault is unlocked. Locking needs the "
            "vault, so a file dropped in while Quenchkey is closed sits there "
            "in the clear until you next open it. A watched folder is a "
            "convenience, not a guard on the folder.", "warning"))
        self.body.addWidget(Banner(
            "A file is locked once it has stopped changing — about six "
            "seconds of the same size and timestamp. Otherwise a download in "
            "progress would be encrypted half-written.", "info"))

        listing = Card()
        row = QHBoxLayout()
        row.setSpacing(10)
        add = QPushButton("Watch a folder…")
        add.setObjectName("Primary")
        add.setMinimumHeight(theme.scaled(38))
        add.setCursor(Qt.PointingHandCursor)
        add.clicked.connect(self._add)
        row.addWidget(add)
        row.addStretch(1)
        self.remove_button = QPushButton("Stop watching")
        self.remove_button.setCursor(Qt.PointingHandCursor)
        self.remove_button.clicked.connect(self._remove)
        row.addWidget(self.remove_button)
        listing.body.addLayout(row)

        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Folder", "What happens", "Waiting"])
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setShowGrid(False)
        self.table.setMinimumHeight(theme.scaled(150))
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table.itemSelectionChanged.connect(self._refresh_buttons)
        listing.body.addWidget(self.table)
        self.empty_note = label("", "Faint", wrap=True)
        self.empty_note.setMinimumWidth(1)
        listing.body.addWidget(self.empty_note)
        self.body.addWidget(listing)

        rule = Card()
        rule.body.addWidget(label("THE RULE FOR A NEW FOLDER", "Section"))
        grid = QHBoxLayout()
        grid.setSpacing(10)
        grid.addWidget(label("Key dies after", "Faint"))
        self.expiry_combo = QComboBox()
        self.expiry_combo.setMinimumWidth(theme.scaled(190))
        for text, seconds in expiry_mod.EXPIRY_PRESETS:
            self.expiry_combo.addItem(text, seconds)
        grid.addWidget(self.expiry_combo)
        grid.addStretch(1)
        rule.body.addLayout(grid)

        self.shred_check = QCheckBox("Shred the original once it is locked")
        self.shred_check.setChecked(True)
        rule.body.addWidget(self.shred_check)
        self.delete_check = QCheckBox(
            "Also delete the locked file when its key is destroyed")
        rule.body.addWidget(self.delete_check)
        self.body.addWidget(rule)

        self.body.addStretch(1)
        self.add_close()
        self._refresh()

    def _add(self) -> None:
        folder = filechooser.choose_directory(
            self, "Which folder should be watched?", os.path.expanduser("~"))
        if not folder:
            return
        vault_dir = os.path.dirname(os.path.abspath(self.session.vault.path))
        if os.path.abspath(folder) == vault_dir:
            self.empty_note.setText(
                "Not the folder the vault is in — that would try to lock the "
                "vault with itself.")
            self.empty_note.setStyleSheet(f"color: {theme.DANGER};")
            return
        rule = watch_mod.WatchRule(
            path=os.path.abspath(folder),
            expires_seconds=self.expiry_combo.currentData(),
            delete_originals=self.shred_check.isChecked(),
            delete_blob_on_expiry=self.delete_check.isChecked())
        with self.session.guard:
            self.session.vault.add_watch_rule(rule)
        self.changed = True
        self._refresh()

    def _selected_rule(self):
        rows = {i.row() for i in self.table.selectedIndexes()}
        rules = self.session.vault.watch_rules()
        if not rows:
            return None
        row = min(rows)
        return rules[row] if row < len(rules) else None

    def _remove(self) -> None:
        rule = self._selected_rule()
        if rule is None:
            return
        with self.session.guard:
            self.session.vault.remove_watch_rule(rule.path)
        self.changed = True
        self._refresh()

    def _refresh(self) -> None:
        rules = self.session.vault.watch_rules()
        self.table.setRowCount(len(rules))
        for row, rule in enumerate(rules):
            waiting = len(watch_mod.candidates(rule))
            cells = [rule.path.replace(os.path.expanduser("~"), "~"),
                     rule.describe(), str(waiting)]
            for column, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if column == 0 and not os.path.isdir(rule.path):
                    item.setText(text + "  (gone)")
                    item.setForeground(QColor(theme.DANGER))
                self.table.setItem(row, column, item)
        if not rules:
            self.empty_note.setText(
                "No folders watched. Set a rule below, then choose a folder.")
            self.empty_note.setStyleSheet("")
        else:
            self.empty_note.setText("")
        self._refresh_buttons()

    def _refresh_buttons(self) -> None:
        self.remove_button.setEnabled(self._selected_rule() is not None)


# --------------------------------------------------------------------------
# the duress passphrase
# --------------------------------------------------------------------------

class DuressDialog(_Base):
    """A second passphrase that destroys the vault instead of opening it."""

    ACKNOWLEDGEMENT = "DESTROY THE VAULT"

    def __init__(self, session: Session, parent: Optional[QWidget] = None):
        super().__init__("Duress passphrase", parent, 820, 760)
        self.session = session
        self.changed = False

        armed = session.vault.duress_armed
        self.body.addWidget(label(
            "A second passphrase. Typing it at the unlock screen destroys "
            "this vault instead of opening it — the file is overwritten and "
            "removed, and Quenchkey comes back as though no vault had ever "
            "been made.", "Muted", wrap=True))

        self.body.addWidget(Banner(
            "This destroys your data, permanently. It is not a decoy that "
            "hides things or a second vault with different contents. Every "
            "key in this vault goes, and every .qkey file you locked with it "
            "becomes unreadable — to you as much as to anybody else.",
            "danger"))
        self.body.addWidget(Banner(
            "It reaches one file on one machine. A backup you took, a copy on "
            "another disk, a filesystem snapshot — none of those are touched, "
            "and somebody who took a copy of the vault before you typed it "
            "still has everything.", "warning"))
        self.body.addWidget(Banner(
            "It has to be nothing like your real passphrase. Mistyping the "
            "real one is simply wrong and costs nothing; the duress one has "
            "to match exactly. Choosing something close to your real "
            "passphrase is how people destroy their own vault by accident.",
            "info"))

        self.status = label("", "Muted", wrap=True)
        self.status.setMinimumWidth(1)
        self.body.addWidget(self.status)

        card = Card()
        card.body.addWidget(label("SET A DURESS PASSPHRASE", "Section"))
        self.field = PassphraseField("Duress passphrase", with_generator=True)
        self.field.changed.connect(self._refresh)
        self.field.generated.connect(self._on_generated)
        card.body.addWidget(self.field)
        self.strength = PassphraseStrengthPanel()
        card.body.addWidget(self.strength)
        self.confirm = PassphraseField("Type it again")
        self.confirm.changed.connect(self._refresh)
        card.body.addWidget(self.confirm)
        self.match_note = label("", "Faint", wrap=True)
        self.match_note.setMinimumWidth(1)
        card.body.addWidget(self.match_note)

        card.body.addWidget(Divider())
        row = QHBoxLayout()
        row.setSpacing(10)
        row.addStretch(1)
        self.clear_button = QPushButton("Remove the duress passphrase")
        self.clear_button.setCursor(Qt.PointingHandCursor)
        self.clear_button.setEnabled(armed)
        self.clear_button.clicked.connect(self._clear)
        row.addWidget(self.clear_button)
        self.arm_button = QPushButton("Arm it")
        self.arm_button.setObjectName("Danger")
        self.arm_button.setMinimumHeight(theme.scaled(40))
        self.arm_button.setCursor(Qt.PointingHandCursor)
        self.arm_button.clicked.connect(self._arm)
        row.addWidget(self.arm_button)
        card.body.addLayout(row)
        self.body.addWidget(card)

        self.body.addStretch(1)
        self.add_close()
        self._refresh()

    def _on_generated(self, value: str, _bits: float) -> None:
        self.confirm.set_text(value)
        self.confirm.reveal.setChecked(True)

    def _refresh(self, *_args) -> None:
        armed = self.session.vault.duress_armed
        self.status.setText(
            "A duress passphrase is armed on this vault."
            if armed else "No duress passphrase is set.")
        self.status.setStyleSheet(
            f"color: {theme.WARNING};" if armed else "")
        self.clear_button.setEnabled(armed)

        text = self.field.text()
        strength = self.strength.update_for(text, self.field.exact_bits())
        confirm = self.confirm.text()
        if confirm and confirm != text:
            self.match_note.setText("The two entries do not match yet.")
            self.match_note.setStyleSheet(f"color: {theme.WARNING};")
        elif confirm:
            self.match_note.setText("Both entries match.")
            self.match_note.setStyleSheet(f"color: {theme.SUCCESS};")
        else:
            self.match_note.setText("")
        self.arm_button.setEnabled(
            bool(text) and confirm == text and strength.meets_minimum)

    def _arm(self) -> None:
        confirmed = ConfirmDialog.ask(
            self, "Arm this passphrase to destroy the vault?",
            "From now on, typing this at the unlock screen overwrites and "
            "deletes the vault without asking anything further. There is no "
            "confirmation at that moment — that is the point of it.",
            confirm_text="Arm it",
            acknowledgement="I understand this destroys my own data, that it "
                            "cannot be undone, and that copies of the vault "
                            "elsewhere are not touched.",
            detail="If you keep backups, a duress passphrase destroys this "
                   "copy and leaves those. Whether that is what you want is "
                   "worth deciding now rather than then.",
            require_typed=self.ACKNOWLEDGEMENT)
        if not confirmed:
            return
        with self.session.guard:
            self.session.vault.set_duress_passphrase(self.field.text())
        self.changed = True
        self.field.clear()
        self.confirm.clear()
        self._refresh()

    def _clear(self) -> None:
        if not ConfirmDialog.ask(
                self, "Remove the duress passphrase?",
                "The vault goes back to having one passphrase, and the one "
                "you set stops doing anything.",
                confirm_text="Remove it", tone="info"):
            return
        with self.session.guard:
            self.session.vault.clear_duress_passphrase()
        self.changed = True
        self._refresh()


# --------------------------------------------------------------------------
# integrity
# --------------------------------------------------------------------------

class IntegrityDialog(_Base):
    """Check every locked file is still the one that was locked."""

    STATE_TONE = {
        integrity_mod.INTACT: theme.TEXT_MUTED,
        integrity_mod.CHANGED: theme.DANGER,
        integrity_mod.MISSING: theme.WARNING,
        integrity_mod.UNKNOWN: theme.TEXT_MUTED,
    }

    def __init__(self, session: Session, parent: Optional[QWidget] = None):
        super().__init__("Check the locked files", parent, 920, 800)
        self.session = session
        self.report = None
        self.found = None

        self.body.addWidget(label(
            "Every entry recorded the SHA-256 of its locked file at the moment "
            "it was written. This reads each of those files back and compares. "
            "It is how a vault notices a failing drive, a copy that never "
            "finished, or a file that has been swapped.", "Muted", wrap=True))

        self.body.addWidget(Banner(
            "This is detection, not prevention. An altered file was already "
            "going to be refused: the encryption authenticates what it "
            "decrypts, so a modified file fails rather than returning wrong "
            "content. What this buys you is finding out now instead of on the "
            "day you need it.", "info"))

        run = Card()
        row = QHBoxLayout()
        row.setSpacing(10)
        self.check_button = QPushButton("Check every file")
        self.check_button.setObjectName("Primary")
        self.check_button.setMinimumHeight(theme.scaled(38))
        self.check_button.setCursor(Qt.PointingHandCursor)
        self.check_button.clicked.connect(self._check)
        row.addWidget(self.check_button)
        row.addStretch(1)
        self.search_button = QPushButton("Look for missing ones…")
        self.search_button.setCursor(Qt.PointingHandCursor)
        self.search_button.setEnabled(False)
        self.search_button.clicked.connect(self._search)
        row.addWidget(self.search_button)
        run.body.addLayout(row)
        self.status = label("", "Faint", wrap=True)
        self.status.setMinimumWidth(1)
        run.body.addWidget(self.status)
        self.body.addWidget(run)

        results = Card()
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Item", "State", "What that means"])
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setShowGrid(False)
        self.table.setMinimumHeight(theme.scaled(170))
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        results.body.addWidget(self.table)
        self.advice = label("", "Faint", wrap=True)
        self.advice.setMinimumWidth(1)
        results.body.addWidget(self.advice)
        self.body.addWidget(results)

        self.body.addStretch(1)
        self.add_close()
        self._show_last()

    # -- checking ---------------------------------------------------------

    def _show_last(self) -> None:
        last = integrity_mod.last_check(self.session.vault)
        if not last:
            self.status.setText("This vault has not been checked yet.")
            return
        self.status.setText(
            f"Last checked {expiry_mod.format_time(last.get('at', 0))} — "
            f"{last.get('intact', 0)} of {last.get('checked', 0)} intact.")

    def _check(self) -> None:
        self.check_button.setEnabled(False)
        self.status.setText("Reading every locked file…")
        self.status.setStyleSheet("")
        try:
            with self.session.guard:
                self.report = integrity_mod.check(self.session.vault)
        finally:
            self.check_button.setEnabled(True)

        self.status.setText(self.report.summary())
        self.status.setStyleSheet(
            "" if self.report.ok else f"color: {theme.WARNING};")
        self.advice.setText(self.report.advice())
        self.search_button.setEnabled(bool(self.report.missing))
        self._fill(self.report.findings)

    def _fill(self, findings) -> None:
        self.table.setRowCount(len(findings))
        for row, finding in enumerate(findings):
            cells = [finding.name, finding.state, finding.explain()]
            for column, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if column == 1:
                    item.setForeground(QColor(self.STATE_TONE.get(
                        finding.state, theme.TEXT_MUTED)))
                self.table.setItem(row, column, item)

    # -- finding what moved -----------------------------------------------

    def _search(self) -> None:
        folder = filechooser.choose_directory(
            self, "Where should the missing files be looked for?",
            os.path.expanduser("~"))
        if not folder:
            return
        self.status.setText(f"Looking through {folder}…")
        with self.session.guard:
            self.found = integrity_mod.search(self.session.vault, folder)
        self.status.setText(self.found.summary())

        if not self.found.matches:
            self.status.setStyleSheet(f"color: {theme.WARNING};")
            return

        listing = "\n".join(f"  {m.describe()}" for m in self.found.matches[:8])
        more = ("" if len(self.found.matches) <= 8
                else f"\n  and {len(self.found.matches) - 8} more")
        confirmed = ConfirmDialog.ask(
            self, "Point the vault at these files?",
            f"{len(self.found.matches)} of the missing files were found, "
            f"matched on the digest recorded when they were locked — not on "
            f"the filename, which may well have changed too.\n\n"
            f"{listing}{more}",
            confirm_text="Point at them",
            detail="Only the path changes. The key, the deadline, the opening "
                   "count and the entry's place in the event log stay exactly "
                   "as they are.")
        if not confirmed:
            return
        with self.session.guard:
            moved = integrity_mod.relink(self.session.vault, self.found.matches)
            self.report = integrity_mod.check(self.session.vault)
        self.status.setText(
            f"{moved} entr{'ies' if moved != 1 else 'y'} now point where the "
            f"files are. {self.report.summary()}")
        self.status.setStyleSheet("")
        self.advice.setText(self.report.advice())
        self.search_button.setEnabled(bool(self.report.missing))
        self._fill(self.report.findings)


# --------------------------------------------------------------------------
# handing a file over to another vault
# --------------------------------------------------------------------------

class HandoverDialog(_Base):
    """Send a locked file to somebody else's vault, deadline and all."""

    def __init__(self, session: Session, parent: Optional[QWidget] = None,
                 initial_paths=None):
        super().__init__("Hand over to another vault", parent, 960, 860)
        self.session = session
        self.paths: list = list(initial_paths or [])
        self.card = None
        self.written = ""
        self.accepted = None

        self.body.addWidget(label(
            "A shared file carries its own key, which is why it can never "
            "expire. A handover is the way round that, and it needs the other "
            "person to be running Quenchkey too: the key is wrapped to their "
            "vault instead of to a passphrase, so when they accept it the "
            "deadline lands inside their vault and their own sweep enforces "
            "it. Nothing has to reach across a network on the day.",
            "Muted", wrap=True))

        self.body.addWidget(Banner(
            "Three things this does not buy. They can decline — a file they "
            "never accept is one they cannot read, which is their choice. "
            "Once they accept and open it, the copy that comes out is an "
            "ordinary file and nothing here reaches it. And it is their "
            "machine: they can restore a backup of their own vault after the "
            "deadline, exactly as you can with yours.", "warning"))

        # -- who it is for
        who = Card()
        who.body.addWidget(label("WHO IT IS FOR", "Section"))
        who.body.addWidget(label(
            "Ask them for their identity card — Vault ▸ Hand over ▸ My "
            "identity card. It holds no secret, so it is safe to send by any "
            "means at all.", "Faint", wrap=True))
        row = QHBoxLayout()
        row.setSpacing(10)
        pick = QPushButton("Open their identity card…")
        pick.setMinimumHeight(theme.scaled(38))
        pick.setCursor(Qt.PointingHandCursor)
        pick.clicked.connect(self._choose_card)
        row.addWidget(pick)
        row.addStretch(1)
        who.body.addLayout(row)
        self.card_note = label("No card chosen yet.", "Faint", wrap=True)
        self.card_note.setMinimumWidth(1)
        who.body.addWidget(self.card_note)
        self.body.addWidget(who)

        # -- what is being sent
        what = Card()
        what.body.addWidget(label("WHAT IS BEING SENT", "Section"))
        files_row = QHBoxLayout()
        files_row.setSpacing(10)
        add = QPushButton("Add files…")
        add.setCursor(Qt.PointingHandCursor)
        add.clicked.connect(self._add_files)
        files_row.addWidget(add)
        files_row.addStretch(1)
        what.body.addLayout(files_row)
        self.files_note = label("", "Faint", wrap=True)
        self.files_note.setMinimumWidth(1)
        what.body.addWidget(self.files_note)
        self.body.addWidget(what)

        # -- the terms
        terms = Card()
        terms.body.addWidget(label("THE TERMS YOU ARE PROPOSING", "Section"))
        terms.body.addWidget(label(
            "These travel inside the file, authenticated, so they can read "
            "them before accepting and neither of you can change them "
            "afterwards without the file failing to open.", "Faint", wrap=True))

        deadline_row = QHBoxLayout()
        deadline_row.setSpacing(10)
        deadline_row.addWidget(label("Key destroyed after", "Faint"))
        self.expiry_combo = QComboBox()
        self.expiry_combo.setMinimumWidth(theme.scaled(190))
        for text, seconds in expiry_mod.EXPIRY_PRESETS:
            self.expiry_combo.addItem(text, seconds)
        deadline_row.addWidget(self.expiry_combo)
        deadline_row.addStretch(1)
        terms.body.addLayout(deadline_row)

        opens_row = QHBoxLayout()
        opens_row.setSpacing(10)
        opens_row.addWidget(label("Openings", "Faint"))
        self.opens_combo = QComboBox()
        self.opens_combo.setMinimumWidth(theme.scaled(190))
        for text, value in expiry_mod.OPEN_LIMIT_PRESETS:
            self.opens_combo.addItem(text, value)
        opens_row.addWidget(self.opens_combo)
        opens_row.addStretch(1)
        terms.body.addLayout(opens_row)
        self.body.addWidget(terms)

        self.note = label("", "Faint", wrap=True)
        self.note.setMinimumWidth(1)
        self.body.addWidget(self.note)

        send_row = QHBoxLayout()
        send_row.setSpacing(10)
        self.send_button = QPushButton("Write the addressed file…")
        self.send_button.setObjectName("Primary")
        self.send_button.setMinimumHeight(theme.scaled(40))
        self.send_button.setCursor(Qt.PointingHandCursor)
        self.send_button.setEnabled(False)
        self.send_button.clicked.connect(self._send)
        send_row.addWidget(self.send_button)
        send_row.addStretch(1)
        self.body.addLayout(send_row)

        self.body.addStretch(1)
        self.add_close()
        self._refresh()

    # -- choosing ---------------------------------------------------------

    def _choose_card(self) -> None:
        path = filechooser.open_file(
            self, "Open their identity card", os.path.expanduser("~"),
            patterns=["Quenchkey identity card (*.qkid)", "All files (*)"])
        if not path:
            return
        try:
            self.card = handover_mod.read_card(path)
        except handover_mod.HandoverError as exc:
            self.card = None
            self.card_note.setText(str(exc))
            self.card_note.setStyleSheet(f"color: {theme.DANGER};")
            self._refresh()
            return
        who = self.card.label or "unnamed"
        self.card_note.setText(
            f"{who} — vault {self.card.vault_id[:16]}, fingerprint "
            f"{self.card.fingerprint}. Read that fingerprint back to them if "
            f"it matters who this really is; the card verified its own key, "
            f"which proves it was not edited, not who wrote it.")
        self.card_note.setStyleSheet("")
        self._refresh()

    def _add_files(self) -> None:
        chosen = filechooser.open_files(
            self, "Which files are being handed over?", os.path.expanduser("~"))
        if chosen:
            self.paths.extend(p for p in chosen if p not in self.paths)
        self._refresh()

    def _refresh(self) -> None:
        if self.paths:
            names = ", ".join(os.path.basename(p) for p in self.paths[:4])
            more = ("" if len(self.paths) <= 4
                    else f" and {len(self.paths) - 4} more")
            self.files_note.setText(f"{len(self.paths)} selected: {names}{more}")
        else:
            self.files_note.setText("Nothing selected yet.")
        self.send_button.setEnabled(bool(self.paths and self.card))

    # -- sending ----------------------------------------------------------

    def _send(self) -> None:
        seconds = self.expiry_combo.currentData()
        expires = None if seconds is None else time.time() + seconds
        suggested = (os.path.splitext(os.path.basename(self.paths[0]))[0]
                     if len(self.paths) == 1 else f"{len(self.paths)} items")
        target = destinations.file_for(
            "shared", self, "Write the addressed file as",
            f"{suggested} for {self.card.vault_id[:8]}.qkey",
            patterns=["Quenchkey locked file (*.qkey)", "All files (*)"])
        if not target:
            return

        self.send_button.setEnabled(False)
        try:
            with self.session.guard:
                self.written = handover_mod.lock_for(
                    self.paths, self.card,
                    expires=expires,
                    max_opens=self.opens_combo.currentData(),
                    output_path=target,
                    sender=self.session.vault)
        except (handover_mod.HandoverError, OSError) as exc:
            self.note.setText(str(exc))
            self.note.setStyleSheet(f"color: {theme.DANGER};")
            self.send_button.setEnabled(True)
            return

        self.note.setText(
            f"Wrote {os.path.basename(self.written)}. It opens in one vault "
            f"and nowhere else, so send it by whatever route suits you. Until "
            f"they accept it, nobody can read it — including you.")
        self.note.setStyleSheet("")
        self.send_button.setEnabled(True)


class IdentityCardDialog(_Base):
    """This vault's identity card: what to give somebody who wants to send."""

    def __init__(self, session: Session, parent: Optional[QWidget] = None):
        super().__init__("My identity card", parent, 880, 720)
        self.session = session
        self.card = handover_mod.my_card(
            session.vault, label=session.vault.custodian.name or "")

        self.body.addWidget(label(
            "Give this to anybody who wants to hand a file over to you. They "
            "address the file to this vault, and only this vault can take the "
            "key in.", "Muted", wrap=True))

        self.body.addWidget(Banner(
            "It holds no secret. There is no private key in it and no way to "
            "work one out from it, so it is safe to email, paste into a chat "
            "or publish. The worst somebody can do with your card is send you "
            "a file only you can open.", "info"))

        details = Card()
        details.body.addWidget(label("THIS VAULT", "Section"))
        for heading, value in (
                ("Vault", self.card.vault_id),
                ("Fingerprint", self.card.fingerprint),
                ("Named", self.card.label or "(no custodian set)")):
            row = QHBoxLayout()
            row.setSpacing(10)
            row.addWidget(label(heading, "Faint"))
            shown = label(value, "Mono")
            shown.setTextInteractionFlags(Qt.TextSelectableByMouse)
            row.addWidget(shown, 1)
            details.body.addLayout(row)
        details.body.addWidget(Divider())
        details.body.addWidget(label(
            "The fingerprint is there so somebody can read it back to you "
            "over the telephone. The signature on the card proves it was not "
            "edited on the way; only that check proves who wrote it.",
            "Faint", wrap=True))
        self.body.addWidget(details)

        row = QHBoxLayout()
        row.setSpacing(10)
        save = QPushButton("Save my card…")
        save.setObjectName("Primary")
        save.setMinimumHeight(theme.scaled(40))
        save.setCursor(Qt.PointingHandCursor)
        save.clicked.connect(self._save)
        row.addWidget(save)
        row.addStretch(1)
        self.body.addLayout(row)
        self.note = label("", "Faint", wrap=True)
        self.note.setMinimumWidth(1)
        self.body.addWidget(self.note)

        self.body.addStretch(1)
        self.add_close()

    def _save(self) -> None:
        target = destinations.file_for(
            "shared", self, "Save the identity card as",
            f"quenchkey-{self.card.vault_id[:8]}.qkid",
            patterns=["Quenchkey identity card (*.qkid)", "All files (*)"])
        if not target:
            return
        try:
            written = handover_mod.write_card(self.card, target)
        except OSError as exc:
            self.note.setText(str(exc))
            self.note.setStyleSheet(f"color: {theme.DANGER};")
            return
        self.note.setText(f"Wrote {os.path.basename(written)}. Send it to "
                          f"anybody who wants to hand a file over to you.")
        self.note.setStyleSheet("")


# --------------------------------------------------------------------------
# the auditor's record
# --------------------------------------------------------------------------

class AuditDialog(_Base):
    """Publish a record an auditor can check without being able to read anything."""

    def __init__(self, session: Session, parent: Optional[QWidget] = None):
        super().__init__("Record for an auditor", parent, 920, 820)
        self.session = session
        self.changed = False

        self.body.addWidget(label(
            "A retention policy is often somebody else\u2019s business \u2014 a data "
            "protection officer confirming last year\u2019s files really did "
            "expire, or a client wanting evidence theirs were destroyed. This "
            "writes a record beside the vault, under a passphrase of its own, "
            "holding what they need: every entry\u2019s name, size, rules and "
            "opening count, when and why each key was destroyed, the whole "
            "event log, and the certificates.", "Muted", wrap=True))

        self.body.addWidget(Banner(
            "There is no file key in it. Not wrapped, not derived, not in any "
            "form that could become one \u2014 the record is built from the "
            "vault rather than being a slice of it, so there is nothing in "
            "the file for a holder to attack however long they keep it. There "
            "is a test that looks for one.", "info"))

        self.body.addWidget(Banner(
            "Choose a passphrase that is not the vault\u2019s. Nothing here can "
            "stop you: the vault does not keep its own passphrase, so it has "
            "nothing to compare against. Using it would hand an auditor every "
            "document, which is the one thing this exists to avoid.",
            "warning"))

        state = Card()
        state.body.addWidget(label("STATE", "Section"))
        self.state_note = label("", "Muted", wrap=True)
        self.state_note.setMinimumWidth(1)
        state.body.addWidget(self.state_note)
        self.body.addWidget(state)

        arm = Card()
        arm.body.addWidget(label("THE AUDITOR\u2019S PASSPHRASE", "Section"))
        self.first = PassphraseField("A passphrase for the record")
        arm.body.addWidget(self.first)
        self.strength = PassphraseStrengthPanel()
        arm.body.addWidget(self.strength)
        self.second = PassphraseField("Type it again")
        arm.body.addWidget(self.second)
        self.match_note = label("", "Faint", wrap=True)
        self.match_note.setMinimumWidth(1)
        arm.body.addWidget(self.match_note)
        self.first.changed.connect(self._on_typed)
        self.second.changed.connect(self._on_typed)

        row = QHBoxLayout()
        row.setSpacing(10)
        self.arm_button = QPushButton("Write the record")
        self.arm_button.setObjectName("Primary")
        self.arm_button.setMinimumHeight(theme.scaled(38))
        self.arm_button.setCursor(Qt.PointingHandCursor)
        self.arm_button.setEnabled(False)
        self.arm_button.clicked.connect(self._arm)
        row.addWidget(self.arm_button)
        row.addStretch(1)
        self.disarm_button = QPushButton("Stop publishing it")
        self.disarm_button.setObjectName("Danger")
        self.disarm_button.setCursor(Qt.PointingHandCursor)
        self.disarm_button.clicked.connect(self._disarm)
        row.addWidget(self.disarm_button)
        arm.body.addLayout(row)
        self.note = label("", "Faint", wrap=True)
        self.note.setMinimumWidth(1)
        arm.body.addWidget(self.note)
        self.body.addWidget(arm)

        how = Card()
        how.body.addWidget(label("WHAT TO TELL THEM", "Section"))
        how.body.addWidget(label(
            "Give them the record and its passphrase. They read it with the "
            "standalone tool, which imports nothing from this application:",
            "Faint", wrap=True))
        command = QPlainTextEdit(
            "quenchkey-recover audit-record vault.qkv.audit \\\n"
            "    --public-key <from any certificate this vault issued>")
        command.setReadOnly(True)
        command.setFont(theme.mono_font(9))
        command.setMaximumHeight(theme.scaled(62))
        how.body.addWidget(command)
        how.body.addWidget(label(
            "It is a snapshot, rewritten when you write it. An auditor "
            "reading a record from a vault last opened in March is reading "
            "March, and the record says so \u2014 comparing its anchor against "
            "one you published independently is how they tell.",
            "Faint", wrap=True))
        self.body.addWidget(how)

        self.body.addStretch(1)
        self.add_close()
        self._refresh()

    def _refresh(self) -> None:
        armed = audit_mod.is_armed(self.session.vault)
        self.disarm_button.setEnabled(armed)
        if not armed:
            self.state_note.setText("No record is being published.")
            return
        when = audit_mod.written_at(self.session.vault.path)
        where = os.path.basename(audit_mod.record_path(self.session.vault.path))
        if when:
            self.state_note.setText(
                f"Publishing to {where}, last written "
                f"{expiry_mod.format_time(when)}. Write it again to bring it "
                f"up to date; the passphrase is needed each time, because the "
                f"vault does not keep it.")
        else:
            self.state_note.setText(
                f"Armed, but {where} is not there. Write it again.")

    def _on_typed(self, _text: str = "") -> None:
        first = self.first.text()
        self.strength.evaluate(first)
        if not first:
            self.match_note.setText("")
            self.arm_button.setEnabled(False)
            return
        if first != self.second.text():
            self.match_note.setText("The two entries do not match yet.")
            self.arm_button.setEnabled(False)
            return
        self.match_note.setText("Both entries match.")
        self.arm_button.setEnabled(True)

    def _arm(self) -> None:
        passphrase = self.first.text()
        self.arm_button.setEnabled(False)
        self.note.setText("Deriving a key with Argon2id\u2026")
        self.note.setStyleSheet("")
        try:
            with self.session.guard:
                if audit_mod.is_armed(self.session.vault):
                    written = audit_mod.write(self.session.vault, passphrase)
                else:
                    written = audit_mod.arm(self.session.vault, passphrase)
        except audit_mod.AuditError as exc:
            self.note.setText(str(exc))
            self.note.setStyleSheet(f"color: {theme.DANGER};")
            self.arm_button.setEnabled(True)
            return
        self.changed = True
        self.first.clear()
        self.second.clear()
        self.note.setText(
            f"Wrote {os.path.basename(written)}. Give an auditor that file "
            f"and that passphrase, and nothing else.")
        self.note.setStyleSheet("")
        self._refresh()

    def _disarm(self) -> None:
        confirmed = ConfirmDialog.ask(
            self, "Stop publishing the record?",
            "The record beside the vault is deleted. Nothing in the vault "
            "changes, and any copy an auditor already has goes on working "
            "with the passphrase you gave them \u2014 there is no way to recall "
            "a file somebody else holds.",
            confirm_text="Stop publishing")
        if not confirmed:
            return
        with self.session.guard:
            audit_mod.disarm(self.session.vault)
        self.changed = True
        self.note.setText("Stopped. The record beside the vault is gone.")
        self.note.setStyleSheet("")
        self._refresh()
