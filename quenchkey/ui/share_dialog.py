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

"""Locking files to send someone, and opening one that was sent to you.

Everything else in this application keeps the key away from the file. This
screen does the opposite on purpose, and the interface's job here is to make
sure nobody leaves it thinking otherwise: a shared file has no deadline, it
cannot be recalled, and the passphrase you choose is the only thing standing
between whoever receives it and the contents — forever.
"""

from __future__ import annotations

import os
from typing import Optional

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import (
    QAbstractItemView, QCheckBox, QDialog, QHBoxLayout, QHeaderView,
    QPushButton, QRadioButton, QScrollArea, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget,
)

from .. import locker
from ..crypto import UnsupportedFormat
from ..session import Session
from . import destinations, filechooser, theme
from .widgets import (
    Banner, Card, ConfirmDialog, Divider, PassphraseField,
    PassphraseStrengthPanel, ProgressPanel, label,
)
from .workers import Task

#: Typed out in full before a shared file is written. Not decoration: it is
#: the one property of this file that cannot be undone later.
ACKNOWLEDGEMENT = "NO DEADLINE"


class ShareDialog(QDialog):
    """Pack files into one self-contained, passphrase-protected file."""

    def __init__(self, session: Optional[Session], parent: Optional[QWidget] = None,
                 initial_paths: Optional[list] = None):
        super().__init__(parent)
        self.setObjectName("Root")
        self.setWindowTitle("Lock files to share")
        self.setModal(True)
        theme.fit(self, 900, 860, 760, 520)

        self.session = session
        self.paths: list = []
        self.output_path: Optional[str] = None
        self.result: Optional[locker.ShareResult] = None
        self._task: Optional[Task] = None

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
        body = QVBoxLayout(canvas)
        body.setContentsMargins(theme.GUTTER, theme.GUTTER, theme.GUTTER, 8)
        body.setSpacing(theme.GAP)

        body.addWidget(label("Lock files to share", "Title", wrap=True))
        body.addWidget(label(
            "One file, encrypted with a passphrase of its own, that anyone can "
            "open on any machine with no vault and nothing installed. It is "
            "saved beside the originals, ready to send.", "Muted", wrap=True))

        body.addWidget(Banner(
            "A shared file has no deadline, and cannot be given one. "
            "Everything else here works by keeping the key in your vault, so "
            "destroying that one key makes every copy of the locked file "
            "unreadable at once. This file carries its own key instead — that "
            "is what lets someone else open it — so there is nothing left "
            "anywhere to destroy. Once you send it, whoever has it and the "
            "passphrase can open it for good.", "warning"))

        body.addWidget(self._build_files())
        body.addWidget(Divider())
        body.addWidget(self._build_passphrase())
        body.addWidget(Divider())
        body.addWidget(self._build_output())

        self.progress = ProgressPanel()
        self.progress.setVisible(False)
        body.addWidget(self.progress)

        self.error = Banner("", "danger")
        self.error.setVisible(False)
        body.addWidget(self.error)
        body.addStretch(1)

        footer = QWidget()
        footer.setObjectName("Root")
        row = QHBoxLayout(footer)
        row.setContentsMargins(theme.GUTTER, 10, theme.GUTTER, theme.GUTTER)
        row.addStretch(1)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setCursor(Qt.PointingHandCursor)
        self.cancel_button.clicked.connect(self.reject)
        row.addWidget(self.cancel_button)
        self.share_button = QPushButton("Lock for sharing")
        self.share_button.setObjectName("Primary")
        self.share_button.setMinimumHeight(42)
        self.share_button.setCursor(Qt.PointingHandCursor)
        self.share_button.clicked.connect(self._start)
        row.addWidget(self.share_button)
        shell.addWidget(footer)

        if initial_paths:
            self.add_paths(initial_paths)
        self._refresh()

    # -- construction -----------------------------------------------------

    def _build_files(self) -> QWidget:
        card = Card()
        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        for text, slot in (("Add files…", self._pick_files),
                           ("Add folder…", self._pick_folder)):
            button = QPushButton(text)
            button.setCursor(Qt.PointingHandCursor)
            button.clicked.connect(slot)
            buttons.addWidget(button)
        buttons.addStretch(1)
        self.remove_button = QPushButton("Remove")
        self.remove_button.setCursor(Qt.PointingHandCursor)
        self.remove_button.clicked.connect(self._remove_selected)
        buttons.addWidget(self.remove_button)
        card.body.addLayout(buttons)

        self.table = QTableWidget(0, 2)
        self.table.setHorizontalHeaderLabels(["File", "Size"])
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setMinimumHeight(theme.scaled(150))
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        card.body.addWidget(self.table)

        self.empty_note = label(
            "Nothing chosen yet. Use the buttons above.", "Faint", wrap=True)
        card.body.addWidget(self.empty_note)
        return card

    def _build_passphrase(self) -> QWidget:
        card = Card()
        card.body.addWidget(label("PASSPHRASE FOR THIS FILE", "Section"))
        card.body.addWidget(label(
            "Not your vault passphrase, and it should not be: you are about to "
            "give this one to somebody else. Generate one, send it by a "
            "different route from the file itself, and keep a copy — there is "
            "no way to recover it and no way to change it once the file is "
            "written.", "Faint", wrap=True))

        self.passphrase_field = PassphraseField("Passphrase for this file",
                                                with_generator=True)
        self.passphrase_field.changed.connect(self._refresh)
        self.passphrase_field.generated.connect(self._on_generated)
        card.body.addWidget(self.passphrase_field)

        self.strength = PassphraseStrengthPanel()
        card.body.addWidget(self.strength)

        self.confirm_field = PassphraseField("Type it again")
        self.confirm_field.changed.connect(self._refresh)
        card.body.addWidget(self.confirm_field)

        self.match_note = label("", "Faint", wrap=True)
        card.body.addWidget(self.match_note)
        return card

    def _build_output(self) -> QWidget:
        card = Card()
        card.body.addWidget(label("WHERE TO SAVE IT", "Section"))
        row = QHBoxLayout()
        row.setSpacing(10)
        button = QPushButton("Choose location…")
        button.setCursor(Qt.PointingHandCursor)
        button.clicked.connect(self._pick_output)
        row.addWidget(button)
        self.output_label = label("Beside the first file chosen", "Faint", wrap=True)
        self.output_label.setMinimumWidth(1)
        row.addWidget(self.output_label, 1)
        card.body.addLayout(row)
        return card

    # -- choosing ---------------------------------------------------------

    def add_paths(self, paths: list) -> None:
        for path in paths:
            path = os.path.abspath(path)
            if path not in self.paths and os.path.exists(path):
                self.paths.append(path)
        self._refresh()

    def _pick_files(self) -> None:
        chosen = filechooser.open_files(self, "Choose files to share",
                                        os.path.expanduser("~"))
        if chosen:
            self.add_paths(chosen)

    def _pick_folder(self) -> None:
        chosen = filechooser.choose_directory(self, "Choose a folder to share",
                                              os.path.expanduser("~"))
        if chosen:
            self.add_paths([chosen])

    def _pick_output(self) -> None:
        suggested = self.output_path or (
            locker.default_blob_path(self.paths, os.path.dirname(self.paths[0]))
            if self.paths else os.path.join(os.path.expanduser("~"), "shared.qkey"))
        chosen = destinations.file_for(
            "shared", self, "Save the shared file as",
            os.path.basename(suggested), beside=self.paths[0] if self.paths else "",
            patterns=["Quenchkey locked file (*.qkey)", "All files (*)"])
        if chosen:
            self.output_path = chosen
            self.output_label.setText(chosen.replace(os.path.expanduser("~"), "~"))

    def _selected_rows(self) -> list:
        return sorted({index.row() for index in self.table.selectedIndexes()})

    def _remove_selected(self) -> None:
        for row in reversed(self._selected_rows()):
            if 0 <= row < len(self.paths):
                del self.paths[row]
        self._refresh()

    def _on_generated(self, value: str, _bits: float) -> None:
        self.confirm_field.set_text(value)
        self.confirm_field.reveal.setChecked(True)

    # -- state ------------------------------------------------------------

    def _refresh(self, *_args) -> None:
        self.table.setRowCount(len(self.paths))
        for row, path in enumerate(self.paths):
            self.table.setItem(row, 0, QTableWidgetItem(
                path.replace(os.path.expanduser("~"), "~")))
            try:
                size = (os.path.getsize(path) if os.path.isfile(path)
                        else _folder_size(path))
                shown = _human(size)
            except OSError:
                shown = "?"
            self.table.setItem(row, 1, QTableWidgetItem(shown))
        self.empty_note.setVisible(not self.paths)
        self.remove_button.setEnabled(bool(self._selected_rows()) or bool(self.paths))

        text = self.passphrase_field.text()
        strength = self.strength.update_for(text, self.passphrase_field.exact_bits())
        confirm = self.confirm_field.text()
        if confirm and confirm != text:
            self.match_note.setText("The two entries do not match yet.")
            self.match_note.setStyleSheet(f"color: {theme.WARNING};")
        elif confirm:
            self.match_note.setText("Both entries match.")
            self.match_note.setStyleSheet(f"color: {theme.SUCCESS};")
        else:
            self.match_note.setText("")

        self.share_button.setEnabled(
            bool(self.paths) and bool(text) and confirm == text
            and strength.meets_minimum and self._task is None)

    # -- doing it ---------------------------------------------------------

    def _start(self) -> None:
        names = ", ".join(os.path.basename(p) for p in self.paths[:3])
        more = "" if len(self.paths) <= 3 else f" and {len(self.paths) - 3} more"
        confirmed = ConfirmDialog.ask(
            self, "Write a file that never expires?",
            f"{names}{more} will be packed into one file whose key travels "
            f"inside it. Anyone you give it to, and anyone they give it to, "
            f"can open it with this passphrase for as long as the file exists.",
            confirm_text="Write it",
            acknowledgement="I understand this file cannot be recalled, "
                            "cannot be given a deadline, and will not appear "
                            "among the items this vault can destroy.",
            detail="Nothing about this is reversible. If you want a deadline, "
                   "close this and lock the files into the vault instead — "
                   "but then only you can open them.",
            require_typed=ACKNOWLEDGEMENT)
        if not confirmed:
            return

        self.share_button.setEnabled(False)
        self.cancel_button.setEnabled(False)
        self.error.setVisible(False)
        self.progress.setVisible(True)
        self.progress.start("Packing…")

        paths = list(self.paths)
        passphrase = self.passphrase_field.text()
        output = self.output_path

        def work(progress=None):
            return locker.lock_to_share(paths, passphrase, output_path=output,
                                        progress=progress)

        self._task = Task(work, error_title="Could not write the shared file")
        self._task.progress.connect(self.progress.update_progress)
        self._task.succeeded.connect(self._finished)
        self._task.failed.connect(self._failed)
        self._task.start()

    def _finished(self, result) -> None:
        self._task = None
        self.progress.finish()
        self.result = result
        if self.session is not None:
            try:
                with self.session.guard:
                    self.session.vault.record_shared(
                        result.path, result.names, result.size,
                        result.plaintext_size, result.sha256)
            except Exception:  # noqa: BLE001 - the file is written either way
                pass
        self.accept()

    def _failed(self, title: str, message: str) -> None:
        self._task = None
        self.progress.finish()
        self.cancel_button.setEnabled(True)
        self.error.show_message(f"{title}: {message}", "danger")
        self._refresh()


class UnlockSharedDialog(QDialog):
    """Open shared files — several at once, with one passphrase.

    Shared files arrive in batches and usually share a passphrase, so this is
    a list with checkboxes rather than a file chooser opened once per file.
    Everything comes back beside the locked file it came from: opening
    somebody's documents is not a reason to move them somewhere else.
    """

    def __init__(self, session: Optional[Session] = None,
                 parent: Optional[QWidget] = None,
                 initial_paths: Optional[list] = None):
        super().__init__(parent)
        self.setObjectName("Root")
        self.setWindowTitle("Unlock shared files")
        self.setModal(True)
        theme.fit(self, 900, 820, 740, 520)

        self.session = session
        self.paths: list = []
        self.outcomes: list = []
        self._task: Optional[Task] = None

        shell = QVBoxLayout(self)
        shell.setContentsMargins(0, 0, 0, 0)
        shell.setSpacing(0)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QScrollArea.NoFrame)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        shell.addWidget(self.scroll, 1)

        canvas = QWidget()
        self.scroll.setWidget(canvas)
        body = QVBoxLayout(canvas)
        body.setContentsMargins(theme.GUTTER, theme.GUTTER, theme.GUTTER, 8)
        body.setSpacing(theme.GAP)

        body.addWidget(label("Unlock shared files", "Title", wrap=True))
        body.addWidget(label(
            "Tick the files to open and give the passphrase once. Files "
            "locked with the same passphrase open together; anything with a "
            "different one is reported on its own line and the rest still "
            "open.", "Muted", wrap=True))

        body.addWidget(self._build_list())
        body.addWidget(Divider())
        body.addWidget(self._build_passphrase())
        body.addWidget(Divider())
        body.addWidget(self._build_output())

        self.progress = ProgressPanel()
        self.progress.setVisible(False)
        body.addWidget(self.progress)

        self.result_banner = Banner("", "info")
        self.result_banner.setVisible(False)
        body.addWidget(self.result_banner)
        body.addStretch(1)

        footer = QWidget()
        footer.setObjectName("Root")
        row = QHBoxLayout(footer)
        row.setContentsMargins(theme.GUTTER, 10, theme.GUTTER, theme.GUTTER)
        row.addStretch(1)
        self.close_button = QPushButton("Close")
        self.close_button.setCursor(Qt.PointingHandCursor)
        self.close_button.clicked.connect(self.reject)
        row.addWidget(self.close_button)
        self.unlock_button = QPushButton("Unlock")
        self.unlock_button.setObjectName("Primary")
        self.unlock_button.setMinimumHeight(42)
        self.unlock_button.setCursor(Qt.PointingHandCursor)
        self.unlock_button.clicked.connect(self._start)
        row.addWidget(self.unlock_button)
        shell.addWidget(footer)

        self._load_known()
        if initial_paths:
            self.add_paths(initial_paths)
        self._refresh()

    # -- construction -----------------------------------------------------

    def _build_list(self) -> QWidget:
        card = Card()
        row = QHBoxLayout()
        row.setSpacing(8)
        add = QPushButton("Add files…")
        add.setCursor(Qt.PointingHandCursor)
        add.setToolTip("Open a .qkey file that this vault did not write — "
                       "one somebody sent you, for instance")
        add.clicked.connect(self._pick_files)
        row.addWidget(add)
        self.select_all_button = QPushButton("Select all")
        self.select_all_button.setCursor(Qt.PointingHandCursor)
        self.select_all_button.clicked.connect(self._select_all)
        row.addWidget(self.select_all_button)
        row.addStretch(1)
        self.remove_button = QPushButton("Remove from list")
        self.remove_button.setCursor(Qt.PointingHandCursor)
        self.remove_button.setToolTip("Takes it off this list only. The file "
                                      "itself is not touched.")
        self.remove_button.clicked.connect(self._remove_selected)
        row.addWidget(self.remove_button)
        card.body.addLayout(row)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Locked file", "Contents",
                                              "Where", "Result"])
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setShowGrid(False)
        self.table.setAlternatingRowColors(True)
        self.table.setMinimumHeight(theme.scaled(170))
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        # The result is the reason for the screen once it has run, so it
        # gets room rather than an ellipsis.
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table.itemChanged.connect(lambda _item: self._refresh_buttons())
        card.body.addWidget(self.table)

        self.empty_note = label("", "Faint", wrap=True)
        self.empty_note.setMinimumWidth(1)
        card.body.addWidget(self.empty_note)
        return card

    def _build_passphrase(self) -> QWidget:
        card = Card()
        card.body.addWidget(label("PASSPHRASE", "Section"))
        card.body.addWidget(label(
            "The one that was set when these files were locked — not your "
            "vault passphrase. Deriving the key takes about a second per "
            "file, deliberately.", "Faint", wrap=True))
        self.field = PassphraseField("Passphrase for these files")
        self.field.changed.connect(self._refresh_buttons)
        self.field.submitted.connect(self._start)
        card.body.addWidget(self.field)
        return card

    def _build_output(self) -> QWidget:
        card = Card()
        card.body.addWidget(label("WHAT TO PRODUCE", "Section"))

        self.extract_radio = QRadioButton(
            "Extract the files, beside the locked file")
        self.extract_radio.setChecked(True)
        self.extract_radio.toggled.connect(self._refresh_buttons)
        card.body.addWidget(self.extract_radio)
        card.body.addWidget(label(
            f"One file comes out as one file; several come out in a folder. "
            f"Either way the name gains {locker.UNLOCKED_SUFFIX}, and nothing "
            f"existing is ever overwritten.", "Faint", wrap=True))

        self.archive_radio = QRadioButton("One 7z archive, with no password")
        self.archive_radio.toggled.connect(self._refresh_buttons)
        card.body.addWidget(self.archive_radio)
        card.body.addWidget(label(
            "For passing on to somebody who should not need a passphrase. Any "
            "archive manager opens it — which is the point, and the risk: "
            "nothing protects it any more.", "Faint", wrap=True))

        card.body.addWidget(Divider())
        self.keep_check = QCheckBox("Keep the locked .qkey file as well")
        self.keep_check.setChecked(True)
        self.keep_check.toggled.connect(self._refresh_buttons)
        card.body.addWidget(self.keep_check)
        self.keep_note = label("", "Faint", wrap=True)
        self.keep_note.setMinimumWidth(1)
        card.body.addWidget(self.keep_note)
        return card

    # -- the list ---------------------------------------------------------

    def _load_known(self) -> None:
        """Everything this vault remembers writing, that is still on disk."""
        if self.session is None or not self.session.is_open:
            return
        for record in self.session.vault.shared_records():
            path = record.get("path", "")
            if path:
                self.add_paths([path], names=record.get("names", []))

    def add_paths(self, paths: list, names: Optional[list] = None) -> None:
        for path in paths:
            path = os.path.abspath(path)
            if any(entry["path"] == path for entry in self.paths):
                continue
            self.paths.append({
                "path": path,
                "names": list(names or []),
                "exists": os.path.exists(path),
                "result": "",
                "ok": None,
            })
        self._describe_unknown()
        self._refresh()

    def _describe_unknown(self) -> None:
        """Read what each file says about itself — no passphrase needed."""
        for entry in self.paths:
            if entry["names"] or not entry["exists"]:
                continue
            try:
                header = locker.read_blob_header(entry["path"])
                entry["self_contained"] = header.self_contained
                if not header.self_contained:
                    entry["result"] = "keeps its key in a vault, not in itself"
                    entry["ok"] = False
            except (OSError, UnsupportedFormat) as exc:
                entry["result"] = str(exc)
                entry["ok"] = False

    def _pick_files(self) -> None:
        chosen = filechooser.open_files(
            self, "Choose locked files to unlock", os.path.expanduser("~"),
            ["Quenchkey locked file (*.qkey)", "All files (*)"])
        if chosen:
            self.add_paths(chosen)

    def _select_all(self) -> None:
        wanted = any(self.table.item(row, 0).checkState() != Qt.Checked
                     for row in range(self.table.rowCount()))
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            if item.flags() & Qt.ItemIsUserCheckable:
                item.setCheckState(Qt.Checked if wanted else Qt.Unchecked)

    def _remove_selected(self) -> None:
        rows = sorted({index.row() for index in self.table.selectedIndexes()},
                      reverse=True)
        for row in rows:
            if 0 <= row < len(self.paths):
                del self.paths[row]
        self._refresh()

    def checked_paths(self) -> list:
        chosen = []
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            if item is not None and item.checkState() == Qt.Checked:
                chosen.append(self.paths[row]["path"])
        return chosen

    def _refresh(self) -> None:
        self.table.blockSignals(True)
        self.table.setRowCount(len(self.paths))
        for row, entry in enumerate(self.paths):
            usable = entry["exists"] and entry.get("ok") is not False
            name = QTableWidgetItem(os.path.basename(entry["path"]))
            name.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable
                          | (Qt.ItemIsUserCheckable if usable else Qt.NoItemFlags))
            if usable:
                previous = self.table.item(row, 0)
                name.setCheckState(previous.checkState() if previous is not None
                                   else Qt.Checked)
            self.table.setItem(row, 0, name)

            contents = ", ".join(entry["names"]) if entry["names"] else "—"
            self.table.setItem(row, 1, QTableWidgetItem(contents))
            where = os.path.dirname(entry["path"]).replace(
                os.path.expanduser("~"), "~")
            self.table.setItem(row, 2, QTableWidgetItem(where))
            result = entry["result"] or ("" if entry["exists"]
                                         else "not found — moved or deleted")
            item = QTableWidgetItem(result)
            if entry.get("ok") is True:
                item.setForeground(QColor(theme.SUCCESS))
            elif entry.get("ok") is False or not entry["exists"]:
                item.setForeground(QColor(theme.DANGER))
            self.table.setItem(row, 3, item)
        self.table.blockSignals(False)

        self.empty_note.setVisible(not self.paths)
        self.empty_note.setText(
            "No shared files known to this vault. Use “Add files…” to open one "
            "that was sent to you.")
        self._refresh_buttons()

    def _refresh_buttons(self) -> None:
        chosen = self.checked_paths()
        self.unlock_button.setEnabled(
            bool(chosen) and bool(self.field.text()) and self._task is None)
        self.select_all_button.setEnabled(bool(self.paths))
        self.remove_button.setEnabled(bool(self.table.selectedIndexes()))
        self.keep_note.setText(
            "" if self.keep_check.isChecked() else
            "The locked file is overwritten and deleted once its contents are "
            "safely out. Any other copy of it, anywhere, still opens with this "
            "passphrase — deleting this one does not reach those.")

    # -- doing it ---------------------------------------------------------

    def _start(self) -> None:
        chosen = self.checked_paths()
        if not chosen or not self.field.text():
            return

        self.unlock_button.setEnabled(False)
        self.close_button.setEnabled(False)
        self.result_banner.setVisible(False)
        self.progress.setVisible(True)
        self.progress.start("Deriving the key…")

        passphrase = self.field.text()
        mode = (locker.MODE_ARCHIVE if self.archive_radio.isChecked()
                else locker.MODE_EXTRACT)
        keep = self.keep_check.isChecked()
        # None means beside each locked file, which is what the default rule
        # asks for; a fixed folder or one chosen now overrides that.
        destination = destinations.folder_for(
            "unlocked_shared", self, "Where should the files go?",
            beside=chosen[0])
        if destination is None:
            self.progress.setVisible(False)
            self._refresh_buttons()
            self.close_button.setEnabled(True)
            return
        if os.path.dirname(os.path.abspath(chosen[0])) == destination:
            destination = None

        def work(progress=None):
            return locker.unlock_shared_files(chosen, passphrase, mode=mode,
                                              keep_locked=keep,
                                              destination_dir=destination,
                                              progress=progress)

        self._task = Task(work, error_title="Could not unlock")
        self._task.progress.connect(self.progress.update_progress)
        self._task.succeeded.connect(self._done)
        self._task.failed.connect(self._failed)
        self._task.start()

    def _done(self, outcomes: list) -> None:
        self._task = None
        self.progress.finish()
        self.close_button.setEnabled(True)
        self.outcomes = outcomes

        by_path = {outcome.source: outcome for outcome in outcomes}
        for entry in self.paths:
            outcome = by_path.get(entry["path"])
            if outcome is None:
                continue
            entry["ok"] = outcome.ok
            entry["exists"] = os.path.exists(entry["path"])
            if outcome.ok:
                entry["result"] = f"unlocked → {os.path.basename(outcome.destination)}"
            else:
                entry["result"] = outcome.reason

        opened = [o for o in outcomes if o.ok]
        failed = [o for o in outcomes if not o.ok]
        if opened and not failed:
            tone, text = "success", self._summary(opened)
        elif opened:
            tone = "warning"
            text = (f"{self._summary(opened)} {len(failed)} could not be "
                    f"opened with this passphrase — see the list.")
        else:
            tone = "danger"
            text = ("Nothing opened. The passphrase does not match these "
                    "files, or they have been altered; there is no way to "
                    "tell which apart.")
        self.result_banner.show_message(text, tone)
        self.result_banner.setVisible(True)
        self._refresh()
        # Scrolled to, because a summary the user has to go looking for is a
        # summary most people will not see.
        self.scroll.ensureWidgetVisible(self.result_banner)

    @staticmethod
    def _summary(opened: list) -> str:
        count = len(opened)
        files = sum(len(o.written) for o in opened)
        where = os.path.dirname(opened[0].destination).replace(
            os.path.expanduser("~"), "~")
        removed = sum(1 for o in opened if o.removed_locked)
        note = (f" {removed} locked file{'s' if removed != 1 else ''} deleted."
                if removed else "")
        return (f"Unlocked {count} file{'s' if count != 1 else ''} — "
                f"{files} item{'s' if files != 1 else ''} written to {where}."
                f"{note}")

    def _failed(self, title: str, message: str) -> None:
        self._task = None
        self.progress.finish()
        self.close_button.setEnabled(True)
        self.result_banner.show_message(f"{title}: {message}", "danger")
        self.result_banner.setVisible(True)
        self._refresh_buttons()



def _folder_size(path: str) -> int:
    total = 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += os.path.getsize(os.path.join(root, name))
            except OSError:
                pass
    return total


def _human(size: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"
