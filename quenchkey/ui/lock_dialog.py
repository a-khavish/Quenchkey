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

"""The lock flow: choose files, choose a deadline, write the .qkey."""

from __future__ import annotations

import os
import time
from typing import Optional

from PyQt5.QtCore import QDateTime, Qt, pyqtSignal
from PyQt5.QtGui import QColor, QDragEnterEvent, QDropEvent
from PyQt5.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QDateTimeEdit, QDialog,
    QHBoxLayout, QHeaderView, QPushButton, QScrollArea, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget,
)

from .. import expiry as expiry_mod, locker
from ..session import Session
from . import destinations, filechooser, theme
from .widgets import Banner, Card, ConfirmDialog, Divider, ProgressPanel, label
from .workers import Task


class SelectionTable(QTableWidget):
    """The chosen files, numbered in the order they were picked.

    Accepts drops anywhere on its surface; the drop order follows the order the
    file manager hands the paths over.
    """

    files_dropped = pyqtSignal(list)

    COLUMNS = ["#", "Name", "Size", "Location"]

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(0, len(self.COLUMNS), parent)
        self.setHorizontalHeaderLabels(self.COLUMNS)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setAlternatingRowColors(True)
        self.verticalHeader().setVisible(False)
        self.setShowGrid(False)
        self.setAcceptDrops(True)
        self.setDragDropMode(QAbstractItemView.DropOnly)

        header = self.horizontalHeader()
        header.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        header.setSectionResizeMode(0, QHeaderView.Fixed)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        self.setColumnWidth(0, 46)

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:  # noqa: N802
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dragMoveEvent(self, event) -> None:  # noqa: N802
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent) -> None:  # noqa: N802
        paths = [url.toLocalFile() for url in event.mimeData().urls()
                 if url.isLocalFile()]
        if paths:
            self.files_dropped.emit(paths)
            event.acceptProposedAction()


class LockDialog(QDialog):
    """Pick files, set a deadline, and produce one locked file."""

    def __init__(self, session: Session, parent: Optional[QWidget] = None,
                 initial_paths: Optional[list[str]] = None):
        super().__init__(parent)
        self.session = session
        self.paths: list[str] = []
        self._task: Optional[Task] = None
        self.result_entry = None

        self.setWindowTitle("Lock files")
        self.setModal(True)
        theme.fit(self, 940, 900, 800, 540)
        self.setAcceptDrops(True)

        self._build()
        if initial_paths:
            self.add_paths(initial_paths)
        self._refresh()

    # -- construction -----------------------------------------------------

    def _build(self) -> None:
        self.setObjectName("Root")
        shell = QVBoxLayout(self)
        shell.setContentsMargins(0, 0, 0, 0)
        shell.setSpacing(0)

        # Scrollable, so the dialog stays usable on a short screen instead of
        # clipping whichever panel happens to be last.
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

        outer.addWidget(label("Lock files", "Title"))
        outer.addWidget(label(
            "The files are packed, encrypted with a fresh 256-bit key, and "
            "written as one .qkey file. The key goes into the vault and "
            "nowhere else.", "Subtitle", wrap=True))

        # -- selection
        selection = Card(padding=18, spacing=12)
        row = QHBoxLayout()
        row.setSpacing(10)
        add_files = QPushButton("Add files…")
        add_files.setCursor(Qt.PointingHandCursor)
        add_files.clicked.connect(self._pick_files)
        row.addWidget(add_files)
        add_folder = QPushButton("Add folder…")
        add_folder.setCursor(Qt.PointingHandCursor)
        add_folder.clicked.connect(self._pick_folder)
        row.addWidget(add_folder)
        row.addStretch(1)
        self.up_button = QPushButton("Move up")
        self.up_button.setObjectName("Ghost")
        self.up_button.clicked.connect(lambda: self._move(-1))
        row.addWidget(self.up_button)
        self.down_button = QPushButton("Move down")
        self.down_button.setObjectName("Ghost")
        self.down_button.clicked.connect(lambda: self._move(1))
        row.addWidget(self.down_button)
        self.remove_button = QPushButton("Remove")
        self.remove_button.setObjectName("Ghost")
        self.remove_button.clicked.connect(self._remove_selected)
        row.addWidget(self.remove_button)
        selection.body.addLayout(row)

        self.table = SelectionTable()
        self.table.files_dropped.connect(self.add_paths)
        self.table.itemSelectionChanged.connect(self._refresh_buttons)
        self.table.setMinimumHeight(170)
        selection.body.addWidget(self.table)

        self.empty_hint = label(
            "Drop files here, or use the buttons above. "
            "The numbers are the order you chose them in, and that order is "
            "preserved inside the locked file.", "Faint", wrap=True)
        self.empty_hint.setAlignment(Qt.AlignCenter)
        selection.body.addWidget(self.empty_hint)

        self.summary = label("", "Muted")
        selection.body.addWidget(self.summary)
        outer.addWidget(selection, 1)

        # -- settings
        settings = Card(padding=18, spacing=12)
        settings.body.addWidget(label("RULES", "SectionHeading"))
        settings.body.addWidget(label(
            "Any rule you set is enough on its own. Whichever comes first "
            "destroys the key.", "Faint", wrap=True))

        expiry_row = QHBoxLayout()
        expiry_row.setSpacing(10)
        self.expiry_combo = QComboBox()
        for name, seconds in expiry_mod.EXPIRY_PRESETS:
            self.expiry_combo.addItem(name, seconds)
        self.expiry_combo.addItem("Custom…", "custom")
        self.expiry_combo.setCurrentIndex(1)
        self.expiry_combo.currentIndexChanged.connect(self._refresh)
        self.expiry_combo.setMinimumWidth(180)
        expiry_row.addWidget(self.expiry_combo)

        self.custom_when = QDateTimeEdit(QDateTime.currentDateTime().addDays(1))
        self.custom_when.setCalendarPopup(True)
        self.custom_when.setDisplayFormat("yyyy-MM-dd  HH:mm")
        self.custom_when.setMinimumDateTime(QDateTime.currentDateTime().addSecs(60))
        self.custom_when.dateTimeChanged.connect(self._refresh)
        self.custom_when.setVisible(False)
        expiry_row.addWidget(self.custom_when)

        expiry_row.addStretch(1)
        self.expiry_note = label("", "Faint")
        expiry_row.addWidget(self.expiry_note)
        settings.body.addLayout(expiry_row)

        # -- opens allowance
        opens_row = QHBoxLayout()
        opens_row.setSpacing(10)
        opens_row.addWidget(label("Openings", "Muted"))
        self.opens_combo = QComboBox()
        for name, value in expiry_mod.OPEN_LIMIT_PRESETS:
            self.opens_combo.addItem(name, value)
        self.opens_combo.setMinimumWidth(180)
        self.opens_combo.currentIndexChanged.connect(self._refresh)
        opens_row.addWidget(self.opens_combo)
        opens_row.addStretch(1)
        self.opens_note = label("", "Faint")
        opens_row.addWidget(self.opens_note)
        settings.body.addLayout(opens_row)

        # -- dead man's switch
        heartbeat_row = QHBoxLayout()
        heartbeat_row.setSpacing(10)
        heartbeat_row.addWidget(label("Check in", "Muted"))
        self.heartbeat_combo = QComboBox()
        for name, value in expiry_mod.HEARTBEAT_PRESETS:
            self.heartbeat_combo.addItem(name, value)
        self.heartbeat_combo.setMinimumWidth(180)
        self.heartbeat_combo.currentIndexChanged.connect(self._refresh)
        heartbeat_row.addWidget(self.heartbeat_combo)
        heartbeat_row.addStretch(1)
        self.heartbeat_note = label("", "Faint")
        heartbeat_row.addWidget(self.heartbeat_note)
        settings.body.addLayout(heartbeat_row)

        self.heartbeat_warning = Banner(
            "A dead man's switch destroys the key if you do not open this "
            "vault in time. Opening the vault is the check-in — you do not "
            "have to do anything else. But it fires whether you were busy, "
            "ill, or simply away, and a system clock that jumps forward brings "
            "it forward with it.", "warning")
        self.heartbeat_warning.setVisible(False)
        settings.body.addWidget(self.heartbeat_warning)

        settings.body.addWidget(Divider())
        settings.body.addWidget(label("OUTPUT", "SectionHeading"))

        output_row = QHBoxLayout()
        output_row.setSpacing(10)
        choose_output = QPushButton("Choose location…")
        choose_output.setCursor(Qt.PointingHandCursor)
        choose_output.clicked.connect(self._pick_output)
        output_row.addWidget(choose_output)
        self.output_label = label("Alongside the first file selected", "Faint")
        output_row.addWidget(self.output_label, 1)
        settings.body.addLayout(output_row)
        self.output_path: Optional[str] = None

        self.delete_blob_check = QCheckBox(
            "Also delete the .qkey file when it expires")
        self.delete_blob_check.setCursor(Qt.PointingHandCursor)
        settings.body.addWidget(self.delete_blob_check)

        self.delete_originals_check = QCheckBox(
            "Shred the original files after locking")
        self.delete_originals_check.setObjectName("DangerCheck")
        self.delete_originals_check.setCursor(Qt.PointingHandCursor)
        self.delete_originals_check.toggled.connect(self._refresh)
        settings.body.addWidget(self.delete_originals_check)

        self.originals_note = Banner(
            "The originals are overwritten with random bytes and unlinked. On a "
            "copy-on-write filesystem or an SSD doing wear levelling the old "
            "blocks may survive anyway, and this does nothing about copies "
            "elsewhere, backups, or what your editor left in a temp directory.",
            "warning")
        self.originals_note.setVisible(False)
        settings.body.addWidget(self.originals_note)

        outer.addWidget(settings)

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
        self.lock_button = QPushButton("Lock files")
        self.lock_button.setObjectName("Primary")
        self.lock_button.setMinimumHeight(42)
        self.lock_button.setCursor(Qt.PointingHandCursor)
        self.lock_button.clicked.connect(self._start)
        buttons.addWidget(self.lock_button)
        shell.addWidget(footer)

    # -- drag and drop on the dialog itself -------------------------------

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:  # noqa: N802
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent) -> None:  # noqa: N802
        paths = [url.toLocalFile() for url in event.mimeData().urls()
                 if url.isLocalFile()]
        if paths:
            self.add_paths(paths)
            event.acceptProposedAction()

    # -- selection --------------------------------------------------------

    def add_paths(self, paths: list[str]) -> None:
        for path in paths:
            path = os.path.abspath(path)
            if path not in self.paths and os.path.exists(path):
                self.paths.append(path)
        self._refresh()

    def _pick_files(self) -> None:
        paths = filechooser.open_files(
            self, "Choose files to lock", os.path.expanduser("~"))
        if paths:
            self.add_paths(paths)

    def _pick_folder(self) -> None:
        path = filechooser.choose_directory(
            self, "Choose a folder to lock", os.path.expanduser("~"))
        if path:
            self.add_paths([path])

    def _pick_output(self) -> None:
        suggested = self.output_path or (
            locker.default_blob_path(self.paths, os.path.dirname(self.paths[0]))
            if self.paths else os.path.join(os.path.expanduser("~"), "locked.qkey"))
        path = destinations.file_for(
            "locked", self, "Save locked file as",
            os.path.basename(suggested), beside=self.paths[0] if self.paths else "",
            patterns=["Quenchkey locked file (*.qkey)", "All files (*)"])
        if path:
            self.output_path = path
            self.output_label.setText(path.replace(os.path.expanduser("~"), "~"))

    def _selected_rows(self) -> list[int]:
        return sorted({index.row() for index in self.table.selectedIndexes()})

    def _remove_selected(self) -> None:
        for row in reversed(self._selected_rows()):
            if 0 <= row < len(self.paths):
                del self.paths[row]
        self._refresh()

    def _move(self, delta: int) -> None:
        rows = self._selected_rows()
        if not rows:
            return
        order = rows if delta < 0 else list(reversed(rows))
        moved: list[int] = []
        for row in order:
            target = row + delta
            if 0 <= target < len(self.paths):
                self.paths[row], self.paths[target] = self.paths[target], self.paths[row]
                moved.append(target)
            else:
                moved.append(row)
        self._refresh()
        self.table.clearSelection()
        for row in moved:
            self.table.selectRow(row)

    # -- state ------------------------------------------------------------

    def chosen_expiry(self) -> Optional[float]:
        data = self.expiry_combo.currentData()
        if data == "custom":
            return self.custom_when.dateTime().toSecsSinceEpoch()
        if data is None:
            return None
        return time.time() + int(data)

    def chosen_max_opens(self) -> Optional[int]:
        return self.opens_combo.currentData()

    def chosen_heartbeat(self) -> Optional[float]:
        return self.heartbeat_combo.currentData()

    def _refresh(self) -> None:
        self.custom_when.setVisible(self.expiry_combo.currentData() == "custom")

        self.table.setRowCount(len(self.paths))
        total = 0
        for row, path in enumerate(self.paths):
            size = _path_size(path)
            total += size
            kind = "folder" if os.path.isdir(path) else ""
            cells = [
                str(row + 1),
                os.path.basename(path.rstrip(os.sep)) + (f"  ({kind})" if kind else ""),
                expiry_mod.format_size(size),
                os.path.dirname(path).replace(os.path.expanduser("~"), "~"),
            ]
            for column, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if column == 2:
                    item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
                if column == 0:
                    item.setForeground(QColor(theme.PRIMARY))
                    item.setTextAlignment(Qt.AlignCenter)
                elif column in (2, 3):
                    item.setForeground(QColor(theme.TEXT_MUTED))
                self.table.setItem(row, column, item)

        self.empty_hint.setVisible(not self.paths)
        self.table.setVisible(bool(self.paths))

        if self.paths:
            self.summary.setText(
                f"{len(self.paths)} item{'s' if len(self.paths) != 1 else ''}, "
                f"{expiry_mod.format_size(total)} → one locked file")
        else:
            self.summary.setText("")

        when = self.chosen_expiry()
        if when is None:
            self.expiry_note.setText("No deadline — the key stays until you destroy it")
            self.expiry_note.setStyleSheet(f"color: {theme.TEXT_MUTED};")
        else:
            self.expiry_note.setText(
                f"Key destroyed {expiry_mod.format_time(when)}  ·  in "
                f"{expiry_mod.format_duration(when - time.time())}")
            self.expiry_note.setStyleSheet(f"color: {theme.PRIMARY};")

        opens = self.chosen_max_opens()
        if opens is None:
            self.opens_note.setText("No limit on how often these can be opened")
            self.opens_note.setStyleSheet(f"color: {theme.TEXT_MUTED};")
        else:
            self.opens_note.setText(
                f"Key destroyed after {opens} opening{'s' if opens != 1 else ''}")
            self.opens_note.setStyleSheet(f"color: {theme.PRIMARY};")

        heartbeat = self.chosen_heartbeat()
        self.heartbeat_warning.setVisible(heartbeat is not None)
        if heartbeat is None:
            self.heartbeat_note.setText("No dead man's switch")
            self.heartbeat_note.setStyleSheet(f"color: {theme.TEXT_MUTED};")
        else:
            self.heartbeat_note.setText(
                f"Key destroyed if the vault is not opened for {heartbeat:g} days")
            self.heartbeat_note.setStyleSheet(f"color: {theme.WARNING};")

        self.originals_note.setVisible(self.delete_originals_check.isChecked())
        self.lock_button.setEnabled(bool(self.paths))
        self._refresh_buttons()

    def _refresh_buttons(self) -> None:
        has_selection = bool(self._selected_rows())
        for button in (self.up_button, self.down_button, self.remove_button):
            button.setEnabled(has_selection)

    # -- run --------------------------------------------------------------

    def _start(self) -> None:
        if not self.paths:
            return
        when = self.chosen_expiry()

        if self.delete_originals_check.isChecked():
            confirmed = ConfirmDialog.ask(
                self, "Shred the originals?",
                f"The {len(self.paths)} selected item"
                f"{'s' if len(self.paths) != 1 else ''} will be overwritten and "
                "deleted once the locked file is written.",
                confirm_text="Lock and shred",
                acknowledgement="I have another copy, or I do not need one.",
                detail="If you then forget the passphrase, or let the file "
                       "expire, this data is gone.")
            if not confirmed:
                return

        opens = self.chosen_max_opens()
        heartbeat = self.chosen_heartbeat()

        if when is not None or opens is not None or heartbeat is not None:
            rules = []
            if when is not None:
                rules.append(f"at {expiry_mod.format_time(when)}")
            if opens is not None:
                rules.append(f"after {opens} opening{'s' if opens != 1 else ''}")
            if heartbeat is not None:
                rules.append(f"if this vault is not opened for {heartbeat:g} days")
            joined = rules[0] if len(rules) == 1 else (
                ", ".join(rules[:-1]) + ", or " + rules[-1] + " — whichever comes first")
            confirmed = ConfirmDialog.ask(
                self, "Confirm the rules",
                f"The key for these files will be destroyed {joined}.",
                confirm_text="Lock it", tone="danger",
                acknowledgement="I understand this cannot be undone.",
                detail="When that moment arrives the key is overwritten in the "
                       "vault and a signed certificate of destruction is issued. "
                       "Every copy of the .qkey file, anywhere, becomes "
                       "permanently unreadable — including yours.")
            if not confirmed:
                return

        self._set_running(True)
        session = self.session
        paths = list(self.paths)
        output = self.output_path
        delete_originals = self.delete_originals_check.isChecked()
        delete_blob = self.delete_blob_check.isChecked()
        max_opens = opens
        heartbeat_days = heartbeat

        def work(progress=None):
            with session.guard:
                return locker.lock_files(
                    session.vault, paths, when, blob_path=output,
                    output_dir=os.path.dirname(paths[0]),
                    delete_originals=delete_originals,
                    delete_blob_on_expiry=delete_blob,
                    max_opens=max_opens,
                    heartbeat_days=heartbeat_days,
                    progress=progress)

        self._task = Task(work, error_title="Could not lock the files")
        self._task.progress.connect(self.progress.update_progress)
        self._task.succeeded.connect(self._on_done)
        self._task.failed.connect(self._on_failed)
        self._task.start()

    def _set_running(self, running: bool) -> None:
        self.lock_button.setEnabled(not running)
        self.cancel_button.setEnabled(not running)
        self.table.setEnabled(not running)
        if running:
            self.error.setVisible(False)
            self.progress.start("Packing…")
        else:
            self.progress.finish()

    def _on_done(self, result: locker.LockResult) -> None:
        self._set_running(False)
        self.result_entry = result.entry
        self.accept()

    def _on_failed(self, title: str, message: str) -> None:
        self._set_running(False)
        self.error.show_message(f"{title}: {message}", "danger")


def _path_size(path: str) -> int:
    if os.path.isfile(path):
        try:
            return os.path.getsize(path)
        except OSError:
            return 0
    total = 0
    for dirpath, _dirnames, filenames in os.walk(path):
        for name in filenames:
            try:
                total += os.path.getsize(os.path.join(dirpath, name))
            except OSError:
                pass
    return total
