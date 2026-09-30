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

"""The main window: what is locked, when each key dies, and the controls."""

from __future__ import annotations

import os
import subprocess
import time
from typing import Optional

from PyQt5.QtCore import (
    QAbstractTableModel, QItemSelectionModel, QModelIndex,
    QSortFilterProxyModel, QTimer, Qt, pyqtSignal,
)
from PyQt5.QtGui import QColor, QDragEnterEvent, QDropEvent, QFont, QIcon
from PyQt5.QtWidgets import (
    QAbstractItemView, QDialog, QHBoxLayout, QHeaderView, QLabel, QMainWindow,
    QPushButton, QScrollArea, QSizePolicy, QTableView, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget,
)

from .. import expiry as expiry_mod, handover as handover_mod, locker
from .. import settings as settings_mod
from .. import warnings as warnings_mod
from .. import uninstall
from ..session import SWEEP_INTERVAL_SECONDS, Session
from ..crypto import UnsupportedFormat
from ..vault import Entry
from . import filechooser, theme
from .dialogs import (
    AnchorDialog, BackgroundExpiryDialog, CertificatesDialog, CustodianDialog,
    RecoverySharesDialog,
)
from .lock_dialog import LockDialog
from .feature_dialogs import (
    AuditDialog, BackupDialog, DuressDialog, HandoverDialog,
    IdentityCardDialog, IntegrityDialog, WatchFoldersDialog,
)
from .help_dialog import HelpDialog
from .settings_dialog import SettingsDialog
from .share_dialog import ShareDialog, UnlockSharedDialog
from .unlock_dialog import UnlockDialog
from .widgets import Banner, ConfirmDialog, Divider, StatTile, WrapRow, label

SORT_ROLE = Qt.UserRole + 1


class EntryTableModel(QAbstractTableModel):
    """The locked files, as a table.

    Row numbers are positional and follow the current sort, so the "#" column
    is the row's place in the view rather than a stored id.
    """

    COLUMNS = ["#", "Name", "Size", "Created", "Ends", "Time remaining",
               "Opens", "Status"]

    def __init__(self, session: Session, parent=None):
        super().__init__(parent)
        self.session = session
        self._entries: list[Entry] = []
        self._now = time.time()

    # -- Qt interface -----------------------------------------------------

    def rowCount(self, parent=QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self._entries)

    def columnCount(self, parent=QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self.COLUMNS)

    #: Columns whose values are right-aligned; their headers follow suit.
    RIGHT_ALIGNED = (0, 2, 6)

    def headerData(self, section, orientation, role=Qt.DisplayRole):  # noqa: N802
        if orientation != Qt.Horizontal:
            return None
        if role == Qt.DisplayRole:
            return self.COLUMNS[section]
        if role == Qt.TextAlignmentRole:
            if section in self.RIGHT_ALIGNED:
                return int(Qt.AlignRight | Qt.AlignVCenter)
            return int(Qt.AlignLeft | Qt.AlignVCenter)
        return None

    def data(self, index: QModelIndex, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        entry = self._entries[index.row()]
        column = index.column()
        level = expiry_mod.urgency(entry, self._now)

        if role in (Qt.DisplayRole, SORT_ROLE):
            raw = role == SORT_ROLE
            if column == 0:
                return index.row() + 1
            if column == 1:
                return entry.display_name
            if column == 2:
                return entry.plaintext_size if raw else expiry_mod.format_size(
                    entry.plaintext_size)
            if column == 3:
                return entry.created if raw else expiry_mod.format_time(entry.created)
            if column == 4:
                deadline = entry.deadline()
                if raw:
                    return float("inf") if deadline is None else deadline
                return expiry_mod.describe_deadline(entry)
            if column == 5:
                if raw:
                    if entry.key_destroyed:
                        return -1
                    deadline = entry.deadline()
                    return float("inf") if deadline is None else deadline - self._now
                return expiry_mod.format_remaining(entry, self._now)
            if column == 6:
                if entry.max_opens is None:
                    return -1 if raw else "—"
                used = f"{entry.open_count}/{entry.max_opens}"
                return (entry.opens_remaining or 0) if raw else used
            if column == 7:
                return _status_text(entry, level)

        if role == Qt.ForegroundRole:
            if entry.key_destroyed:
                return QColor(theme.TEXT_FAINT)
            if column == 6 and entry.max_opens is not None:
                remaining = entry.opens_remaining or 0
                return QColor(theme.DANGER if remaining <= 1 else theme.PRIMARY)
            if column in (5, 7):
                return QColor({
                    expiry_mod.URGENCY_CRITICAL_KEY: theme.DANGER,
                    expiry_mod.URGENCY_WARNING_KEY: theme.WARNING,
                    expiry_mod.URGENCY_CALM: theme.SUCCESS,
                    expiry_mod.URGENCY_NONE: theme.TEXT_MUTED,
                }.get(level, theme.TEXT))
            if column in (0, 2, 3, 4):
                return QColor(theme.TEXT_MUTED)

        if role == Qt.FontRole and column == 5:
            font = QFont()
            font.setBold(level in (expiry_mod.URGENCY_CRITICAL_KEY,
                                   expiry_mod.URGENCY_WARNING_KEY))
            return font

        if role == Qt.TextAlignmentRole and column in self.RIGHT_ALIGNED:
            return int(Qt.AlignRight | Qt.AlignVCenter)

        if role == Qt.ToolTipRole:
            if entry.key_destroyed:
                return (f"The key was destroyed "
                        f"{expiry_mod.format_time(entry.expired_at)}.\n"
                        f"{entry.blob_path}\nNothing can decrypt this file now.")
            return (f"{entry.blob_path}\n{len(entry.names)} file(s) inside\n"
                    f"Rules: {entry.rule_summary()}")

        return None

    # -- data -------------------------------------------------------------

    def refresh(self) -> None:
        self.beginResetModel()
        self._entries = self.session.vault.entries() if self.session.is_open else []
        self._now = self.session.vault.effective_now() if self.session.is_open else time.time()
        self.endResetModel()

    def tick(self) -> None:
        """Repaint the countdown columns without rebuilding the model."""
        if not self._entries:
            return
        self._now = self.session.vault.effective_now() if self.session.is_open else time.time()
        top = self.index(0, 4)
        bottom = self.index(len(self._entries) - 1, 7)
        self.dataChanged.emit(top, bottom, [Qt.DisplayRole, Qt.ForegroundRole,
                                            Qt.FontRole])

    def entry_at(self, row: int) -> Optional[Entry]:
        if 0 <= row < len(self._entries):
            return self._entries[row]
        return None


def _status_text(entry: Entry, level: str) -> str:
    if entry.key_destroyed:
        return "key destroyed"
    if entry.checked_out:
        return "out on loan"
    if not os.path.exists(entry.blob_path):
        return "file missing"
    if entry.opens_remaining == 1:
        return "last opening"
    if level == expiry_mod.URGENCY_CRITICAL_KEY:
        return "expiring"
    if entry.heartbeat_days is not None:
        return "awaiting check-in"
    if not entry.has_rules:
        return "held"
    return "locked"


class MainWindow(QMainWindow):
    """The vault, open."""

    closed = pyqtSignal()

    def __init__(self, session: Session, parent=None):
        super().__init__(parent)
        self.session = session
        self.setWindowTitle("Quenchkey")
        # Opens filling the screen, and stays resizable: the same first
        # impression every time without taking the screen hostage. The minimum
        # is still clamped, because one larger than the display leaves a
        # window that cannot be resized to fit it.
        theme.fit_to_screen(self, 1000, 680,
                            fill=settings_mod.current().get("fill_screen", True))

        #: Set when the window is closing for good rather than to the tray.
        self._really_quitting = False
        self.tray = None
        #: Filling the screen needs the title bar's real height, which Qt only
        #: knows once the window manager has drawn it — so it happens on the
        #: first show, and only the first, or a restore from the tray would
        #: undo whatever size the user had chosen.
        self._placed = False
        self.setAcceptDrops(True)

        self._build()
        self._wire_timers()
        self.refresh()
        # Catch anything that fell due while the app was not running.
        QTimer.singleShot(60, self._sweep)

    # -- construction -----------------------------------------------------

    def _build(self) -> None:
        # The content scrolls, the way every dialog here does. On a small screen
        # at large text the table, the stats and the footnote together need more
        # height than the display has, and the choice is between a window that
        # cannot be resized to fit and one the user scrolls. Nothing is hidden
        # either way, which was the requirement.
        page = QScrollArea()
        page.setObjectName("Root")
        page.setWidgetResizable(True)
        page.setFrameShape(QScrollArea.NoFrame)
        page.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setCentralWidget(page)

        root = QWidget()
        root.setObjectName("Root")
        page.setWidget(root)
        outer = QVBoxLayout(root)
        outer.setContentsMargins(theme.GUTTER, 22, theme.GUTTER, 20)
        outer.setSpacing(theme.GAP)

        self._build_menu()
        outer.addLayout(self._build_header())
        outer.addLayout(self._build_stats())

        self.notice = Banner("", "success")
        self.notice.setVisible(False)
        outer.addWidget(self.notice)

        outer.addLayout(self._build_actions())
        outer.addWidget(self._build_table(), 1)
        outer.addLayout(self._build_footer())

        self.statusBar().showMessage(self._status_text())

    def _build_menu(self) -> None:
        menu = self.menuBar().addMenu("&Vault")
        menu.addAction("Lock files…", self._lock_files)
        menu.addAction("Lock files to share…", self._lock_to_share)
        menu.addAction("Unlock shared files…", lambda: self._open_shared_file())
        menu.addSeparator()
        menu.addAction("Hand over to another vault…", self._hand_over)
        menu.addAction("Accept a handover…", self._accept_handover)
        menu.addAction("My identity card…", self._show_identity)
        menu.addSeparator()
        menu.addAction("Certificates of destruction…", self._show_certificates)
        menu.addAction("Anchor this vault's history…", self._show_anchor)
        menu.addAction("Recovery shares…", self._show_shares)
        menu.addAction("Vault backups…", self._show_backups)
        menu.addSeparator()
        menu.addAction("Check the locked files…", self._show_integrity)
        menu.addAction("Record for an auditor…", self._show_audit)
        menu.addAction("Watched folders…", self._show_watch)
        menu.addAction("Duress passphrase…", self._show_duress)
        menu.addSeparator()
        menu.addAction("Expiry while Quenchkey is closed…", self._show_background)
        menu.addAction("Custodian details…", self._show_custodian)
        menu.addAction("Security details…", self._show_security)
        menu.addAction("What this does not protect against…",
                       self._show_limitations)
        menu.addSeparator()
        menu.addAction("Settings…", self._show_settings)
        menu.addSeparator()
        menu.addAction("Lock vault", self._lock_vault)
        menu.addAction("Quit Quenchkey", self.quit_fully)

        help_menu = self.menuBar().addMenu("&Help")
        help_menu.addAction("How to use Quenchkey…", self._show_help)
        help_menu.addAction("How do I open a .qkey file?…",
                            lambda: self._show_help(page=1))
        help_menu.addAction("What this does not protect against…",
                            self._show_limitations)
        help_menu.addSeparator()
        help_menu.addAction("Security details…", self._show_security)
        help_menu.addAction("About Quenchkey…", self._show_about)
        help_menu.addSeparator()
        help_menu.addAction("Uninstall Quenchkey…", self._uninstall)

    def _build_header(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(14)

        mark = QLabel()
        mark.setPixmap(theme.logo_pixmap(44))
        row.addWidget(mark)

        titles = QVBoxLayout()
        titles.setSpacing(1)
        name = label("Quenchkey", "Title")
        name.setStyleSheet("font-size: 21px; font-weight: 600;")
        titles.addWidget(name)
        titles.addWidget(label("The key goes out.", "Tagline"))
        row.addLayout(titles)
        row.addStretch(1)

        self.idle_label = label("", "Faint")
        row.addWidget(self.idle_label)

        self.anchor_button = QPushButton("")
        self.anchor_button.setObjectName("Ghost")
        self.anchor_button.setCursor(Qt.PointingHandCursor)
        self.anchor_button.setToolTip(
            "A fingerprint of this vault's whole history. Write it down "
            "somewhere else and you can tell later if the history was replaced.")
        self.anchor_button.setFont(theme.mono_font(9))
        self.anchor_button.clicked.connect(self._show_anchor)
        row.addWidget(self.anchor_button)

        lock_button = QPushButton("Lock vault")
        lock_button.setCursor(Qt.PointingHandCursor)
        lock_button.setToolTip("Wipe the keys from memory and return to the unlock screen")
        lock_button.clicked.connect(self._lock_vault)
        row.addWidget(lock_button)
        return row

    def _build_stats(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(12)
        self.stat_locked = StatTile("Locked", "0")
        self.stat_soon = StatTile("Due within 24h", "0", theme.WARNING)
        self.stat_destroyed = StatTile("Keys destroyed", "0", theme.TEXT_MUTED)
        self.stat_next = StatTile("Next deadline", "—", theme.PRIMARY)
        for tile in (self.stat_locked, self.stat_soon, self.stat_destroyed, self.stat_next):
            row.addWidget(tile, 1)
        return row

    def _build_actions(self) -> WrapRow:
        # A folding row rather than a plain one: six buttons side by side would
        # otherwise set the window's minimum width, and on a small screen at
        # large text that means a window nothing can resize to fit.
        row = WrapRow(spacing=10)

        self.lock_files_button = QPushButton("Lock files…")
        self.lock_files_button.setObjectName("Primary")
        self.lock_files_button.setMinimumHeight(40)
        self.lock_files_button.setCursor(Qt.PointingHandCursor)
        self.lock_files_button.clicked.connect(self._lock_files)
        row.addWidget(self.lock_files_button)

        self.open_button = QPushButton("Open…")
        self.open_button.setMinimumHeight(40)
        self.open_button.setCursor(Qt.PointingHandCursor)
        self.open_button.clicked.connect(self._open_selected)
        row.addWidget(self.open_button)

        self.bring_back_button = QPushButton("Bring back")
        self.bring_back_button.setMinimumHeight(40)
        self.bring_back_button.setCursor(Qt.PointingHandCursor)
        self.bring_back_button.setToolTip(
            "Lock any edits back in, then shred the working copies")
        self.bring_back_button.clicked.connect(self._bring_back_selected)
        # Shown only when something is actually out, so the action row does not
        # carry a permanently dead button — or widen the window's floor for it.
        self.bring_back_button.setVisible(False)
        row.addWidget(self.bring_back_button)

        self.reveal_button = QPushButton("Show in folder")
        self.reveal_button.setMinimumHeight(40)
        self.reveal_button.setCursor(Qt.PointingHandCursor)
        self.reveal_button.clicked.connect(self._reveal_selected)
        row.addWidget(self.reveal_button)

        row.addStretch(1)

        self.expire_button = QPushButton("Destroy key now")
        self.expire_button.setObjectName("Danger")
        self.expire_button.setMinimumHeight(40)
        self.expire_button.setCursor(Qt.PointingHandCursor)
        self.expire_button.clicked.connect(self._expire_selected)
        row.addWidget(self.expire_button)

        self.forget_button = QPushButton("Remove from vault")
        self.forget_button.setObjectName("Danger")
        self.forget_button.setMinimumHeight(40)
        self.forget_button.setCursor(Qt.PointingHandCursor)
        self.forget_button.clicked.connect(self._forget_selected)
        row.addWidget(self.forget_button)
        return row

    def _build_table(self) -> QWidget:
        self.model = EntryTableModel(self.session, self)
        self.proxy = QSortFilterProxyModel(self)
        self.proxy.setSourceModel(self.model)
        self.proxy.setSortRole(SORT_ROLE)
        self.proxy.setDynamicSortFilter(False)

        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        # Room for several rows without being a floor the window has to
        # honour: the page around it scrolls, so this is a preference.
        self.table.setMinimumHeight(theme.scaled(60))
        self.table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.table.setSortingEnabled(True)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(40)
        self.table.doubleClicked.connect(lambda _index: self._open_selected())
        self.table.selectionModel().selectionChanged.connect(self._refresh_buttons)

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Fixed)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        for column in (2, 3, 4, 5, 6, 7):
            header.setSectionResizeMode(column, QHeaderView.ResizeToContents)
        self.table.setColumnWidth(0, 48)
        # Oldest first, matching the numbering, rather than whatever Qt picks.
        self.table.sortByColumn(0, Qt.AscendingOrder)

        wrapper = QWidget()
        wrapper.setObjectName("Root")
        column = QVBoxLayout(wrapper)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(10)
        column.addWidget(self.table, 1)

        self.empty_state = label(
            "Nothing is locked yet. Use “Lock files…”, or drop files onto this "
            "window.", "Faint", wrap=True)
        self.empty_state.setAlignment(Qt.AlignCenter)
        column.addWidget(self.empty_state)

        column.addWidget(self._build_shared())
        return wrapper

    def _build_shared(self) -> QWidget:
        """Shared files, kept visibly apart from everything with a deadline.

        These are not entries and never appear in the table above. Nothing in
        this vault holds a key for them, nothing here can destroy them, and
        showing them in the same list — even greyed out, even with a dash in
        the deadline column — would invite exactly the assumption the rest of
        this application exists to prevent.
        """
        self.shared_panel = QWidget()
        self.shared_panel.setObjectName("Root")
        column = QVBoxLayout(self.shared_panel)
        column.setContentsMargins(0, 8, 0, 0)
        column.setSpacing(8)
        column.addWidget(Divider())

        heading = QHBoxLayout()
        heading.setSpacing(10)
        heading.addWidget(label("SHARED FILES — NO DEADLINE, NOT RECALLABLE",
                                "Section"))
        heading.addStretch(1)
        self.open_shared_button = QPushButton("Unlock shared files…")
        self.open_shared_button.setCursor(Qt.PointingHandCursor)
        self.open_shared_button.clicked.connect(self._open_shared_file)
        heading.addWidget(self.open_shared_button)
        self.forget_shared_button = QPushButton("Forget")
        self.forget_shared_button.setCursor(Qt.PointingHandCursor)
        self.forget_shared_button.setToolTip(
            "Remove it from this list. The file itself is untouched and still "
            "opens with its passphrase — there is nothing here that could "
            "change that.")
        self.forget_shared_button.clicked.connect(self._forget_shared)
        heading.addWidget(self.forget_shared_button)
        column.addLayout(heading)

        caveat = label(
            "Each of these carries its own key. Whoever has a copy and the "
            "passphrase can open it for as long as it exists; this vault "
            "holds nothing that could stop them.", "Faint", wrap=True)
        caveat.setMinimumWidth(1)
        column.addWidget(caveat)

        self.shared_table = QTableWidget(0, 4)
        self.shared_table.setHorizontalHeaderLabels(
            ["Written", "Files", "Size", "Saved at"])
        self.shared_table.verticalHeader().setVisible(False)
        self.shared_table.verticalHeader().setDefaultSectionSize(theme.scaled(34))
        self.shared_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.shared_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.shared_table.setShowGrid(False)
        self.shared_table.setAlternatingRowColors(True)
        header = self.shared_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.shared_table.doubleClicked.connect(
            lambda _index: self._open_selected_shared())
        column.addWidget(self.shared_table)
        return self.shared_panel

    def _build_footer(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(10)
        # Wrapping, and allowed to shrink: unwrapped this sentence is the
        # widest thing in the window, and it would set the minimum width of
        # the whole application to something a small screen cannot give it.
        caveat = label(
            "Expiry here is tamper-evident, not tamper-proof: a copy of the "
            "vault folder taken before a deadline and restored afterwards "
            "defeats it.", "Faint", wrap=True)
        caveat.setMinimumWidth(1)
        row.addWidget(caveat, 1)
        link = QPushButton("What this does not protect against")
        link.setObjectName("Ghost")
        link.setCursor(Qt.PointingHandCursor)
        link.clicked.connect(self._show_limitations)
        row.addWidget(link)
        row.addStretch(1)
        return row

    # -- timers -----------------------------------------------------------

    def _wire_timers(self) -> None:
        self.tick_timer = QTimer(self)
        self.tick_timer.setInterval(1000)
        self.tick_timer.timeout.connect(self._tick)
        self.tick_timer.start()

        self.sweep_timer = QTimer(self)
        self.sweep_timer.setInterval(SWEEP_INTERVAL_SECONDS * 1000)
        self.sweep_timer.timeout.connect(self._sweep)
        self.sweep_timer.start()

    def _tick(self) -> None:
        self.model.tick()
        self._refresh_stats()
        remaining = self.session.auto_lock_seconds - self.session.idle_seconds()
        if self.session.auto_lock_seconds:
            self.idle_label.setText(
                f"auto-lock in {expiry_mod.format_duration(max(0, remaining))}")
        if self.session.should_auto_lock():
            self._lock_vault(automatic=True)

    def _sweep(self) -> None:
        if not self.session.is_open:
            return
        report = self.session.sweep()
        if report.changed:
            self.refresh()
            extra = ""
            if report.blobs_deleted:
                extra = (f" {len(report.blobs_deleted)} locked file"
                         f"{'s' if len(report.blobs_deleted) != 1 else ''} deleted too.")
            self.notice.show_message(report.summary() + extra, "warning")
        self._warn_ahead()

    def _warn_ahead(self) -> None:
        """Say what is coming, once, before it happens.

        The banner is for whoever is looking at the window; the tray message is
        for whoever is not. Both come from the same pass, so a warning is never
        delivered twice by two routes.
        """
        with self.session.guard:
            said = warnings_mod.send(self.session.vault, self._deliver_warning)
        if said.due:
            self.notice.show_message(said.summary() + " Move the deadline or "
                                     "check in if that is not what you want.",
                                     "warning")

    def _deliver_warning(self, title: str, message: str, urgency: str) -> None:
        if self.tray is not None:
            self.tray.notify(title, message)

    # -- actions ----------------------------------------------------------

    def _selected_entries(self) -> list[Entry]:
        rows = {index.row() for index in self.table.selectionModel().selectedRows()}
        entries = []
        for row in sorted(rows):
            source = self.proxy.mapToSource(self.proxy.index(row, 0))
            entry = self.model.entry_at(source.row())
            if entry is not None:
                entries.append(entry)
        return entries

    def _lock_files(self, initial_paths: Optional[list[str]] = None) -> None:
        self.session.touch()
        dialog = LockDialog(self.session, self, initial_paths)
        if dialog.exec_() == QDialog.Accepted and dialog.result_entry is not None:
            self.refresh()
            entry = dialog.result_entry
            when = ("no deadline" if entry.expires is None
                    else f"key dies {expiry_mod.format_time(entry.expires)}")
            self.notice.show_message(
                f"Locked {entry.display_name} → "
                f"{os.path.basename(entry.blob_path)} ({when}).", "success")

    def _open_selected(self) -> None:
        self.session.touch()
        entries = self._selected_entries()
        if not entries:
            return
        entry = entries[0]
        if entry.key_destroyed:
            self.notice.show_message(
                f"The key for {entry.display_name} was destroyed "
                f"{expiry_mod.format_time(entry.expired_at)}. The .qkey file may "
                "still be on disk, and it is permanently unreadable — by this "
                "app and by anything else.", "danger")
            return
        dialog = UnlockDialog(self.session, entry, self)
        if dialog.exec_() == QDialog.Accepted:
            self.refresh()
            count = len(dialog.written)
            plural = "s" if count != 1 else ""
            if dialog.on_loan:
                until = self.session.vault and [
                    e for e in self.session.vault.entries() if e.id == entry.id]
                deadline = (expiry_mod.format_time(until[0].checkout_until)
                            if until and until[0].checkout_until else "shortly")
                self.notice.show_message(
                    f"Lent {count} file{plural} to {dialog.destination} until "
                    f"{deadline}. Anything you edit there is locked back in "
                    f"when it comes back; the working copies are then "
                    f"shredded. Copies you make elsewhere are not reached.",
                    "warning")
            else:
                self.notice.show_message(
                    f"Extracted {count} file{plural} to {dialog.destination}. "
                    "Those copies are now ordinary files — expiry cannot "
                    "reach them.", "success")

    def _bring_back_selected(self) -> None:
        self.session.touch()
        out = [e for e in self._selected_entries() if e.checked_out]
        if not out:
            return
        reports = []
        with self.session.guard:
            for entry in out:
                reports.append((entry, locker.check_in(self.session.vault, entry.id)))
        self.refresh()

        saved = [r for _e, r in reports if r.saved]
        stranded = [r for _e, r in reports if r.edited and not r.saved]
        if stranded:
            first = stranded[0]
            self.notice.show_message(
                f"{len(first.edited)} edited file"
                f"{'s were' if len(first.edited) != 1 else ' was'} left on "
                f"disk rather than destroyed, because {first.not_saved_because}. "
                f"Deal with them yourself, then lock them again.", "warning")
        elif saved:
            total = sum(len(r.edited) for r in saved)
            self.notice.show_message(
                f"Brought back {len(reports)} item"
                f"{'s' if len(reports) != 1 else ''}. {total} edited file"
                f"{'s were' if total != 1 else ' was'} locked back into the "
                f"vault, and the working copies shredded.", "success")
        else:
            shredded = sum(len(r.shredded) for _e, r in reports)
            self.notice.show_message(
                f"Brought back {len(reports)} item"
                f"{'s' if len(reports) != 1 else ''}. {shredded} working cop"
                f"{'ies' if shredded != 1 else 'y'} shredded; nothing had "
                f"been edited, so the vault is unchanged.", "success")

    def _lock_to_share(self, initial_paths=None) -> None:
        self.session.touch()
        dialog = ShareDialog(self.session, self, initial_paths)
        if dialog.exec_() == QDialog.Accepted and dialog.result is not None:
            self.refresh()
            self.notice.show_message(
                f"Wrote {os.path.basename(dialog.result.path)}. It opens with "
                f"the passphrase you chose, on any machine, with no vault — "
                f"and it has no deadline, so nothing here can take it back.",
                "warning")

    def _selected_shared(self):
        rows = {index.row() for index in self.shared_table.selectedIndexes()}
        records = self.session.vault.shared_records()
        return [records[row] for row in sorted(rows) if row < len(records)]

    def _open_shared_file(self, path: str = "") -> None:
        """The unlock screen, optionally with one file pre-selected."""
        self.session.touch()
        dialog = UnlockSharedDialog(self.session, self,
                                    [path] if path else None)
        dialog.exec_()
        opened = [o for o in dialog.outcomes if o.ok]
        if opened:
            self.refresh()
            files = sum(len(o.written) for o in opened)
            self.notice.show_message(
                f"Unlocked {len(opened)} file"
                f"{'s' if len(opened) != 1 else ''} — {files} item"
                f"{'s' if files != 1 else ''} written beside them, named "
                f"{locker.UNLOCKED_SUFFIX}. Those copies are ordinary files "
                f"now.", "success")

    def _open_selected_shared(self) -> None:
        records = self._selected_shared()
        if records:
            self._open_shared_file(records[0].get("path", ""))

    def _forget_shared(self) -> None:
        records = self._selected_shared()
        if not records:
            return
        names = ", ".join(os.path.basename(r.get("path", "?")) for r in records[:3])
        confirmed = ConfirmDialog.ask(
            self, "Forget these shared files?",
            f"{names} will be taken off this list. The files themselves are "
            f"not touched and go on opening with their passphrases.",
            confirm_text="Forget",
            detail="There is no way to revoke a shared file. Forgetting one "
                   "only stops this vault reminding you that it exists.")
        if not confirmed:
            return
        with self.session.guard:
            for record in records:
                self.session.vault.forget_shared(record["id"])
        self.refresh()

    def _refresh_shared(self) -> None:
        records = self.session.vault.shared_records()
        self.shared_panel.setVisible(bool(records))
        self.shared_table.setRowCount(len(records))
        for row, record in enumerate(records):
            path = record.get("path", "")
            cells = [
                expiry_mod.format_time(record.get("created", 0)),
                ", ".join(record.get("names", [])) or "(none recorded)",
                expiry_mod.format_size(record.get("size", 0)),
                path.replace(os.path.expanduser("~"), "~"),
            ]
            for column, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if column == 0:
                    item.setIcon(QIcon(theme.no_deadline_pixmap(
                        theme.scaled(11))))
                    item.setToolTip("No deadline. This file carries its own "
                                    "key and cannot be recalled.")
                if column == 3 and path and not os.path.exists(path):
                    item.setText(text + "  (moved or deleted)")
                self.shared_table.setItem(row, column, item)

        # Only as tall as it needs to be: an empty expanse under one row makes
        # the section look like the main list, which is the impression this
        # whole arrangement exists to avoid.
        rows = max(1, min(len(records), 4))
        self.shared_table.setFixedHeight(
            self.shared_table.horizontalHeader().height()
            + rows * theme.scaled(34) + theme.scaled(8))
        self.forget_shared_button.setEnabled(bool(records))

    def _reveal_selected(self) -> None:
        entries = self._selected_entries()
        if not entries:
            return
        folder = os.path.dirname(entries[0].blob_path)
        try:
            subprocess.Popen(["xdg-open", folder])
        except OSError:
            self.notice.show_message(f"The locked file is in {folder}", "info")

    def _expire_selected(self) -> None:
        self.session.touch()
        entries = [e for e in self._selected_entries() if not e.key_destroyed]
        if not entries:
            return
        names = ", ".join(e.display_name for e in entries[:4])
        more = "" if len(entries) <= 4 else f" and {len(entries) - 4} more"
        confirmed = ConfirmDialog.ask(
            self, "Destroy the key now?",
            f"This overwrites the key for {names}{more} in the vault, right now, "
            "ahead of any deadline.",
            confirm_text="Destroy the key",
            acknowledgement="I understand this cannot be undone.",
            detail="Every copy of the locked file becomes permanently "
                   "unreadable — the ones you have, and the ones you do not.")
        if not confirmed:
            return
        with self.session.guard:
            report = expiry_mod.expire_now(self.session.vault, [e.id for e in entries],
                                           delete_blobs=False)
        self.refresh()
        self.notice.show_message(
            f"Destroyed {len(report.expired)} key"
            f"{'s' if len(report.expired) != 1 else ''}.", "warning")

    def _forget_selected(self) -> None:
        self.session.touch()
        entries = self._selected_entries()
        if not entries:
            return
        live = [e for e in entries if not e.key_destroyed]
        detail = ("The .qkey files stay where they are. Removing a live entry "
                  "wipes its key as it goes, so those files become unreadable "
                  "too." if live else
                  "These keys are already gone; this only tidies the list.")
        confirmed = ConfirmDialog.ask(
            self, "Remove from the vault?",
            f"Remove {len(entries)} entr{'ies' if len(entries) != 1 else 'y'} "
            "from the vault's list.",
            confirm_text="Remove",
            acknowledgement=("I understand the keys go with them."
                             if live else "Remove these entries."),
            detail=detail)
        if not confirmed:
            return
        with self.session.guard:
            for entry in entries:
                self.session.vault.remove_entry(entry.id)
            self.session.vault.save()
        self.refresh()
        self.notice.show_message(f"Removed {len(entries)} entr"
                                 f"{'ies' if len(entries) != 1 else 'y'}.", "muted")

    def _lock_vault(self, automatic: bool = False) -> None:
        self.tick_timer.stop()
        self.sweep_timer.stop()
        self.session.close()
        self.closed.emit()
        self.close()

    # -- dialogs ----------------------------------------------------------

    def security_report(self) -> str:
        """Everything this vault will admit about itself, as plain text.

        Separate from the dialog that shows it so the same text can be
        checked by a test rather than only looked at.
        """
        vault = self.session.vault
        header = vault.header
        from ..crypto import cipher_name

        # The strength recorded when the vault was created, if it was recorded.
        recorded = next((e for e in reversed(vault.events)
                         if e.get("kind") == "passphrase_strength"), None)
        if recorded is None:
            passphrase_line = "not recorded (vault predates this field)"
        else:
            basis = "exact" if recorded.get("generated") else "estimated"
            warning = "  <-- below the recommended floor, accepted deliberately" \
                if recorded.get("below_floor") else ""
            passphrase_line = (f"{recorded['bits']:.0f} bits {basis} "
                               f"({recorded.get('label', '?')}){warning}")

        report = vault.chain_report()
        custodian = vault.custodian
        lines = [
            ("Vault file", vault.path),
            ("Vault id", vault.vault_id),
            ("Cipher", cipher_name(header.cipher_id) + " (AEAD)"),
            ("Key derivation", f"Argon2id — {header.kdf.memory_kib // 1024} MiB, "
                               f"{header.kdf.time_cost} pass"
                               f"{'es' if header.kdf.time_cost != 1 else ''}, "
                               f"parallelism {header.kdf.parallelism}"),
            ("Second factor", {
                "keyfile": "keyfile required",
                "fido2": "hardware security key required",
            }.get(header.factor_kind, "none — passphrase only")),
            ("Passphrase at creation", passphrase_line),
            ("Per-file keys", "256-bit, from os.urandom, one per locked item"),
            ("Clock watermark", expiry_mod.format_time(vault.last_seen)),
            ("Entries", str(len(vault.entries()))),
            ("Event chain", report.summary()),
            ("Anchor", vault.chain_fingerprint),
            ("Certificates issued", str(len(vault.certificates))),
            ("Custodian", (f"{custodian.name} — {custodian.title}"
                           if custodian.is_set else "not set")),
        ]
        body = "\n".join(f"{name}:  {value}" for name, value in lines)

        recent = vault.events[-12:]
        log = "\n".join(
            f"{expiry_mod.format_time(event['at'])}  {event['kind']}"
            for event in reversed(recent))

        return body + "\n\nRecent events\n" + log

    def _show_security(self) -> None:
        _TextDialog("Security details", self.security_report(),
                    self, monospace=True).exec_()

    def _show_anchor(self) -> None:
        self.session.touch()
        AnchorDialog(self.session, self).exec_()

    def _show_certificates(self) -> None:
        self.session.touch()
        CertificatesDialog(self.session, self).exec_()

    def _show_backups(self) -> None:
        dialog = BackupDialog(self.session, self)
        if dialog.exec_() == QDialog.Accepted and dialog.restored:
            # The vault on disk is no longer the one in memory, so the session
            # has to end here rather than carry on against a stale copy.
            self.notice.show_message(
                f"Restored {dialog.restore_info.name}. The vault it replaced "
                f"was kept as {os.path.basename(dialog.displaced)}. Quenchkey "
                f"will lock now so the restored vault can be opened.",
                "warning")
            self._pending_restore = (dialog.restore_info, dialog.restore_cost,
                                     dialog.displaced)
            QTimer.singleShot(2500, self._lock_vault)

    def _hand_over(self, initial_paths=None) -> None:
        self.session.touch()
        dialog = HandoverDialog(self.session, self, initial_paths)
        dialog.exec_()
        if dialog.written:
            self.refresh()
            self.notice.show_message(
                f"Wrote {os.path.basename(dialog.written)}. It opens in one "
                f"vault and nowhere else. When they accept it the deadline "
                f"lands in their vault and their own sweep enforces it \u2014 "
                f"but they can decline, and nothing here reaches a copy they "
                f"have already extracted.", "warning")

    def _accept_handover(self, path: Optional[str] = None) -> None:
        self.session.touch()
        if not path:
            path = filechooser.open_file(
                self, "Which addressed file?", os.path.expanduser("~"),
                patterns=["Quenchkey locked file (*.qkey)", "All files (*)"])
        if not path:
            return
        try:
            described = handover_mod.describe(path)
        except (handover_mod.HandoverError, OSError, UnsupportedFormat) as exc:
            self.notice.show_message(str(exc), "danger")
            return

        if not handover_mod.addressed_to_me(self.session.vault, path):
            self.notice.show_message(
                "That file is addressed to a different vault, and no "
                "passphrase will change that. Ask whoever sent it for one "
                "addressed to yours \u2014 your identity card is under "
                "Vault \u25b8 My identity card.", "danger")
            return

        terms = described["terms"]
        who = (terms.sender_label or terms.sender_vault_id[:16]
               or "somebody unidentified")
        names = ", ".join(terms.names[:4]) or "(nothing recorded)"
        more = "" if len(terms.names) <= 4 else f" and {len(terms.names) - 4} more"
        body = f"From {who}.\n\n{names}{more}\n\nTerms: {terms.describe()}."
        if terms.note:
            body += f"\n\n\u201c{terms.note}\u201d"
        confirmed = ConfirmDialog.ask(
            self, "Accept these terms?", body,
            confirm_text="Accept",
            detail="Accepting puts the key in this vault, where these rules "
                   "are enforced by your own sweep. There is no way to read "
                   "the file without accepting them. Once you open it, the "
                   "copy that comes out is an ordinary file and expiry cannot "
                   "reach it.")
        if not confirmed:
            return

        try:
            with self.session.guard:
                entry = handover_mod.accept(self.session.vault, path)
        except (handover_mod.HandoverError, OSError) as exc:
            self.notice.show_message(str(exc), "danger")
            return
        self.refresh()
        self.notice.show_message(
            f"Accepted {entry.display_name}. It is an ordinary entry now: "
            f"{entry.rule_summary()}, enforced by this vault.", "success")

    def _show_identity(self) -> None:
        self.session.touch()
        IdentityCardDialog(self.session, self).exec_()

    def _show_audit(self) -> None:
        self.session.touch()
        dialog = AuditDialog(self.session, self)
        dialog.exec_()
        if dialog.changed:
            self.refresh()

    def _show_integrity(self) -> None:
        self.session.touch()
        dialog = IntegrityDialog(self.session, self)
        dialog.exec_()
        self.refresh()
        if dialog.report is not None and not dialog.report.ok:
            self.notice.show_message(dialog.report.summary() + " "
                                     + dialog.report.advice(), "warning")

    def _show_watch(self) -> None:
        dialog = WatchFoldersDialog(self.session, self)
        dialog.exec_()
        if dialog.changed:
            rules = self.session.vault.watch_rules()
            self.notice.show_message(
                f"{len(rules)} folder{'s are' if len(rules) != 1 else ' is'} "
                f"being watched. Anything dropped in is locked a few seconds "
                f"later — while Quenchkey is open." if rules else
                "No folders are being watched any more.",
                "info")

    def _show_duress(self) -> None:
        dialog = DuressDialog(self.session, self)
        dialog.exec_()
        if dialog.changed:
            armed = self.session.vault.duress_armed
            self.notice.show_message(
                "A duress passphrase is armed. Typing it at the unlock screen "
                "destroys this vault without asking." if armed else
                "The duress passphrase has been removed.",
                "warning" if armed else "info")

    def _show_settings(self) -> None:
        SettingsDialog(self).exec_()

    def _show_help(self, page: int = 0) -> None:
        HelpDialog(self, page=page).exec_()

    def _show_about(self) -> None:
        from .app import version_report
        _TextDialog("About Quenchkey", version_report(), self,
                    monospace=True).exec_()

    def _uninstall(self) -> None:
        """Remove the application. The vault is deliberately left alone.

        Only reachable with the vault unlocked, which is friction rather than
        security: this menu item is not what stands between anybody and your
        files. Deleting Quenchkey grants access to nothing — what protects a
        locked file is that it is encrypted and its key is elsewhere or gone.
        Somebody who wants the application gone can delete it from a terminal
        without ever opening it, and would end up in exactly the same place:
        unreadable files and a recovery script that still asks for the
        passphrase.
        """
        if not self.session.is_open:
            _TextDialog(
                "Unlock the vault first",
                "Uninstalling from inside Quenchkey needs the vault open.\n\n"
                "To be clear about what that is and is not: it is a pause, "
                "not a lock. Removing this application has never given "
                "anybody access to anything, and deleting the vault does the "
                "opposite of unlocking it — it destroys every key at once and "
                "makes every file you locked permanently unreadable.",
                self).exec_()
            return

        report = uninstall.describe()
        if not report.found:
            _TextDialog(
                "Uninstall Quenchkey",
                "No installation was found to remove.\n\n"
                f"{report.detail}\n\n"
                "If you are running Quenchkey from a source checkout there is "
                "nothing installed to take away — delete the folder.",
                self).exec_()
            return

        confirmed = ConfirmDialog.ask(
            self, "Uninstall Quenchkey?",
            f"This removes the application from {report.prefix}: the "
            f"quenchkey and quenchkey-recover commands, the menu entry, the icons, "
            f"the .qkey file type and the background timer.",
            confirm_text="Uninstall",
            acknowledgement="I understand my vault and my locked files are "
                            "not touched.",
            detail="Your vault stays at ~/.quenchkey and every .qkey file stays "
                   "where it is. Removing the application destroys no keys — "
                   "that only happens on a deadline you set, or when you ask. "
                   "Nor does it unlock anything: what protects your files is "
                   "the encryption, not this application.")
        if not confirmed:
            return

        result = uninstall.run()
        if result.ok:
            _TextDialog(
                "Quenchkey has been removed",
                f"{result.detail}\n\n"
                "Your vault and your locked files were left alone. To remove "
                "the vault as well — which makes every .qkey file you "
                "locked permanently unreadable — delete ~/.quenchkey yourself.\n\n"
                "This window is the last thing running. Close it and Quenchkey "
                "is gone.",
                self).exec_()
            self.quit_fully()
        else:
            _TextDialog("Could not uninstall",
                        f"{result.detail}\n\nYou can remove it by hand with:\n"
                        f"    ./install.sh --uninstall",
                        self, monospace=True).exec_()

    def _show_background(self) -> None:
        dialog = BackgroundExpiryDialog(self.session, self)
        dialog.exec_()
        if dialog.changed:
            on = self.session.vault.background_expiry
            self.notice.show_message(
                "Expiry while Quenchkey is closed is on. Deadlines for this "
                "vault are now listed in a file beside it, which is how the "
                "background task can see them." if on else
                "Expiry while Quenchkey is closed is off, and the list of "
                "deadlines beside the vault has been removed.",
                "warning" if on else "info")

    def _show_custodian(self) -> None:
        self.session.touch()
        if CustodianDialog(self.session, self).exec_() == QDialog.Accepted:
            self.refresh()
            self.notice.show_message(
                "Custodian details saved. They will appear on certificates "
                "issued from now on; certificates already issued are signed and "
                "cannot be changed.", "success")

    def _show_shares(self) -> None:
        self.session.touch()
        RecoverySharesDialog(self.session, self).exec_()
        self.refresh()

    def _show_limitations(self) -> None:
        _TextDialog("What Quenchkey does not protect against",
                    limitations_html(), self, rich=True).exec_()

    # -- drag and drop ----------------------------------------------------

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:  # noqa: N802
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent) -> None:  # noqa: N802
        paths = [url.toLocalFile() for url in event.mimeData().urls()
                 if url.isLocalFile()]
        if paths:
            event.acceptProposedAction()
            self._lock_files(paths)

    # -- refresh ----------------------------------------------------------

    def refresh(self) -> None:
        self.session.touch()
        # Resetting the model clears the selection, and losing your place after
        # every action means hunting for the same row again. Held by entry id,
        # because the row number may well have moved.
        chosen = {entry.id for entry in self._selected_entries()}
        self.model.refresh()
        self.proxy.invalidate()
        self._reselect(chosen)
        self._refresh_stats()
        self._refresh_buttons()
        has_rows = self.model.rowCount() > 0
        self.table.setVisible(has_rows)
        self.empty_state.setVisible(not has_rows)
        self._refresh_shared()
        self._refresh_anchor()
        self.statusBar().showMessage(self._status_text())

    def _reselect(self, entry_ids: set) -> None:
        """Put the selection back on the same entries, wherever they moved to."""
        if not entry_ids:
            return
        selection = self.table.selectionModel()
        if selection is None:
            return
        mode = QItemSelectionModel.Select | QItemSelectionModel.Rows
        selection.clearSelection()
        for row in range(self.proxy.rowCount()):
            index = self.proxy.index(row, 0)
            entry = self.model.entry_at(self.proxy.mapToSource(index).row())
            if entry is not None and entry.id in entry_ids:
                selection.select(index, mode)

    def _refresh_anchor(self) -> None:
        if self.session.is_open:
            self.anchor_button.setText(self.session.vault.chain_fingerprint)

    def _refresh_stats(self) -> None:
        if not self.session.is_open:
            return
        now = self.session.vault.effective_now()
        entries = self.session.vault.entries()
        live = [e for e in entries if not e.key_destroyed]
        destroyed = [e for e in entries if e.key_destroyed]
        soon = [e for e in live if e.expires is not None
                and 0 <= e.expires - now <= expiry_mod.URGENCY_WARNING]
        upcoming = sorted((e for e in live if e.expires is not None),
                          key=lambda e: e.expires)

        self.stat_locked.set_value(str(len(live)))
        self.stat_soon.set_value(str(len(soon)),
                                 theme.WARNING if soon else theme.TEXT_MUTED)
        self.stat_destroyed.set_value(str(len(destroyed)))
        if upcoming:
            remaining = upcoming[0].expires - now
            tone = (theme.DANGER if remaining <= expiry_mod.URGENCY_CRITICAL
                    else theme.WARNING if remaining <= expiry_mod.URGENCY_WARNING
                    else theme.PRIMARY)
            self.stat_next.set_value(expiry_mod.format_duration(max(0, remaining)), tone)
        else:
            self.stat_next.set_value("—", theme.TEXT_MUTED)

    def _refresh_buttons(self) -> None:
        entries = self._selected_entries()
        live = [e for e in entries if not e.key_destroyed]
        self.open_button.setEnabled(len(live) == 1)
        anywhere = any(e.checked_out for e in self.session.vault.entries()) \
            if self.session.is_open else False
        out = [e for e in entries if e.checked_out]
        self.bring_back_button.setVisible(anywhere)
        self.bring_back_button.setEnabled(bool(out))
        self.reveal_button.setEnabled(len(entries) == 1)
        self.expire_button.setEnabled(bool(live))
        self.forget_button.setEnabled(bool(entries))

    def _status_text(self) -> str:
        if not self.session.is_open:
            return "Vault locked"
        return (f"Vault open · {self.session.vault.path} · keys are in memory "
                f"only until this window locks")

    def showEvent(self, event) -> None:  # noqa: N802
        super().showEvent(event)
        if self._placed:
            return
        self._placed = True
        if settings_mod.current().get("fill_screen", True):
            # Retried, not deferred once. A window manager decorates the
            # window some time after it is mapped, and until it has, Qt
            # reports a frame identical to the client area — which would size
            # the window as if it had no title bar and push that title bar off
            # the top of the screen. Each pass re-reads the real frame, so
            # this converges within two.
            for delay in (0, 150, 500):
                QTimer.singleShot(delay,
                                  lambda: theme.fill_available_screen(self))

    # -- closing -----------------------------------------------------------

    def attach_tray(self, tray_icon) -> None:
        """Give the window the tray icon, if one appeared."""
        self.tray = tray_icon

    def quit_fully(self) -> None:
        """Lock the vault and close for good, whatever the close rule says."""
        self._really_quitting = True
        self.close()

    def _tray_is_usable(self) -> bool:
        return self.tray is not None and self.tray.active

    def closeEvent(self, event) -> None:  # noqa: N802
        """Quit, hide to the tray, or ask — and never silently vanish.

        The dangerous outcome is somebody closing the window believing it
        carried on running. So the tray is only offered when there is really
        one there, and a desktop without one quits regardless of the setting.
        """
        if self._really_quitting or not self.session.is_open:
            self._shut_down()
            super().closeEvent(event)
            return

        action = settings_mod.current().get("close_action")
        if not self._tray_is_usable():
            action = settings_mod.CLOSE_QUIT

        if action == settings_mod.CLOSE_ASK:
            action = self._ask_how_to_close()
            if action is None:
                event.ignore()
                return

        if action == settings_mod.CLOSE_TRAY:
            event.ignore()
            self.hide()
            self.tray.notify(
                "Quenchkey is still running",
                "Deadlines are still being checked, and the vault still locks "
                "itself when idle. Quit from the tray menu to close it.")
            return

        self._shut_down()
        super().closeEvent(event)

    def _ask_how_to_close(self):
        """Ask once, and offer to stop asking."""
        dialog = ConfirmDialog(
            "Keep Quenchkey running?",
            "The vault is unlocked. Keeping it in the tray means deadlines go "
            "on being checked and the vault still locks itself when idle. "
            "Quitting locks it now and wipes every key from memory.",
            confirm_text="Keep it running",
            cancel_text="Quit and lock",
            acknowledgement="Remember this and stop asking",
            acknowledgement_gates=False,
            tone="info",
            parent=self)
        outcome = dialog.exec_()
        remember = dialog.acknowledged()
        if outcome == QDialog.Accepted:
            if remember:
                settings_mod.current().set("close_action", settings_mod.CLOSE_TRAY)
            return settings_mod.CLOSE_TRAY
        if remember:
            settings_mod.current().set("close_action", settings_mod.CLOSE_QUIT)
        return settings_mod.CLOSE_QUIT

    def _shut_down(self) -> None:
        self.tick_timer.stop()
        self.sweep_timer.stop()
        self.session.close()
        if self.tray is not None:
            self.tray.hide()


class _TextDialog(QDialog):
    """A scrollable block of text."""

    def __init__(self, title: str, body: str, parent=None, monospace: bool = False,
                 rich: bool = False):
        super().__init__(parent)
        self.setObjectName("Root")
        self.setWindowTitle(title)
        self.setModal(True)
        theme.fit(self, 700, 560, 620, 420)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(theme.GUTTER, theme.GUTTER, theme.GUTTER, theme.GUTTER)
        outer.setSpacing(theme.GAP)
        # Wrapping, because a long title is otherwise a hard minimum width on
        # the whole dialog — at a large font that alone can make it wider than
        # the screen.
        outer.addWidget(label(title, "Title", wrap=True))
        outer.addWidget(Divider())

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)
        content = label(body, wrap=True)
        content.setTextFormat(Qt.RichText if rich else Qt.PlainText)
        content.setTextInteractionFlags(Qt.TextSelectableByMouse)
        content.setAlignment(Qt.AlignTop)
        if monospace:
            content.setFont(theme.mono_font(9))
        # A rich-text label reports the width of its widest unbreakable run as
        # its minimum, and a resizable scroll area passes that straight up to
        # the dialog. On a small screen at a large font that is enough to make
        # the dialog wider than the display it has to open on. Letting the
        # label shrink and offering a horizontal scrollbar instead keeps the
        # dialog inside the screen, which matters more than never scrolling.
        content.setMinimumWidth(1)
        holder = QWidget()
        holder.setMinimumWidth(1)
        holder_layout = QVBoxLayout(holder)
        holder_layout.setContentsMargins(2, 2, 12, 2)
        holder_layout.addWidget(content)
        holder_layout.addStretch(1)
        scroll.setWidget(holder)
        scroll.setMinimumWidth(1)
        outer.addWidget(scroll, 1)

        close = QPushButton("Close")
        close.setObjectName("Primary")
        close.setCursor(Qt.PointingHandCursor)
        close.clicked.connect(self.accept)
        row = QHBoxLayout()
        row.addStretch(1)
        row.addWidget(close)
        outer.addLayout(row)


#: The honest limitations, as (heading, body) pairs so the dialog can style
#: the headings and anything else can still read the plain text.
LIMITATIONS: list[tuple[str, str]] = [
    ("", "Quenchkey does one thing well: it keeps the key somewhere separate "
         "from the locked file, and destroys the key on a deadline. Everything "
         "below is outside what that can do, and no amount of interface would "
         "change it."),
    ("Rolling back local state",
     "Expiry is enforced by this machine, using this machine's clock and this "
     "machine's vault file. Someone who copies ~/.quenchkey before a deadline "
     "and restores it afterwards gets the key back.\n\n"
     "Winding the system clock backwards does not work — deadlines are judged "
     "against the latest time the vault has ever seen, and a backwards step is "
     "refused and logged. A filesystem snapshot, a backup, or a copied folder "
     "does work, and cannot be stopped from here. This is unavoidable for any "
     "tool that runs entirely on your own computer. Local state is "
     "tamper-evident at best; it is never tamper-proof."),
    ("Files that have already been opened",
     "Once a recipient decrypts and extracts a file, it is an ordinary file on "
     "their disk. It can be copied, printed, photographed or forwarded, and "
     "none of that passes through Quenchkey. Expiry destroys the key to the "
     "locked copy. It cannot recall anything that has already come out of one."),
    ("Screenshots and screen capture",
     "Quenchkey does not block screenshots, and will not pretend to. Blocking "
     "the Print Screen key stops nothing: a phone camera defeats it in a "
     "second, as does a virtual machine, a capture card, or a screen reader. "
     "Tools that advertise this are selling theatre."),
    ("\"Only our app can open these files\"",
     "Not a claim Quenchkey makes. This app can decrypt, so shipping this app "
     "ships that ability, and the format is documented. A custom extension "
     "changes the filename and nothing else. What actually protects the "
     "contents is that the key is 256 bits of randomness held in an encrypted "
     "vault — not obscurity about the file format."),
    ("Hidden or permission-protected folders",
     "Quenchkey does not hide anything or rely on file permissions to keep you "
     "out of a folder. Root defeats permissions and a live USB defeats both. "
     "The only honest version of \"inaccessible\" is that the plaintext "
     "genuinely does not exist while the file is locked, which is what locking "
     "actually does."),
    ("Failed-attempt lockout",
     "The delay after repeated wrong passphrases is a convenience feature. It "
     "slows down someone sitting at this keyboard. An attacker who copies the "
     "vault file attacks it offline, at whatever rate their hardware allows, "
     "where this app never runs and no counter exists. The Argon2id cost "
     "parameters are the real defence, and they are the reason unlocking takes "
     "about a second."),
    ("Data left behind on disk",
     "When Quenchkey deletes something it overwrites the bytes first, but on a "
     "copy-on-write filesystem (Btrfs, ZFS), a log-structured one, or an SSD "
     "doing wear levelling, the original blocks can survive untouched. "
     "Snapshots, backups and your editor's temporary files are all outside its "
     "reach. Treat \"shredded\" as \"removed with reasonable care\", not "
     "\"provably gone\"."),
    ("Memory",
     "The master key is held in a wipeable buffer and overwritten when the "
     "vault locks, and keys are kept out of logs and tracebacks. This is best "
     "effort: Python copies objects freely, and nothing here prevents a key "
     "reaching swap or a core dump. It shortens the window; it does not close "
     "it."),
    ("A compromised machine",
     "If something is already running as you — a keylogger, a memory scraper, a "
     "malicious extension — it can take the passphrase as you type it, or the "
     "keys out of memory while the vault is open. No file encryption tool "
     "solves this."),
    ("Coercion",
     "There is no duress passphrase and no hidden volume. If someone can compel "
     "you to unlock the vault, it unlocks."),
    ("What is left",
     "The passphrase, Argon2id, an authenticated cipher, and the fact that a "
     "key which no longer exists cannot be recovered by anyone, including "
     "whoever holds the encrypted file. That part is real, and it is the whole "
     "product."),
]


def limitations_text() -> str:
    """The limitations as plain text."""
    blocks = []
    for heading, body in LIMITATIONS:
        blocks.append(f"{heading.upper()}\n{body}" if heading else body)
    return "\n\n".join(blocks)


def limitations_html() -> str:
    """The same, with headings picked out in the accent colour."""
    import html as html_module

    blocks = []
    for heading, body in LIMITATIONS:
        if heading:
            blocks.append(
                f'<p style="color:{theme.PRIMARY}; font-weight:600; '
                f'margin-top:20px; margin-bottom:4px;">'
                f'{html_module.escape(heading)}</p>')
        for paragraph in body.split("\n\n"):
            blocks.append(f'<p style="margin-top:0; margin-bottom:8px;">'
                          f'{html_module.escape(paragraph)}</p>')
    return f'<div style="color:{theme.TEXT};">' + "".join(blocks) + "</div>"


#: Kept as a module-level name because the screenshot tool and tests read it.
LIMITATIONS_TEXT = limitations_text()
