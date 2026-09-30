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

"""The dialogs behind the evidence features: anchor, certificates, shares.

These are the parts of the interface whose job is to make a claim checkable
rather than to move files around, so each of them is written to say plainly
what it does and does not establish.
"""

from __future__ import annotations

import os
import time
from typing import Optional

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QAbstractItemView, QApplication, QCheckBox, QComboBox, QDialog, QHBoxLayout,
    QHeaderView, QLineEdit, QPlainTextEdit, QPushButton, QScrollArea,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from .. import certificate as certificate_module
from .. import expiry as expiry_mod, recovery, schedule
from .. import timestamping
from ..certificate import Custodian
from ..session import Session
from . import destinations, filechooser, theme
from .widgets import Banner, Card, label


class _Base(QDialog):
    """Shared scaffolding: a title, a scrollable body, a pinned footer."""

    def __init__(self, title: str, parent: Optional[QWidget] = None,
                 width: int = 760, height: int = 640):
        super().__init__(parent)
        self.setObjectName("Root")
        self.setWindowTitle(title)
        self.setModal(True)
        theme.fit(self, width, height, min(width, 660), 450)

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
        self.body = QVBoxLayout(canvas)
        self.body.setContentsMargins(theme.GUTTER, theme.GUTTER, theme.GUTTER, 8)
        self.body.setSpacing(theme.GAP)
        self.body.addWidget(label(title, "Title", wrap=True))

        footer = QWidget()
        footer.setObjectName("Root")
        self.footer = QHBoxLayout(footer)
        self.footer.setContentsMargins(theme.GUTTER, 10, theme.GUTTER, theme.GUTTER)
        self.footer.addStretch(1)
        shell.addWidget(footer)

    def add_close(self, text: str = "Close") -> QPushButton:
        button = QPushButton(text)
        button.setObjectName("Primary")
        button.setCursor(Qt.PointingHandCursor)
        button.clicked.connect(self.accept)
        self.footer.addWidget(button)
        return button


# --------------------------------------------------------------------------
# the anchor
# --------------------------------------------------------------------------

class AnchorDialog(_Base):
    """Shows the chain head and explains what writing it down achieves."""

    def __init__(self, session: Session, parent: Optional[QWidget] = None):
        super().__init__("Anchor this vault's history", parent, 800, 880)
        self.session = session
        self.certificate = ""
        vault = session.vault
        report = vault.chain_report()

        self.body.addWidget(label(
            "Every event in this vault records the hash of the one before it, "
            "so the value below is a fingerprint of its entire history. Write "
            "it down somewhere outside the vault and you gain something the "
            "vault cannot give you on its own: the ability to tell later "
            "whether its history has been replaced.", "Subtitle", wrap=True))

        card = Card(padding=20, spacing=10)
        card.body.addWidget(label("ANCHOR", "SectionHeading"))
        value = QLineEdit(vault.chain_fingerprint)
        value.setObjectName("Mono")
        value.setReadOnly(True)
        value.setMinimumHeight(48)
        value.setAlignment(Qt.AlignCenter)
        value.setStyleSheet(
            f"font-size: 20px; letter-spacing: 3px; color: {theme.PRIMARY};")
        card.body.addWidget(value)

        full = QLineEdit(vault.chain_head)
        full.setObjectName("Mono")
        full.setReadOnly(True)
        card.body.addWidget(label("Full head (if you would rather store all of it)",
                                  "Faint"))
        card.body.addWidget(full)

        row = QHBoxLayout()
        row.setSpacing(10)
        copy_short = QPushButton("Copy anchor")
        copy_short.setCursor(Qt.PointingHandCursor)
        copy_short.clicked.connect(
            lambda: QApplication.clipboard().setText(vault.chain_fingerprint))
        row.addWidget(copy_short)
        copy_full = QPushButton("Copy full head")
        copy_full.setObjectName("Ghost")
        copy_full.setCursor(Qt.PointingHandCursor)
        copy_full.clicked.connect(
            lambda: QApplication.clipboard().setText(vault.chain_head))
        row.addWidget(copy_full)
        row.addStretch(1)
        card.body.addLayout(row)
        self.body.addWidget(card)

        status = Card(padding=18, spacing=8)
        status.body.addWidget(label("CURRENT STATE", "SectionHeading"))
        status.body.addWidget(label(report.summary(),
                                    "SuccessText" if report.ok else "ErrorText",
                                    wrap=True))
        if vault.chain_was_migrated:
            status.body.addWidget(label(
                f"This vault predates chaining and was upgraded on "
                f"{expiry_mod.format_time(vault.chain_origin)}. Events before "
                "that were linked retroactively, which proves nothing about "
                "them — whoever ran the upgrade could have edited them first. "
                "Only events after that point carry tamper-evidence.",
                "Faint", wrap=True))
        elif vault.chain_origin:
            status.body.addWidget(label(
                f"Chained from the first event, {expiry_mod.format_time(vault.chain_origin)}.",
                "Faint", wrap=True))
        self.body.addWidget(status)

        self.body.addWidget(Banner(
            "Be clear about what this does. The chain alone proves only that "
            "the log is self-consistent — anyone holding your passphrase could "
            "rewrite the whole thing and recompute every hash, and a vault "
            "restored from an old backup is perfectly consistent too, because "
            "it was consistent when the backup was taken.\n\n"
            "The anchor is what turns that around. A rewritten or restored "
            "vault cannot reproduce a fingerprint recorded after the events it "
            "is missing. So write this down, somewhere the vault is not, and "
            "check it when it matters. It is detection, not prevention — "
            "nothing running only on your own computer can offer prevention.",
            "info"))

        # -- having somebody else sign it
        stamp = Card(padding=18, spacing=10)
        stamp.body.addWidget(label("HAVE SOMEBODY ELSE SIGN IT", "SectionHeading"))
        stamp.body.addWidget(label(
            "Writing the anchor down yourself works, and it depends on you "
            "remembering to. A timestamp authority will sign the anchor and a "
            "time for you, which is the same idea with somebody else doing "
            "the remembering \u2014 and it is proof anybody can check, "
            "offline, years later.", "Muted", wrap=True))
        stamp.body.addWidget(Banner(
            "Only a hash leaves this machine. The authority is handed 32 "
            "bytes and learns nothing else: not what is in the vault, not how "
            "many entries it has, not that it is a Quenchkey vault at all. It "
            "needs the network, so it is off unless you ask for it.", "info"))

        picker = QHBoxLayout()
        picker.setSpacing(10)
        picker.addWidget(label("Authority", "Faint"))
        self.authority = QComboBox()
        self.authority.setEditable(True)
        self.authority.setMinimumWidth(theme.scaled(260))
        for name, url in timestamping.KNOWN_AUTHORITIES:
            self.authority.addItem(f"{name} \u2014 {url}", url)
        picker.addWidget(self.authority, 1)
        stamp.body.addLayout(picker)

        certificate_row = QHBoxLayout()
        certificate_row.setSpacing(10)
        self.certificate_button = QPushButton("Their certificate\u2026")
        self.certificate_button.setCursor(Qt.PointingHandCursor)
        self.certificate_button.clicked.connect(self._choose_certificate)
        certificate_row.addWidget(self.certificate_button)
        self.certificate_label = label(
            "None chosen \u2014 a token will be stored, but not checked.",
            "Faint", wrap=True)
        self.certificate_label.setMinimumWidth(1)
        certificate_row.addWidget(self.certificate_label, 1)
        stamp.body.addLayout(certificate_row)

        self.stamp_button = QPushButton("Get a timestamp\u2026")
        self.stamp_button.setMinimumHeight(theme.scaled(38))
        self.stamp_button.setCursor(Qt.PointingHandCursor)
        self.stamp_button.clicked.connect(self._stamp)
        stamp.body.addWidget(self.stamp_button)

        self.stamp_note = label(_collected_note(vault), "Faint", wrap=True)
        self.stamp_note.setMinimumWidth(1)
        stamp.body.addWidget(self.stamp_note)
        self.body.addWidget(stamp)

        self.body.addWidget(label(
            "To check it later, without this application:", "Muted", wrap=True))
        command = QPlainTextEdit(
            f"./tools/quenchkey-recover.py audit vault.qkv "
            f"--expect {vault.chain_fingerprint}")
        command.setReadOnly(True)
        command.setFont(theme.mono_font(9))
        command.setMaximumHeight(60)
        self.body.addWidget(command)

        self.body.addStretch(1)
        self.add_close()

    def _choose_certificate(self) -> None:
        path = filechooser.open_file(
            self, "The authority's certificate",
            os.path.expanduser("~"),
            patterns=["Certificates (*.pem *.crt *.cer)", "All files (*)"])
        if not path:
            return
        self.certificate = path
        self.certificate_label.setText(
            f"{os.path.basename(path)} \u2014 tokens will be checked against "
            f"it, so a token that verifies is proof rather than a note.")

    def _stamp(self) -> None:
        url = (self.authority.currentData()
               or self.authority.currentText().split()[-1])
        target = destinations.file_for(
            "timestamps", self, "Save the timestamp token as",
            f"quenchkey-anchor-{time.strftime('%Y%m%d-%H%M%S')}.tsr",
            patterns=["Timestamp token (*.tsr)", "All files (*)"])
        if not target:
            return
        self.stamp_button.setEnabled(False)
        self.stamp_note.setText(f"Asking {url}\u2026")
        self.stamp_note.setStyleSheet("")
        QApplication.processEvents()
        try:
            with self.session.guard:
                report = timestamping.stamp_anchor(
                    self.session.vault, url, ca_file=self.certificate or None,
                    output_path=target)
        finally:
            self.stamp_button.setEnabled(True)
        self.stamp_note.setText(report.summary())
        self.stamp_note.setStyleSheet(
            "" if report.ok else f"color: {theme.WARNING};")


def _collected_note(vault) -> str:
    """What this vault has already collected, if anything."""
    tokens = timestamping.collected(vault)
    if not tokens:
        return "No timestamp has been taken for this vault yet."
    latest = tokens[-1]
    return (f"{len(tokens)} taken. Most recent: {latest.describe()}.")


# --------------------------------------------------------------------------
# certificates
# --------------------------------------------------------------------------

class CertificatesDialog(_Base):
    """Lists the destruction certificates this vault has issued."""

    COLUMNS = ["Destroyed", "Item", "Reason", "Signature"]

    def __init__(self, session: Session, parent: Optional[QWidget] = None):
        super().__init__("Certificates of destruction", parent, 900, 680)
        self.session = session
        vault = session.vault
        self.documents = vault.certificates

        self.body.addWidget(label(
            "When a key is destroyed, the vault signs a record of what went and "
            "when. Anyone can check that signature without your passphrase, "
            "without the vault, and without this application.", "Subtitle",
            wrap=True))

        if not self.documents:
            self.body.addWidget(Banner(
                "Nothing has been destroyed yet, so there are no certificates. "
                "One is issued automatically the first time a key is destroyed "
                "— by a deadline, by running out of openings, by a dead man's "
                "switch, or by your own hand.", "muted"))
            self.body.addStretch(1)
            self.add_close()
            return

        table = QTableWidget(len(self.documents), len(self.COLUMNS))
        table.setHorizontalHeaderLabels(self.COLUMNS)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setSelectionMode(QAbstractItemView.SingleSelection)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setAlternatingRowColors(True)
        table.verticalHeader().setVisible(False)
        table.setShowGrid(False)
        table.horizontalHeader().setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        for column in (0, 2, 3):
            table.horizontalHeader().setSectionResizeMode(column,
                                                          QHeaderView.ResizeToContents)

        public = vault.public_key
        for row, document in enumerate(self.documents):
            body = document["certificate"]
            item = body["item"]
            result = certificate_module.verify(document, public)
            cells = [
                expiry_mod.format_time(body["destruction"]["destroyed_at"]),
                ", ".join(item.get("names", [])) or item["entry_id"][:12],
                body["destruction"]["reason"],
                "valid" if result.ok else "INVALID",
            ]
            for column, text in enumerate(cells):
                cell = QTableWidgetItem(text)
                if column == 3:
                    from PyQt5.QtGui import QColor
                    cell.setForeground(QColor(theme.SUCCESS if result.ok
                                              else theme.DANGER))
                table.setItem(row, column, cell)
        table.selectRow(0)
        table.setMinimumHeight(220)
        self.table = table
        self.body.addWidget(table)

        self.body.addWidget(Banner(
            "A certificate proves that this vault destroyed that key at that "
            "time, and that the document has not been altered since. It does "
            "not prove that no copy of the key was taken beforehand, nor that "
            "no copy of the content exists elsewhere. Every certificate says so "
            "in its own text, so the caveat travels with the document.", "muted"))

        self.body.addStretch(1)

        export_one = QPushButton("Export selected…")
        export_one.setCursor(Qt.PointingHandCursor)
        export_one.clicked.connect(self._export_selected)
        self.footer.insertWidget(0, export_one)
        export_all = QPushButton("Export all…")
        export_all.setCursor(Qt.PointingHandCursor)
        export_all.clicked.connect(self._export_all)
        self.footer.insertWidget(1, export_all)
        self.add_close()

    def _export_selected(self) -> None:
        rows = {index.row() for index in self.table.selectedIndexes()}
        if not rows:
            return
        document = self.documents[min(rows)]
        path = destinations.file_for(
            "certificates", self, "Export certificate",
            certificate_module.filename_for(document),
            patterns=["Certificate (*.json)", "All files (*)"])
        if path:
            with open(path, "w") as fh:
                fh.write(certificate_module.to_json(document))

    def _export_all(self) -> None:
        directory = destinations.folder_for(
            "certificates", self, "Export every certificate")
        if not directory:
            return
        for document in self.documents:
            target = os.path.join(directory,
                                  certificate_module.filename_for(document))
            with open(target, "w") as fh:
                fh.write(certificate_module.to_json(document))


# --------------------------------------------------------------------------
# custodian
# --------------------------------------------------------------------------

class CustodianDialog(_Base):
    """Who is answerable for destructions, as NIST SP 800-88 asks."""

    def __init__(self, session: Session, parent: Optional[QWidget] = None):
        super().__init__("Custodian details", parent, 720, 560)
        self.session = session
        current = session.vault.custodian

        self.body.addWidget(label(
            "NIST SP 800-88 asks that a record of sanitization name the person "
            "responsible. These details are optional and empty by default — a "
            "personal vault has no use for them — and they are written into "
            "every certificate issued from now on.", "Subtitle", wrap=True))

        card = Card(padding=20, spacing=12)
        self.fields = {}
        for key, caption, placeholder in (
            ("name", "Name", "A. Mensah"),
            ("title", "Position or title", "Data Protection Officer"),
            ("organisation", "Organisation", "Example Ltd"),
            ("contact", "Contact", "dpo@example.org"),
        ):
            card.body.addWidget(label(caption, "Muted"))
            edit = QLineEdit(getattr(current, key))
            edit.setPlaceholderText(placeholder)
            edit.setMinimumHeight(38)
            card.body.addWidget(edit)
            self.fields[key] = edit
        self.body.addWidget(card)

        self.body.addWidget(Banner(
            "These are a label, not a credential. The vault does not verify "
            "them and neither can a reader — they record who said they were "
            "responsible, in the same way a signature block on a paper form "
            "does.", "muted"))

        self.body.addStretch(1)

        save = QPushButton("Save")
        save.setObjectName("Primary")
        save.setCursor(Qt.PointingHandCursor)
        save.clicked.connect(self._save)
        cancel = QPushButton("Cancel")
        cancel.setCursor(Qt.PointingHandCursor)
        cancel.clicked.connect(self.reject)
        self.footer.addWidget(cancel)
        self.footer.addWidget(save)

    def _save(self) -> None:
        with self.session.guard:
            self.session.vault.set_custodian(Custodian(
                name=self.fields["name"].text().strip(),
                title=self.fields["title"].text().strip(),
                contact=self.fields["contact"].text().strip(),
                organisation=self.fields["organisation"].text().strip()))
            self.session.vault.save()
        self.accept()


# --------------------------------------------------------------------------
# recovery shares
# --------------------------------------------------------------------------

class RecoverySharesDialog(_Base):
    """Generate a k-of-n split of the master key."""

    def __init__(self, session: Session, parent: Optional[QWidget] = None):
        super().__init__("Recovery shares", parent, 860, 720)
        self.session = session
        self.share_set: Optional[recovery.ShareSet] = None

        self.body.addWidget(label(
            "Split this vault's master key into shares. Any quorum of them "
            "reopens the vault without the passphrase; fewer than a quorum "
            "reveal nothing at all.", "Subtitle", wrap=True))

        chooser = Card(padding=18, spacing=12)
        chooser.body.addWidget(label("SPLIT", "SectionHeading"))
        row = QHBoxLayout()
        row.setSpacing(10)
        row.addWidget(label("Need", "Muted"))  # minimum of two, see recovery.py
        self.threshold = QComboBox()
        row.addWidget(self.threshold)
        row.addWidget(label("of", "Muted"))
        self.count = QComboBox()
        for value in range(recovery.MIN_SHARES, recovery.MAX_SHARES + 1):
            self.count.addItem(str(value), value)
        self.count.setCurrentIndex(1)
        self.count.currentIndexChanged.connect(self._refresh_thresholds)
        row.addWidget(self.count)
        row.addWidget(label("shares", "Muted"))
        row.addStretch(1)
        generate = QPushButton("Generate shares")
        generate.setObjectName("Primary")
        generate.setCursor(Qt.PointingHandCursor)
        generate.clicked.connect(self._generate)
        row.addWidget(generate)
        chooser.body.addLayout(row)
        self.body.addWidget(chooser)
        self._refresh_thresholds()

        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setFont(theme.mono_font(9))
        self.output.setPlaceholderText(
            "Generated shares will appear here. They are shown once — the "
            "vault does not keep a copy.")
        self.output.setMinimumHeight(240)
        self.body.addWidget(self.output)

        self.body.addWidget(Banner(
            "A quorum of shares is exactly as powerful as the passphrase: it "
            "opens the vault outright. Keep them apart from each other and "
            "apart from the vault, and treat each one as a secret.\n\n"
            "Changing the vault's passphrase replaces the master key, so shares "
            "made now stop working. Generate a fresh set afterwards.\n\n"
            "Shares do not resurrect keys that have already been destroyed. "
            "They rebuild the key that opens the vault as it stands, and a "
            "destroyed per-file key is zeros inside it.", "warning"))

        self.body.addStretch(1)

        self.save_button = QPushButton("Save to files…")
        self.save_button.setCursor(Qt.PointingHandCursor)
        self.save_button.setEnabled(False)
        self.save_button.clicked.connect(self._save)
        self.footer.insertWidget(0, self.save_button)

        self.copy_button = QPushButton("Copy all")
        self.copy_button.setObjectName("Ghost")
        self.copy_button.setCursor(Qt.PointingHandCursor)
        self.copy_button.setEnabled(False)
        self.copy_button.clicked.connect(
            lambda: QApplication.clipboard().setText(self.output.toPlainText()))
        self.footer.insertWidget(1, self.copy_button)
        self.add_close("Done")

    def _refresh_thresholds(self) -> None:
        total = self.count.currentData() or 3
        previous = self.threshold.currentData()
        self.threshold.clear()
        for value in range(recovery.MIN_THRESHOLD, total + 1):
            self.threshold.addItem(str(value), value)
        target = previous if previous and previous <= total else recovery.MIN_THRESHOLD
        index = self.threshold.findData(target)
        self.threshold.setCurrentIndex(max(0, index))

    def _generate(self) -> None:
        threshold = self.threshold.currentData()
        total = self.count.currentData()
        try:
            with self.session.guard:
                self.share_set = recovery.generate(
                    self.session.vault.master_key(), threshold, total)
                self.session.vault.log_event(
                    "recovery_shares_issued", threshold=threshold, count=total)
                self.session.vault.save()
        except recovery.RecoveryError as exc:
            self.output.setPlainText(f"Could not generate shares: {exc}")
            return

        lines = [f"# Quenchkey recovery shares for vault "
                 f"{self.session.vault.vault_id}",
                 f"# Any {threshold} of these {total} reopen the vault.",
                 f"# Generated {expiry_mod.format_time(time.time())}",
                 ""]
        for index, share in enumerate(self.share_set.shares, start=1):
            lines.append(f"--- share {index} of {total} ---")
            lines.append(share)
            lines.append("")
        self.output.setPlainText("\n".join(lines))
        self.save_button.setEnabled(True)
        self.copy_button.setEnabled(True)

    def _save(self) -> None:
        if not self.share_set:
            return
        directory = destinations.folder_for(
            "shares", self, "Save shares (one file each)")
        if not directory:
            return
        vault_id = self.session.vault.vault_id[:8]
        for index, share in enumerate(self.share_set.shares, start=1):
            target = os.path.join(
                directory, f"quenchkey-share-{vault_id}-{index}of"
                           f"{self.share_set.count}.txt")
            with open(target, "w") as fh:
                fh.write(f"# Quenchkey recovery share {index} of "
                         f"{self.share_set.count}\n"
                         f"# Vault {self.session.vault.vault_id}\n"
                         f"# Any {self.share_set.threshold} shares reopen the "
                         f"vault. Keep this apart from the others.\n\n")
                fh.write(share + "\n")
            os.chmod(target, 0o600)


# --------------------------------------------------------------------------
# unlocking with shares
# --------------------------------------------------------------------------

class ShareUnlockDialog(_Base):
    """Collect a quorum of shares and hand back the reconstructed key."""

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__("Open with recovery shares", parent, 820, 660)
        self.master_key = None

        self.body.addWidget(label(
            "Paste your shares below, one per line. Extra shares are fine — "
            "only as many as the threshold are used, and each is checked "
            "individually so a mistyped one can be pinpointed.", "Subtitle",
            wrap=True))

        self.input = QPlainTextEdit()
        self.input.setFont(theme.mono_font(9))
        self.input.setPlaceholderText(
            "detailed scared academic acne aviation living activity …")
        self.input.setMinimumHeight(220)
        self.input.textChanged.connect(self._refresh)
        self.body.addWidget(self.input)

        self.status = Banner("", "muted")
        self.status.setVisible(False)
        self.body.addWidget(self.status)

        self.body.addWidget(Banner(
            "A quorum of shares opens this vault completely, bypassing the "
            "passphrase and any second factor. That is what they are for.",
            "warning"))

        self.body.addStretch(1)

        self.unlock_button = QPushButton("Reconstruct and unlock")
        self.unlock_button.setObjectName("Primary")
        self.unlock_button.setCursor(Qt.PointingHandCursor)
        self.unlock_button.setEnabled(False)
        self.unlock_button.clicked.connect(self._combine)
        cancel = QPushButton("Cancel")
        cancel.setCursor(Qt.PointingHandCursor)
        cancel.clicked.connect(self.reject)
        self.footer.addWidget(cancel)
        self.footer.addWidget(self.unlock_button)

    def _shares(self) -> list:
        return [line for line in self.input.toPlainText().splitlines()
                if line.strip() and not line.strip().startswith("#")]

    def _refresh(self) -> None:
        shares = self._shares()
        if not shares:
            self.status.setVisible(False)
            self.unlock_button.setEnabled(False)
            return

        accepted, complaints = recovery.inspect(shares)
        needed = recovery.detect_threshold(accepted[0]) if accepted else None
        pieces = []
        if accepted:
            pieces.append(f"{len(accepted)} valid share"
                          f"{'s' if len(accepted) != 1 else ''}")
            if needed:
                pieces.append(f"{needed} needed")
        message = ", ".join(pieces)
        if complaints:
            message = (message + ". " if message else "") + " ".join(complaints)

        enough = bool(accepted) and needed is not None and len(accepted) >= needed
        self.status.show_message(
            message, "success" if enough else ("danger" if complaints else "muted"))
        self.unlock_button.setEnabled(enough)

    def _combine(self) -> None:
        try:
            self.master_key = recovery.combine(self._shares())
        except recovery.RecoveryError as exc:
            self.status.show_message(str(exc), "danger")
            return
        self.accept()


# --------------------------------------------------------------------------
# background expiry
# --------------------------------------------------------------------------

class BackgroundExpiryDialog(_Base):
    """Turning on the outside index, with what it costs stated first."""

    def __init__(self, session: Session, parent: Optional[QWidget] = None):
        super().__init__("Expiry while Quenchkey is closed", parent, 780, 640)
        self.session = session
        vault = session.vault
        self.changed = False

        self.body.addWidget(label(
            "Deadlines are enforced whenever this application is open. With "
            "this switched on, a small background task also deletes locked "
            "files whose deadline has passed while it is closed.",
            "Muted", wrap=True))

        self.body.addWidget(Banner(
            "It deletes files. It does not destroy keys. "
            "The vault is one encrypted blob, and a background task that does "
            "not know your passphrase cannot open it, read a deadline from it, "
            "or write to it. Keys are destroyed the next time you unlock — "
            "which is the first moment the vault can be written at all. Until "
            "then an expired entry is still refused by every part of this "
            "application that could read it.", "info"))

        self.body.addWidget(Banner(
            "It writes a list of your deadlines outside the vault. "
            f"So the background task has something it can read. The file is "
            f"{os.path.basename(vault.path)}.schedule, readable only by you, "
            f"and it is not encrypted — encrypting it under a key kept beside "
            f"it would protect nothing. It lists, for each item with a "
            f"deadline: when that deadline falls, where the locked file is, "
            f"and whether it should be deleted. It holds no keys and no file "
            f"contents. Anyone who can read your home directory learns when "
            f"your locked files expire.", "warning"))

        self.toggle = QCheckBox("Delete expired files while Quenchkey is closed")
        self.toggle.setChecked(vault.background_expiry)
        self.toggle.toggled.connect(self._apply)
        self.body.addWidget(self.toggle)

        self.status = label("", "Faint", wrap=True)
        self.body.addWidget(self.status)
        self._refresh()

        self.body.addStretch(1)
        self.add_close()

    def _apply(self, enabled: bool) -> None:
        with self.session.guard:
            self.session.vault.set_background_expiry(enabled)
        self.changed = True
        self._refresh()

    def _refresh(self) -> None:
        vault = self.session.vault
        if not vault.background_expiry:
            self.status.setText(
                "Off. Nothing is written outside the vault, and nothing "
                "expires unless this application is running.")
            return
        index = schedule.index_path(vault.path)
        scheduled = schedule.read_index(vault.path) or []
        deletes = sum(1 for entry in scheduled if entry.delete_blob)
        self.status.setText(
            f"On. {len(scheduled)} deadline"
            f"{'s are' if len(scheduled) != 1 else ' is'} listed in {index}, "
            f"of which {deletes} ask"
            f"{'' if deletes != 1 else 's'} for the locked file to be deleted. "
            f"The timer runs every fifteen minutes and shortly after you log "
            f"in; `systemctl --user status quenchkey-sweep.timer` says whether "
            f"it is running.")
