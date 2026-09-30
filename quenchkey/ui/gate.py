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

"""The first screen: create a vault, or open the one that is already there.

Most of the effort in this window goes on passphrase quality, because the
passphrase is the only thing standing between an attacker with a copy of the
files and their contents. The meter is pessimistic, the Generate button is the
prominent one, and the minimum is enforced rather than suggested.
"""

from __future__ import annotations

import os
import time
from typing import Optional

from PyQt5.QtCore import QTimer, Qt, pyqtSignal
from PyQt5.QtWidgets import QApplication
from PyQt5.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QHBoxLayout, QLabel,
    QPushButton, QScrollArea, QStackedWidget, QVBoxLayout, QWidget,
)

from .. import crypto, factors, keyfile, passphrase as pp
from ..session import Session
from ..vault import (
    DuressTriggered, destroy_vault, duress_matches,
    DEFAULT_VAULT_PATH, ClockRollback, KeyfileRequired, SecurityKeyRequired,
    Vault, VaultNotFound, read_header,
)
from ..crypto import AuthenticationError, UnsupportedFormat
from . import destinations, filechooser, theme
from .dialogs import ShareUnlockDialog
from .widgets import (
    Banner, Card, ConfirmDialog, Divider, PassphraseField,
    PassphraseStrengthPanel, label,
)
from .workers import KeyDerivationTask

#: Delay applied after consecutive failures. A speed bump for someone at this
#: keyboard, and nothing at all against an offline attack — see the note shown
#: in the UI alongside it.
BACKOFF_SECONDS = [0, 0, 1, 2, 4, 8, 15, 30]


def _settled(card: QWidget) -> QWidget:
    """Put a card at the top of a page so spare height collects below it.

    A QStackedWidget is as tall as its tallest page; without this the shorter
    page's rows would stretch to fill, opening gaps between them.
    """
    page = QWidget()
    column = QVBoxLayout(page)
    column.setContentsMargins(0, 0, 0, 0)
    column.setSpacing(0)
    column.addWidget(card)
    column.addStretch(1)
    return page


class GateWindow(QWidget):
    """Vault creation and unlock, in one window."""

    opened = pyqtSignal(object)   # emits a Session

    def __init__(self, vault_path: str = DEFAULT_VAULT_PATH,
                 parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.vault_path = vault_path
        self.setWindowTitle("Quenchkey")
        # The body scrolls, so it is safe to clamp this to the screen — and
        # necessary, since a scaled-up minimum can otherwise exceed the
        # display and leave the unlock button below its bottom edge.
        theme.fit(self, 700, 820, 640, 560)
        self._task: Optional[KeyDerivationTask] = None
        self._keyfile_path: Optional[str] = None
        self._failures = 0
        self._locked_until = 0.0
        self._pending_rollback: Optional[ClockRollback] = None
        self._busy = False
        self._strength = None
        self._security_key_factor = None
        self._header_kind = factors.FACTOR_NONE

        self._build()
        self._on_factor_changed()
        self._refresh_mode()

        self._backoff_timer = QTimer(self)
        self._backoff_timer.setInterval(500)
        self._backoff_timer.timeout.connect(self._tick_backoff)
        self._backoff_timer.start()

    # -- construction -----------------------------------------------------

    def _build(self) -> None:
        self.setObjectName("Root")
        shell = QVBoxLayout(self)
        shell.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        shell.addWidget(scroll)

        canvas = QWidget()
        scroll.setWidget(canvas)

        outer = QVBoxLayout(canvas)
        outer.setContentsMargins(theme.GUTTER + 12, theme.GUTTER, theme.GUTTER + 12,
                                 theme.GUTTER)
        outer.setSpacing(theme.GAP)
        outer.addStretch(1)

        # -- masthead
        mark = QLabel()
        mark.setPixmap(theme.logo_pixmap(76))
        mark.setAlignment(Qt.AlignCenter)
        outer.addWidget(mark)

        title = label("Quenchkey", "Title")
        title.setAlignment(Qt.AlignCenter)
        outer.addWidget(title)

        tagline = label("The key goes out.", "Tagline")
        tagline.setAlignment(Qt.AlignCenter)
        outer.addWidget(tagline)

        outer.addSpacing(6)

        self.stack = QStackedWidget()
        self.stack.addWidget(_settled(self._build_create_page()))
        self.stack.addWidget(_settled(self._build_unlock_page()))
        outer.addWidget(self.stack)

        outer.addSpacing(4)
        self.path_row = QHBoxLayout()
        self.path_label = label("", "Faint")
        self.path_label.setAlignment(Qt.AlignCenter)
        self.path_row.addStretch(1)
        self.path_row.addWidget(self.path_label)
        change = QPushButton("Change…")
        change.setObjectName("Ghost")
        change.setCursor(Qt.PointingHandCursor)
        change.clicked.connect(self._choose_vault_path)
        self.path_row.addWidget(change)
        self.path_row.addStretch(1)
        outer.addLayout(self.path_row)

        outer.addStretch(1)

    def _build_create_page(self) -> QWidget:
        page = Card(padding=26, spacing=14)

        page.body.addWidget(label("CREATE A VAULT", "SectionHeading"))
        page.body.addWidget(label(
            "The vault holds the keys to everything you lock. Choose the "
            "passphrase carefully: it is the only thing protecting those keys, "
            "and there is no way to reset it.", "Muted", wrap=True))

        page.body.addWidget(Divider())

        self.create_field = PassphraseField("Choose a passphrase", with_generator=True)
        self.create_field.changed.connect(self._on_create_changed)
        self.create_field.generated.connect(self._on_generated)
        page.body.addWidget(self.create_field)

        self.strength = PassphraseStrengthPanel()
        page.body.addWidget(self.strength)

        self.confirm_field = PassphraseField("Type it again")
        self.confirm_field.changed.connect(self._on_create_changed)
        self.confirm_field.submitted.connect(self._create_vault)
        page.body.addWidget(self.confirm_field)

        self.match_note = label("", "Faint")
        page.body.addWidget(self.match_note)

        # The floor is enforced, but it is the user's vault. Rather than
        # blocking outright, the override makes the trade explicit and costs
        # enough effort that nobody clicks through it by accident.
        self.override_check = QCheckBox("Use this passphrase anyway")
        self.override_check.setObjectName("DangerCheck")
        self.override_check.setCursor(Qt.PointingHandCursor)
        self.override_check.setVisible(False)
        self.override_check.toggled.connect(self._on_override_toggled)
        page.body.addWidget(self.override_check)

        self.override_note = Banner("", "danger")
        self.override_note.setVisible(False)
        page.body.addWidget(self.override_note)

        page.body.addWidget(Divider())

        page.body.addWidget(label("SECOND FACTOR", "SectionHeading"))
        factor_row = QHBoxLayout()
        factor_row.setSpacing(10)
        self.factor_combo = QComboBox()
        self.factor_combo.addItem("None — passphrase only", factors.FACTOR_NONE)
        self.factor_combo.addItem("Keyfile", factors.FACTOR_KEYFILE)
        self.factor_combo.addItem("Hardware security key (FIDO2)",
                                  factors.FACTOR_FIDO2)
        self.factor_combo.setMinimumWidth(260)
        self.factor_combo.currentIndexChanged.connect(self._on_factor_changed)
        factor_row.addWidget(self.factor_combo)
        factor_row.addStretch(1)
        page.body.addLayout(factor_row)

        # Kept for the keyfile branch and for the existing tests, which drive
        # this checkbox directly.
        self.keyfile_check = QCheckBox("Also require a keyfile (second factor)")
        self.keyfile_check.setVisible(False)
        self.keyfile_check.toggled.connect(self._on_keyfile_toggled)

        keyfile_row = QHBoxLayout()
        keyfile_row.setSpacing(10)
        self.keyfile_button = QPushButton("Create keyfile…")
        self.keyfile_button.setCursor(Qt.PointingHandCursor)
        self.keyfile_button.setEnabled(False)
        self.keyfile_button.clicked.connect(self._create_keyfile)
        keyfile_row.addWidget(self.keyfile_button)
        self.keyfile_label = label("No keyfile yet", "Faint")
        keyfile_row.addWidget(self.keyfile_label, 1)
        page.body.addLayout(keyfile_row)

        self.keyfile_advice = Banner(keyfile.ADVICE, "warning")
        self.keyfile_advice.setVisible(False)
        page.body.addWidget(self.keyfile_advice)

        self.security_key_row = QWidget()
        key_row = QHBoxLayout(self.security_key_row)
        key_row.setContentsMargins(0, 0, 0, 0)
        key_row.setSpacing(10)
        self.enrol_button = QPushButton("Register security key…")
        self.enrol_button.setCursor(Qt.PointingHandCursor)
        self.enrol_button.clicked.connect(self._enrol_security_key)
        key_row.addWidget(self.enrol_button)
        self.security_key_label = label("No security key registered", "Faint")
        key_row.addWidget(self.security_key_label, 1)
        self.security_key_row.setVisible(False)
        page.body.addWidget(self.security_key_row)

        self.security_key_note = Banner("", "warning")
        self.security_key_note.setVisible(False)
        page.body.addWidget(self.security_key_note)

        page.body.addWidget(Banner(
            "There is no recovery and no back door. Forget the passphrase, or "
            "lose the keyfile, and every file you locked with this vault stays "
            "locked for good.", "danger"))

        self.create_error = Banner("", "danger")
        self.create_error.setVisible(False)
        page.body.addWidget(self.create_error)

        self.create_button = QPushButton("Create vault")
        self.create_button.setObjectName("Primary")
        self.create_button.setMinimumHeight(44)
        self.create_button.setCursor(Qt.PointingHandCursor)
        self.create_button.setEnabled(False)
        self.create_button.clicked.connect(self._create_vault)
        page.body.addWidget(self.create_button)

        self.create_status = label("", "Faint")
        self.create_status.setAlignment(Qt.AlignCenter)
        page.body.addWidget(self.create_status)

        return page

    def _build_unlock_page(self) -> QWidget:
        page = Card(padding=26, spacing=14)

        page.body.addWidget(label("UNLOCK", "SectionHeading"))
        self.unlock_intro = label("", "Muted", wrap=True)
        page.body.addWidget(self.unlock_intro)

        page.body.addWidget(Divider())

        self.unlock_field = PassphraseField("Passphrase")
        self.unlock_field.submitted.connect(self._unlock_vault)
        page.body.addWidget(self.unlock_field)

        self.unlock_keyfile_row = QWidget()
        row = QHBoxLayout(self.unlock_keyfile_row)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(10)
        pick = QPushButton("Choose keyfile…")
        pick.setCursor(Qt.PointingHandCursor)
        pick.clicked.connect(self._choose_keyfile)
        row.addWidget(pick)
        self.unlock_keyfile_label = label("This vault requires its keyfile", "Faint")
        row.addWidget(self.unlock_keyfile_label, 1)
        page.body.addWidget(self.unlock_keyfile_row)

        self.unlock_error = Banner("", "danger")
        self.unlock_error.setVisible(False)
        page.body.addWidget(self.unlock_error)

        self.rollback_button = QPushButton("Unlock anyway, and record it")
        self.rollback_button.setObjectName("Danger")
        self.rollback_button.setCursor(Qt.PointingHandCursor)
        self.rollback_button.setVisible(False)
        self.rollback_button.clicked.connect(self._accept_rollback)
        page.body.addWidget(self.rollback_button)

        self.unlock_button = QPushButton("Unlock")
        self.unlock_button.setObjectName("Primary")
        self.unlock_button.setMinimumHeight(44)
        self.unlock_button.setCursor(Qt.PointingHandCursor)
        self.unlock_button.clicked.connect(self._unlock_vault)
        page.body.addWidget(self.unlock_button)

        self.shares_button = QPushButton("Forgotten it? Open with recovery shares")
        self.shares_button.setObjectName("Ghost")
        self.shares_button.setCursor(Qt.PointingHandCursor)
        self.shares_button.clicked.connect(self._unlock_with_shares)
        page.body.addWidget(self.shares_button)

        self.unlock_status = label("", "Faint")
        self.unlock_status.setAlignment(Qt.AlignCenter)
        page.body.addWidget(self.unlock_status)

        self.attempt_note = Banner("", "muted")
        self.attempt_note.setVisible(False)
        page.body.addWidget(self.attempt_note)

        return page

    # -- mode -------------------------------------------------------------

    def _refresh_mode(self) -> None:
        self.path_label.setText(self.vault_path.replace(os.path.expanduser("~"), "~"))
        if os.path.exists(self.vault_path):
            self.stack.setCurrentIndex(1)
            try:
                header = read_header(self.vault_path)
            except (UnsupportedFormat, VaultNotFound) as exc:
                self.unlock_intro.setText(str(exc))
                self.unlock_button.setEnabled(False)
                self.unlock_keyfile_row.setVisible(False)
                return
            self.unlock_button.setEnabled(True)
            self.unlock_keyfile_row.setVisible(header.keyfile_required)
            self._header_kind = header.factor_kind
            self.unlock_intro.setText(
                f"{crypto.cipher_name(header.cipher_id)}, keys wrapped with Argon2id "
                f"at {header.kdf.memory_kib // 1024} MiB and {header.kdf.time_cost} "
                f"pass{'es' if header.kdf.time_cost != 1 else ''}. Deriving the key "
                f"takes about a second — that delay is the point.")
            self.unlock_field.setFocus()
        else:
            self.stack.setCurrentIndex(0)
            self.create_field.setFocus()

    def _choose_vault_path(self) -> None:
        path = filechooser.save_file(
            self, "Vault location", self.vault_path,
            ["Quenchkey vault (*.qkv)", "All files (*)"],
            # An existing vault is a perfectly good answer here: picking one
            # is how you unlock a vault that lives somewhere else.
            confirm_overwrite=False)
        if path:
            self.vault_path = path
            self._refresh_mode()

    # -- create -----------------------------------------------------------

    def _on_generated(self, value: str, _bits: float) -> None:
        """Copy a generated passphrase into the confirmation field.

        The second field exists to catch a typo, and there is no typo to
        catch when the application typed it: making someone transcribe 24
        random characters by hand only invites them to pick something weaker
        instead. A passphrase they typed themselves still has to be confirmed.
        """
        self.confirm_field.set_text(value)
        self.confirm_field.reveal.setChecked(True)

    def _on_create_changed(self) -> None:
        text = self.create_field.text()
        strength = self.strength.update_for(text, self.create_field.exact_bits())
        self._strength = strength
        confirm = self.confirm_field.text()

        if confirm and confirm != text:
            self.match_note.setText("The two entries do not match yet.")
            self.match_note.setStyleSheet(f"color: {theme.WARNING};")
        elif confirm:
            self.match_note.setText("Both entries match.")
            self.match_note.setStyleSheet(f"color: {theme.SUCCESS};")
        else:
            self.match_note.setText("")

        # Offer the override only once there is something to override: a
        # passphrase that is below the floor but otherwise complete.
        weak = bool(text) and not strength.meets_minimum
        self.override_check.setVisible(weak)
        if not weak and self.override_check.isChecked():
            self.override_check.setChecked(False)
        if weak:
            self.override_check.setText(
                f"Use this passphrase anyway "
                f"({strength.bits:.0f} bits — {pp.crack_time_note(strength.bits)})")
        self._refresh_override_note()

        kind = self._chosen_factor_kind()
        if kind == factors.FACTOR_KEYFILE:
            keyfile_ready = bool(self._keyfile_path)
        elif kind == factors.FACTOR_FIDO2:
            keyfile_ready = self._security_key_factor is not None
        else:
            keyfile_ready = True
        acceptable = strength.meets_minimum or (weak and self.override_check.isChecked())
        self.create_button.setEnabled(
            acceptable and bool(confirm) and confirm == text and keyfile_ready)

    def _on_override_toggled(self, _checked: bool) -> None:
        self._refresh_override_note()
        self._on_create_changed()

    def _refresh_override_note(self) -> None:
        """Spell out what accepting a weak passphrase actually costs."""
        # isHidden() reflects what this widget was told to do; isVisible() is
        # also false whenever an ancestor has not been shown yet.
        if self.override_check.isHidden() or not self.override_check.isChecked():
            self.override_note.setVisible(False)
            return
        strength = self._strength
        bits = strength.bits if strength else 0.0
        self.override_note.show_message(
            f"This passphrase is worth about {bits:.0f} bits. Anyone who copies "
            f"your vault file can attack it offline, on their own hardware, "
            f"where nothing in this app can slow them down beyond the Argon2id "
            f"cost — {pp.crack_time_note(bits)} on a single machine, and less "
            f"than that on many.\n\n"
            "Concretely: your locked files stay locked only for as long as that "
            "guessing takes. Expiry still destroys keys on schedule, but a "
            "guessed passphrase opens the vault before any deadline arrives, "
            "and copies the attacker already holds become readable. You can "
            "change the passphrase later, but files they have already opened "
            "cannot be un-opened.", "danger")

    def _on_keyfile_toggled(self, checked: bool) -> None:
        self.keyfile_button.setEnabled(checked)
        self.keyfile_advice.setVisible(checked)
        if not checked:
            self._keyfile_path = None
            self.keyfile_label.setText("No keyfile yet")
        self._on_create_changed()

    def _chosen_factor_kind(self) -> str:
        return self.factor_combo.currentData()

    def _on_factor_changed(self) -> None:
        kind = self._chosen_factor_kind()
        wants_keyfile = kind == factors.FACTOR_KEYFILE
        wants_key = kind == factors.FACTOR_FIDO2

        self.keyfile_check.setChecked(wants_keyfile)
        self.keyfile_button.setVisible(wants_keyfile)
        self.keyfile_label.setVisible(wants_keyfile)
        self.keyfile_advice.setVisible(wants_keyfile)
        self.security_key_row.setVisible(wants_key)

        if wants_key:
            available, reason = factors.fido2_available()
            self.enrol_button.setEnabled(available)
            self.security_key_note.show_message(
                ("A security key holds a secret that never leaves the device, "
                 "so unlike a keyfile it cannot be copied off this machine. "
                 "Registering one here stores only its credential id and a "
                 "salt — both public — in the vault header.\n\n"
                 "Be aware: lose the key and the vault is unopenable, exactly "
                 "as if you had forgotten the passphrase. Register a second "
                 "key or generate recovery shares before you rely on it. This "
                 "path has been built against the CTAP2 specification but has "
                 "not been exercised against physical hardware by its author, "
                 "so test it with a file you can afford to lose first.")
                if available else
                f"No security key usable right now: {reason}.", "warning")
        else:
            self._security_key_factor = None
            self.security_key_label.setText("No security key registered")
            self.security_key_note.setVisible(False)
        self._on_create_changed()

    def _enrol_security_key(self) -> None:
        self.security_key_note.show_message(
            "Touch your security key when it flashes…", "info")
        QApplication.processEvents()
        try:
            self._security_key_factor = factors.Fido2Factor.enrol()
        except factors.FactorError as exc:
            self._security_key_factor = None
            self.security_key_note.show_message(str(exc), "danger")
            self._on_create_changed()
            return
        self.security_key_label.setText(
            f"Registered: {self._security_key_factor.device_hint}")
        self.security_key_label.setStyleSheet(f"color: {theme.SUCCESS};")
        self.security_key_note.show_message(
            "Registered. Keep a second key or a set of recovery shares: if "
            "this one is lost, the vault cannot be opened.", "warning")
        self._on_create_changed()

    def _build_factor(self):
        """The second factor the user has configured, ready to create with."""
        kind = self._chosen_factor_kind()
        if kind == factors.FACTOR_KEYFILE and self._keyfile_path:
            return factors.KeyfileFactor(self._keyfile_path)
        if kind == factors.FACTOR_FIDO2 and self._security_key_factor:
            return self._security_key_factor
        return factors.NoFactor()

    def _create_keyfile(self) -> None:
        path = destinations.file_for(
            "keyfile", self, "Create keyfile", keyfile.SUGGESTED_NAME,
            patterns=["Keyfile (*.keyfile)", "All files (*)"])
        if not path:
            return
        try:
            keyfile.generate(path, overwrite=True)
        except Exception as exc:  # noqa: BLE001
            self.create_error.show_message(f"Could not create the keyfile: {exc}", "danger")
            return
        self._keyfile_path = path
        self.keyfile_label.setText(path.replace(os.path.expanduser("~"), "~"))
        self.keyfile_label.setStyleSheet(f"color: {theme.SUCCESS};")
        self.create_error.setVisible(False)
        self._on_create_changed()

    def _create_vault(self) -> None:
        if not self.create_button.isEnabled():
            return
        passphrase = self.create_field.text()
        strength = self._strength or pp.estimate(passphrase)
        overridden = not strength.meets_minimum

        if overridden:
            accepted = ConfirmDialog.ask(
                self, "Create the vault with a weak passphrase?",
                f"You have chosen a passphrase worth roughly {strength.bits:.0f} "
                f"bits. The recommended floor is {pp.MIN_BITS} bits, and the "
                f"Generate button produces {pp.generated_bits(pp.RECOMMENDED_WORDS)}.",
                confirm_text="Create it anyway",
                acknowledgement="I understand this is the weakest part of the "
                                "system, and that no other setting compensates "
                                "for it.",
                detail=f"Estimated offline attack cost: "
                       f"{pp.crack_time_note(strength.bits)}. That figure "
                       "assumes an attacker with a copy of your vault file and "
                       "no interest in this application's own delays.",
                require_typed="I ACCEPT THE RISK")
            if not accepted:
                return

        if os.path.exists(self.vault_path):
            confirmed = ConfirmDialog.ask(
                self, "Replace the existing vault?",
                "A vault already exists at this location. Creating a new one "
                "destroys every key it holds.",
                confirm_text="Replace it",
                acknowledgement="I understand the files locked by that vault "
                                "can never be opened again.",
                detail="The encrypted .qkey files stay on disk. Without their "
                       "keys, nothing — including Quenchkey — can read them.")
            if not confirmed:
                return

        self._set_busy(True, "Deriving the key with Argon2id — about a second…")
        factor = self._build_factor()

        def work():
            params = crypto.calibrate_kdf(target_seconds=1.0)
            created = Vault.create(self.vault_path, passphrase,
                                   kdf_params=params, overwrite=True,
                                   factor=factor)
            # Kept so the security panel can state, later and honestly, how
            # strong the passphrase protecting this vault was judged to be.
            created.log_event("passphrase_strength",
                              bits=round(strength.bits, 1),
                              label=strength.label,
                              generated=strength.is_generated_phrase,
                              below_floor=overridden)
            created.save()
            return created

        self._task = KeyDerivationTask(work, "Could not create the vault")
        self._task.succeeded.connect(self._on_vault_ready)
        self._task.failed.connect(self._on_create_failed)
        self._task.start()

    def _on_create_failed(self, title: str, message: str) -> None:
        self._set_busy(False)
        self.create_error.show_message(f"{title}: {message}", "danger")

    # -- unlock -----------------------------------------------------------

    def _choose_keyfile(self) -> None:
        path = filechooser.open_file(
            self, "Choose keyfile", os.path.expanduser("~"),
            ["Keyfile (*.keyfile)", "All files (*)"])
        if not path:
            return
        info = keyfile.verify(path)
        self._keyfile_path = path
        self.unlock_keyfile_label.setText(
            os.path.basename(path) + (" — " + info.message if not info.intact else ""))
        self.unlock_keyfile_label.setStyleSheet(
            f"color: {theme.SUCCESS if info.intact else theme.DANGER};")

    def _unlock_vault(self, accept_rollback: bool = False) -> None:
        if time.monotonic() < self._locked_until:
            return
        passphrase = self.unlock_field.text()
        if not passphrase:
            self.unlock_error.show_message("Enter the passphrase.", "warning")
            return
        self.unlock_error.setVisible(False)
        self.rollback_button.setVisible(False)
        self._set_busy(True, "Deriving the key with Argon2id — about a second…")
        keyfile_path = self._keyfile_path

        def work():
            try:
                return Vault.unlock(self.vault_path, passphrase, keyfile_path,
                                    accept_clock_rollback=accept_rollback)
            except AuthenticationError:
                # Only now, and only after a real unlock has already failed,
                # is the duress digest consulted. A correct passphrase never
                # reaches this, and a mistyped one is simply wrong.
                if duress_matches(self.vault_path, passphrase, keyfile_path):
                    destroy_vault(self.vault_path)
                    raise DuressTriggered(self.vault_path, True) from None
                raise

        if getattr(self, "_header_kind", None) == factors.FACTOR_FIDO2:
            self.unlock_status.setText("Touch your security key when it flashes…")

        self._task = KeyDerivationTask(work, "Could not open the vault")
        self._task.succeeded.connect(self._on_vault_ready)
        self._task.failed.connect(self._on_unlock_failed)
        self._task.start()

    def _accept_rollback(self) -> None:
        self._unlock_vault(accept_rollback=True)

    def _unlock_with_shares(self) -> None:
        """Reconstruct the master key from a quorum and open the vault."""
        dialog = ShareUnlockDialog(self)
        if dialog.exec_() != QDialog.Accepted or dialog.master_key is None:
            return
        master_key = dialog.master_key
        self._set_busy(True, "Opening with the reconstructed key…")

        def work():
            return Vault.unlock_with_master_key(self.vault_path, master_key)

        self._task = KeyDerivationTask(work, "Could not open the vault")
        self._task.succeeded.connect(self._on_vault_ready)
        self._task.failed.connect(self._on_unlock_failed)
        self._task.start()

    def _on_unlock_failed(self, title: str, message: str) -> None:
        self._set_busy(False)
        error = self._task.error if self._task else None

        if isinstance(error, DuressTriggered):
            # On purpose indistinguishable from opening a machine that never
            # had a vault. No message saying what happened, because anyone
            # standing over your shoulder would read it.
            self.unlock_field.clear()
            self._refresh_mode()
            return

        if isinstance(error, ClockRollback):
            self._pending_rollback = error
            hours = error.delta / 3600.0
            self.unlock_error.show_message(
                f"The system clock is {hours:,.1f} hours earlier than the last "
                f"time this vault was opened "
                f"({time.strftime('%Y-%m-%d %H:%M', time.localtime(error.last_seen))}). "
                "That is what winding the clock back to keep an expired file "
                "alive looks like — and it is also what a flat CMOS battery or "
                "a bad time sync looks like. Quenchkey cannot tell the two "
                "apart, so it is stopping to ask.\n\n"
                "Nothing is lost either way: deadlines are judged against the "
                "latest time this vault has ever seen, so unlocking now will "
                "not extend any of them.", "danger")
            self.rollback_button.setVisible(True)
            return

        if isinstance(error, KeyfileRequired):
            self.unlock_error.show_message(str(error), "warning")
            self.unlock_keyfile_row.setVisible(True)
            return

        if isinstance(error, (SecurityKeyRequired, factors.FactorUnavailable)):
            self.unlock_error.show_message(
                f"{error} If the key is lost for good, recovery shares are the "
                "only way back in.", "warning")
            return

        if isinstance(error, AuthenticationError):
            self._failures += 1
            delay = BACKOFF_SECONDS[min(self._failures, len(BACKOFF_SECONDS) - 1)]
            self._locked_until = time.monotonic() + delay
            self.unlock_error.show_message(
                "That did not open the vault. The passphrase is wrong, the "
                "keyfile is wrong or missing, or the vault file has been "
                "altered — the authentication tag cannot tell you which, and "
                "deliberately so.", "danger")
            if self._failures >= 3:
                self.attempt_note.show_message(
                    f"{self._failures} failed attempts. Quenchkey now waits a "
                    "few seconds between tries. Be clear about what that is "
                    "worth: it slows down someone sitting at this keyboard and "
                    "nothing else. Anyone who copies the vault file attacks it "
                    "offline, at their own speed, where this app never runs. "
                    "The Argon2id cost is the real defence.", "muted")
            return

        self.unlock_error.show_message(f"{title}: {message}", "danger")

    # -- shared -----------------------------------------------------------

    def _set_busy(self, busy: bool, message: str = "") -> None:
        """Disable input while Argon2id runs, without losing button state."""
        self._busy = busy
        for widget in (self.create_field, self.confirm_field, self.unlock_field,
                       self.keyfile_check):
            widget.setEnabled(not busy)
        self.keyfile_button.setEnabled(not busy and self.keyfile_check.isChecked())
        self.unlock_button.setEnabled(not busy and time.monotonic() >= self._locked_until)
        self.create_status.setText(message if self.stack.currentIndex() == 0 else "")
        self.unlock_status.setText(message if self.stack.currentIndex() == 1 else "")
        if busy:
            self.create_button.setEnabled(False)
        else:
            self._on_create_changed()

    def _on_vault_ready(self, vault: Vault) -> None:
        self._set_busy(False)
        self.create_field.clear()
        self.confirm_field.clear()
        self.unlock_field.clear()
        self._failures = 0
        self.attempt_note.setVisible(False)
        self.opened.emit(Session(vault))

    def _tick_backoff(self) -> None:
        if self._busy:
            return
        remaining = self._locked_until - time.monotonic()
        if remaining > 0:
            self.unlock_button.setEnabled(False)
            self.unlock_button.setText(f"Unlock  ({remaining:.0f}s)")
        elif self.unlock_button.text() != "Unlock":
            self.unlock_button.setEnabled(True)
            self.unlock_button.setText("Unlock")
