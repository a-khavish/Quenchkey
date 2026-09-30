#!/usr/bin/env python3
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

"""Drive the real windows and save a PNG of each screen.

Run under a virtual display::

    xvfb-run -a -s "-screen 0 1600x1200x24" python3 tools/screenshots.py docs/screenshots

Every image comes from the actual widget tree via ``QWidget.grab()`` — nothing
here is mocked up, so a screenshot that looks wrong means the screen is wrong.
"""

from __future__ import annotations

import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PyQt5.QtWidgets import QApplication  # noqa: E402

from quenchkey import crypto, locker  # noqa: E402
from quenchkey.certificate import Custodian  # noqa: E402
from quenchkey.session import Session  # noqa: E402
from quenchkey.vault import Vault  # noqa: E402
from quenchkey.ui import theme  # noqa: E402
from quenchkey.ui.gate import GateWindow  # noqa: E402
from quenchkey.ui.lock_dialog import LockDialog  # noqa: E402
from quenchkey.ui.main_window import MainWindow, _TextDialog, limitations_html  # noqa: E402
from quenchkey.ui.unlock_dialog import UnlockDialog  # noqa: E402
from quenchkey.ui.dialogs import (  # noqa: E402
    AnchorDialog, BackgroundExpiryDialog, CertificatesDialog, CustodianDialog,
    RecoverySharesDialog, ShareUnlockDialog,
)
from quenchkey.ui.feature_dialogs import (  # noqa: E402
    AuditDialog, BackupDialog, DuressDialog, HandoverDialog,
    IdentityCardDialog, IntegrityDialog, WatchFoldersDialog,
)
from quenchkey.ui.help_dialog import HelpDialog  # noqa: E402
from quenchkey.ui.settings_dialog import SettingsDialog  # noqa: E402
from quenchkey.ui.share_dialog import ShareDialog, UnlockSharedDialog  # noqa: E402
from quenchkey.ui.widgets import ConfirmDialog  # noqa: E402

# A genuine output of the app's own generator, so the create screen shows the
# exact-entropy message rather than the heuristic estimate.
PASSPHRASE = "trad-once-nacho-utmost-ozone-noil-fjeld"

#: The vault behind the screenshots is created with real calibrated Argon2id
#: parameters, so the unlock screen and the security panel show the numbers a
#: user would actually see rather than test values. It costs about a second.
REAL_KDF = crypto.calibrate_kdf(target_seconds=1.0)

#: name, size, seconds until the deadline, open allowance, heartbeat days
SAMPLES = [
    ("Q3 board pack.pdf", 2_400_000, 3 * 3600, None, None),
    ("salary-review.xlsx", 180_000, 40 * 3600, 2, None),
    ("term-sheet-draft.docx", 96_000, 21 * 86400, None, None),
    ("site-survey-photos", 5_100_000, None, None, 30),
    ("incident-notes.md", 14_000, 40, 1, None),
]


def make_sample(directory: str, name: str, size: int) -> str:
    path = os.path.join(directory, name)
    if "." not in name:
        os.makedirs(path, exist_ok=True)
        for index in range(3):
            with open(os.path.join(path, f"IMG_{4120 + index}.jpg"), "wb") as fh:
                fh.write(os.urandom(size // 3))
        return path
    with open(path, "wb") as fh:
        fh.write(os.urandom(size))
    return path


class Shots:
    """Saves numbered screenshots in the order they are taken.

    Numbering is derived from call order rather than written into each
    filename, so inserting a screen in the middle does not mean renaming the
    rest of the set by hand.
    """

    def __init__(self, out_dir: str, app: QApplication):
        self.out_dir = out_dir
        self.app = app
        self.index = 0
        self.written: list[str] = []

    def take(self, widget, name: str) -> str:
        self.index += 1
        for _ in range(4):
            self.app.processEvents()
        filename = f"{self.index:02d}-{name}.png"
        path = os.path.join(self.out_dir, filename)
        widget.grab().save(path)
        self.written.append(filename)
        print("wrote", path)
        return path



def mask_secrets(widget) -> int:
    """Put every revealed passphrase and share list out of sight.

    These images go into a public README. A screenshot of a passphrase is a
    screenshot of a passphrase, whether or not the vault behind it still
    exists, and a reader should not have to take "that one was a throwaway" on
    trust.
    """
    from PyQt5.QtWidgets import QLineEdit, QPlainTextEdit

    hidden = 0
    for field in widget.findChildren(QLineEdit):
        if field.echoMode() == QLineEdit.Normal and field.text():
            toggle = getattr(field.parentWidget(), "reveal", None)
            if toggle is not None and toggle.isChecked():
                toggle.setChecked(False)
            else:
                field.setEchoMode(QLineEdit.Password)
            hidden += 1
    for box in widget.findChildren(QPlainTextEdit):
        text = box.toPlainText()
        if "share" in text.lower() and len(text.split()) > 30:
            box.setPlainText(
                "# Five recovery shares were generated here.\n"
                "# They are not shown in this screenshot: each one is worth\n"
                "# as much as the passphrase.\n"
                "#\n"
                "# Save to files... writes them where you choose.")
            hidden += 1
    return hidden

def main(out_dir: str) -> int:
    os.makedirs(out_dir, exist_ok=True)
    # A config of its own, so taking screenshots never edits real preferences.
    os.environ["XDG_CONFIG_HOME"] = tempfile.mkdtemp(prefix="quenchkey-shots-config-")
    app = QApplication(sys.argv[:1])
    theme.apply(app)
    shots = Shots(out_dir, app)

    workspace = tempfile.mkdtemp(prefix="quenchkey-shots-")
    sources = os.path.join(workspace, "documents")
    blobs = os.path.join(workspace, "locked")
    os.makedirs(sources, exist_ok=True)
    os.makedirs(blobs, exist_ok=True)

    # -- vault creation, mid-typing with a weak passphrase
    fresh = GateWindow(os.path.join(workspace, "new.vk"))
    fresh.resize(700, 940)
    fresh.show()
    fresh.create_field.set_text("Manchester1878!")
    fresh.confirm_field.set_text("Manchester18")
    shots.take(fresh, "create-weak")

    # -- the override, with the consequences spelled out
    fresh.confirm_field.set_text("Manchester1878!")
    fresh.override_check.setChecked(True)
    shots.take(fresh, "create-override")

    # -- the typed confirmation that stands between a weak passphrase and a vault
    confirm = ConfirmDialog(
        "Create the vault with a weak passphrase?",
        "You have chosen a passphrase worth roughly 35 bits. The recommended "
        "floor is 60 bits, and the Generate button produces 77.",
        confirm_text="Create it anyway",
        acknowledgement="I understand this is the weakest part of the system, "
                        "and that no other setting compensates for it.",
        detail="Estimated offline attack cost: roughly 4 hours of offline "
               "guessing. That figure assumes an attacker with a copy of your "
               "vault file and no interest in this application's own delays.",
        require_typed="I ACCEPT THE RISK")
    confirm.resize(620, 480)
    confirm.show()
    confirm._check.setChecked(True)
    confirm._typed.setText("I ACCEPT THE RIS")
    shots.take(confirm, "override-confirmation")
    confirm.close()

    # -- the same screen once the generator has been used
    fresh.override_check.setChecked(False)
    fresh.create_field.set_text(PASSPHRASE)
    fresh.confirm_field.set_text(PASSPHRASE)
    fresh.keyfile_check.setChecked(True)
    mask_secrets(fresh)
    shots.take(fresh, "create-strong")
    fresh.close()

    # -- build a populated vault for the remaining screens
    vault_path = os.path.join(workspace, "vault.qkv")
    vault = Vault.create(vault_path, PASSPHRASE, kdf_params=REAL_KDF)
    vault.set_custodian(Custodian("A. Mensah", "Data Protection Officer",
                                  "dpo@example.org", "Example Ltd"))
    paths = []
    for name, size, ttl, opens, heartbeat in SAMPLES:
        path = make_sample(sources, name, size)
        paths.append(path)
        locker.lock_files(vault, [path], None if ttl is None else time.time() + ttl,
                          output_dir=blobs, max_opens=opens,
                          heartbeat_days=heartbeat)
    # one entry whose key has already been destroyed, so there is a certificate
    spent = make_sample(sources, "expired-contract.pdf", 40_000)
    result = locker.lock_files(vault, [spent], time.time() + 1, output_dir=blobs)
    vault.shred_key(result.entry.id)
    vault.save()

    session = Session(vault)

    # -- unlock screen against that vault
    gate = GateWindow(vault_path)
    gate.resize(700, 760)
    gate.show()
    gate.unlock_field.set_text(PASSPHRASE)
    shots.take(gate, "unlock")
    gate.close()

    # -- main window
    window = MainWindow(session)
    window.resize(1280, 800)
    window.show()
    window.refresh()
    window.notice.show_message(
        "Locked incident-notes.md → incident-notes.qkey "
        "(key dies in 40 seconds).", "success")
    shots.take(window, "main")

    # -- main window with a selection, showing the destructive actions live
    window.table.selectRow(0)
    shots.take(window, "main-selected")

    # -- lock flow, mid-selection
    lock = LockDialog(session, window, paths[:4])
    lock.resize(940, 940)
    lock.expiry_combo.setCurrentIndex(2)
    lock.opens_combo.setCurrentIndex(3)
    lock.heartbeat_combo.setCurrentIndex(2)
    lock.show()
    lock.table.selectRow(1)
    shots.take(lock, "lock-flow")
    lock.close()

    # -- unlock flow
    live = [entry for entry in vault.entries() if not entry.key_destroyed]
    unlock = UnlockDialog(session, live[0], window)
    unlock.resize(820, 900)
    unlock.show()
    shots.take(unlock, "unlock-flow")
    # -- the same dialog with the loan chosen, which changes what the button does
    unlock.loan_radio.setChecked(True)
    shots.take(unlock, "loan")
    unlock.close()

    # -- the anchor: the headline evidence feature
    anchor = AnchorDialog(session, window)
    anchor.resize(800, 780)
    anchor.show()
    shots.take(anchor, "anchor")
    anchor.close()

    # -- certificates of destruction
    certificates = CertificatesDialog(session, window)
    certificates.resize(920, 700)
    certificates.show()
    shots.take(certificates, "certificates")
    certificates.close()

    # -- recovery shares, generated
    shares = RecoverySharesDialog(session, window)
    shares.resize(880, 760)
    shares.show()
    shares.count.setCurrentIndex(shares.count.findData(5))
    shares.threshold.setCurrentIndex(shares.threshold.findData(3))
    shares._generate()
    generated = shares.share_set
    mask_secrets(shares)
    shots.take(shares, "recovery-shares")
    shares.close()

    # -- unlocking with a quorum
    share_unlock = ShareUnlockDialog(window)
    share_unlock.resize(840, 680)
    share_unlock.show()
    if generated:
        share_unlock.input.setPlainText("\n".join(generated.shares[:3]))
    mask_secrets(share_unlock)
    shots.take(share_unlock, "share-unlock")
    share_unlock.close()

    # -- locking files to send someone, which has no deadline
    share = ShareDialog(session, window, paths[:2])
    share.resize(900, 900)
    share.show()
    share.passphrase_field.generate_characters()
    mask_secrets(share)
    shots.take(share, "share")
    share.close()

    # -- unlocking several shared files at once, after the fact
    shared_one = locker.lock_to_share(
        [paths[1]], "ephemeral-lantern-above-the-quay",
        output_path=os.path.join(blobs, "term-sheet.qkey"), kdf_params=REAL_KDF)
    shared_many = locker.lock_to_share(
        paths[:3], "ephemeral-lantern-above-the-quay",
        output_path=os.path.join(blobs, "q3-handover.qkey"), kdf_params=REAL_KDF)
    for result in (shared_one, shared_many):
        vault.record_shared(result.path, result.names, result.size,
                            result.plaintext_size, result.sha256)

    unlock_shared = UnlockSharedDialog(session, window)
    unlock_shared.resize(940, 900)
    unlock_shared.show()
    unlock_shared.field.set_text("ephemeral-lantern-above-the-quay")
    unlock_shared._done(locker.unlock_shared_files(
        [shared_one.path, shared_many.path], "ephemeral-lantern-above-the-quay"))
    shots.take(unlock_shared, "unlock-shared")
    unlock_shared.close()

    # -- the background sweeper, and what switching it on costs
    background = BackgroundExpiryDialog(session, window)
    background.show()
    shots.take(background, "background-expiry")
    background.close()

    # -- backups, and the price of restoring one
    backups = BackupDialog(session, window)
    backups.resize(900, 880)
    backups.show()
    shots.take(backups, "backups")
    backups.close()

    # -- a folder that locks what lands in it
    watched = WatchFoldersDialog(session, window)
    watched.resize(920, 900)
    watched.show()
    shots.take(watched, "watched-folders")
    watched.close()

    # -- the duress passphrase, with all three warnings visible
    duress = DuressDialog(session, window)
    duress.resize(840, 900)
    duress.show()
    shots.take(duress, "duress")
    duress.close()

    # -- every locked file, read back and compared
    integrity = IntegrityDialog(session, window)
    integrity.resize(940, 900)
    integrity.show()
    integrity._check()
    shots.take(integrity, "integrity")
    integrity.close()

    # -- this vault's identity, which is what a handover is addressed to
    identity = IdentityCardDialog(session, window)
    identity.resize(900, 780)
    identity.show()
    shots.take(identity, "identity-card")
    identity.close()

    # -- handing a file to another vault, deadline and all
    handing = HandoverDialog(session, window, paths[:2])
    handing.resize(960, 920)
    handing.show()
    shots.take(handing, "handover")
    handing.close()

    # -- the auditor's record, which holds no key at all
    auditor = AuditDialog(session, window)
    auditor.resize(940, 900)
    auditor.show()
    shots.take(auditor, "auditor")
    auditor.close()

    # -- settings: where things are saved, and what closing does
    preferences = SettingsDialog(window)
    preferences.resize(860, 900)
    preferences.show()
    shots.take(preferences, "settings")
    preferences.close()

    # -- the manual, on the page that answers the commonest question
    manual = HelpDialog(window, page=1)
    manual.resize(1040, 820)
    manual.show()
    shots.take(manual, "help")
    manual.close()

    # -- who the certificates are issued by
    custodian = CustodianDialog(session, window)
    custodian.show()
    shots.take(custodian, "custodian")
    custodian.close()

    # -- the limitations text, reachable from the footer
    limits = _TextDialog("What Quenchkey does not protect against",
                         limitations_html(), window, rich=True)
    limits.resize(820, 700)
    limits.show()
    shots.take(limits, "limitations")
    limits.close()

    # -- security details
    window._show_security_for_shot = True
    from quenchkey.crypto import cipher_name
    header = vault.header
    body = "\n".join(f"{name}:  {value}" for name, value in [
        ("Vault file", vault.path),
        ("Cipher", cipher_name(header.cipher_id) + " (AEAD)"),
        ("Key derivation", f"Argon2id — {header.kdf.memory_kib // 1024} MiB, "
                           f"{header.kdf.time_cost} pass"
                           f"{'es' if header.kdf.time_cost != 1 else ''}, "
                           f"parallelism {header.kdf.parallelism}"),
        ("Keyfile", "required" if header.keyfile_required else "not in use"),
        ("Per-file keys", "256-bit, from os.urandom, one per locked item"),
        ("Entries", str(len(vault.entries()))),
    ])
    log = "\n".join(f"{time.strftime('%Y-%m-%d %H:%M', time.localtime(e['at']))}  "
                    f"{e['kind']}" for e in reversed(vault.events[-12:]))
    details = _TextDialog("Security details", body + "\n\nRecent events\n" + log,
                          window, monospace=True)
    details.resize(760, 600)
    details.show()
    shots.take(details, "security-details")
    details.close()

    window.close()
    session.close()
    print(f"{len(shots.written)} screenshots written to {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "docs/screenshots"))
