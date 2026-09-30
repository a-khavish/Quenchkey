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

"""Open every dialog in the app and check it is actually on screen.

Grabbing a widget renders it whether or not it would ever appear, so a
screenshot is not evidence that a dialog works. This shows each one on a real
display and then asks harder questions:

* is it mapped and visible, with a window the compositor knows about?
* is it at least as large as its own layout needs, or is content cut off?
* does every visible child sit inside the dialog, rather than off its edge?
* would it fit on a small laptop screen, or does it open bigger than the
  display it has to live on?

Run it under a virtual display::

    xvfb-run -a -s "-screen 0 1600x1200x24" python3 tools/dialog_parade.py

Add ``--out DIR`` to keep a PNG of each one. Exit status is non-zero if any
dialog failed a check, so this is usable as a test.
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PyQt5.QtCore import QTimer  # noqa: E402
from PyQt5.QtWidgets import QApplication, QLabel, QWidget  # noqa: E402

from quenchkey import locker  # noqa: E402
from quenchkey.certificate import Custodian  # noqa: E402
from quenchkey.crypto import KdfParams  # noqa: E402
from quenchkey.session import Session  # noqa: E402
from quenchkey.vault import Vault  # noqa: E402
from quenchkey.ui import theme  # noqa: E402
from quenchkey.ui.gate import GateWindow  # noqa: E402
from quenchkey.ui.main_window import MainWindow  # noqa: E402

PASSPHRASE = "trad-once-nacho-utmost-ozone-noil-fjeld"

#: Cheap parameters — this harness is about layout, not key derivation.
FAST_KDF = KdfParams.create(time_cost=1, memory_kib=8192, parallelism=1)

#: The screen every window has to survive. Still the commonest laptop panel,
#: and the one where a window sized for a desktop stops fitting.
#:
#: Quenchkey fits this at every font scale up to 200%. It also fits a 1024x600
#: display up to 125%; past that the toolbar's own buttons are wider than the
#: screen, and no amount of clamping helps because the row cannot get smaller
#: than the words on it.
SMALL_SCREEN = (1366, 768)


class Failure(Exception):
    pass


def settle(app: QApplication, seconds: float = 0.35) -> None:
    """Let Qt map the window and run the layout before anything is measured."""
    deadline = time.time() + seconds
    while time.time() < deadline:
        app.processEvents()
        time.sleep(0.01)


def offending_children(dialog: QWidget) -> list[str]:
    """Visible children whose geometry leaves the dialog's own rectangle."""
    bounds = dialog.rect()
    strays = []
    for child in dialog.findChildren(QWidget):
        if not child.isVisible() or child.width() == 0 or child.height() == 0:
            continue
        if child.window() is not dialog:
            continue  # a popup of its own, not laid out inside this dialog
        top_left = child.mapTo(dialog, child.rect().topLeft())
        rect = child.rect().translated(top_left)
        if bounds.contains(rect):
            continue
        # A scroll area's contents are meant to overflow; it is the viewport's
        # job to clip them, and that is not a defect.
        if any(parent.inherits("QAbstractScrollArea")
               for parent in _ancestors(child, dialog)):
            continue
        strays.append(f"{child.metaObject().className()}"
                      f"{'#' + child.objectName() if child.objectName() else ''} "
                      f"at {rect.x()},{rect.y()} {rect.width()}x{rect.height()}")
    return strays


def _ancestors(widget: QWidget, stop: QWidget) -> list[QWidget]:
    chain = []
    parent = widget.parentWidget()
    while parent is not None and parent is not stop:
        chain.append(parent)
        parent = parent.parentWidget()
    return chain


def clipped_labels(dialog: QWidget) -> list[str]:
    """Wrapping labels given less height than their own text needs."""
    bad = []
    for label in dialog.findChildren(QLabel):
        if not label.isVisible() or not label.wordWrap() or not label.text():
            continue
        needed = label.heightForWidth(label.width())
        if needed > 0 and label.height() + 1 < needed:
            snippet = label.text()[:60].replace("\n", " ")
            bad.append(f"{label.height()}px for {needed}px of text: “{snippet}…”")
    return bad


def complaints(dialog: QWidget) -> list[str]:
    """Everything wrong with a dialog that is supposedly on screen."""
    problems: list[str] = []
    if not dialog.isVisible():
        problems.append("never became visible")
    handle = dialog.windowHandle()
    if handle is None or not handle.isExposed():
        problems.append("has no exposed window — the display never mapped it")
    if dialog.width() <= 0 or dialog.height() <= 0:
        problems.append(f"opened at {dialog.width()}x{dialog.height()}")

    wanted = dialog.minimumSizeHint()
    if wanted.width() > dialog.width() + 1 or wanted.height() > dialog.height() + 1:
        problems.append(
            f"opened at {dialog.width()}x{dialog.height()} but its layout needs "
            f"{wanted.width()}x{wanted.height()} — content is cut off")

    # The size it actually opens at is what matters. A dialog whose minimum
    # would fit but which opens larger than the display still has its buttons
    # somewhere off the bottom of the screen, where nobody can reach them.
    limit_w, limit_h = SMALL_SCREEN
    if dialog.width() > limit_w or dialog.height() > limit_h:
        problems.append(
            f"opens at {dialog.width()}x{dialog.height()}, larger than the "
            f"{limit_w}x{limit_h} screen it has to fit on")
    if wanted.width() > limit_w or wanted.height() > limit_h:
        problems.append(
            f"cannot shrink below {wanted.width()}x{wanted.height()}, which "
            f"still does not fit a {limit_w}x{limit_h} screen")

    problems += [f"child outside the dialog: {s}" for s in offending_children(dialog)]
    problems += [f"clipped label: {c}" for c in clipped_labels(dialog)]
    return problems


class Parade:
    """Triggers a real UI action and inspects whatever dialog it puts up.

    Every one of these actions ends in ``exec_()``, which spins its own event
    loop and does not return until the dialog closes. So the inspection runs
    from a timer inside that loop, and closes the dialog itself to let the
    trigger return. That is the whole point: the dialog is examined exactly as
    the user's own click would have produced it, menu item and all, rather
    than being constructed by hand in a way no user can reach.
    """

    def __init__(self, app: QApplication, out_dir: str | None):
        self.app = app
        self.out_dir = out_dir
        self.failures = 0
        self.total = 0

    def run(self, name: str, trigger, expect: str) -> None:
        self.total += 1
        found: dict = {"problems": None, "class": None, "size": None}

        def probe() -> None:
            dialog = self.app.activeModalWidget() or self.app.activeWindow()
            if dialog is None or dialog.inherits("QMainWindow"):
                found["problems"] = ["no dialog appeared"]
                return
            settle(self.app, 0.25)
            found["class"] = dialog.metaObject().className()
            found["size"] = f"{dialog.width()}x{dialog.height()}"
            found["problems"] = complaints(dialog)
            if self.out_dir:
                dialog.grab().save(os.path.join(self.out_dir, f"{name}.png"))
            dialog.reject() if hasattr(dialog, "reject") else dialog.close()

        QTimer.singleShot(500, probe)
        trigger()
        settle(self.app, 0.15)

        problems = found["problems"]
        if problems is None:
            problems = ["the trigger returned without ever showing a dialog"]
        if found["class"] and found["class"] != expect:
            problems.append(f"showed {found['class']}, expected {expect}")

        if problems:
            self.failures += 1
            print(f"FAIL  {name}")
            for problem in problems:
                print(f"        {problem}")
        else:
            print(f"ok    {name}  {found['class']} {found['size']}")


def build_fixture(root: str):
    """A vault with enough in it that every dialog has something to show."""
    sources = os.path.join(root, "documents")
    blobs = os.path.join(root, "locked")
    os.makedirs(sources, exist_ok=True)
    os.makedirs(blobs, exist_ok=True)

    paths = []
    for name, size in (("Q3 board pack.pdf", 240_000),
                       ("salary-review.xlsx", 18_000),
                       ("term-sheet-draft.docx", 9_600)):
        path = os.path.join(sources, name)
        with open(path, "wb") as fh:
            fh.write(os.urandom(size))
        paths.append(path)

    vault = Vault.create(os.path.join(root, "vault.qkv"), PASSPHRASE,
                         kdf_params=FAST_KDF)
    vault.set_custodian(Custodian("A. Mensah", "Data Protection Officer",
                                  "dpo@example.org", "Example Ltd"))
    for index, path in enumerate(paths):
        locker.lock_files(vault, [path], time.time() + 3600 * (index + 1),
                          output_dir=blobs)
    # One destroyed key, so the certificates dialog has a row to draw.
    spent = os.path.join(sources, "expired-contract.pdf")
    with open(spent, "wb") as fh:
        fh.write(os.urandom(4_000))
    result = locker.lock_files(vault, [spent], time.time() + 1, output_dir=blobs)
    vault.shred_key(result.entry.id)
    vault.save()
    return vault, paths


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", help="write a PNG of each dialog here")
    parser.add_argument("--font-scale", type=float, default=1.0,
                        help="enlarge the interface, as a scaled desktop would")
    parser.add_argument("--screen", default="1366x768",
                        help="the screen every dialog has to fit on")
    args = parser.parse_args()

    global SMALL_SCREEN
    width, _, height = args.screen.partition("x")
    SMALL_SCREEN = (int(width), int(height))
    if args.out:
        os.makedirs(args.out, exist_ok=True)

    # The desktop's own chooser belongs to another process and cannot be
    # inspected from here; this harness is about Quenchkey's own dialogs.
    os.environ["QUENCHKEY_FILE_DIALOG"] = "qt"
    os.environ["XDG_CONFIG_HOME"] = tempfile.mkdtemp(prefix="quenchkey-parade-config-")

    app = QApplication(sys.argv[:1])
    theme.apply(app, font_scale=args.font_scale)

    root = tempfile.mkdtemp(prefix="quenchkey-parade-")
    vault, paths = build_fixture(root)
    session = Session(vault)

    window = MainWindow(session)
    window.show()
    window.refresh()
    settle(app, 0.5)
    window.table.selectRow(0)

    parade = Parade(app, args.out)

    for name, widget in (("main-window", window),):
        problems = complaints(widget)
        parade.total += 1
        if problems:
            parade.failures += 1
            print(f"FAIL  {name}")
            for problem in problems:
                print(f"        {problem}")
        else:
            print(f"ok    {name}  {widget.metaObject().className()} "
                  f"{widget.width()}x{widget.height()}")

    # Every one of these is the action a menu item or button is wired to, so
    # a dialog that has come adrift from the interface fails here.
    parade.run("lock", lambda: window._lock_files(paths[:3]), "LockDialog")
    parade.run("unlock", window._open_selected, "UnlockDialog")
    parade.run("expire-confirm", window._expire_selected, "ConfirmDialog")
    parade.run("forget-confirm", window._forget_selected, "ConfirmDialog")
    parade.run("certificates", window._show_certificates, "CertificatesDialog")
    parade.run("anchor", window._show_anchor, "AnchorDialog")
    parade.run("recovery-shares", window._show_shares, "RecoverySharesDialog")
    parade.run("custodian", window._show_custodian, "CustodianDialog")
    parade.run("background-expiry", window._show_background,
               "BackgroundExpiryDialog")
    parade.run("share", lambda: window._lock_to_share(paths[:2]), "ShareDialog")
    parade.run("backups", window._show_backups, "BackupDialog")
    parade.run("watch-folders", window._show_watch, "WatchFoldersDialog")
    parade.run("duress", window._show_duress, "DuressDialog")
    parade.run("integrity", window._show_integrity, "IntegrityDialog")
    parade.run("audit", window._show_audit, "AuditDialog")
    parade.run("handover", lambda: window._hand_over(paths[:2]), "HandoverDialog")
    parade.run("identity-card", window._show_identity, "IdentityCardDialog")
    parade.run("settings", window._show_settings, "SettingsDialog")
    parade.run("help", window._show_help, "HelpDialog")
    parade.run("about", window._show_about, "_TextDialog")
    parade.run("security-details", window._show_security, "_TextDialog")
    parade.run("limitations", window._show_limitations, "_TextDialog")

    # Opening a shared file needs one to exist, so one is made here rather
    # than reached through a file chooser the driver cannot drive.
    from quenchkey import locker
    from quenchkey.crypto import KdfParams as _Kdf
    shared = locker.lock_to_share(
        paths[:1], "ephemeral-lantern-above-the-quay",
        output_path=os.path.join(root, "shared.qkey"),
        kdf_params=_Kdf.create(time_cost=1, memory_kib=8192, parallelism=1))
    parade.run("unlock-shared", lambda: window._open_shared_file(shared.path),
               "UnlockSharedDialog")

    # The share-recovery dialog hangs off the unlock screen, not the vault.
    gate = GateWindow(vault.path)
    gate.show()
    settle(app, 0.4)
    parade.total += 1
    gate_problems = complaints(gate)
    if gate_problems:
        parade.failures += 1
        print("FAIL  gate-window")
        for problem in gate_problems:
            print(f"        {problem}")
    else:
        print(f"ok    gate-window  GateWindow {gate.width()}x{gate.height()}")
    parade.run("share-unlock", gate._unlock_with_shares, "ShareUnlockDialog")
    gate.close()

    window.close()
    settle(app, 0.2)
    print()
    print(f"{parade.total - parade.failures}/{parade.total} windows appeared "
          f"at font scale {args.font_scale:g}, from the actions that are "
          f"supposed to raise them, and fit {SMALL_SCREEN[0]}x{SMALL_SCREEN[1]}")
    return 1 if parade.failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
