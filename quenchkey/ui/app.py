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

"""Application bootstrap: the gate, then the main window, and back again."""

from __future__ import annotations

import argparse
import os
import signal
import sys
from typing import Optional

from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtWidgets import QApplication

from .. import settings as settings_mod
from ..session import Session
from ..vault import DEFAULT_VAULT_PATH
from . import filechooser, theme, tray as tray_mod
from .gate import GateWindow
from .main_window import MainWindow


class Application:
    """Owns the two top-level windows and the transition between them."""

    def __init__(self, vault_path: str = DEFAULT_VAULT_PATH,
                 auto_lock_seconds: Optional[int] = None,
                 minimised: bool = False):
        self.vault_path = vault_path
        self.auto_lock_seconds = auto_lock_seconds
        self.minimised = minimised
        self.gate: Optional[GateWindow] = None
        self.main: Optional[MainWindow] = None
        self.tray = None

    def start(self) -> None:
        self.gate = GateWindow(self.vault_path)
        self.gate.opened.connect(self._on_opened)

        # Starting minimised only makes sense if there is a tray to minimise
        # to. Without one the window would be hidden with no way back, so it
        # opens normally and says nothing.
        wanted = self.minimised or settings_mod.current().get("start_minimised")
        if wanted and tray_mod.looks_reliable():
            self.tray = tray_mod.Tray(self.gate, self.quit)
            self.gate.hide()
        else:
            self.gate.show()

    def _on_opened(self, session: Session) -> None:
        if self.auto_lock_seconds is not None:
            session.auto_lock_seconds = self.auto_lock_seconds
        self.main = MainWindow(session)
        self.main.closed.connect(self._on_locked)

        if self.tray is not None:
            self.tray.hide()
        if settings_mod.current().get("tray_enabled", True):
            self.tray = tray_mod.Tray(self.main, self.quit)
            self.main.attach_tray(self.tray)

        self.main.show()
        if self.gate is not None:
            self.gate.hide()

    def _on_locked(self) -> None:
        """Back to the unlock screen, with the tray following the window."""
        self.main = None
        if self.tray is not None:
            self.tray.hide()
            self.tray = None
        if self.gate is not None:
            self.gate._refresh_mode()
            self.gate.show()
            self.gate.raise_()
            self.gate.activateWindow()

    def quit(self) -> None:
        """Lock everything and go, from the tray menu or anywhere else."""
        if self.main is not None:
            self.main.quit_fully()
        if self.tray is not None:
            self.tray.hide()
        if self.gate is not None:
            self.gate.close()
        QApplication.quit()


def _cli_commands() -> set:
    """The subcommands that belong to the terminal rather than the window."""
    from ..cli import build_parser as cli_parser

    for action in cli_parser()._actions:
        if isinstance(action, argparse._SubParsersAction):
            return set(action.choices)
    return set()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="quenchkey",
        description="Quenchkey — files that expire for real.",
        epilog="There is a command line too: `quenchkey lock --help`, and "
               "`quenchkey --help-commands` for the rest of it.")
    parser.add_argument("--vault", default=DEFAULT_VAULT_PATH,
                        help=f"path to the vault file (default: {DEFAULT_VAULT_PATH})")
    parser.add_argument("--auto-lock", type=int, default=None, metavar="SECONDS",
                        help="lock the vault after this many idle seconds "
                             "(0 disables auto-locking)")
    parser.add_argument("--version", action="store_true",
                        help="print version and cryptographic details, then exit")
    parser.add_argument("--scale", type=float, default=None, metavar="FACTOR",
                        help="override the display scale factor, e.g. 1.5. Only "
                             "needed when the desktop reports the wrong one — "
                             "on XWayland under fractional scaling, it often does")
    parser.add_argument("--font-scale", type=float, default=1.0, metavar="FACTOR",
                        help="make all text larger or smaller (default 1.0), "
                             "on top of the desktop's own font setting")
    parser.add_argument("--sweep", action="store_true",
                        help="delete locked files whose deadline has passed, "
                             "then exit. Opens no window and needs no "
                             "passphrase, so it deletes files but cannot "
                             "destroy keys; that happens at the next unlock")
    parser.add_argument("--minimised", "--minimized", action="store_true",
                        dest="minimised",
                        help="start in the tray rather than showing the "
                             "window. Ignored where the desktop has no tray")
    parser.add_argument("--notify", action="store_true",
                        help="with --sweep, send a desktop notification when "
                             "something was deleted")
    parser.add_argument("--help-commands", action="store_true",
                        help="list the terminal commands and exit")
    return parser


def run_sweep(vault_path: str, notify: bool = False) -> int:
    """The background cleanup: no Qt, no passphrase, no window.

    Prints what it did and returns 0 whether or not anything was due, because
    "nothing had expired" is a successful run and a systemd timer that goes
    red every few minutes is a timer people switch off.
    """
    from .. import schedule

    if schedule.read_index(vault_path) is None:
        print(f"No expiry schedule beside {vault_path}. Background expiry is "
              f"off for this vault, or it has nothing with a deadline.")
        return 0

    report = schedule.sweep(vault_path)
    print(report.summary())
    for path in report.deleted:
        print(f"  deleted {path}")
    for path, reason in report.failed:
        print(f"  could not delete {path}: {reason}")

    if notify and report.deleted:
        _notify("Quenchkey", report.summary())

    # And look a little way ahead. A deadline that arrives unannounced is the
    # one way this tool loses somebody's work without being asked to, and the
    # dead man's switch is armed precisely for when nobody is watching.
    if notify:
        for said in schedule.warn_upcoming(vault_path, _notify):
            print(f"  warned: {said.title()}")
    else:
        for coming in schedule.upcoming(vault_path):
            print(f"  coming: {coming.title().lower()} — {coming.message()}")
    return 0


def _notify(title: str, body: str) -> None:
    """Best effort, through whatever the desktop provides."""
    import shutil
    import subprocess

    binary = shutil.which("notify-send")
    if not binary:
        return
    try:
        subprocess.run([binary, "--app-name=Quenchkey", "--icon=quenchkey",
                        title, body], check=False, timeout=10)
    except (OSError, subprocess.SubprocessError):
        pass


def enable_high_dpi(scale: Optional[float] = None) -> None:
    """Make the interface follow the display's scale factor.

    These attributes have to be set *before* the QApplication exists — Qt reads
    them while constructing it, and setting them afterwards silently does
    nothing. Without them the interface renders at 1:1 on a scaled display,
    which on a HiDPI screen means a window a quarter of the size it should be
    with text to match.

    ``PassThrough`` rounding matters on desktops using fractional scaling
    (125%, 150%). Qt 5's default rounds that to the nearest integer, so a 150%
    display gets either a cramped 1x or an oversized 2x.
    """
    if scale is not None:
        os.environ["QT_SCALE_FACTOR"] = str(scale)
    else:
        # Let Qt read the scale factor from the platform rather than guessing.
        os.environ.setdefault("QT_AUTO_SCREEN_SCALE_FACTOR", "1")

    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    try:
        QApplication.setHighDpiScaleFactorRoundingPolicy(
            Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    except AttributeError:
        # Qt older than 5.14 has no rounding policy; integer scaling is all
        # it can do, and that is better than none.
        pass


def version_report() -> str:
    """Version, plus what is actually doing the cryptography on this machine.

    Printed rather than hard-coded, so a bug report says which OpenSSL and
    which Argon2 actually ran — not which ones the README assumed.
    """
    from .. import __version__
    from ..crypto import cipher_name, CIPHER_AES_256_GCM, CIPHER_CHACHA20_POLY1305
    from ..vault import FORMAT_VERSION, PAYLOAD_VERSION

    lines = [f"Quenchkey {__version__}",
             f"vault format {FORMAT_VERSION}, payload {PAYLOAD_VERSION}",
             f"ciphers: {cipher_name(CIPHER_CHACHA20_POLY1305)}, "
             f"{cipher_name(CIPHER_AES_256_GCM)}",
             ""]

    import platform
    lines.append(f"python {platform.python_version()} on "
                 f"{platform.system()} {platform.machine()}")

    def report(label: str, loader):
        try:
            lines.append(f"{label}: {loader()}")
        except Exception as exc:  # noqa: BLE001 - a missing optional is news
            lines.append(f"{label}: unavailable ({exc})")

    report("cryptography", lambda: __import__("cryptography").__version__)
    report("openssl", lambda: __import__(
        "cryptography.hazmat.backends.openssl.backend", fromlist=["backend"]
    ).backend.openssl_version_text())
    report("argon2-cffi", lambda: __import__(
        "importlib.metadata", fromlist=["version"]).version("argon2-cffi"))
    report("py7zr", lambda: __import__("py7zr").__version__)
    report("shamir-mnemonic", lambda: __import__(
        "importlib.metadata", fromlist=["version"]).version("shamir-mnemonic"))

    from .. import factors
    available, reason = factors.fido2_available()
    lines.append(f"security keys: {reason}")

    # Which file chooser will open. Worth printing: "the file dialog looks
    # wrong" is otherwise impossible to diagnose from a bug report.
    if filechooser.mode() != "auto":
        lines.append(f"file chooser: {filechooser.mode()} "
                     f"(forced by {filechooser.MODE_ENV})")
    elif filechooser.portal_installed():
        lines.append("file chooser: the desktop's own, via the XDG portal")
    else:
        lines.append("file chooser: Qt's built-in "
                     "(no desktop portal found on this session bus)")

    lines.append("")
    lines.append("Licensed under the Apache License 2.0. This software comes "
                 "with no warranty;")
    lines.append("see LICENSE for the terms, and the README for what it does "
                 "not protect against.")
    return "\n".join(lines)


def main(argv: Optional[list[str]] = None) -> int:
    # One command, two ways of being used. `quenchkey` on its own opens the
    # window; `quenchkey lock …` is the terminal. Dispatched on the first
    # argument rather than by a separate binary, because "quenchkey lock" is
    # what somebody types and being told there is no such command would be a
    # poor greeting. Qt is never imported on the terminal path, so the
    # command line works over SSH and in a container.
    arguments = list(sys.argv[1:] if argv is None else argv)
    # Looked for anywhere rather than only first, because `quenchkey --vault
    # x lock file` is as natural to type as `quenchkey lock file --vault x`,
    # and the two sets of names do not overlap: nothing the window takes is
    # called lock, ls or sweep.
    if any(token in _cli_commands() for token in arguments):
        from ..cli import main as cli_main

        return cli_main(arguments)

    args = build_parser().parse_args(argv)

    # Answered before Qt is touched, so --version works over SSH, in a
    # container, and anywhere else without a display — which is exactly where
    # someone writing a bug report tends to be.
    if args.version:
        print(version_report())
        return 0

    if args.help_commands:
        from ..cli import build_parser as cli_parser

        cli_parser().print_help()
        return 0

    # Also answered before Qt is touched: this runs from a systemd timer, on a
    # machine with no session bus and no display, and must not need either.
    if args.sweep:
        return run_sweep(os.path.expanduser(args.vault), notify=args.notify)

    # Ctrl-C at the terminal should close the app, not be swallowed by Qt.
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    enable_high_dpi(args.scale)

    # Both of these have to happen before the QApplication exists: Qt reads
    # the scale attributes and picks its platform theme while constructing
    # itself, and setting either afterwards does nothing at all.
    filechooser.configure()

    app = QApplication(sys.argv[:1])
    app.setApplicationName("Quenchkey")
    app.setApplicationDisplayName("Quenchkey")
    app.setOrganizationName("Quenchkey")
    theme.apply(app, font_scale=args.font_scale)

    # Let Python process signals between Qt events.
    heartbeat = QTimer()
    heartbeat.start(250)
    heartbeat.timeout.connect(lambda: None)

    controller = Application(os.path.expanduser(args.vault), args.auto_lock,
                             minimised=args.minimised)
    controller.start()
    return app.exec_()
