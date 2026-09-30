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

"""Drive the real interface with real X input events.

This is not a mock. The application runs normally, and this sends genuine
pointer and keyboard events through the X server's XTEST extension — the same
mechanism ``xdotool`` uses — so every click goes through Qt's ordinary event
handling, hit-testing and focus logic. If a button is covered by something, or
disabled, or two pixels from where the layout says it is, this notices, because
the click lands where a person's click would land.

Why it is built the way it is
-----------------------------

A modal dialog blocks the thread that opened it inside a nested event loop, so
a driver running on that thread would stall the moment it opened one. Instead:

* the **Qt thread** runs a timer that keeps publishing a map of what is
  currently on screen — every button, field and checkbox, by its visible text,
  with its position in screen coordinates. Timers keep firing inside a modal
  loop, so the map stays live even while a dialog is up.
* the **driver thread** never touches a widget. It reads that map, and moves
  the mouse and types with its own connection to the X server.

The driver therefore finds controls the way a person does — by reading their
labels — and fails the way a person would if a label is wrong or a control is
missing.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from PyQt5.QtCore import QMetaObject, QObject, Qt, QTimer, pyqtSlot
from PyQt5.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QLabel, QLineEdit, QMenu, QMenuBar,
    QPlainTextEdit, QPushButton, QRadioButton, QTableView, QTableWidget,
    QToolButton, QWidget,
)
from Xlib import X, XK, display as xdisplay
from Xlib.ext import xtest


class DriverError(Exception):
    """The interface did not offer what the script asked for."""


@dataclass
class Control:
    kind: str
    text: str
    x: int
    y: int
    width: int
    height: int
    enabled: bool
    visible: bool
    #: What the control currently holds, as distinct from how it is labelled.
    #: A field is found by its placeholder but read by its value, and the two
    #: are rarely the same thing.
    value: str = ""

    @property
    def centre(self) -> tuple[int, int]:
        return self.x + self.width // 2, self.y + self.height // 2


# --------------------------------------------------------------------------
# the Qt side: publish what is on screen
# --------------------------------------------------------------------------

class ScreenMap:
    """A live index of the visible controls, maintained on the Qt thread."""

    def __init__(self, interval_ms: int = 150):
        self._lock = threading.Lock()
        self._controls: dict[str, Control] = {}
        self._timer = QTimer()
        self._timer.setInterval(interval_ms)
        self._timer.timeout.connect(self._scan)

    def start(self) -> None:
        self._timer.start()
        self._scan()

    def stop(self) -> None:
        self._timer.stop()

    def _scan(self) -> None:
        found: dict[str, Control] = {}
        modal = QApplication.activeModalWidget()
        roots = [modal] if modal is not None else [
            w for w in QApplication.topLevelWidgets() if w.isVisible()]

        # An open popup menu is its own top-level window and is not a child of
        # anything being scanned, so it has to be collected separately.
        popups = [w for w in QApplication.topLevelWidgets()
                  if isinstance(w, QMenu) and w.isVisible()]

        for root in roots + popups:
            if root is None:
                continue
            for control_entry in self._menu_entries(root):
                found[control_entry[0]] = control_entry[1]
            for widget in root.findChildren(QWidget):
                for control_entry in self._menu_entries(widget):
                    found[control_entry[0]] = control_entry[1]
                entry = self._describe(widget)
                if entry is None:
                    continue
                key, control = entry
                # A control inside the active modal wins over one behind it.
                if key not in found or control.visible:
                    found[key] = control

        with self._lock:
            self._controls = found

    @staticmethod
    def _menu_entries(widget: QWidget) -> list:
        """Menu bar titles and open menu items, with their on-screen rects.

        Menu actions are not widgets, so they are invisible to a plain widget
        scan — which is why a driver that only knows about buttons ends up
        clicking something else with a similar label.
        """
        if not isinstance(widget, (QMenuBar, QMenu)) or not widget.isVisible():
            return []
        kind = "menu" if isinstance(widget, QMenuBar) else "menuitem"
        entries = []
        for action in widget.actions():
            text = action.text().replace("&", "").strip()
            if not text or action.isSeparator():
                continue
            rect = widget.actionGeometry(action)
            if rect.width() < 2 or rect.height() < 2:
                continue
            top_left = widget.mapToGlobal(rect.topLeft())
            entries.append((f"{kind}:{text}", Control(
                kind, text, top_left.x(), top_left.y(),
                rect.width(), rect.height(),
                action.isEnabled(), action.isVisible())))
        return entries

    @staticmethod
    def _describe(widget: QWidget) -> Optional[tuple[str, Control]]:
        if not widget.isVisible() or widget.width() < 2 or widget.height() < 2:
            return None

        value = ""
        # Before QPushButton: a radio is an QAbstractButton too, and a run that
        # has to pick between two options needs to find it as one.
        if isinstance(widget, QRadioButton):
            kind, text = "radio", widget.text().replace("&", "")
            value = "checked" if widget.isChecked() else ""
        elif isinstance(widget, (QPushButton, QToolButton)):
            kind, text = "button", widget.text().replace("&", "")
        elif isinstance(widget, QCheckBox):
            kind, text = "check", widget.text() or _label_beside(widget)
            value = "checked" if widget.isChecked() else ""
        elif isinstance(widget, QComboBox):
            kind, text = "combo", widget.currentText()
            value = widget.currentText()
        elif isinstance(widget, QLineEdit):
            # Found by placeholder (what a person reads), or failing that by
            # object name — which is how Qt's own file dialog, whose field
            # carries neither a placeholder nor a label, can still be located.
            kind = "field"
            text = (widget.placeholderText() or widget.objectName()
                    or widget.text())
            value = widget.text()
        elif isinstance(widget, QPlainTextEdit):
            kind, text = "textarea", widget.placeholderText()[:40]
            value = widget.toPlainText()[:4000]
        elif isinstance(widget, (QTableView, QTableWidget)):
            kind, text = "table", widget.objectName() or "table"
        elif isinstance(widget, QLabel):
            # So a run can check that a warning is on the screen rather than
            # only that a dialog opened. Keyed by a short prefix because the
            # full text of a paragraph makes an unusable key.
            words = " ".join(widget.text().split())
            if len(words) < 4:
                return None
            kind, text = "label", words[:60]
            value = words
        else:
            return None

        if not text:
            return None
        top_left = widget.mapToGlobal(widget.rect().topLeft())
        return (f"{kind}:{text}", Control(
            kind, text, top_left.x(), top_left.y(),
            widget.width(), widget.height(),
            widget.isEnabled(), widget.isVisible(), value))

    def snapshot(self) -> dict[str, Control]:
        with self._lock:
            return dict(self._controls)


def _label_beside(widget: QWidget) -> str:
    """A checkbox whose text lives in a neighbouring label."""
    parent = widget.parentWidget()
    if parent is None:
        return ""
    for sibling in parent.findChildren(QLabel):
        if abs(sibling.y() - widget.y()) < 24 and sibling.x() > widget.x():
            return sibling.text()[:60]
    return ""


# --------------------------------------------------------------------------
# the driver side: real input events
# --------------------------------------------------------------------------

class _Errand(QObject):
    """Runs a callable on the thread this object lives on.

    Qt will not start a timer from a thread it did not create, so the usual
    ``QTimer.singleShot`` trick does nothing when called from the script
    thread. A queued invocation on an object constructed on the Qt thread is
    the mechanism that does work, and it needs a real slot to invoke.
    """

    def __init__(self):
        super().__init__()
        self._work = None
        self._box: dict = {}
        self._done = threading.Event()

    def ask(self, work, timeout: float):
        self._work = work
        self._box = {}
        self._done.clear()
        QMetaObject.invokeMethod(self, "_run", Qt.QueuedConnection)
        if not self._done.wait(timeout):
            raise DriverError(f"the Qt thread did not run that within {timeout}s")
        if "error" in self._box:
            raise self._box["error"]
        return self._box.get("value")

    @pyqtSlot()
    def _run(self) -> None:
        try:
            self._box["value"] = self._work()
        except BaseException as exc:  # noqa: BLE001 - handed back to the caller
            self._box["error"] = exc
        finally:
            self._done.set()


@dataclass
class Driver:
    """Sends genuine pointer and keyboard events to the X server."""

    screen: ScreenMap
    log: list = field(default_factory=list)
    started: float = field(default_factory=time.monotonic)
    _display: object = None
    pointer: tuple[int, int] = (20, 20)

    def __post_init__(self):
        self._display = xdisplay.Display()
        # Constructed here, which runs on the Qt thread, so queued
        # invocations on it land there rather than on the script thread.
        self._errand = _Errand()

    # -- narration ------------------------------------------------------

    def say(self, caption: str) -> None:
        """Record a caption against the current time, for burning into the video."""
        stamp = time.monotonic() - self.started
        self.log.append((stamp, caption))
        print(f"  [{stamp:6.1f}s] {caption}", flush=True)

    def elapsed(self) -> float:
        return time.monotonic() - self.started

    # -- pointer --------------------------------------------------------

    def move_to(self, x: int, y: int, duration: float = 0.45) -> None:
        """Glide the pointer, so a viewer can follow where it is going."""
        start_x, start_y = self.pointer
        steps = max(8, int(duration * 60))
        for index in range(1, steps + 1):
            fraction = index / steps
            # ease-in-out: slow at both ends, like a hand moving
            eased = fraction * fraction * (3 - 2 * fraction)
            xtest.fake_input(
                self._display, X.MotionNotify, x=int(start_x + (x - start_x) * eased),
                y=int(start_y + (y - start_y) * eased))
            self._display.sync()
            time.sleep(duration / steps)
        self.pointer = (x, y)

    def click_at(self, x: int, y: int, settle: float = 0.35) -> None:
        self.move_to(x, y)
        time.sleep(0.12)
        xtest.fake_input(self._display, X.ButtonPress, 1)
        self._display.sync()
        time.sleep(0.09)
        xtest.fake_input(self._display, X.ButtonRelease, 1)
        self._display.sync()
        time.sleep(settle)

    # -- finding things -------------------------------------------------

    def find(self, kind: str, text: str, timeout: float = 8.0,
             require_enabled: bool = True) -> Control:
        """Wait for a control whose visible label contains ``text``."""
        deadline = time.monotonic() + timeout
        seen: dict[str, Control] = {}
        wanted = text.lower()
        while time.monotonic() < deadline:
            seen = self.screen.snapshot()
            candidates = [c for key, c in seen.items()
                          if key.startswith(f"{kind}:")
                          and (not require_enabled or c.enabled)]
            # Exact first. Without this, asking for "Vault" happily matches
            # "Lock vault" and the run ends somewhere it did not intend to be.
            for control in candidates:
                if control.text.lower().strip() == wanted:
                    return control
            for control in candidates:
                if wanted in control.text.lower():
                    return control
            time.sleep(0.15)

        available = sorted(k for k in seen if k.startswith(f"{kind}:"))
        raise DriverError(
            f"no enabled {kind} matching {text!r} appeared within {timeout:g}s. "
            f"On screen: {available}")

    def read_value(self, kind: str, text: str, timeout: float = 8.0) -> str:
        """What a control currently holds — its text, not its label."""
        return self.find(kind, text, timeout, require_enabled=False).value

    def exists(self, kind: str, text: str, timeout: float = 1.5) -> bool:
        try:
            self.find(kind, text, timeout=timeout, require_enabled=False)
            return True
        except DriverError:
            return False

    # -- acting ---------------------------------------------------------

    def click(self, kind: str, text: str, timeout: float = 8.0,
              settle: float = 0.45) -> Control:
        control = self.find(kind, text, timeout)
        self.click_at(*control.centre, settle=settle)
        return control

    def focus(self, kind: str, text: str, timeout: float = 8.0) -> Control:
        return self.click(kind, text, timeout, settle=0.2)

    def select_in_combo(self, current: str, steps_down: int) -> None:
        """Change a combo box the way a keyboard user would.

        Clicking opens the popup, which lives in its own window that the screen
        map does not index; arrow keys and Return work regardless and exercise
        the same signal.
        """
        self.click("combo", current, settle=0.6)
        self.pause(0.4)
        self.key("Down", times=steps_down)
        self.pause(0.3)
        self.key("Return")
        self.pause(0.7)

    def type_text(self, text: str, per_char: float = 0.035) -> None:
        for character in text:
            self._press(character)
            time.sleep(per_char)
        time.sleep(0.15)

    def key(self, name: str, times: int = 1) -> None:
        for _ in range(times):
            self._press_keysym(XK.string_to_keysym(name))
            time.sleep(0.08)

    def _press(self, character: str) -> None:
        keysym = XK.string_to_keysym(_KEYSYM_NAMES.get(character, character))
        if keysym == 0:
            return
        shifted = character.isupper() or character in '~!@#$%^&*()_+{}|:"<>?'
        self._press_keysym(keysym, shift=shifted)

    def _press_keysym(self, keysym: int, shift: bool = False) -> None:
        keycode = self._display.keysym_to_keycode(keysym)
        if not keycode:
            return
        shift_code = self._display.keysym_to_keycode(XK.XK_Shift_L)
        if shift:
            xtest.fake_input(self._display, X.KeyPress, shift_code)
        xtest.fake_input(self._display, X.KeyPress, keycode)
        xtest.fake_input(self._display, X.KeyRelease, keycode)
        if shift:
            xtest.fake_input(self._display, X.KeyRelease, shift_code)
        self._display.sync()

    def on_ui_thread(self, work, timeout: float = 10.0):
        """Run something on the Qt thread and wait for its result.

        The script runs on a worker thread, and Qt refuses almost everything
        from one. Used sparingly: the point of this harness is to drive the
        interface through real input events, and a scene that reaches in and
        calls a method is not testing the interface. What it is for is the
        handful of things a person triggers by waiting — a timer that fires
        every few minutes by design — where a recording cannot wait.
        """
        return self._errand.ask(work, timeout)

    def pause(self, seconds: float) -> None:
        time.sleep(seconds)


#: X keysym names for characters whose literal form is not a keysym name.
_KEYSYM_NAMES = {
    " ": "space", "-": "minus", "_": "underscore", ".": "period",
    ",": "comma", "!": "exclam", "?": "question", "/": "slash",
    ":": "colon", ";": "semicolon", "'": "apostrophe", '"': "quotedbl",
    "(": "parenleft", ")": "parenright", "@": "at", "#": "numbersign",
    "&": "ampersand", "*": "asterisk", "+": "plus", "=": "equal",
    "0": "0", "1": "1", "2": "2", "3": "3", "4": "4",
    "5": "5", "6": "6", "7": "7", "8": "8", "9": "9",
}
