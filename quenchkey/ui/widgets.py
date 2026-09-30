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

"""Reusable pieces of the interface."""

from __future__ import annotations

from typing import Optional

from PyQt5.QtCore import QPoint, QRect, QSize, Qt, pyqtSignal
from PyQt5.QtGui import QColor, QPainter, QPainterPath
from PyQt5.QtWidgets import (
    QCheckBox, QDialog, QFrame, QHBoxLayout, QLabel, QLayout, QLineEdit,
    QMenu, QPushButton, QSizePolicy, QToolButton, QVBoxLayout, QWidget,
)

from .. import passphrase as pp
from . import theme


# --------------------------------------------------------------------------
# simple building blocks
# --------------------------------------------------------------------------

class Card(QFrame):
    """A raised panel."""

    def __init__(self, parent: Optional[QWidget] = None, sunken: bool = False,
                 padding: int = 20, spacing: int = theme.GAP):
        super().__init__(parent)
        self.setObjectName("SunkenCard" if sunken else "Card")
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(padding, padding, padding, padding)
        self.body.setSpacing(spacing)


class Divider(QFrame):
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setObjectName("Divider")
        self.setFixedHeight(1)


class WrapLabel(QLabel):
    """A word-wrapping label that actually claims the height it needs.

    Qt's layouts do not consult ``heightForWidth`` for a plain ``QLabel``
    reliably, so wrapped text ends up clipped to a single line. Recomputing the
    minimum height on every resize fixes it for good.
    """

    def __init__(self, text: str = "", parent: Optional[QWidget] = None):
        super().__init__(text, parent)
        self.setWordWrap(True)
        policy = QSizePolicy(QSizePolicy.Preferred, QSizePolicy.Minimum)
        policy.setHeightForWidth(True)
        self.setSizePolicy(policy)

    def resizeEvent(self, event):  # noqa: N802 - Qt naming
        super().resizeEvent(event)
        self._sync_height()

    def setText(self, text):  # noqa: N802 - Qt naming
        super().setText(text)
        self._sync_height()

    def _sync_height(self) -> None:
        if self.width() <= 0:
            return
        needed = self.heightForWidth(self.width())
        if needed > 0 and needed != self.minimumHeight():
            self.setMinimumHeight(needed)
            # Tell the parent layout the requirement changed, or a label that
            # grew from one line to three stays clipped to one.
            self.updateGeometry()


def label(text: str, role: str = "", wrap: bool = False,
          parent: Optional[QWidget] = None) -> QLabel:
    widget = WrapLabel(text, parent) if wrap else QLabel(text, parent)
    if role:
        widget.setObjectName(role)
    return widget


class Banner(QFrame):
    """An inline notice. Used for the honesty notes as much as for errors."""

    TONES = {
        "info": (theme.PRIMARY, theme.PRIMARY_DARK),
        "success": (theme.SUCCESS, theme.SUCCESS_DARK),
        "warning": (theme.WARNING, theme.WARNING_DARK),
        "danger": (theme.DANGER, theme.DANGER_DARK),
        "muted": (theme.TEXT_MUTED, theme.SURFACE_SUNKEN),
    }

    def __init__(self, text: str = "", tone: str = "info",
                 parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._layout = QHBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 14, 0)
        self._layout.setSpacing(12)

        # A real widget rather than a CSS border: a rounded border-left renders
        # its corners as visible arcs, which read as a stray bracket.
        self._accent = QFrame()
        self._accent.setFixedWidth(3)
        self._accent.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Expanding)
        self._layout.addWidget(self._accent)

        self._text = WrapLabel(text)
        self._text.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self._text.setContentsMargins(11, 12, 0, 12)
        self._layout.addWidget(self._text, 1)
        policy = QSizePolicy(QSizePolicy.Preferred, QSizePolicy.Minimum)
        policy.setHeightForWidth(True)
        self.setSizePolicy(policy)
        self.set_tone(tone)

    def hasHeightForWidth(self) -> bool:  # noqa: N802 - Qt naming
        return True

    def heightForWidth(self, width: int) -> int:  # noqa: N802 - Qt naming
        outer = self._layout.contentsMargins()
        inner = self._text.contentsMargins()
        available = (width - outer.left() - outer.right() - self._accent.width()
                     - self._layout.spacing() - inner.left() - inner.right())
        if available <= 0:
            return super().heightForWidth(width)
        return (self._text.heightForWidth(available) + inner.top() + inner.bottom()
                + outer.top() + outer.bottom())

    def resizeEvent(self, event):  # noqa: N802 - Qt naming
        super().resizeEvent(event)
        needed = self.heightForWidth(self.width())
        if needed > 0 and needed != self.minimumHeight():
            self.setMinimumHeight(needed)
            self.updateGeometry()

    def set_tone(self, tone: str) -> None:
        accent, background = self.TONES.get(tone, self.TONES["info"])
        self._tone = tone
        self.setStyleSheet(
            f"Banner {{ background-color: {background}; border: none;"
            f" border-radius: {theme.RADIUS_SMALL}px; }}"
            f" QLabel {{ background: transparent; color: {theme.TEXT}; }}"
        )
        self._accent.setStyleSheet(
            f"background-color: {accent};"
            f" border-top-left-radius: {theme.RADIUS_SMALL}px;"
            f" border-bottom-left-radius: {theme.RADIUS_SMALL}px;")

    def set_text(self, text: str) -> None:
        self._text.setText(text)

    def show_message(self, text: str, tone: str = "info") -> None:
        self.set_text(text)
        self.set_tone(tone)
        self.setVisible(bool(text))


class StatTile(Card):
    """A number with a caption, for the summary strip."""

    def __init__(self, caption: str, value: str = "—", tone: str = theme.TEXT,
                 parent: Optional[QWidget] = None):
        super().__init__(parent, padding=16, spacing=4)
        self.value = label(value, "StatValue")
        self.value.setStyleSheet(f"color: {tone}; background: transparent;")
        self.caption = label(caption.upper(), "StatLabel", wrap=True)
        self.caption.setStyleSheet("background: transparent;")
        self.body.addWidget(self.value)
        self.body.addWidget(self.caption)
        # Four of these sit side by side. Left at their natural width they set
        # the minimum width of the whole window between them, which at a large
        # font is more than a small screen has. The caption wraps instead.
        self.caption.setMinimumWidth(1)
        self.value.setMinimumWidth(1)
        self.setMinimumWidth(1)

    def set_value(self, text: str, tone: Optional[str] = None) -> None:
        self.value.setText(text)
        if tone:
            self.value.setStyleSheet(f"color: {tone}; background: transparent;")


# --------------------------------------------------------------------------
# passphrase entry
# --------------------------------------------------------------------------

class StrengthMeter(QWidget):
    """A segmented bar plus a label, driven by :mod:`quenchkey.passphrase`."""

    SEGMENTS = 5
    COLOURS = [theme.DANGER, theme.DANGER, theme.WARNING, theme.PRIMARY, theme.SUCCESS]

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._strength: Optional[pp.Strength] = None
        self.setMinimumHeight(8)
        self.setMaximumHeight(8)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

    def set_strength(self, strength: Optional[pp.Strength]) -> None:
        self._strength = strength
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802 - Qt naming
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)
        gap = 5
        width = (self.width() - gap * (self.SEGMENTS - 1)) / self.SEGMENTS
        filled = 0
        colour = QColor(theme.BORDER)
        if self._strength is not None:
            filled = self._strength.band + (1 if self._strength.bits > 0 else 0)
            colour = QColor(self.COLOURS[min(self._strength.band, len(self.COLOURS) - 1)])
        for index in range(self.SEGMENTS):
            x = index * (width + gap)
            path = QPainterPath()
            path.addRoundedRect(x, 0, width, self.height(), 4, 4)
            painter.fillPath(path, colour if index < filled else QColor(theme.BORDER))
        painter.end()


class PassphraseField(QWidget):
    """Passphrase entry with a reveal toggle and, optionally, a generator."""

    changed = pyqtSignal(str)
    submitted = pyqtSignal()
    #: Emitted with the new passphrase and its exact entropy whenever this
    #: widget generated one itself.
    generated = pyqtSignal(str, float)

    def __init__(self, placeholder: str = "Passphrase", with_generator: bool = False,
                 parent: Optional[QWidget] = None):
        super().__init__(parent)
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(8)

        self.edit = QLineEdit()
        self.edit.setObjectName("Mono")
        self.edit.setEchoMode(QLineEdit.Password)
        self.edit.setPlaceholderText(placeholder)
        self.edit.setMinimumHeight(40)
        self.edit.textChanged.connect(self.changed.emit)
        self.edit.returnPressed.connect(self.submitted.emit)
        row.addWidget(self.edit, 1)

        self.reveal = QToolButton()
        self.reveal.setCheckable(True)
        self.reveal.setText("Show")
        self.reveal.setCursor(Qt.PointingHandCursor)
        self.reveal.setToolTip("Show the passphrase in clear text")
        self.reveal.setMinimumHeight(40)
        self.reveal.setStyleSheet(
            f"QToolButton {{ background: {theme.SURFACE_RAISED}; color: {theme.TEXT_MUTED};"
            f" border: 1px solid {theme.BORDER_STRONG}; border-radius: {theme.RADIUS_SMALL}px;"
            f" padding: 0 12px; }}"
            f" QToolButton:checked {{ color: {theme.PRIMARY}; border-color: {theme.PRIMARY}; }}"
        )
        self.reveal.toggled.connect(self._on_reveal)
        row.addWidget(self.reveal)

        self.generate_button: Optional[QToolButton] = None
        #: What this widget last generated, and its exact entropy. Kept so the
        #: meter can report a real number instead of an upper bound — but only
        #: while the text is still untouched, which is why the string is held
        #: alongside the figure rather than a flag.
        self._generated_text: Optional[str] = None
        self._generated_bits: Optional[float] = None

        if with_generator:
            self.generate_button = QToolButton()
            self.generate_button.setObjectName("Primary")
            self.generate_button.setText("Generate")
            self.generate_button.setMinimumHeight(40)
            self.generate_button.setCursor(Qt.PointingHandCursor)
            self.generate_button.setPopupMode(QToolButton.MenuButtonPopup)
            self.generate_button.setToolButtonStyle(Qt.ToolButtonTextOnly)
            # Through a lambda: QToolButton.clicked passes its checked
            # state, which would arrive here as the password length.
            self.generate_button.clicked.connect(
                lambda _checked=False: self.generate_characters())

            menu = QMenu(self.generate_button)
            for length in pp.CHARACTER_LENGTHS:
                bits = pp.character_bits(length)
                action = menu.addAction(
                    f"{length} random characters — {bits:.0f} bits")
                action.triggered.connect(
                    lambda _checked=False, n=length: self.generate_characters(n))
            menu.addSeparator()
            for words in (pp.RECOMMENDED_WORDS, 10, 12):
                bits = pp.generated_bits(words)
                action = menu.addAction(
                    f"{words} words — {bits} bits, memorable")
                action.triggered.connect(
                    lambda _checked=False, n=words: self.generate_words(n))
            self.generate_button.setMenu(menu)
            self._retune_generate_tooltip()
            row.addWidget(self.generate_button)

    def _retune_generate_tooltip(self) -> None:
        if self.generate_button is None:
            return
        bits = pp.character_bits(pp.DEFAULT_CHARACTER_LENGTH)
        self.generate_button.setToolTip(
            f"{pp.DEFAULT_CHARACTER_LENGTH} random characters — upper case, "
            f"lower case, digits and punctuation, {bits:.0f} bits exactly. "
            f"Use the arrow for other lengths, or for a phrase you can "
            f"actually remember.")

    def _on_reveal(self, shown: bool) -> None:
        self.edit.setEchoMode(QLineEdit.Normal if shown else QLineEdit.Password)
        self.reveal.setText("Hide" if shown else "Show")

    def generate_characters(self, length: Optional[int] = None) -> str:
        """Fill the field with a random character password."""
        count = pp.DEFAULT_CHARACTER_LENGTH if not length else int(length)
        return self._accept(pp.generate_characters(count),
                            pp.character_bits(count))

    def generate_words(self, words: Optional[int] = None) -> str:
        """Fill the field with a random wordlist phrase."""
        count = pp.RECOMMENDED_WORDS if not words else int(words)
        return self._accept(pp.generate_passphrase(count),
                            float(pp.generated_bits(count)))

    def _accept(self, value: str, bits: float) -> str:
        self._generated_text = value
        self._generated_bits = bits
        self.edit.setText(value)
        # Shown by default: a password nobody can memorise has to be readable
        # long enough to be written down or pasted somewhere safe.
        self.reveal.setChecked(True)
        self.generated.emit(value, bits)
        return value

    def exact_bits(self) -> Optional[float]:
        """The real entropy, if this field still holds what it generated."""
        if self._generated_text is not None and self.edit.text() == self._generated_text:
            return self._generated_bits
        return None

    def text(self) -> str:
        return self.edit.text()

    def set_text(self, value: str) -> None:
        self.edit.setText(value)

    def clear(self) -> None:
        self.edit.clear()

    def setFocus(self) -> None:  # noqa: N802 - Qt naming
        self.edit.setFocus()


class PassphraseStrengthPanel(QWidget):
    """The meter, its verdict, and the specific reasons behind it."""

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        column = QVBoxLayout(self)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(9)

        self.meter = StrengthMeter()
        column.addWidget(self.meter)

        verdict_row = QHBoxLayout()
        verdict_row.setSpacing(10)
        self.verdict = label("", "Muted")
        self.bits = label("", "Faint")
        verdict_row.addWidget(self.verdict)
        verdict_row.addStretch(1)
        verdict_row.addWidget(self.bits)
        column.addLayout(verdict_row)

        self.notes = label("", "Faint", wrap=True)
        column.addWidget(self.notes)

    def update_for(self, text: str,
                   exact_bits: Optional[float] = None) -> pp.Strength:
        strength = pp.estimate(text, exact_bits)
        self.meter.set_strength(strength if text else None)
        colour = StrengthMeter.COLOURS[min(strength.band, len(StrengthMeter.COLOURS) - 1)]
        if text:
            self.verdict.setText(strength.label)
            self.verdict.setStyleSheet(f"color: {colour}; font-weight: 600;")
            exact = "exactly" if strength.is_generated_phrase else "at most about"
            self.bits.setText(f"{exact} {strength.bits:.0f} bits  ·  "
                              f"{pp.crack_time_note(strength.bits)}")
        else:
            self.verdict.setText("")
            self.bits.setText("")
        self.notes.setText("  ".join(f"• {note}" for note in strength.notes))
        return strength


# --------------------------------------------------------------------------
# confirmation
# --------------------------------------------------------------------------

class ConfirmDialog(QDialog):
    """A confirmation that makes the consequence explicit.

    For irreversible actions the OK button stays disabled until the user ticks
    an acknowledgement, so the dialog cannot be dismissed on muscle memory.
    Where the consequence is severe enough that a tick is too cheap, pass
    ``require_typed`` and the user has to type the phrase out.
    """

    def __init__(self, title: str, message: str, confirm_text: str = "Continue",
                 acknowledgement: Optional[str] = None, tone: str = "danger",
                 detail: str = "", parent: Optional[QWidget] = None,
                 require_typed: Optional[str] = None,
                 cancel_text: str = "Cancel",
                 acknowledgement_gates: bool = True):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        # Scaled, so the text has the same room at a larger font, but never
        # wider than the screen it has to open on.
        self.setMinimumWidth(min(theme.scaled(520), theme.available_size(self)[0]))

        column = QVBoxLayout(self)
        column.setContentsMargins(theme.GUTTER, theme.GUTTER, theme.GUTTER, theme.GUTTER)
        column.setSpacing(theme.GAP)

        heading = label(title, "Title")
        heading.setStyleSheet(f"font-size: 19px; font-weight: 600; color: {theme.TEXT};")
        column.addWidget(heading)

        body = label(message, wrap=True)
        column.addWidget(body)
        self.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Minimum)

        if detail:
            note = Banner(detail, tone)
            column.addWidget(note)

        self._check: Optional[QCheckBox] = None
        if acknowledgement:
            # QCheckBox does not wrap its own label, and an acknowledgement
            # worth reading is usually longer than one line, so the text lives
            # in a wrapping label beside a bare box.
            self._check = QCheckBox()
            if tone == "danger":
                self._check.setObjectName("DangerCheck")
            self._check.setCursor(Qt.PointingHandCursor)

            row = QHBoxLayout()
            row.setSpacing(9)
            row.setContentsMargins(0, 0, 0, 0)
            row.addWidget(self._check, 0, Qt.AlignTop)
            wording = WrapLabel(acknowledgement)
            wording.setCursor(Qt.PointingHandCursor)
            wording.mousePressEvent = (
                lambda _event: self._check.setChecked(not self._check.isChecked()))
            row.addWidget(wording, 1)
            column.addLayout(row)

        self._required_phrase = require_typed
        self._typed: Optional[QLineEdit] = None
        if require_typed:
            column.addWidget(label(
                f"Type <b>{require_typed}</b> to continue.", wrap=True))
            self._typed = QLineEdit()
            self._typed.setObjectName("Mono")
            self._typed.setMinimumHeight(38)
            self._typed.setPlaceholderText(require_typed)
            column.addWidget(self._typed)

        column.addStretch(1)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        cancel = QPushButton(cancel_text)
        cancel.setCursor(Qt.PointingHandCursor)
        cancel.clicked.connect(self.reject)
        buttons.addWidget(cancel)

        self.confirm = QPushButton(confirm_text)
        self.confirm.setObjectName("DangerSolid" if tone == "danger" else "Primary")
        self.confirm.setCursor(Qt.PointingHandCursor)
        self.confirm.clicked.connect(self.accept)
        buttons.addWidget(self.confirm)
        column.addLayout(buttons)

        # Not every tick box is a consent gate. Where it only records a
        # preference — "remember this and stop asking" — it must not hold the
        # buttons hostage, and either button has to stay usable with it set.
        self._gated = acknowledgement_gates
        if self._gated and (self._check is not None or self._typed is not None):
            self.confirm.setEnabled(False)
        if self._check is not None and self._gated:
            self._check.toggled.connect(self._refresh_confirm)
        if self._typed is not None:
            self._typed.textChanged.connect(self._refresh_confirm)

    def acknowledged(self) -> bool:
        """Whether the tick box was set, whatever the user then chose."""
        return self._check is not None and self._check.isChecked()

    def _refresh_confirm(self) -> None:
        ticked = self._check is None or self._check.isChecked()
        typed = (self._typed is None
                 or self._typed.text().strip() == self._required_phrase)
        self.confirm.setEnabled(ticked and typed)

    @staticmethod
    def ask(parent: Optional[QWidget], title: str, message: str,
            confirm_text: str = "Continue", acknowledgement: Optional[str] = None,
            tone: str = "danger", detail: str = "",
            require_typed: Optional[str] = None) -> bool:
        dialog = ConfirmDialog(title, message, confirm_text, acknowledgement,
                               tone, detail, parent, require_typed)
        return dialog.exec_() == QDialog.Accepted


class ProgressPanel(Card):
    """A label plus a bar, shown while a worker runs."""

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent, sunken=True, padding=16, spacing=10)
        from PyQt5.QtWidgets import QProgressBar

        self.caption = label("Working…", "Muted")
        self.caption.setStyleSheet("background: transparent;")
        self.bar = QProgressBar()
        self.bar.setRange(0, 1000)
        self.bar.setValue(0)
        self.bar.setTextVisible(False)
        self.body.addWidget(self.caption)
        self.body.addWidget(self.bar)
        self.setVisible(False)

    def start(self, caption: str = "Working…") -> None:
        self.caption.setText(caption)
        self.bar.setValue(0)
        self.setVisible(True)

    def update_progress(self, stage: str, fraction: float) -> None:
        if stage:
            self.caption.setText(stage[:1].upper() + stage[1:] + "…")
        self.bar.setValue(int(max(0.0, min(1.0, fraction)) * 1000))

    def finish(self) -> None:
        self.setVisible(False)


class WrapRow(QLayout):
    """A horizontal row of widgets that folds onto more lines when narrow.

    Qt has no such layout of its own, and the alternative is a window whose
    minimum width is the sum of its buttons — which on a small screen at large
    text means a window that cannot be made to fit at all. Buttons here keep
    their natural size and move down a line instead.
    """

    def __init__(self, parent=None, spacing: int = 10):
        super().__init__(parent)
        self._items: list = []
        self._space = spacing
        self.setContentsMargins(0, 0, 0, 0)

    # -- QLayout plumbing -------------------------------------------------

    def addItem(self, item) -> None:  # noqa: N802
        self._items.append(item)

    def addStretch(self, _weight: int = 0) -> None:  # noqa: N802
        """Accepted and ignored: a folding row has no place to put slack."""

    def count(self) -> int:
        return len(self._items)

    def itemAt(self, index: int):  # noqa: N802
        return self._items[index] if 0 <= index < len(self._items) else None

    def takeAt(self, index: int):  # noqa: N802
        return self._items.pop(index) if 0 <= index < len(self._items) else None

    def expandingDirections(self):  # noqa: N802
        return Qt.Orientations(0)

    def hasHeightForWidth(self) -> bool:  # noqa: N802
        return True

    def heightForWidth(self, width: int) -> int:  # noqa: N802
        return self._lay_out(QRect(0, 0, width, 0), apply=False)

    def setGeometry(self, rect: QRect) -> None:  # noqa: N802
        super().setGeometry(rect)
        self._lay_out(rect, apply=True)

    def sizeHint(self) -> QSize:  # noqa: N802
        return self.minimumSize()

    def minimumSize(self) -> QSize:  # noqa: N802
        # The widest single item, not the sum of them: that is what it is for.
        size = QSize(0, 0)
        for item in self._items:
            size = size.expandedTo(item.minimumSize())
        left, top, right, bottom = self.getContentsMargins()
        return size + QSize(left + right, top + bottom)

    # -- the folding itself -----------------------------------------------

    def _lay_out(self, rect: QRect, apply: bool) -> int:
        left, top, right, bottom = self.getContentsMargins()
        area = rect.adjusted(left, top, -right, -bottom)
        x, y, line_height = area.x(), area.y(), 0
        for item in self._items:
            widget = item.widget()
            if widget is not None and widget.isHidden():
                continue
            hint = item.sizeHint()
            nudge = x + hint.width()
            if nudge > area.right() + 1 and line_height > 0:
                x = area.x()
                y += line_height + self._space
                nudge = x + hint.width()
                line_height = 0
            if apply:
                item.setGeometry(QRect(QPoint(x, y), hint))
            x = nudge + self._space
            line_height = max(line_height, hint.height())
        return y + line_height - rect.y() + bottom
