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

"""Colours, spacing and the application stylesheet.

Everything visual is defined here so the rest of the UI never hard-codes a
colour. The palette is dark with a cyan primary and a green "safe" accent;
Qt's stock grey does not appear anywhere.
"""

from __future__ import annotations

import os
import re
import tempfile
from typing import Optional

from PyQt5.QtGui import QColor, QFont, QFontDatabase, QIcon, QPixmap, QPolygonF
from PyQt5.QtCore import QByteArray, QPointF, QRectF, Qt
from PyQt5.QtGui import QBrush, QImage, QPainter
from PyQt5.QtSvg import QSvgRenderer

# -- palette ---------------------------------------------------------------

BACKGROUND = "#0F1419"
SURFACE = "#1A2128"
SURFACE_RAISED = "#222B34"
SURFACE_SUNKEN = "#141A20"
BORDER = "#2A343E"
BORDER_STRONG = "#39454F"

PRIMARY = "#4DD0E1"
PRIMARY_DIM = "#2E7A85"
PRIMARY_DARK = "#173C43"
SUCCESS = "#66BB6A"
SUCCESS_DARK = "#1D3A21"
WARNING = "#FFA726"
WARNING_DARK = "#3E2E12"
DANGER = "#EF5350"
DANGER_DARK = "#3C1D1D"

TEXT = "#E3E8EC"
TEXT_MUTED = "#7A8896"
TEXT_FAINT = "#5A6672"
ON_ACCENT = "#06222A"

# -- metrics ---------------------------------------------------------------

RADIUS = 10
RADIUS_SMALL = 6
GUTTER = 28
GAP = 16

def _find_assets() -> str:
    """Where the logo lives, installed or in a checkout.

    Shipped inside the package so it survives installation — the repository's
    top-level ``assets/`` directory does not exist under site-packages, and
    looking only there is why an installed build came up with no logo at all.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(os.path.dirname(here), "assets"),          # quenchkey/assets
        os.path.join(os.path.dirname(os.path.dirname(here)), "assets"),
    ]
    for candidate in candidates:
        if os.path.isfile(os.path.join(candidate, "quenchkey-logo.svg")):
            return candidate
    return candidates[0]


ASSETS_DIR = _find_assets()
LOGO_PATH = os.path.join(ASSETS_DIR, "quenchkey-logo.svg")


def qcolor(hex_string: str, alpha: int = 255) -> QColor:
    colour = QColor(hex_string)
    colour.setAlpha(alpha)
    return colour


def logo_pixmap(size: int) -> QPixmap:
    """Render the logo SVG at an exact pixel size."""
    try:
        with open(LOGO_PATH, "rb") as fh:
            data = QByteArray(fh.read())
    except OSError:
        return QPixmap()
    renderer = QSvgRenderer(data)
    image = QImage(size, size, QImage.Format_ARGB32_Premultiplied)
    image.fill(Qt.transparent)
    painter = QPainter(image)
    painter.setRenderHint(QPainter.Antialiasing, True)
    renderer.render(painter, QRectF(0, 0, size, size))
    painter.end()
    return QPixmap.fromImage(image)


def app_icon() -> QIcon:
    icon = QIcon()
    for size in (16, 32, 64, 128, 256):
        pixmap = logo_pixmap(size)
        if not pixmap.isNull():
            icon.addPixmap(pixmap)
    return icon


#: Multiplies every font size. Set by :func:`apply` from --font-scale, for
#: people who want the interface larger than their desktop's own setting.
FONT_SCALE = 1.0

#: The point size the stylesheet's pixel values were chosen against. If the
#: desktop asks for a larger default, sizes are raised in proportion rather
#: than ignoring it.
REFERENCE_POINT_SIZE = 10.0


#: The desktop's default font size, captured once before the application font
#: is replaced. Reading it afterwards would return the value this module just
#: set, and the scale would compound every time the stylesheet was rebuilt.
_SYSTEM_POINT_SIZE: Optional[float] = None


def system_point_size() -> float:
    """The desktop's own default font size, if it has told us one."""
    if _SYSTEM_POINT_SIZE is not None:
        return _SYSTEM_POINT_SIZE
    from PyQt5.QtWidgets import QApplication

    app = QApplication.instance()
    if app is None:
        return REFERENCE_POINT_SIZE
    size = app.font().pointSizeF()
    return size if size > 0 else REFERENCE_POINT_SIZE


def effective_scale() -> float:
    """How much to multiply the stylesheet's sizes by.

    Two things feed in: the desktop's default font size, and any explicit
    ``--font-scale``. The font-size component only ever enlarges — a desktop
    asking for bigger text is an accessibility preference worth honouring,
    whereas a smaller default should not shrink an interface whose padding and
    minimum widths are fixed. Anyone who does want it smaller can say so with
    ``--font-scale``.

    Qt's own high-DPI handling is separate and deals with the device pixel
    ratio; this is about a font preference, which a display scale does not
    express.
    """
    from_system = max(1.0, min(2.0, system_point_size() / REFERENCE_POINT_SIZE))
    return FONT_SCALE * from_system


def base_font() -> QFont:
    families = QFontDatabase().families()
    size = max(REFERENCE_POINT_SIZE, system_point_size()) * FONT_SCALE
    for name in ("Inter", "Cantarell", "Ubuntu", "Noto Sans", "DejaVu Sans",
                 "Liberation Sans", "Helvetica Neue", "Arial"):
        if name in families:
            font = QFont(name)
            font.setPointSizeF(size)
            font.setHintingPreference(QFont.PreferFullHinting)
            return font
    font = QFont()
    font.setPointSizeF(size)
    return font


def mono_font(size: int = 10) -> QFont:
    families = QFontDatabase().families()
    scaled = size * effective_scale()
    for name in ("JetBrains Mono", "Fira Mono", "DejaVu Sans Mono",
                 "Liberation Mono", "Noto Sans Mono", "Courier New"):
        if name in families:
            font = QFont(name)
            font.setPointSizeF(scaled)
            return font
    font = QFont()
    font.setStyleHint(QFont.Monospace)
    font.setPointSizeF(scaled)
    return font


def _draw_arrow(path: str, colour: str, pointing: str, size: int = 9) -> str:
    """Render one triangular arrow to a PNG and return its path.

    Qt's stylesheet engine will not build a triangle out of CSS borders for a
    subcontrol the way a browser does — it wants an image. Rather than ship
    four tiny binaries, the arrows are drawn once at start-up into a temporary
    directory and referenced from the stylesheet.
    """
    width, height = size + 3, size
    image = QImage(width, height, QImage.Format_ARGB32_Premultiplied)
    image.fill(Qt.transparent)
    painter = QPainter(image)
    painter.setRenderHint(QPainter.Antialiasing, True)
    painter.setPen(Qt.NoPen)
    painter.setBrush(QBrush(QColor(colour)))
    inset = 1.0
    if pointing == "down":
        points = [QPointF(inset, inset), QPointF(width - inset, inset),
                  QPointF(width / 2, height - inset)]
    else:
        points = [QPointF(inset, height - inset), QPointF(width - inset, height - inset),
                  QPointF(width / 2, inset)]
    painter.drawPolygon(QPolygonF(points))
    painter.end()
    image.save(path)
    return path


def no_deadline_pixmap(size: int = 12):
    """A small marker for a file that carries its own key.

    Deliberately not a padlock: everything in this application is locked, and
    what sets these apart is that nothing can ever unlock them *away* again.
    A hollow ring reads as "open-ended", and it is the only place this colour
    is used for a row marker.
    """
    from PyQt5.QtGui import QPen

    pixmap = QPixmap(size, size)
    pixmap.fill(QColor(0, 0, 0, 0))
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing, True)
    pen = QPen(QColor(WARNING))
    pen.setWidthF(max(1.4, size / 7.0))
    painter.setPen(pen)
    painter.setBrush(QBrush(QColor(0, 0, 0, 0)))
    inset = pen.widthF()
    painter.drawEllipse(QRectF(inset, inset,
                               size - 2 * inset, size - 2 * inset))
    painter.end()
    return pixmap


def _draw_radio_dot(path: str, size: int = 17) -> str:
    """Render the selected radio indicator to a PNG.

    Qt will not clip a thick border to a border-radius, so the obvious QSS —
    a coloured background with a wide inset border — comes out as a rounded
    square and reads as a checkbox. Drawing the whole indicator sidesteps the
    renderer entirely.
    """
    from PyQt5.QtGui import QPen

    pixmap = QPixmap(size, size)
    pixmap.fill(QColor(0, 0, 0, 0))
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing, True)
    pen = QPen(QColor(PRIMARY))
    pen.setWidthF(1.6)
    painter.setPen(pen)
    painter.setBrush(QBrush(QColor(SURFACE_SUNKEN)))
    painter.drawEllipse(QRectF(0.8, 0.8, size - 1.6, size - 1.6))
    painter.setPen(Qt.NoPen)
    painter.setBrush(QBrush(QColor(PRIMARY)))
    inset = size * 0.3
    painter.drawEllipse(QRectF(inset, inset, size - 2 * inset, size - 2 * inset))
    painter.end()
    pixmap.save(path, "PNG")
    return path


def _arrow_paths() -> dict:
    directory = os.path.join(tempfile.gettempdir(), f"quenchkey-ui-{os.getuid()}")
    os.makedirs(directory, exist_ok=True)
    arrows = {}
    for name, colour, pointing in (
        ("down_muted", TEXT_MUTED, "down"),
        ("up_muted", TEXT_MUTED, "up"),
        ("down_accent", PRIMARY, "down"),
        ("down_on_accent", ON_ACCENT, "down"),
        ("up_accent", PRIMARY, "up"),
    ):
        target = os.path.join(directory, f"{name}.png")
        if not os.path.exists(target):
            _draw_arrow(target, colour, pointing)
        arrows[name] = target.replace("\\", "/")

    dot = os.path.join(directory, "radio_on.png")
    if not os.path.exists(dot):
        _draw_radio_dot(dot)
    arrows["radio_on"] = dot.replace("\\", "/")
    return arrows


ARROWS = None


STYLESHEET = f"""
* {{
    outline: none;
}}

/* Only roots paint a background. If QWidget did, every label would paint
   the window colour over the card it sits on. */
QWidget {{
    color: {TEXT};
    font-size: 13px;
}}

QDialog, QMainWindow, QWidget#Root {{
    background-color: {BACKGROUND};
}}

QLabel, QCheckBox, QRadioButton {{
    background: transparent;
}}

QScrollArea {{
    background: transparent;
    border: none;
}}

QScrollArea > QWidget > QWidget {{
    background: transparent;
}}

QToolTip {{
    background-color: {SURFACE_RAISED};
    color: {TEXT};
    border: 1px solid {BORDER_STRONG};
    border-radius: {RADIUS_SMALL}px;
    padding: 7px 10px;
}}

/* ---- surfaces ---- */

QFrame#Card {{
    background-color: {SURFACE};
    border: 1px solid {BORDER};
    border-radius: {RADIUS}px;
}}

QFrame#SunkenCard {{
    background-color: {SURFACE_SUNKEN};
    border: 1px solid {BORDER};
    border-radius: {RADIUS}px;
}}

QFrame#Divider {{
    background-color: {BORDER};
    max-height: 1px;
    border: none;
}}

/* ---- text ---- */

QLabel#Title {{
    font-size: 25px;
    font-weight: 600;
    color: {TEXT};
}}

QLabel#Subtitle {{
    font-size: 14px;
    color: {TEXT_MUTED};
}}

QLabel#SectionHeading {{
    font-size: 11px;
    font-weight: 700;
    color: {TEXT_MUTED};
    letter-spacing: 1.4px;
}}

QLabel#Muted {{
    color: {TEXT_MUTED};
}}

QLabel#Faint {{
    color: {TEXT_FAINT};
    font-size: 12px;
}}

QLabel#Mono {{
    color: {TEXT};
    font-family: monospace;
    font-size: 13px;
    letter-spacing: 0.5px;
}}

QLabel#Tagline {{
    color: {PRIMARY};
    font-size: 14px;
    font-style: italic;
}}

QLabel#StatValue {{
    font-size: 21px;
    font-weight: 600;
    color: {TEXT};
}}

QLabel#StatLabel {{
    font-size: 11px;
    color: {TEXT_MUTED};
    letter-spacing: 1.1px;
    font-weight: 600;
}}

QLabel#ErrorText {{
    color: {DANGER};
}}

QLabel#SuccessText {{
    color: {SUCCESS};
}}

/* ---- buttons ---- */

QPushButton {{
    background-color: {SURFACE_RAISED};
    color: {TEXT};
    border: 1px solid {BORDER_STRONG};
    border-radius: {RADIUS_SMALL}px;
    padding: 9px 18px;
    font-weight: 500;
}}

QPushButton:hover {{
    background-color: #2A343E;
    border-color: {PRIMARY_DIM};
}}

QPushButton:pressed {{
    background-color: #1E272F;
}}

QPushButton:disabled {{
    background-color: {SURFACE_SUNKEN};
    color: {TEXT_FAINT};
    border-color: {BORDER};
}}

QPushButton#Primary {{
    background-color: {PRIMARY};
    color: {ON_ACCENT};
    border: none;
    font-weight: 600;
    padding: 10px 22px;
}}

QPushButton#Primary:hover {{
    background-color: #63DCEC;
}}

QPushButton#Primary:pressed {{
    background-color: #3FB6C6;
}}

QPushButton#Primary:disabled {{
    background-color: {PRIMARY_DARK};
    color: {TEXT_FAINT};
}}

/* The Generate button is a QToolButton so it can carry a menu of lengths.
   None of the QPushButton#Primary rules reach it, so it is dressed to match
   here rather than looking like a stray system widget beside them. */
QToolButton#Primary {{
    background-color: {PRIMARY};
    color: {ON_ACCENT};
    border: none;
    border-radius: {RADIUS_SMALL}px;
    font-weight: 600;
    padding: 10px 14px 10px 18px;
}}

QToolButton#Primary:hover {{
    background-color: #63DCEC;
}}

QToolButton#Primary:pressed, QToolButton#Primary:on {{
    background-color: #3FB6C6;
}}

QToolButton#Primary:disabled {{
    background-color: {PRIMARY_DARK};
    color: {TEXT_FAINT};
}}

QToolButton#Primary::menu-button {{
    border: none;
    border-left: 1px solid rgba(0, 0, 0, 0.22);
    width: 22px;
}}

QToolButton#Primary::menu-arrow {{
    image: url(__DOWN_ON_ACCENT__);
}}

QPushButton#Danger {{
    background-color: transparent;
    color: {DANGER};
    border: 1px solid {DANGER};
}}

QPushButton#Danger:hover {{
    background-color: {DANGER_DARK};
}}

QPushButton#DangerSolid {{
    background-color: {DANGER};
    color: #2A0E0E;
    border: none;
    font-weight: 600;
}}

QPushButton#DangerSolid:hover {{
    background-color: #F4726F;
}}

/* An id selector outranks QPushButton:disabled, so the disabled look has to
   be restated per variant or a dead button stays fully saturated. */
QPushButton#DangerSolid:disabled {{
    background-color: {DANGER_DARK};
    color: {TEXT_FAINT};
}}

QPushButton#Danger:disabled {{
    color: {TEXT_FAINT};
    border-color: {BORDER};
    background-color: transparent;
}}

QPushButton#Ghost {{
    background-color: transparent;
    border: none;
    color: {PRIMARY};
    padding: 6px 10px;
    font-weight: 500;
}}

QPushButton#Ghost:hover {{
    color: #7FE3F0;
    background-color: {PRIMARY_DARK};
}}

QPushButton#Ghost:disabled {{
    color: {TEXT_FAINT};
    background-color: transparent;
}}

/* ---- inputs ---- */

QLineEdit, QPlainTextEdit, QTextEdit, QDateTimeEdit, QSpinBox, QComboBox {{
    background-color: {SURFACE_SUNKEN};
    border: 1px solid {BORDER_STRONG};
    border-radius: {RADIUS_SMALL}px;
    padding: 9px 12px;
    selection-background-color: {PRIMARY_DIM};
    selection-color: {TEXT};
    color: {TEXT};
}}

QLineEdit:focus, QPlainTextEdit:focus, QDateTimeEdit:focus,
QSpinBox:focus, QComboBox:focus {{
    border-color: {PRIMARY};
}}

QLineEdit:disabled, QComboBox:disabled, QDateTimeEdit:disabled {{
    color: {TEXT_FAINT};
    background-color: #11171C;
}}

QLineEdit#Mono {{
    font-family: monospace;
    letter-spacing: 0.6px;
}}

QComboBox::drop-down {{
    border: none;
    width: 26px;
}}

QComboBox::down-arrow {{
    image: url(__DOWN_MUTED__);
    margin-right: 10px;
}}

QComboBox QAbstractItemView {{
    background-color: {SURFACE_RAISED};
    border: 1px solid {BORDER_STRONG};
    border-radius: {RADIUS_SMALL}px;
    selection-background-color: {PRIMARY_DARK};
    selection-color: {TEXT};
    padding: 4px;
    outline: none;
}}

QDateTimeEdit::up-button, QDateTimeEdit::down-button,
QSpinBox::up-button, QSpinBox::down-button {{
    background-color: {SURFACE_RAISED};
    border: none;
    width: 18px;
}}

QDateTimeEdit::up-arrow, QSpinBox::up-arrow {{
    image: url(__UP_MUTED__);
}}

QDateTimeEdit::down-arrow, QSpinBox::down-arrow {{
    image: url(__DOWN_MUTED__);
}}

QCalendarWidget QWidget {{
    alternate-background-color: {SURFACE};
}}

QCalendarWidget QAbstractItemView:enabled {{
    background-color: {SURFACE};
    color: {TEXT};
    selection-background-color: {PRIMARY_DARK};
    selection-color: {TEXT};
}}

QCalendarWidget QToolButton {{
    background-color: {SURFACE};
    color: {TEXT};
    border: none;
    padding: 6px;
}}

/* ---- checkbox / radio ---- */

QCheckBox, QRadioButton {{
    spacing: 9px;
    color: {TEXT};
}}

QCheckBox::indicator, QRadioButton::indicator {{
    width: 17px;
    height: 17px;
    border: 1px solid {BORDER_STRONG};
    background-color: {SURFACE_SUNKEN};
}}

QCheckBox::indicator {{
    border-radius: 4px;
}}

QRadioButton::indicator {{
    border-radius: 9px;
}}

QCheckBox::indicator:hover, QRadioButton::indicator:hover {{
    border-color: {PRIMARY};
}}

QCheckBox::indicator:checked {{
    background-color: {PRIMARY};
    border-color: {PRIMARY};
}}

QRadioButton::indicator:checked {{
    border: none;
    background: transparent;
    image: url(__RADIO_ON__);
}}

QCheckBox#DangerCheck::indicator:checked {{
    background-color: {DANGER};
    border-color: {DANGER};
}}

/* ---- lists ---- */

QListWidget, QListView {{
    background-color: {SURFACE};
    border: 1px solid {BORDER};
    border-radius: {RADIUS}px;
    color: {TEXT};
    outline: none;
    padding: 5px;
}}

QListWidget::item, QListView::item {{
    padding: 8px 10px;
    border-radius: {RADIUS_SMALL}px;
    color: {TEXT_MUTED};
}}

QListWidget::item:hover, QListView::item:hover {{
    background-color: {SURFACE_RAISED};
    color: {TEXT};
}}

QListWidget::item:selected, QListView::item:selected {{
    background-color: {PRIMARY_DARK};
    color: {TEXT};
}}

/* ---- table ---- */

QTableView {{
    background-color: {SURFACE};
    alternate-background-color: #1D252D;
    border: 1px solid {BORDER};
    border-radius: {RADIUS}px;
    gridline-color: transparent;
    selection-background-color: {PRIMARY_DARK};
    selection-color: {TEXT};
    color: {TEXT};
}}

QTableView::item {{
    padding: 9px 8px;
    border: none;
    border-bottom: 1px solid {SURFACE_SUNKEN};
}}

QTableView::item:selected {{
    background-color: {PRIMARY_DARK};
    color: {TEXT};
}}

QHeaderView::section {{
    background-color: {SURFACE_SUNKEN};
    color: {TEXT_MUTED};
    border: none;
    border-bottom: 1px solid {BORDER};
    padding: 10px 8px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.9px;
}}

QHeaderView::section:hover {{
    color: {PRIMARY};
}}

QHeaderView::up-arrow {{
    image: url(__UP_ACCENT__);
    subcontrol-position: center right;
    margin-right: 5px;
}}

QHeaderView::down-arrow {{
    image: url(__DOWN_ACCENT__);
    subcontrol-position: center right;
    margin-right: 5px;
}}

QTableCornerButton::section {{
    background-color: {SURFACE_SUNKEN};
    border: none;
}}

/* ---- scrollbars ---- */

QScrollBar:vertical {{
    background: transparent;
    width: 11px;
    margin: 2px;
}}

QScrollBar::handle:vertical {{
    background: {BORDER_STRONG};
    border-radius: 5px;
    min-height: 32px;
}}

QScrollBar::handle:vertical:hover {{
    background: {PRIMARY_DIM};
}}

QScrollBar:horizontal {{
    background: transparent;
    height: 11px;
    margin: 2px;
}}

QScrollBar::handle:horizontal {{
    background: {BORDER_STRONG};
    border-radius: 5px;
    min-width: 32px;
}}

QScrollBar::handle:horizontal:hover {{
    background: {PRIMARY_DIM};
}}

QScrollBar::add-line, QScrollBar::sub-line {{
    height: 0;
    width: 0;
}}

QScrollBar::add-page, QScrollBar::sub-page {{
    background: transparent;
}}

/* ---- progress ---- */

QProgressBar {{
    background-color: {SURFACE_SUNKEN};
    border: none;
    border-radius: 5px;
    height: 8px;
    text-align: center;
    color: transparent;
}}

QProgressBar::chunk {{
    background-color: {PRIMARY};
    border-radius: 5px;
}}

/* ---- menus ---- */

QMenu {{
    background-color: {SURFACE_RAISED};
    border: 1px solid {BORDER_STRONG};
    border-radius: {RADIUS_SMALL}px;
    padding: 6px;
}}

QMenu::item {{
    padding: 8px 26px 8px 14px;
    border-radius: 4px;
}}

QMenu::item:selected {{
    background-color: {PRIMARY_DARK};
    color: {TEXT};
}}

QMenu::item:disabled {{
    color: {TEXT_FAINT};
}}

QMenu::separator {{
    height: 1px;
    background: {BORDER};
    margin: 6px 8px;
}}

QMenuBar {{
    background-color: {BACKGROUND};
    border-bottom: 1px solid {BORDER};
}}

QMenuBar::item {{
    padding: 8px 12px;
    background: transparent;
}}

QMenuBar::item:selected {{
    background-color: {SURFACE_RAISED};
    border-radius: 4px;
}}

QStatusBar {{
    background-color: {SURFACE_SUNKEN};
    color: {TEXT_MUTED};
    border-top: 1px solid {BORDER};
}}

QStatusBar::item {{
    border: none;
}}

QSplitter::handle {{
    background-color: {BORDER};
}}

QTabWidget::pane {{
    border: 1px solid {BORDER};
    border-radius: {RADIUS}px;
    top: -1px;
}}

QTabBar::tab {{
    background: transparent;
    color: {TEXT_MUTED};
    padding: 10px 18px;
    border-bottom: 2px solid transparent;
}}

QTabBar::tab:selected {{
    color: {PRIMARY};
    border-bottom: 2px solid {PRIMARY};
}}

QTabBar::tab:hover {{
    color: {TEXT};
}}
"""


def scaled(pixels: int) -> int:
    """A fixed pixel measurement, adjusted for the current font scale.

    Minimum window sizes and the like are chosen against the default font. At
    a larger scale the same content needs proportionally more room, and a
    window that keeps its original minimum simply clips its own text.
    """
    return max(1, round(pixels * effective_scale()))


#: Room left around a window for its own title bar and the desktop's edges.
#: Qt sizes the widget, not the frame, so a window exactly as tall as the
#: available area pushes its title bar off the top of the screen.
SCREEN_MARGIN_W = 48
SCREEN_MARGIN_H = 96


def available_size(widget=None) -> tuple:
    """How much room a window actually has, on the screen it will open on.

    ``availableGeometry`` already excludes docks and panels, so what comes
    back is the space a window can occupy without anything covering it.
    """
    from PyQt5.QtGui import QGuiApplication

    screen = None
    for candidate in (widget, widget.parentWidget() if widget else None):
        if candidate is None:
            continue
        handle = candidate.window().windowHandle()
        if handle is not None and handle.screen() is not None:
            screen = handle.screen()
            break
    if screen is None:
        screen = QGuiApplication.primaryScreen()
    if screen is None:
        # No screen to measure against — headless, most likely. Nothing to
        # clamp to, so do not pretend otherwise.
        return (1 << 20, 1 << 20)
    rect = screen.availableGeometry()
    return (max(320, rect.width() - SCREEN_MARGIN_W),
            max(240, rect.height() - SCREEN_MARGIN_H))


def fit_to_screen(widget, min_width: int, min_height: int,
                  fill: bool = True) -> None:
    """Open a window at the size of the screen it will appear on.

    Not fullscreen and not maximised — an ordinary window that happens to
    start the size of the usable screen area, so it can still be resized,
    moved and put beside something else. ``availableGeometry`` already
    excludes panels and docks, so this does not sit under anybody's taskbar.

    The minimum is clamped as well, because a minimum larger than the display
    leaves a window that cannot be resized down to fit it.
    """
    room_w, room_h = available_size(widget)
    widget.setMinimumSize(min(scaled(min_width), room_w),
                          min(scaled(min_height), room_h))
    if fill:
        widget.resize(room_w, room_h)
    else:
        widget.resize(min(scaled(1280), room_w), min(scaled(820), room_h))


def fill_available_screen(window) -> bool:
    """Size a shown window so its *frame* exactly fills the usable screen.

    Called after the window is on screen, because the title bar's height is
    not knowable before then: Qt only learns the frame once the window manager
    has drawn it. Guessing instead is what leaves either a strip of wasted
    screen or, worse, a title bar pushed off the top edge where the close
    button cannot be reached.

    ``availableGeometry`` already excludes panels, docks and taskbars, so the
    result sits beside them rather than under them. Returns False when there
    is nothing to measure against.
    """
    from PyQt5.QtGui import QGuiApplication

    handle = window.windowHandle()
    screen = handle.screen() if handle is not None else None
    if screen is None:
        screen = QGuiApplication.primaryScreen()
    if screen is None:
        return False

    available = screen.availableGeometry()
    frame = window.frameGeometry()
    inner = window.geometry()

    # What the window manager adds around the client area. Zero under a bare
    # X server with no window manager, which is exactly right there.
    left = inner.left() - frame.left()
    top = inner.top() - frame.top()
    right = frame.right() - inner.right()
    bottom = frame.bottom() - inner.bottom()

    width = max(window.minimumWidth(), available.width() - left - right)
    height = max(window.minimumHeight(), available.height() - top - bottom)
    window.resize(width, height)
    # move() positions the *frame* of a top-level window, not its client
    # area, so the margins must not be added again here — doing so pushes the
    # window down and right by the height of its own title bar.
    window.move(available.left(), available.top())
    return True


def fit(widget, width: int, height: int,
        min_width: Optional[int] = None,
        min_height: Optional[int] = None) -> None:
    """Size a window to what it asks for, but never past its screen.

    A dialog scaled up for a large font can easily want more height than a
    laptop panel has. Qt will happily grant that, and the result is a window
    whose buttons sit below the bottom edge of the display where nobody can
    click them — the dialog is on screen in every sense except the one that
    matters. Every dialog here keeps its body in a scroll area with the
    buttons pinned underneath, so losing height costs nothing but scrolling.

    The minimum is clamped alongside the size, because a minimum larger than
    the screen is just as unreachable and stops the user resizing out of it.
    """
    room_w, room_h = available_size(widget)
    want_w = min(scaled(width), room_w)
    want_h = min(scaled(height), room_h)
    floor_w = min(scaled(width if min_width is None else min_width), want_w)
    floor_h = min(scaled(height if min_height is None else min_height), want_h)
    widget.setMinimumSize(floor_w, floor_h)
    widget.resize(want_w, want_h)


def _scale_font_sizes(sheet: str, scale: float) -> str:
    """Multiply every ``font-size: Npx`` in the stylesheet."""
    if abs(scale - 1.0) < 0.01:
        return sheet
    return re.sub(r"font-size:\s*(\d+)px",
                  lambda m: f"font-size: {max(9, round(int(m.group(1)) * scale))}px",
                  sheet)


def stylesheet() -> str:
    """The stylesheet with arrow images resolved and font sizes scaled.

    Needs a live QApplication, since drawing the arrows uses QPainter.
    """
    arrows = _arrow_paths()
    sheet = (STYLESHEET
             .replace("__DOWN_MUTED__", arrows["down_muted"])
             .replace("__UP_MUTED__", arrows["up_muted"])
             .replace("__DOWN_ACCENT__", arrows["down_accent"])
             .replace("__UP_ACCENT__", arrows["up_accent"])
             .replace("__DOWN_ON_ACCENT__", arrows["down_on_accent"])
             .replace("__RADIO_ON__", arrows["radio_on"]))
    return _scale_font_sizes(sheet, effective_scale())


def apply(app, font_scale: float = 1.0) -> None:
    """Apply the Quenchkey look to a QApplication."""
    global FONT_SCALE, _SYSTEM_POINT_SIZE

    # Read the desktop's preference before overwriting it, once.
    measured = app.font().pointSizeF()
    _SYSTEM_POINT_SIZE = measured if measured > 0 else REFERENCE_POINT_SIZE

    FONT_SCALE = max(0.5, min(4.0, font_scale))
    app.setStyle("Fusion")
    app.setFont(base_font())
    app.setStyleSheet(stylesheet())
    app.setWindowIcon(app_icon())
