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

"""The manual, with a page list down the side."""

from __future__ import annotations

import html
from typing import Optional

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QSizePolicy,
    QDialog, QHBoxLayout, QLineEdit, QListWidget, QPushButton, QScrollArea,
    QVBoxLayout, QWidget,
)

from .. import help_text
from . import theme
from .widgets import Divider, label


def _render(sections: list, needle: str = "") -> str:
    """One page as rich text, with any search term highlighted."""
    parts = []
    for heading, paragraphs in sections:
        parts.append(f'<h3 style="color:{theme.PRIMARY}; margin-bottom:4px;">'
                     f'{html.escape(heading)}</h3>')
        bullets: list = []
        for paragraph in paragraphs:
            if paragraph.startswith("- "):
                bullets.append(_mark(paragraph[2:], needle))
                continue
            if bullets:
                parts.append("<ul style='margin-top:2px;'>"
                             + "".join(f"<li style='margin-bottom:5px;'>{b}</li>"
                                       for b in bullets) + "</ul>")
                bullets = []
            if paragraph.startswith("> "):
                parts.append(
                    f"<pre style='background:{theme.SURFACE_SUNKEN};"
                    f"padding:9px; border-radius:6px; margin:6px 0;'>"
                    f"{_mark(paragraph[2:], needle)}</pre>")
            else:
                parts.append(f"<p style='margin:6px 0; line-height:150%;'>"
                             f"{_mark(paragraph, needle)}</p>")
        if bullets:
            parts.append("<ul style='margin-top:2px;'>"
                         + "".join(f"<li style='margin-bottom:5px;'>{b}</li>"
                                   for b in bullets) + "</ul>")
    return "".join(parts)


def _mark(text: str, needle: str) -> str:
    escaped = html.escape(text)
    if not needle:
        return escaped
    lowered = escaped.lower()
    target = html.escape(needle).lower()
    out = []
    start = 0
    while True:
        found = lowered.find(target, start)
        if found < 0:
            out.append(escaped[start:])
            break
        out.append(escaped[start:found])
        out.append(f"<span style='background:{theme.PRIMARY_DARK}; "
                   f"color:{theme.TEXT};'>"
                   f"{escaped[found:found + len(target)]}</span>")
        start = found + len(target)
    return "".join(out)


class HelpDialog(QDialog):
    """Everything the application does, page by page."""

    def __init__(self, parent: Optional[QWidget] = None, page: int = 0):
        super().__init__(parent)
        self.setObjectName("Root")
        self.setWindowTitle("Quenchkey — help")
        self.setModal(True)
        theme.fit(self, 1000, 760, 760, 480)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(theme.GUTTER, theme.GUTTER, theme.GUTTER,
                                 theme.GUTTER)
        outer.setSpacing(theme.GAP)

        heading = QHBoxLayout()
        heading.setSpacing(12)
        title = label("Help", "Title", wrap=True)
        heading.addWidget(title)
        heading.addStretch(1)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search the manual")
        self.search.setMinimumHeight(theme.scaled(34))
        self.search.setMinimumWidth(theme.scaled(240))
        self.search.textChanged.connect(self._on_search)
        heading.addWidget(self.search)
        outer.addLayout(heading)
        outer.addWidget(Divider())

        split = QHBoxLayout()
        split.setSpacing(theme.GAP)

        self.pages = QListWidget()
        self.pages.setMaximumWidth(theme.scaled(220))
        self.pages.setMinimumWidth(theme.scaled(140))
        # Twelve rows' worth of minimumSizeHint would put the window's floor
        # above a 768-pixel screen at 200% text. The list scrolls; it does not
        # need room for every page at once.
        self.pages.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Ignored)
        for name in help_text.page_titles():
            self.pages.addItem(name)
        self.pages.currentRowChanged.connect(self._show_page)
        split.addWidget(self.pages)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QScrollArea.NoFrame)
        self.content = label("", wrap=True)
        self.content.setTextFormat(Qt.RichText)
        self.content.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.content.setAlignment(Qt.AlignTop)
        self.content.setMinimumWidth(1)
        holder = QWidget()
        holder_layout = QVBoxLayout(holder)
        holder_layout.setContentsMargins(4, 0, 14, 0)
        holder_layout.addWidget(self.content)
        holder_layout.addStretch(1)
        self.scroll.setWidget(holder)
        self.scroll.setMinimumWidth(1)
        self.scroll.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Ignored)
        split.addWidget(self.scroll, 1)
        outer.addLayout(split, 1)

        self.hits = label("", "Faint", wrap=True)
        self.hits.setMinimumWidth(1)
        outer.addWidget(self.hits)

        row = QHBoxLayout()
        row.addStretch(1)
        close = QPushButton("Close")
        close.setObjectName("Primary")
        close.setCursor(Qt.PointingHandCursor)
        close.clicked.connect(self.accept)
        row.addWidget(close)
        outer.addLayout(row)

        self.pages.setCurrentRow(max(0, min(page, self.pages.count() - 1)))

    # -- pages ------------------------------------------------------------

    def _show_page(self, row: int) -> None:
        if not 0 <= row < len(help_text.PAGES):
            return
        _title, sections = help_text.PAGES[row]
        self.content.setText(_render(sections, self.search.text().strip()))
        self.scroll.verticalScrollBar().setValue(0)

    def _on_search(self, text: str) -> None:
        needle = text.strip().lower()
        if not needle:
            self.hits.setText("")
            for row in range(self.pages.count()):
                self.pages.item(row).setHidden(False)
            self._show_page(self.pages.currentRow())
            return

        matches = []
        for row, (title, sections) in enumerate(help_text.PAGES):
            haystack = (title + " " + " ".join(
                heading + " " + " ".join(paragraphs)
                for heading, paragraphs in sections)).lower()
            hit = needle in haystack
            self.pages.item(row).setHidden(not hit)
            if hit:
                matches.append(row)

        if matches:
            self.hits.setText(
                f"{len(matches)} page{'s' if len(matches) != 1 else ''} mention "
                f"“{text.strip()}”.")
            if self.pages.currentRow() not in matches:
                self.pages.setCurrentRow(matches[0])
            else:
                self._show_page(self.pages.currentRow())
        else:
            self.hits.setText(f"Nothing in the manual mentions “{text.strip()}”.")
            self.content.setText("")
