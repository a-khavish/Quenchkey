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

"""Render the PNG exports from the logo SVG.

The SVG in ``assets/`` is the source of truth and is meant to be edited by
hand; this script only rasterises it, using the same Qt SVG renderer the
application uses, so the exported icons match what the window shows.

    xvfb-run -a python3 tools/render_logo.py
"""

from __future__ import annotations

import os
import sys

from PyQt5.QtCore import QByteArray, QRectF, Qt
from PyQt5.QtGui import QColor, QImage, QPainter
from PyQt5.QtSvg import QSvgRenderer
from PyQt5.QtWidgets import QApplication

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCE = os.path.join(ROOT, "assets", "quenchkey-logo.svg")
SIZES = (16, 32, 64, 256)

#: The application background, so the preview sheet shows the mark in context
#: rather than on white or on transparency.
BACKDROP = "#0F1419"


def render(data: QByteArray, size: int) -> QImage:
    image = QImage(size, size, QImage.Format_ARGB32_Premultiplied)
    image.fill(Qt.transparent)
    painter = QPainter(image)
    painter.setRenderHint(QPainter.Antialiasing, True)
    QSvgRenderer(data).render(painter, QRectF(0, 0, size, size))
    painter.end()
    return image


def main() -> int:
    # The reference matters. QPainter needs a live QApplication, and dropping
    # it on the floor lets Python collect it while Qt is still using it —
    # which shows up as fonts reporting a negative size, and is undefined
    # behaviour rather than merely noisy.
    app = QApplication(sys.argv[:1])
    assert app is not None

    with open(SOURCE, "rb") as fh:
        data = QByteArray(fh.read())

    for size in SIZES:
        target = os.path.join(ROOT, "assets", f"quenchkey-{size}.png")
        render(data, size).save(target)
        print("wrote", os.path.relpath(target, ROOT))

    # A single sheet showing every export side by side, for eyeballing how the
    # mark holds up as it shrinks.
    sheet = QImage(560, 300, QImage.Format_ARGB32)
    sheet.fill(QColor(BACKDROP))
    painter = QPainter(sheet)
    painter.setRenderHint(QPainter.Antialiasing, True)
    x = 24
    for size in sorted(SIZES, reverse=True):
        QSvgRenderer(data).render(painter, QRectF(x, 24, size, size))
        x += size + 28
    painter.end()
    target = os.path.join(ROOT, "assets", "quenchkey-sizes.png")
    sheet.save(target)
    print("wrote", os.path.relpath(target, ROOT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
