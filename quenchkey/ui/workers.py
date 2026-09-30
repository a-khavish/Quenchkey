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

"""Background work.

Every operation that touches a file — deriving a key, packing an archive,
encrypting a few gigabytes — runs on a :class:`QThread` so the window keeps
repainting and stays responsive. The worker reports progress through a signal;
it never touches a widget itself.
"""

from __future__ import annotations

import traceback
from typing import Any, Callable, Optional

from PyQt5.QtCore import QThread, pyqtSignal


class Task(QThread):
    """Runs one callable off the UI thread.

    The callable is handed a ``progress(stage, fraction)`` function it may call
    as often as it likes; those calls are marshalled back to the UI thread by
    Qt's queued connections.
    """

    progress = pyqtSignal(str, float)
    succeeded = pyqtSignal(object)
    failed = pyqtSignal(str, str)

    def __init__(self, fn: Callable[..., Any], *args,
                 error_title: str = "Something went wrong", **kwargs):
        super().__init__()
        self._fn = fn
        self._args = args
        self._kwargs = kwargs
        self._error_title = error_title
        self.result: Any = None
        self.error: Optional[BaseException] = None

    def run(self) -> None:  # noqa: D102 - QThread entry point
        try:
            self.result = self._fn(*self._args, progress=self._emit, **self._kwargs)
        except BaseException as exc:  # noqa: BLE001 - reported, not swallowed
            self.error = exc
            traceback.print_exc()
            self.failed.emit(self._error_title, str(exc) or exc.__class__.__name__)
        else:
            self.succeeded.emit(self.result)

    def _emit(self, stage: str, fraction: float) -> None:
        self.progress.emit(stage, float(fraction))


class KeyDerivationTask(QThread):
    """Argon2id takes about a second by design; it does not belong on the UI thread."""

    succeeded = pyqtSignal(object)
    failed = pyqtSignal(str, str)

    def __init__(self, fn: Callable[[], Any], error_title: str = "Could not open the vault"):
        super().__init__()
        self._fn = fn
        self._error_title = error_title
        self.result: Any = None
        self.error: Optional[BaseException] = None

    def run(self) -> None:  # noqa: D102
        try:
            self.result = self._fn()
        except BaseException as exc:  # noqa: BLE001
            self.error = exc
            self.failed.emit(self._error_title, str(exc) or exc.__class__.__name__)
        else:
            self.succeeded.emit(self.result)
