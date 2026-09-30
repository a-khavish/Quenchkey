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

"""Where a file being written should go — asked once, in one place.

Every screen that writes something comes through here, so "always save these
in ~/Documents" and "ask me every time" are decided once rather than in eight
slightly different ways. Asking always means the desktop's own chooser, which
is also where somebody renames the file on the way out.
"""

from __future__ import annotations

import os
from typing import Optional, Sequence

from .. import settings as settings_mod
from . import filechooser


def folder_for(kind: str, parent, title: str,
               beside: str = "", suggested: str = "") -> Optional[str]:
    """A directory to write into, or None if the chooser was dismissed.

    ``beside`` is the file the output belongs next to, for the kinds where
    that is the sensible default.
    """
    mode, path = settings_mod.current().output_rule(kind)
    if mode == settings_mod.BESIDE and beside:
        return os.path.dirname(os.path.abspath(beside)) or "."
    if mode == settings_mod.FIXED and path:
        return path
    start = suggested or path or (os.path.dirname(os.path.abspath(beside))
                                  if beside else os.path.expanduser("~"))
    return filechooser.choose_directory(parent, title, start)


def file_for(kind: str, parent, title: str, suggested_name: str,
             beside: str = "", patterns: Optional[Sequence[str]] = None,
             confirm_overwrite: bool = True) -> Optional[str]:
    """A full path to write to, or None if the chooser was dismissed.

    With a remembered folder the name is not asked for — that is the point of
    remembering one — so the suggested name is used as it stands, made unique
    rather than overwriting anything.
    """
    mode, path = settings_mod.current().output_rule(kind)

    if mode == settings_mod.BESIDE and beside:
        directory = os.path.dirname(os.path.abspath(beside)) or "."
        return _free(directory, suggested_name)
    if mode == settings_mod.FIXED and path:
        return _free(path, suggested_name)

    start = path or (os.path.dirname(os.path.abspath(beside)) if beside
                     else os.path.expanduser("~"))
    return filechooser.save_file(parent, title,
                                 os.path.join(start, suggested_name),
                                 patterns, confirm_overwrite=confirm_overwrite)


def _free(directory: str, name: str) -> str:
    """A path in ``directory`` that does not already exist.

    Only reached when the chooser was skipped. Nobody was asked, so nobody
    agreed to an overwrite, so nothing is overwritten.
    """
    stem, extension = os.path.splitext(name)
    candidate = os.path.join(directory, name)
    index = 2
    while os.path.exists(candidate):
        candidate = os.path.join(directory, f"{stem} ({index}){extension}")
        index += 1
    return candidate


def describe(kind: str) -> str:
    """One line for a screen to show about where this kind of file goes."""
    mode, path = settings_mod.current().output_rule(kind)
    if mode == settings_mod.BESIDE:
        return "Saved beside the file it came from."
    if mode == settings_mod.FIXED:
        return f"Saved in {path.replace(os.path.expanduser('~'), '~')}."
    return "You will be asked where to save it."
